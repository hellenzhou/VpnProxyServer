/*
 * 极简VPN服务器转发器 - 专注于让基本功能工作
 * 目标：确保单个PC的网络访问能被代理
 */

#include "packet_forwarder.h"
#include "vpn_server_globals.h"
#include "packet_builder.h"
#include "nat_table.h"
#include <hilog/log.h>
#include <thread>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <cstring>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <map>
#include <chrono>
#include <mutex>

#define MAKE_FILE_NAME (strrchr(__FILE__, '/') ? (strrchr(__FILE__, '/') + 1) : __FILE__)
#define LOG(fmt, ...) \
  OH_LOG_Print(LOG_APP, LOG_INFO, 0x15b1, "VpnServer", "[%{public}s:%{public}d] " fmt, MAKE_FILE_NAME, __LINE__, ##__VA_ARGS__)

// 静态辅助函数声明
static void HandleUdpResponseSimple(int sockFd, sockaddr_in originalPeer, const PacketInfo& packetInfo);
static void HandleTcpResponseSimple(int sockFd, sockaddr_in originalPeer, const PacketInfo& packetInfo);

// 🔧 数据包去重缓存（防止循环转发）
static std::map<std::string, std::chrono::steady_clock::time_point> g_recentPackets;
static std::mutex g_recentPacketsMutex;

// 🔧 Socket复用缓存（避免频繁创建/销毁socket）
static std::map<std::string, int> g_socketCache;
static std::mutex g_socketCacheMutex;

// ========== 主转发函数 ==========
int PacketForwarder::ForwardPacket(const uint8_t* data, int dataSize, 
                                  const PacketInfo& packetInfo, 
                                  const sockaddr_in& originalPeer) {
    LOG("📦 转发: %s:%d -> %s:%d (%s, %d字节)",
        packetInfo.sourceIP.c_str(), packetInfo.sourcePort,
        packetInfo.targetIP.c_str(), packetInfo.targetPort,
        ProtocolHandler::GetProtocolName(packetInfo.protocol).c_str(),
        dataSize);
    
    // 🔧 1. 防止路由循环：检测重复数据包
    std::string packetHash;
    {
        // 使用数据包关键信息生成hash
        char hashBuf[256];
        snprintf(hashBuf, sizeof(hashBuf), "%s:%d->%s:%d:%d",
                packetInfo.sourceIP.c_str(), packetInfo.sourcePort,
                packetInfo.targetIP.c_str(), packetInfo.targetPort,
                dataSize);
        packetHash = std::string(hashBuf);
        
        std::lock_guard<std::mutex> lock(g_recentPacketsMutex);
        auto now = std::chrono::steady_clock::now();
        
        // 清理过期的数据包记录（超过1秒）
        for (auto it = g_recentPackets.begin(); it != g_recentPackets.end();) {
            if (std::chrono::duration_cast<std::chrono::milliseconds>(now - it->second).count() > 1000) {
                it = g_recentPackets.erase(it);
            } else {
                ++it;
            }
        }
        
        // 检查是否是重复数据包（100ms内的重复认为是循环）
        auto it = g_recentPackets.find(packetHash);
        if (it != g_recentPackets.end()) {
            auto timeSinceLastSeen = std::chrono::duration_cast<std::chrono::milliseconds>(now - it->second).count();
            if (timeSinceLastSeen < 100) {
                LOG("⚠️ 检测到可能的路由循环！拒绝转发重复数据包 (间隔%lldms): %s",
                    timeSinceLastSeen, packetHash.c_str());
                return -1;
            }
        }
        
        // 记录本次数据包
        g_recentPackets[packetHash] = now;
    }
    
    // 2. 提取payload
    const uint8_t* payload = nullptr;
    int payloadSize = 0;
    if (!PacketBuilder::ExtractPayload(data, dataSize, packetInfo, &payload, &payloadSize)) {
        LOG("❌ 提取payload失败");
        return -1;
    }
    
    if (payloadSize <= 0) {
        LOG("⚠️ payload为空，跳过");
        return 0;
    }
    
    LOG("✅ 提取payload: %d字节", payloadSize);
    
    // 🔧 3. Socket复用：检查是否已有可用socket
    std::string socketKey = packetInfo.targetIP + ":" + std::to_string(packetInfo.targetPort);
    int sockFd = -1;
    bool isNewSocket = false;
    
    {
        std::lock_guard<std::mutex> lock(g_socketCacheMutex);
        auto it = g_socketCache.find(socketKey);
        if (it != g_socketCache.end()) {
            sockFd = it->second;
            // 验证socket是否仍然有效
            int error = 0;
            socklen_t len = sizeof(error);
            if (getsockopt(sockFd, SOL_SOCKET, SO_ERROR, &error, &len) == 0 && error == 0) {
                LOG("♻️ 复用已有socket: fd=%d, key=%s", sockFd, socketKey.c_str());
            } else {
                LOG("⚠️ 缓存的socket无效，将创建新socket");
                close(sockFd);
                g_socketCache.erase(it);
                sockFd = -1;
            }
        }
    }
    
    // 如果没有可用socket，创建新的
    if (sockFd < 0) {
        sockFd = socket(AF_INET, (packetInfo.protocol == PROTOCOL_UDP) ? SOCK_DGRAM : SOCK_STREAM, 0);
        if (sockFd < 0) {
            LOG("❌ 创建socket失败: %s", strerror(errno));
            return -1;
        }
        isNewSocket = true;
        
        // 添加到缓存
        std::lock_guard<std::mutex> lock(g_socketCacheMutex);
        g_socketCache[socketKey] = sockFd;
        LOG("✅ 创建新socket: fd=%d, key=%s", sockFd, socketKey.c_str());
    }
    
    // 4. 先创建NAT映射（重要！必须在启动响应线程之前）
    std::string natKey = NATTable::GenerateKey(packetInfo);
    NATTable::CreateMapping(natKey, originalPeer, packetInfo, sockFd);
    LOG("✅ NAT映射已创建: %s", natKey.c_str());
    
    // 4. 配置目标地址
    struct sockaddr_in targetAddr{};
    targetAddr.sin_family = AF_INET;
    targetAddr.sin_port = htons(packetInfo.targetPort);
    inet_pton(AF_INET, packetInfo.targetIP.c_str(), &targetAddr.sin_addr);
    
    // 5. 根据协议转发
    // 🔧 临时修复：暂时只支持UDP
    if (packetInfo.protocol == PROTOCOL_TCP) {
        LOG("⚠️ TCP暂不支持，跳过此包（仅支持UDP/DNS）");
        NATTable::RemoveMapping(natKey);
        close(sockFd);
        return -1;
    }
    
    if (packetInfo.protocol == PROTOCOL_UDP) {
        // UDP：直接发送
        ssize_t sent = sendto(sockFd, payload, payloadSize, 0, 
                             (struct sockaddr*)&targetAddr, sizeof(targetAddr));
        if (sent < 0) {
            LOG("❌ UDP发送失败: socket=%d, errno=%d (%s), target=%s:%d, size=%d", 
                sockFd, errno, strerror(errno), 
                packetInfo.targetIP.c_str(), packetInfo.targetPort, payloadSize);
            NATTable::RemoveMapping(natKey);
            // 🔧 只有新socket才关闭，复用的socket保留在缓存中
            if (isNewSocket) {
                std::lock_guard<std::mutex> lock(g_socketCacheMutex);
                g_socketCache.erase(socketKey);
                close(sockFd);
            }
            return -1;
        }
        LOG("✅ UDP发送成功: socket=%d, %zd字节 -> %s:%d", 
            sockFd, sent, packetInfo.targetIP.c_str(), packetInfo.targetPort);
        
        // 🔧 只有新socket才启动响应线程，复用socket的响应线程已在运行
        if (isNewSocket) {
            LOG("🚀 启动新的UDP响应线程 for socket %d", sockFd);
            std::thread([sockFd, originalPeer, packetInfo, socketKey]() {
                LOG("🔥🔥🔥 响应线程已进入 - socket=%d 🔥🔥🔥", sockFd);
                HandleUdpResponseSimple(sockFd, originalPeer, packetInfo);
                
                // 响应线程结束时，从缓存中删除socket
                std::lock_guard<std::mutex> lock(g_socketCacheMutex);
                g_socketCache.erase(socketKey);
                LOG("🔥🔥🔥 响应线程已退出 - socket=%d 🔥🔥🔥", sockFd);
            }).detach();
        } else {
            LOG("♻️ 复用现有响应线程 for socket %d", sockFd);
        }
    } else {
        // 不应该到这里（TCP已经在上面被拦截）
        LOG("❌ 未知协议: %d", packetInfo.protocol);
        NATTable::RemoveMapping(natKey);
        if (isNewSocket) {
            std::lock_guard<std::mutex> lock(g_socketCacheMutex);
            g_socketCache.erase(socketKey);
            close(sockFd);
        }
        return -1;
    }
    
    return sockFd;
}

// ========== UDP响应处理（改进版：持续监听）==========
static void HandleUdpResponseSimple(int sockFd, sockaddr_in originalPeer, const PacketInfo& packetInfo) {
    LOG("📥📥📥 UDP响应线程启动: socket=%d, 目标=%s:%d 📥📥📥", 
        sockFd, packetInfo.targetIP.c_str(), packetInfo.targetPort);
    
    // 设置短超时（200ms），这样可以快速检查是否有响应
    struct timeval timeout = {0, 200000};  // 200ms
    int ret = setsockopt(sockFd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    if (ret < 0) {
        LOG("❌ 设置socket超时失败: %s", strerror(errno));
    }
    
    int consecutiveTimeouts = 0;
    const int MAX_CONSECUTIVE_TIMEOUTS = 50;  // 50次超时 = 10秒无活动后退出
    int totalResponses = 0;
    
    // 🔧 持续监听响应，直到长时间无活动
    LOG("🔄 开始持续监听UDP响应... socket=%d", sockFd);
    while (consecutiveTimeouts < MAX_CONSECUTIVE_TIMEOUTS) {
        // 每次循环都重新查找NAT映射（可能已被更新）
        NATConnection conn;
        if (!NATTable::FindMappingBySocket(sockFd, conn)) {
            LOG("❌ NAT映射已被删除，退出响应线程 socket=%d", sockFd);
            break;
        }
        
        uint8_t responsePayload[4096];
        struct sockaddr_in responseAddr{};
        socklen_t addrLen = sizeof(responseAddr);
        
        ssize_t received = recvfrom(sockFd, responsePayload, sizeof(responsePayload), 0,
                                    (struct sockaddr*)&responseAddr, &addrLen);
        
        if (received <= 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                consecutiveTimeouts++;
                // 第1次、第5次和每隔25次打印一次状态（避免日志爆炸）
                if (consecutiveTimeouts == 1 || consecutiveTimeouts == 5 || consecutiveTimeouts % 25 == 0) {
                    LOG("⏱️ UDP响应线程等待中... socket=%d (已收%d个响应, 空闲%.1f秒)",
                        sockFd, totalResponses, consecutiveTimeouts * 0.2);
                }
                continue;
            } else {
                LOG("❌ UDP响应接收失败: socket=%d, errno=%d (%s)", sockFd, errno, strerror(errno));
                break;
            }
        }
        
        // 收到响应，重置超时计数
        consecutiveTimeouts = 0;
        totalResponses++;
        LOG("✅✅✅ 收到UDP响应 #%d: socket=%d, %zd字节 ✅✅✅", totalResponses, sockFd, received);
        
        // 封装成IP包
        uint8_t ipPacket[4096 + 60];
        int packetLen = PacketBuilder::BuildResponsePacket(
            ipPacket, sizeof(ipPacket),
            responsePayload, received,
            conn.originalRequest
        );
        
        if (packetLen < 0) {
            LOG("❌ 构建响应包失败");
            continue;
        }
        
        // 发送给客户端
        ssize_t sent = sendto(g_sockFd, ipPacket, packetLen, 0,
                              (struct sockaddr*)&conn.clientPhysicalAddr, 
                              sizeof(conn.clientPhysicalAddr));
        
        if (sent > 0) {
            LOG("✅ 发送给客户端成功: %zd字节", sent);
        } else {
            LOG("❌ 发送给客户端失败: %s", strerror(errno));
        }
        
        // 更新活动时间
        std::string natKey = NATTable::GenerateKey(conn.originalRequest);
        NATTable::UpdateActivity(natKey);
    }
    
    // 清理
    LOG("🔒 UDP响应线程退出: 总共接收%d个响应", totalResponses);
    std::string natKey = NATTable::GenerateKey(packetInfo);
    NATTable::RemoveMapping(natKey);
    close(sockFd);
    LOG("🧹 清理完成: socket=%d", sockFd);
}

// ========== TCP响应处理（简化版）==========
static void HandleTcpResponseSimple(int sockFd, sockaddr_in originalPeer, const PacketInfo& packetInfo) {
    LOG("📥 TCP响应线程启动: socket=%d", sockFd);
    
    // 查找NAT映射
    NATConnection conn;
    if (!NATTable::FindMappingBySocket(sockFd, conn)) {
        LOG("❌ 找不到NAT映射，退出");
        close(sockFd);
        return;
    }
    LOG("✅ 找到NAT映射");
    
    // 设置超时
    struct timeval timeout = {30, 0};
    setsockopt(sockFd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    
    uint8_t responsePayload[4096];
    
    while (true) {
        ssize_t received = recv(sockFd, responsePayload, sizeof(responsePayload), 0);
        
        if (received <= 0) {
            if (received == 0) {
                LOG("🔚 TCP连接关闭");
            } else {
                LOG("❌ TCP响应接收失败: %s", strerror(errno));
            }
            break;
        }
        
        LOG("✅ 收到TCP响应: %zd字节", received);
        
        // 封装成IP包
        uint8_t ipPacket[4096 + 60];
        int packetLen = PacketBuilder::BuildResponsePacket(
            ipPacket, sizeof(ipPacket),
            responsePayload, received,
            conn.originalRequest
        );
        
        if (packetLen < 0) {
            LOG("❌ 构建响应包失败");
            break;
        }
        
        LOG("✅ 构建IP包: %d字节", packetLen);
        
        // 发送给客户端
        ssize_t sent = sendto(g_sockFd, ipPacket, packetLen, 0,
                             (struct sockaddr*)&conn.clientPhysicalAddr,
                             sizeof(conn.clientPhysicalAddr));
        
        if (sent > 0) {
            LOG("✅ 发送给客户端成功: %zd字节", sent);
        } else {
            LOG("❌ 发送给客户端失败: %s", strerror(errno));
            break;
        }
        
        // 更新活动时间
        std::string natKey = NATTable::GenerateKey(conn.originalRequest);
        NATTable::UpdateActivity(natKey);
    }
    
    // 清理
    std::string natKey = NATTable::GenerateKey(conn.originalRequest);
    NATTable::RemoveMapping(natKey);
    close(sockFd);
    LOG("🔒 清理完成");
}

// ========== 辅助函数 ==========
int PacketForwarder::CreateSocket(int addressFamily, uint8_t protocol) {
    int sockType = (protocol == PROTOCOL_UDP) ? SOCK_DGRAM : SOCK_STREAM;
    return socket(addressFamily, sockType, 0);
}

// 兼容旧接口
int PacketForwarder::HandleUDPForwarding(int sockFd, const uint8_t* payload, int payloadSize,
                                        const PacketInfo& packetInfo,
                                        int addressFamily, const sockaddr_in& originalPeer) {
    return sockFd;  // 在ForwardPacket中已处理
}

int PacketForwarder::HandleTCPForwarding(int sockFd, const uint8_t* payload, int payloadSize,
                                        const PacketInfo& packetInfo,
                                        int addressFamily, const sockaddr_in& originalPeer) {
    return sockFd;  // 在ForwardPacket中已处理
}

void PacketForwarder::HandleUdpResponse(int sockFd, sockaddr_in originalPeer, const PacketInfo& packetInfo) {
    HandleUdpResponseSimple(sockFd, originalPeer, packetInfo);
}

void PacketForwarder::HandleTcpResponse(int sockFd, sockaddr_in originalPeer, const PacketInfo& packetInfo) {
    HandleTcpResponseSimple(sockFd, originalPeer, packetInfo);
}

bool PacketForwarder::IsDNSQuery(const std::string& targetIP, int targetPort) {
    return targetPort == 53;
}

bool PacketForwarder::TestNetworkConnectivity() {
    return true;
}
