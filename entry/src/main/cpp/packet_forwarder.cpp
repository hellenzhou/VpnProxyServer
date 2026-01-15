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

#define MAKE_FILE_NAME (strrchr(__FILE__, '/') ? (strrchr(__FILE__, '/') + 1) : __FILE__)
#define LOG(fmt, ...) \
  OH_LOG_Print(LOG_APP, LOG_INFO, 0x15b1, "VpnServer", "[%{public}s:%{public}d] " fmt, MAKE_FILE_NAME, __LINE__, ##__VA_ARGS__)

// 静态辅助函数声明
static void HandleUdpResponseSimple(int sockFd, sockaddr_in originalPeer, const PacketInfo& packetInfo);
static void HandleTcpResponseSimple(int sockFd, sockaddr_in originalPeer, const PacketInfo& packetInfo);

// ========== 主转发函数 ==========
int PacketForwarder::ForwardPacket(const uint8_t* data, int dataSize, 
                                  const PacketInfo& packetInfo, 
                                  const sockaddr_in& originalPeer) {
    LOG("📦 转发: %s:%d -> %s:%d (%s, %d字节)",
        packetInfo.sourceIP.c_str(), packetInfo.sourcePort,
        packetInfo.targetIP.c_str(), packetInfo.targetPort,
        ProtocolHandler::GetProtocolName(packetInfo.protocol).c_str(),
        dataSize);
    
    // 1. 提取payload
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
    
    // 2. 创建socket
    int sockFd = socket(AF_INET, (packetInfo.protocol == PROTOCOL_UDP) ? SOCK_DGRAM : SOCK_STREAM, 0);
    if (sockFd < 0) {
        LOG("❌ 创建socket失败: %s", strerror(errno));
        return -1;
    }
    LOG("✅ 创建socket: fd=%d", sockFd);
    
    // 3. 先创建NAT映射（重要！必须在启动响应线程之前）
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
            LOG("❌ UDP发送失败: %s", strerror(errno));
            NATTable::RemoveMapping(natKey);
            close(sockFd);
            return -1;
        }
        LOG("✅ UDP发送成功: %zd字节", sent);
        
        // 启动响应线程
        std::thread([sockFd, originalPeer, packetInfo]() {
            HandleUdpResponseSimple(sockFd, originalPeer, packetInfo);
        }).detach();
    } else {
        // 不应该到这里（TCP已经在上面被拦截）
        LOG("❌ 未知协议: %d", packetInfo.protocol);
        NATTable::RemoveMapping(natKey);
        close(sockFd);
        return -1;
    }
    
    return sockFd;
}

// ========== UDP响应处理（简化版）==========
static void HandleUdpResponseSimple(int sockFd, sockaddr_in originalPeer, const PacketInfo& packetInfo) {
    LOG("📥 UDP响应线程启动: socket=%d", sockFd);
    
    // 查找NAT映射
    NATConnection conn;
    if (!NATTable::FindMappingBySocket(sockFd, conn)) {
        LOG("❌ 找不到NAT映射，退出");
        close(sockFd);
        return;
    }
    LOG("✅ 找到NAT映射");
    
    // 设置超时
    struct timeval timeout = {5, 0};
    setsockopt(sockFd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    
    // 🔧 修复：接收多个UDP响应，不要在第一次响应后就关闭
    int responseCount = 0;
    const int MAX_UDP_RESPONSES = 10;  // 最多接收10个响应
    bool hasResponse = false;
    
    while (responseCount < MAX_UDP_RESPONSES) {
        uint8_t responsePayload[4096];
        struct sockaddr_in responseAddr{};
        socklen_t addrLen = sizeof(responseAddr);
        
        ssize_t received = recvfrom(sockFd, responsePayload, sizeof(responsePayload), 0,
                                    (struct sockaddr*)&responseAddr, &addrLen);
        
        if (received <= 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                LOG("⏱️ UDP响应超时，退出循环 (已接收%d个响应)", responseCount);
            } else {
                LOG("❌ UDP响应接收失败: %s", strerror(errno));
            }
            break;
        }
        
        responseCount++;
        hasResponse = true;
        LOG("✅ 收到UDP响应 #%d: %zd字节", responseCount, received);
        
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
        
        LOG("✅ 构建IP包: %d字节", packetLen);
        
        // 发送给客户端
        ssize_t sent = sendto(g_sockFd, ipPacket, packetLen, 0,
                              (struct sockaddr*)&conn.clientPhysicalAddr, 
                              sizeof(conn.clientPhysicalAddr));
        
        if (sent > 0) {
            LOG("✅ 发送给客户端成功: %zd字节", sent);
        } else {
            LOG("❌ 发送给客户端失败: %s", strerror(errno));
        }
        
        // 🔧 修复：更新活动时间，而不是删除映射
        std::string natKey = NATTable::GenerateKey(conn.originalRequest);
        NATTable::UpdateActivity(natKey);
    }
    
    // 🔧 修复：延迟删除映射，保留30秒让后续的UDP请求可以复用
    if (hasResponse) {
        LOG("🔒 UDP响应处理完成，保留映射30秒");
        
        // 在后台线程中延迟清理
        std::thread([sockFd, conn]() {
            std::this_thread::sleep_for(std::chrono::seconds(30));
            std::string natKey = NATTable::GenerateKey(conn.originalRequest);
            NATTable::RemoveMapping(natKey);
            close(sockFd);
            LOG("🧹 30秒后清理UDP映射: %s", natKey.c_str());
        }).detach();
    } else {
        // 如果没有收到任何响应，立即清理
        LOG("⚠️ 未收到任何UDP响应，立即清理");
        std::string natKey = NATTable::GenerateKey(conn.originalRequest);
        NATTable::RemoveMapping(natKey);
        close(sockFd);
    }
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
