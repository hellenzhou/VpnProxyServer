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
#include <sys/select.h>
#include <netinet/tcp.h>
#include <ctime>
#include <map>
#include <chrono>  // 仅用于 sleep_for
#include <mutex>

#define MAKE_FILE_NAME (strrchr(__FILE__, '/') ? (strrchr(__FILE__, '/') + 1) : __FILE__)
#define LOG(fmt, ...) \
  OH_LOG_Print(LOG_APP, LOG_INFO, 0x15b1, "VpnServer", "[%{public}s:%{public}d] " fmt, MAKE_FILE_NAME, __LINE__, ##__VA_ARGS__)

// 静态辅助函数声明
static void HandleUdpResponseSimple(int sockFd, sockaddr_in originalPeer, const PacketInfo& packetInfo);
static void HandleTcpResponseSimple(int sockFd, sockaddr_in originalPeer, const PacketInfo& packetInfo);

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
    
    // ✅ 路由循环已通过 vpnConnection.protect(tunnelFd) 防止
    // 无需额外的重复数据包检测，让所有合法请求正常转发
    
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
        // 根据协议选择socket类型和地址族
        int addressFamily = packetInfo.addressFamily;
        int sockType = SOCK_DGRAM;
        int protocol = 0;
        
        if (packetInfo.protocol == PROTOCOL_ICMPV6) {
            // ICMPv6 需要使用 RAW socket 和 IPv6
            addressFamily = AF_INET6;
            sockType = SOCK_RAW;
            protocol = IPPROTO_ICMPV6;
            LOG("🔧 创建ICMPv6 RAW socket");
        } else if (packetInfo.protocol == PROTOCOL_UDP) {
            sockType = SOCK_DGRAM;
        } else if (packetInfo.protocol == PROTOCOL_TCP) {
            sockType = SOCK_STREAM;
        }
        
        sockFd = socket(addressFamily, sockType, protocol);
        if (sockFd < 0) {
            LOG("❌ 创建socket失败: %s (family=%d, type=%d, proto=%d)", 
                strerror(errno), addressFamily, sockType, protocol);
            return -1;
        }
        isNewSocket = true;
        
        // 添加到缓存
        std::lock_guard<std::mutex> lock(g_socketCacheMutex);
        g_socketCache[socketKey] = sockFd;
        LOG("✅ 创建新socket: fd=%d, key=%s, type=%d", sockFd, socketKey.c_str(), sockType);
    }
    
    // 4. 先创建NAT映射（重要！必须在启动响应线程之前）
    std::string natKey = NATTable::GenerateKey(packetInfo);
    NATTable::CreateMapping(natKey, originalPeer, packetInfo, sockFd);
    LOG("✅ NAT映射已创建: %s", natKey.c_str());
    
    // 4. 🔧 DNS重定向：如果是DNS查询且目标是223.5.5.5，重定向到8.8.8.8
    std::string actualTargetIP = packetInfo.targetIP;
    if (packetInfo.targetPort == 53 && packetInfo.targetIP == "223.5.5.5") {
        actualTargetIP = "8.8.8.8";
        LOG("🔄 DNS重定向: %s:%d -> %s:%d", packetInfo.targetIP.c_str(), packetInfo.targetPort, actualTargetIP.c_str(), packetInfo.targetPort);
    }
    
    // 5. 配置目标地址（根据地址族）
    struct sockaddr_in targetAddr{};
    struct sockaddr_in6 targetAddr6{};
    struct sockaddr* pTargetAddr = nullptr;
    socklen_t targetAddrLen = 0;
    
    if (packetInfo.addressFamily == AF_INET6 || packetInfo.protocol == PROTOCOL_ICMPV6) {
        // IPv6 地址
        targetAddr6.sin6_family = AF_INET6;
        targetAddr6.sin6_port = htons(packetInfo.targetPort);
        inet_pton(AF_INET6, actualTargetIP.c_str(), &targetAddr6.sin6_addr);
        pTargetAddr = (struct sockaddr*)&targetAddr6;
        targetAddrLen = sizeof(targetAddr6);
    } else {
        // IPv4 地址
        targetAddr.sin_family = AF_INET;
        targetAddr.sin_port = htons(packetInfo.targetPort);
        inet_pton(AF_INET, actualTargetIP.c_str(), &targetAddr.sin_addr);
        pTargetAddr = (struct sockaddr*)&targetAddr;
        targetAddrLen = sizeof(targetAddr);
    }
    
    // 5. 根据协议转发
    if (packetInfo.protocol == PROTOCOL_TCP) {
        // 🔧 新增：TCP转发支持
        LOG("🔗 处理TCP连接: %s:%d", actualTargetIP.c_str(), packetInfo.targetPort);
        
        // 连接到目标服务器
        int connectResult = connect(sockFd, pTargetAddr, targetAddrLen);
        if (connectResult < 0) {
            LOG("❌ TCP连接失败: socket=%d, errno=%d (%s), target=%s:%d", 
                sockFd, errno, strerror(errno), 
                actualTargetIP.c_str(), packetInfo.targetPort);
            NATTable::RemoveMapping(natKey);
            if (isNewSocket) {
                std::lock_guard<std::mutex> lock(g_socketCacheMutex);
                g_socketCache.erase(socketKey);
                close(sockFd);
            }
            return -1;
        }
        
        LOG("✅ TCP连接成功: socket=%d -> %s:%d", 
            sockFd, actualTargetIP.c_str(), packetInfo.targetPort);
        
        // 发送TCP数据
        ssize_t sent = send(sockFd, payload, payloadSize, 0);
        if (sent < 0) {
            LOG("❌ TCP发送失败: socket=%d, errno=%d (%s)", 
                sockFd, errno, strerror(errno));
            NATTable::RemoveMapping(natKey);
            if (isNewSocket) {
                std::lock_guard<std::mutex> lock(g_socketCacheMutex);
                g_socketCache.erase(socketKey);
                close(sockFd);
            }
            return -1;
        }
        
        LOG("✅ TCP发送成功: socket=%d, %zd字节 -> %s:%d", 
            sockFd, sent, actualTargetIP.c_str(), packetInfo.targetPort);
        
        // 🔧 启动TCP响应线程
        if (isNewSocket) {
            LOG("🚀 启动新的TCP响应线程 for socket %d", sockFd);
            std::thread([sockFd, originalPeer, packetInfo, socketKey]() {
                LOG("🔥🔥🔥 TCP响应线程已进入 - socket=%d 🔥🔥🔥", sockFd);
                HandleTcpResponseSimple(sockFd, originalPeer, packetInfo);
                
                // 响应线程结束时，从缓存中删除socket
                std::lock_guard<std::mutex> lock(g_socketCacheMutex);
                g_socketCache.erase(socketKey);
                LOG("🔥🔥🔥 TCP响应线程已退出 - socket=%d 🔥🔥🔥", sockFd);
            }).detach();
        } else {
            LOG("♻️ 复用现有TCP响应线程 for socket %d", sockFd);
        }
        
        return sockFd;
    }
    
    if (packetInfo.protocol == PROTOCOL_UDP) {
        // 🔧 优化：UDP发送重试机制
        ssize_t sent = -1;
        int retryCount = 0;
        const int maxRetries = 3;
        
        while (sent < 0 && retryCount < maxRetries) {
            sent = sendto(sockFd, payload, payloadSize, 0, 
                         pTargetAddr, targetAddrLen);
            
            if (sent < 0) {
                retryCount++;
                LOG("⚠️ UDP发送失败，重试 %d/%d: socket=%d, errno=%d (%s)", 
                    retryCount, maxRetries, sockFd, errno, strerror(errno));
                
                if (retryCount < maxRetries) {
                    // 短暂延迟后重试
                    std::this_thread::sleep_for(std::chrono::milliseconds(10));
                    
                    // 🔧 检查socket状态
                    int error = 0;
                    socklen_t len = sizeof(error);
                    if (getsockopt(sockFd, SOL_SOCKET, SO_ERROR, &error, &len) == 0 && error != 0) {
                        LOG("❌ Socket错误，停止重试: %s", strerror(error));
                        break;
                    }
                }
            }
        }
        
        if (sent < 0) {
            LOG("❌ UDP发送最终失败: socket=%d, errno=%d (%s), target=%s:%d, size=%d, 重试次数=%d", 
                sockFd, errno, strerror(errno), 
                actualTargetIP.c_str(), packetInfo.targetPort, payloadSize, retryCount);
            NATTable::RemoveMapping(natKey);
            // 🔧 只有新socket才关闭，复用的socket保留在缓存中
            if (isNewSocket) {
                std::lock_guard<std::mutex> lock(g_socketCacheMutex);
                g_socketCache.erase(socketKey);
                close(sockFd);
            }
            return -1;
        }
        
        LOG("✅ UDP发送成功: socket=%d, %zd字节 -> %s:%d (重试次数=%d)", 
            sockFd, sent, actualTargetIP.c_str(), packetInfo.targetPort, retryCount);
        
        // 🔧 优化：确保每个socket都有响应线程
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
            // 🔧 修复：复用socket时也要确保响应线程存在
            LOG("♻️ 复用现有响应线程 for socket %d", sockFd);
            // 验证响应线程是否还在运行，如果不在则重新启动
            static std::map<int, std::thread::id> socketThreadMap;
            static std::mutex threadMapMutex;
            
            std::lock_guard<std::mutex> threadLock(threadMapMutex);
            if (socketThreadMap.find(sockFd) == socketThreadMap.end()) {
                LOG("⚠️ 检测到响应线程丢失，重新启动 for socket %d", sockFd);
                std::thread([sockFd, originalPeer, packetInfo, socketKey]() {
                    socketThreadMap[sockFd] = std::this_thread::get_id();
                    LOG("🔄 重启响应线程 - socket=%d", sockFd);
                    HandleUdpResponseSimple(sockFd, originalPeer, packetInfo);
                    
                    // 清理线程映射
                    std::lock_guard<std::mutex> lock(threadMapMutex);
                    socketThreadMap.erase(sockFd);
                    std::lock_guard<std::mutex> cacheLock(g_socketCacheMutex);
                    g_socketCache.erase(socketKey);
                    LOG("🔄 重启响应线程退出 - socket=%d", sockFd);
                }).detach();
            }
        }
    } else if (packetInfo.protocol == PROTOCOL_ICMPV6) {
        // ICMPv6 处理
        LOG("🧊 处理ICMPv6消息: Type=%d -> %s", packetInfo.icmpv6Type, actualTargetIP.c_str());
        
        // 发送ICMPv6数据包（整个IP包，包含IPv6头和ICMPv6数据）
        ssize_t sent = sendto(sockFd, data, dataSize, 0, pTargetAddr, targetAddrLen);
        
        if (sent < 0) {
            LOG("❌ ICMPv6发送失败: socket=%d, errno=%d (%s), target=%s, type=%d", 
                sockFd, errno, strerror(errno), actualTargetIP.c_str(), packetInfo.icmpv6Type);
            NATTable::RemoveMapping(natKey);
            if (isNewSocket) {
                std::lock_guard<std::mutex> lock(g_socketCacheMutex);
                g_socketCache.erase(socketKey);
                close(sockFd);
            }
            return -1;
        }
        
        LOG("✅ ICMPv6发送成功: socket=%d, %zd字节 -> %s, Type=%d", 
            sockFd, sent, actualTargetIP.c_str(), packetInfo.icmpv6Type);
        
        // ICMPv6 通常不需要响应线程（除了 Echo Request/Reply）
        // 但为了统一处理，我们还是启动一个
        if (isNewSocket && (packetInfo.icmpv6Type == ICMPV6_ECHO_REQUEST || 
                            packetInfo.icmpv6Type == ICMPV6_ECHO_REPLY)) {
            LOG("🚀 启动ICMPv6响应线程 for socket %d", sockFd);
            std::thread([sockFd, originalPeer, packetInfo, socketKey]() {
                LOG("🔥 ICMPv6响应线程已进入 - socket=%d", sockFd);
                // 使用类似 UDP 的响应处理
                HandleUdpResponseSimple(sockFd, originalPeer, packetInfo);
                
                std::lock_guard<std::mutex> lock(g_socketCacheMutex);
                g_socketCache.erase(socketKey);
                LOG("🔥 ICMPv6响应线程已退出 - socket=%d", sockFd);
            }).detach();
        } else if (!isNewSocket) {
            LOG("♻️ 复用现有ICMPv6响应线程 for socket %d", sockFd);
        } else {
            LOG("ℹ️  ICMPv6 Type=%d 不需要响应线程", packetInfo.icmpv6Type);
        }
    } else {
        // 不应该到这里
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

// ========== UDP响应处理（稳健版：持续监听）==========
static void HandleUdpResponseSimple(int sockFd, sockaddr_in originalPeer, const PacketInfo& packetInfo) {
    LOG("📥📥📥 UDP响应线程启动: socket=%d, 目标=%s:%d 📥📥📥", 
        sockFd, packetInfo.targetIP.c_str(), packetInfo.targetPort);
    
    // 🔧 优化：根据协议类型设置不同的超时策略
    struct timeval timeout;
    if (packetInfo.targetPort == 53) {
        // DNS查询：短超时，快速响应
        timeout = {0, 100000};  // 100ms
    } else {
        // 其他UDP：较长超时
        timeout = {0, 500000};  // 500ms
    }
    
    int ret = setsockopt(sockFd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    if (ret < 0) {
        LOG("❌ 设置socket超时失败: %s", strerror(errno));
    } else {
        LOG("✅ socket超时设置成功: %ldms", timeout.tv_usec / 1000);
    }
    
    // 🔧 优化：动态调整超时限制
    int consecutiveTimeouts = 0;
    int maxTimeouts = (packetInfo.targetPort == 53) ? 30 : 20;  // DNS: 3秒, 其他: 2秒
    int totalResponses = 0;
    int lastActivityTime = time(nullptr);
    
    // 🔧 优化：添加socket状态检查
    int lastErrorCheck = time(nullptr);
    
    LOG("🔄 开始持续监听UDP响应... socket=%d, 超时限制=%d", sockFd, maxTimeouts);
    while (consecutiveTimeouts < maxTimeouts) {
        // 🔧 每5秒检查一次socket状态
        int currentTime = time(nullptr);
        if (currentTime - lastErrorCheck >= 5) {
            lastErrorCheck = currentTime;
            
            int error = 0;
            socklen_t len = sizeof(error);
            if (getsockopt(sockFd, SOL_SOCKET, SO_ERROR, &error, &len) == 0 && error != 0) {
                LOG("❌ Socket错误检测: %s，退出响应线程", strerror(error));
                break;
            }
        }
        
        // 每次循环都重新查找NAT映射（可能已被更新）
        NATConnection conn;
        if (!NATTable::FindMappingBySocket(sockFd, conn)) {
            LOG("❌ NAT映射已被删除，退出响应线程 socket=%d", sockFd);
            break;
        }
        
        uint8_t responsePayload[4096];
        struct sockaddr_in responseAddr{};
        socklen_t addrLen = sizeof(responseAddr);
        
        // 🔧 调试：记录接收尝试
        LOG("🔍 尝试接收UDP响应... socket=%d", sockFd);
        ssize_t received = recvfrom(sockFd, responsePayload, sizeof(responsePayload), 0,
                                    (struct sockaddr*)&responseAddr, &addrLen);
        
        if (received <= 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                consecutiveTimeouts++;
                lastActivityTime = currentTime;
                
                // 🔧 优化：减少日志频率，避免日志爆炸
                if (consecutiveTimeouts == 1 || consecutiveTimeouts == 5 || consecutiveTimeouts % 10 == 0) {
                    LOG("⏱️ UDP响应线程等待中... socket=%d (已收%d个响应, 空闲%.1f秒)",
                        sockFd, totalResponses, consecutiveTimeouts * 0.1);
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
        
        // 🔧 验证响应来源
        char responseIP[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &responseAddr.sin_addr, responseIP, INET_ADDRSTRLEN);
        if (strcmp(responseIP, packetInfo.targetIP.c_str()) != 0) {
            LOG("⚠️ 响应来源不匹配: 期望%s，实际%s", packetInfo.targetIP.c_str(), responseIP);
            continue;
        }
        
        LOG("✅✅✅ 收到UDP响应: socket=%d, %zd字节, 来源=%s:%d", 
            sockFd, received, responseIP, ntohs(responseAddr.sin_port));
        
        // 🔧 优化：添加响应内容摘要（仅DNS）
        if (packetInfo.targetPort == 53 && received >= 12) {
            // DNS响应前12字节包含头部信息
            uint16_t dnsId = (responsePayload[0] << 8) | responsePayload[1];
            uint8_t flags = responsePayload[2];
            uint8_t rcode = flags & 0x0F;
            uint16_t answerCount = (responsePayload[6] << 8) | responsePayload[7];
            
            LOG("🔍 DNS响应详情: ID=%d, 标志=0x%02X, RCODE=%d, 答案数=%d", 
                dnsId, flags, rcode, answerCount);
        }
        
        // 🔧 优化：重试发送给客户端
        int sendRetries = 3;
        bool sendSuccess = false;
        
        while (sendRetries > 0 && !sendSuccess) {
            ssize_t sent = sendto(g_sockFd, responsePayload, received, 0,
                                (struct sockaddr*)&originalPeer, sizeof(originalPeer));
            
            if (sent == received) {
                LOG("✅ 响应已发送给客户端: %zd字节", sent);
                sendSuccess = true;
            } else {
                sendRetries--;
                if (sendRetries > 0) {
                    LOG("⚠️ 发送响应失败，重试中... 剩余次数=%d", sendRetries);
                    std::this_thread::sleep_for(std::chrono::milliseconds(10));
                } else {
                    LOG("❌ 发送给客户端失败: %s", strerror(errno));
                }
            }
        }
        
        if (sendSuccess) {
            // 更新活动时间
            std::string natKey = NATTable::GenerateKey(packetInfo);
            NATTable::UpdateActivity(natKey);
        }
    }
    
    // 清理
    LOG("🔒 UDP响应线程退出: 总共接收%d个响应", totalResponses);
    std::string natKey = NATTable::GenerateKey(packetInfo);
    NATTable::RemoveMapping(natKey);
    close(sockFd);
    LOG("🧹 清理完成: socket=%d", sockFd);
}

// ========== TCP响应处理（增强版）==========
static void HandleTcpResponseSimple(int sockFd, sockaddr_in originalPeer, const PacketInfo& packetInfo) {
    LOG("📥 TCP响应线程启动: socket=%d, 目标=%s:%d", sockFd, packetInfo.targetIP.c_str(), packetInfo.targetPort);
    
    // 🔧 优化：设置TCP socket选项
    int nodelay = 1;
    setsockopt(sockFd, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));
    
    // 设置接收超时
    struct timeval timeout = {30, 0};  // 30秒超时
    setsockopt(sockFd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(sockFd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    
    // 查找NAT映射
    NATConnection conn;
    if (!NATTable::FindMappingBySocket(sockFd, conn)) {
        LOG("❌ 找不到NAT映射，退出TCP响应线程");
        close(sockFd);
        return;
    }
    LOG("✅ 找到NAT映射: %s", conn.originalRequest.sourceIP.c_str());
    
    uint8_t responsePayload[4096];
    int totalResponses = 0;
    
    LOG("🔄 开始TCP数据转发... socket=%d", sockFd);
    while (true) {
        ssize_t received = recv(sockFd, responsePayload, sizeof(responsePayload), 0);
        
        if (received <= 0) {
            if (received == 0) {
                LOG("🔚 TCP连接关闭: socket=%d", sockFd);
            } else {
                LOG("❌ TCP响应接收失败: socket=%d, errno=%d (%s)", sockFd, errno, strerror(errno));
            }
            break;
        }
        
        totalResponses++;
        LOG("✅ 收到TCP响应 #%d: socket=%d, %zd字节", totalResponses, sockFd, received);
        
        // 🔧 调试：记录TCP响应内容
        if (received >= 20) {
            // 检查是否是HTTP响应
            if (strncmp((char*)responsePayload, "HTTP/", 5) == 0) {
                LOG("🌐 检测到HTTP响应: %.20s...", responsePayload);
            }
        }
        
        // 封装成IP包
        uint8_t ipPacket[4096 + 60];
        int packetLen = PacketBuilder::BuildResponsePacket(
            ipPacket, sizeof(ipPacket),
            responsePayload, received,
            conn.originalRequest
        );
        
        if (packetLen < 0) {
            LOG("❌ 构建TCP响应包失败");
            continue;
        }
        
        LOG("✅ 构建TCP IP包: %d字节", packetLen);
        
        // 🔧 优化：TCP响应发送重试
        int tcpRetryCount = 0;
        const int maxTcpRetries = 3;
        bool tcpSendSuccess = false;
        
        while (!tcpSendSuccess && tcpRetryCount < maxTcpRetries) {
            ssize_t sent = sendto(g_sockFd, ipPacket, packetLen, 0,
                                 (struct sockaddr*)&conn.clientPhysicalAddr,
                                 sizeof(conn.clientPhysicalAddr));
            
            if (sent == packetLen) {
                LOG("✅ TCP响应发送成功: %zd字节", sent);
                tcpSendSuccess = true;
            } else {
                tcpRetryCount++;
                if (tcpRetryCount < maxTcpRetries) {
                    LOG("⚠️ TCP响应发送失败，重试 %d/%d: errno=%d (%s)", 
                        tcpRetryCount, maxTcpRetries, errno, strerror(errno));
                    std::this_thread::sleep_for(std::chrono::milliseconds(10));
                } else {
                    LOG("❌ TCP响应发送最终失败: %s", strerror(errno));
                }
            }
        }
        
        if (tcpSendSuccess) {
            // 更新活动时间
            std::string natKey = NATTable::GenerateKey(conn.originalRequest);
            NATTable::UpdateActivity(natKey);
        }
    }
    
    // 清理
    LOG("🔒 TCP响应线程退出: 总共处理%d个响应", totalResponses);
    std::string natKey = NATTable::GenerateKey(packetInfo);
    NATTable::RemoveMapping(natKey);
    close(sockFd);
    LOG("🧹 TCP清理完成: socket=%d", sockFd);
}

// ========== 辅助函数 ==========
int PacketForwarder::CreateSocket(int addressFamily, uint8_t protocol) {
    int sockType = SOCK_DGRAM;
    int socketProtocol = 0;
    
    if (protocol == PROTOCOL_ICMPV6) {
        sockType = SOCK_RAW;
        socketProtocol = IPPROTO_ICMPV6;
    } else if (protocol == PROTOCOL_UDP) {
        sockType = SOCK_DGRAM;
    } else if (protocol == PROTOCOL_TCP) {
        sockType = SOCK_STREAM;
    }
    
    return socket(addressFamily, sockType, socketProtocol);
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
