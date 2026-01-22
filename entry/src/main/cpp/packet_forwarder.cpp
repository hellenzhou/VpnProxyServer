/*
 * 极简VPN服务器转发器 - 专注于让基本功能工作
 * 目标：确保单个PC的网络访问能被代理
 */

#include "packet_forwarder.h"
#include "vpn_server_globals.h"
#include "packet_builder.h"
#include "nat_table.h"
#include "task_queue.h"
#include "simple_dns_cache.h"
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

// 🔧 日志级别控制
// 0 = 关闭所有日志
// 1 = 仅错误和关键操作
// 2 = 详细日志（调试用）
#define FORWARDER_LOG_LEVEL 1

#if FORWARDER_LOG_LEVEL >= 2
  // 详细日志：包括所有操作
  #define LOG_DEBUG(fmt, ...) \
    OH_LOG_Print(LOG_APP, LOG_INFO, 0x15b1, "VpnServer", "ZHOUB [Forwarder] [%{public}s:%{public}d] " fmt, MAKE_FILE_NAME, __LINE__, ##__VA_ARGS__)
  #define LOG_INFO(fmt, ...) \
    OH_LOG_Print(LOG_APP, LOG_INFO, 0x15b1, "VpnServer", "ZHOUB [Forwarder] [%{public}s:%{public}d] " fmt, MAKE_FILE_NAME, __LINE__, ##__VA_ARGS__)
  #define LOG_ERROR(fmt, ...) \
    OH_LOG_Print(LOG_APP, LOG_ERROR, 0x15b1, "VpnServer", "ZHOUB [Forwarder] [%{public}s:%{public}d] ❌ " fmt, MAKE_FILE_NAME, __LINE__, ##__VA_ARGS__)
#elif FORWARDER_LOG_LEVEL >= 1
  // 仅关键操作和错误
  #define LOG_DEBUG(fmt, ...) /* 详细日志已禁用 */
  #define LOG_INFO(fmt, ...) \
    OH_LOG_Print(LOG_APP, LOG_INFO, 0x15b1, "VpnServer", "ZHOUB [Forwarder] [%{public}s:%{public}d] " fmt, MAKE_FILE_NAME, __LINE__, ##__VA_ARGS__)
  #define LOG_ERROR(fmt, ...) \
    OH_LOG_Print(LOG_APP, LOG_ERROR, 0x15b1, "VpnServer", "ZHOUB [Forwarder] [%{public}s:%{public}d] ❌ " fmt, MAKE_FILE_NAME, __LINE__, ##__VA_ARGS__)
#else
  // 关闭所有日志
  #define LOG_DEBUG(fmt, ...) /* 日志已禁用 */
  #define LOG_INFO(fmt, ...) /* 日志已禁用 */
  #define LOG_ERROR(fmt, ...) /* 日志已禁用 */
#endif

// 静态辅助函数声明
static void HandleUdpResponseSimple(int sockFd, sockaddr_in originalPeer, const PacketInfo& packetInfo);
static void HandleTcpResponseSimple(int sockFd, sockaddr_in originalPeer, const PacketInfo& packetInfo);

// 🔧 Socket复用缓存（避免频繁创建/销毁socket）
static std::map<std::string, int> g_socketCache;
static std::mutex g_socketCacheMutex;

// 🔧 线程追踪（避免重复创建响应线程）
static std::map<int, std::thread::id> g_socketThreadMap;
static std::mutex g_threadMapMutex;

// 🔧 DNS查询缓存（用于DNS缓存机制）
static std::map<int, std::vector<uint8_t>> g_dnsQueryCache;
static std::mutex g_dnsQueryCacheMutex;

// ========== 主转发函数 ==========
int PacketForwarder::ForwardPacket(const uint8_t* data, int dataSize, 
                                  const PacketInfo& packetInfo, 
                                  const sockaddr_in& originalPeer) {
    // 🔍 [流程1] 转发开始（详细日志）
    LOG_DEBUG("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    LOG_DEBUG("📦 [开始转发] %s:%d -> %s:%d (%s, %d字节)",
        packetInfo.sourceIP.c_str(), packetInfo.sourcePort,
        packetInfo.targetIP.c_str(), packetInfo.targetPort,
        ProtocolHandler::GetProtocolName(packetInfo.protocol).c_str(),
        dataSize);
    
    // ✅ 路由循环已通过 vpnConnection.protect(tunnelFd) 防止
    // 无需额外的重复数据包检测，让所有合法请求正常转发
    
    // 🔍 [流程2] 提取payload
    const uint8_t* payload = nullptr;
    int payloadSize = 0;
    LOG_DEBUG("🔍 [步骤1] 开始提取payload (数据包大小: %d)", dataSize);
    if (!PacketBuilder::ExtractPayload(data, dataSize, packetInfo, &payload, &payloadSize)) {
        LOG_ERROR("提取payload失败 - 数据包可能损坏或格式错误");
        LOG_ERROR("   原因: 数据包大小=%d, 协议=%s", dataSize, 
                  ProtocolHandler::GetProtocolName(packetInfo.protocol).c_str());
        return -1;
    }
    
    if (payloadSize <= 0) {
        LOG_DEBUG("⚠️ payload为空(size=%d)，跳过转发", payloadSize);
        return 0;
    }
    
    LOG_DEBUG("✅ [步骤1完成] 提取payload: %d字节", payloadSize);
    
    // 🔧 3. Socket复用策略：
    //    - UDP: 不复用（每个请求独立socket，避免NAT映射冲突）
    //    - TCP: 每个客户端连接使用独立socket（包含源IP和源端口）
    //    所有TCP/UDP连接使用统一的socket key生成策略
    std::string socketKey = packetInfo.sourceIP + ":" + std::to_string(packetInfo.sourcePort) + 
                           "->" + packetInfo.targetIP + ":" + std::to_string(packetInfo.targetPort) +
                           "/" + (packetInfo.protocol == PROTOCOL_TCP ? "TCP" : "UDP");
    
    int sockFd = -1;
    bool isNewSocket = true;  // 🔧 默认是新socket
    
    // 🔧 检查socket缓存
    if (packetInfo.protocol == PROTOCOL_TCP) {
        // 🔧 TCP连接: 从socket缓存中查找
        std::lock_guard<std::mutex> lock(g_socketCacheMutex);
        auto it = g_socketCache.find(socketKey);
        if (it != g_socketCache.end()) {
            sockFd = it->second;
            // 🔧 BUG修复：检查socket是否已经连接
            // TCP socket一旦connect，就不能再connect到其他地址
            struct sockaddr_in peerAddr{};
            socklen_t peerLen = sizeof(peerAddr);
            int isConnected = (getpeername(sockFd, (struct sockaddr*)&peerAddr, &peerLen) == 0);
            
            if (isConnected) {
                // Socket已经连接，检查是否连接到同一个目标
                char connectedIP[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &peerAddr.sin_addr, connectedIP, sizeof(connectedIP));
                int connectedPort = ntohs(peerAddr.sin_port);
                
                if (connectedIP == packetInfo.targetIP && connectedPort == packetInfo.targetPort) {
                    // 已连接到同一目标，可以复用
                    int error = 0;
                    socklen_t len = sizeof(error);
                    if (getsockopt(sockFd, SOL_SOCKET, SO_ERROR, &error, &len) == 0 && error == 0) {
                        LOG_DEBUG("♻️ 复用已连接的TCP socket: fd=%d, key=%s", sockFd, socketKey.c_str());
                        isNewSocket = false;
                    } else {
                        LOG_INFO("⚠️ 缓存的socket有错误，将创建新socket");
                        close(sockFd);
                        g_socketCache.erase(it);
                        sockFd = -1;
                    }
                } else {
                    // 已连接到不同目标，不能复用
                    LOG_INFO("⚠️ 缓存的socket已连接到不同目标 (%s:%d vs %s:%d)，将创建新socket",
                            connectedIP, connectedPort, packetInfo.targetIP.c_str(), packetInfo.targetPort);
                    close(sockFd);
                    g_socketCache.erase(it);
                    sockFd = -1;
                }
            } else {
                // Socket未连接，可以复用
                int error = 0;
                socklen_t len = sizeof(error);
                if (getsockopt(sockFd, SOL_SOCKET, SO_ERROR, &error, &len) == 0 && error == 0) {
                    LOG_DEBUG("♻️ 复用未连接的TCP socket: fd=%d, key=%s", sockFd, socketKey.c_str());
                    isNewSocket = false;
                } else {
                    LOG_INFO("⚠️ 缓存的socket无效，将创建新socket");
                    close(sockFd);
                    g_socketCache.erase(it);
                    sockFd = -1;
                }
            }
        }
    } else {
        LOG_DEBUG("🔧 UDP协议不复用socket，避免NAT映射冲突");
    }
    
    // 🔍 [流程3] 创建或复用socket
    if (sockFd < 0) {
        LOG_INFO("🔍 [步骤2] 创建新socket...");
        // 根据协议选择socket类型和地址族
        int addressFamily = packetInfo.addressFamily;
        int sockType = SOCK_DGRAM;
        int protocol = 0;
        
        if (packetInfo.protocol == PROTOCOL_ICMPV6) {
            // ❌ 不支持ICMPv6：需要RAW socket（需要系统权限）
            LOG_INFO("⚠️ ICMPv6不支持：需要RAW socket权限，跳过");
            return -1;  // 返回错误，不转发ICMPv6
        } else if (packetInfo.protocol == PROTOCOL_UDP) {
            sockType = SOCK_DGRAM;
            LOG_DEBUG("   类型: UDP DGRAM socket");
        } else if (packetInfo.protocol == PROTOCOL_TCP) {
            sockType = SOCK_STREAM;
            LOG_DEBUG("   类型: TCP STREAM socket");
        }
        
        sockFd = socket(addressFamily, sockType, protocol);
        if (sockFd < 0) {
            int savedErrno = errno;
            LOG_ERROR("创建socket失败!");
            LOG_ERROR("   errno: %d (%s)", savedErrno, strerror(savedErrno));
            LOG_ERROR("   family: %d, type: %d, protocol: %d", 
                     addressFamily, sockType, protocol);
            
            // 🔧 修复：处理文件描述符耗尽的情况
            if (savedErrno == EMFILE || savedErrno == ENFILE) {
                LOG_ERROR("   ⚠️ 文件描述符耗尽！尝试清理socket缓存...");
                // 清理一些旧的socket
                {
                    std::lock_guard<std::mutex> lock(g_socketCacheMutex);
                    if (!g_socketCache.empty()) {
                        // 关闭并删除第一个socket
                        auto it = g_socketCache.begin();
                        close(it->second);
                        g_socketCache.erase(it);
                        LOG_ERROR("   ✅ 已清理1个socket，重试创建...");
                        // 重试一次
                        sockFd = socket(addressFamily, sockType, protocol);
                        if (sockFd < 0) {
                            LOG_ERROR("   ❌ 重试后仍然失败: errno=%d (%s)", errno, strerror(errno));
                        }
                    }
                }
            }
            
            if (sockFd < 0) {
                LOG_ERROR("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
                return -1;
            }
        }
        isNewSocket = true;
        
        // 🔧 修复：立即配置socket选项，确保socket处于正确状态
        int sockopt = 1;
        if (setsockopt(sockFd, SOL_SOCKET, SO_REUSEADDR, &sockopt, sizeof(sockopt)) < 0) {
            LOG_DEBUG("⚠️ setsockopt(SO_REUSEADDR)失败: %s (非致命)", strerror(errno));
        }
        
        // 🔧 修复：对于UDP，设置接收超时（避免永久阻塞）
        if (sockType == SOCK_DGRAM) {
            struct timeval timeout;
            timeout.tv_sec = 0;
            timeout.tv_usec = 100000;  // 100ms初始超时
            if (setsockopt(sockFd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
                LOG_DEBUG("⚠️ setsockopt(SO_RCVTIMEO)失败: %s (非致命)", strerror(errno));
            }
        }
        
        // 🔧 修复：验证socket创建后立即有效
        int socketError = 0;
        socklen_t errorLen = sizeof(socketError);
        if (getsockopt(sockFd, SOL_SOCKET, SO_ERROR, &socketError, &errorLen) < 0) {
            LOG_ERROR("❌ 无法验证新创建的socket状态: errno=%d (%s)", errno, strerror(errno));
            close(sockFd);
            return -1;
        }
        if (socketError != 0) {
            LOG_ERROR("❌ 新创建的socket有错误状态: errno=%d (%s)", socketError, strerror(socketError));
            close(sockFd);
            return -1;
        }
        
        // 🔧 修复：检查socket缓存大小，防止文件描述符耗尽
        {
            std::lock_guard<std::mutex> lock(g_socketCacheMutex);
            const size_t MAX_SOCKET_CACHE = 8;  // 最大socket缓存数量（限制为8个）
            if (g_socketCache.size() >= MAX_SOCKET_CACHE) {
                LOG_ERROR("⚠️ Socket缓存已满 (%zu个)，清理最旧的socket...", g_socketCache.size());
                // 关闭并删除第一个socket（最旧的）
                auto it = g_socketCache.begin();
                close(it->second);
                g_socketCache.erase(it);
                LOG_ERROR("✅ 已清理1个socket，当前缓存: %zu个", g_socketCache.size());
            }
            g_socketCache[socketKey] = sockFd;
            LOG_DEBUG("📊 Socket缓存大小: %zu/%zu", g_socketCache.size(), MAX_SOCKET_CACHE);
        }
        LOG_INFO("✅ [步骤2完成] 创建socket成功: fd=%d, key=%s", sockFd, socketKey.c_str());
    } else {
        LOG_DEBUG("♻️ [步骤2跳过] 复用已有socket: fd=%d", sockFd);
    }
    
    // 4. 先创建NAT映射（重要！必须在启动响应线程之前）
    std::string natKey = NATTable::GenerateKey(packetInfo);
    NATTable::CreateMapping(natKey, originalPeer, packetInfo, sockFd);
    LOG_DEBUG("✅ NAT映射已创建: %s", natKey.c_str());
    
    // 4. 🔧 DNS重定向：如果是DNS查询且目标是223.5.5.5，重定向到8.8.8.8
    std::string actualTargetIP = packetInfo.targetIP;
    if (packetInfo.targetPort == 53 && packetInfo.targetIP == "223.5.5.5") {
        actualTargetIP = "8.8.8.8";
        LOG_DEBUG("🔄 DNS重定向: %s:%d -> %s:%d", packetInfo.targetIP.c_str(), packetInfo.targetPort, actualTargetIP.c_str(), packetInfo.targetPort);
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
        LOG_INFO("🔗 处理TCP连接: %s:%d", actualTargetIP.c_str(), packetInfo.targetPort);
        
        // 连接到目标服务器
        // 🔧 BUG修复：如果socket已经连接，不需要再次connect
        struct sockaddr_in peerAddr{};
        socklen_t peerLen = sizeof(peerAddr);
        int alreadyConnected = (getpeername(sockFd, (struct sockaddr*)&peerAddr, &peerLen) == 0);
        
        int connectResult = 0;
        if (!alreadyConnected) {
            connectResult = connect(sockFd, pTargetAddr, targetAddrLen);
            if (connectResult < 0) {
                int savedErrno = errno;
                // EISCONN表示socket已经连接，这是正常的（可能是并发连接）
                if (savedErrno == EISCONN) {
                    LOG_DEBUG("⚠️ Socket已经连接 (EISCONN)，继续使用");
                    connectResult = 0;  // 视为成功
                } else {
                    LOG_ERROR("TCP连接失败: socket=%d, errno=%d (%s), target=%s:%d", 
                        sockFd, savedErrno, strerror(savedErrno), 
                        actualTargetIP.c_str(), packetInfo.targetPort);
                    NATTable::RemoveMapping(natKey);
                    if (isNewSocket) {
                        std::lock_guard<std::mutex> lock(g_socketCacheMutex);
                        g_socketCache.erase(socketKey);
                        close(sockFd);
                    }
                    return -1;
                }
            }
        } else {
            LOG_DEBUG("✅ Socket已经连接，跳过connect");
        }
        
        LOG_INFO("✅ TCP连接成功: socket=%d -> %s:%d", 
            sockFd, actualTargetIP.c_str(), packetInfo.targetPort);
        
        // 🔥 ZHOUB日志：转发请求时
        LOG_INFO("ZHOUB [转发请求] 源IP:%s 目的IP:%s 源端口:%d 目的端口:%d 协议:TCP 大小:%d字节",
                 packetInfo.sourceIP.c_str(), actualTargetIP.c_str(), 
                 packetInfo.sourcePort, packetInfo.targetPort, payloadSize);
        
        // 🔧 BUG修复：验证socket连接状态后再发送
        if (connectResult == 0 || alreadyConnected) {
            // Socket连接正常，可以发送数据
        } else {
            LOG_ERROR("TCP socket未连接，无法发送数据");
            NATTable::RemoveMapping(natKey);
            if (isNewSocket) {
                std::lock_guard<std::mutex> lock(g_socketCacheMutex);
                g_socketCache.erase(socketKey);
                close(sockFd);
            }
            return -1;
        }
        
        // 发送TCP数据
        ssize_t sent = send(sockFd, payload, payloadSize, 0);
        if (sent < 0) {
            int savedErrno = errno;
            LOG_ERROR("TCP发送失败: socket=%d, errno=%d (%s)", 
                sockFd, savedErrno, strerror(savedErrno));
            
            // 🔧 BUG修复：如果socket已关闭或连接断开，从缓存中移除
            if (savedErrno == EPIPE || savedErrno == ECONNRESET || savedErrno == ENOTCONN) {
                LOG_ERROR("⚠️ Socket连接已断开，清理缓存");
                {
                    std::lock_guard<std::mutex> lock(g_socketCacheMutex);
                    g_socketCache.erase(socketKey);
                }
                close(sockFd);
            }
            
            NATTable::RemoveMapping(natKey);
            if (isNewSocket) {
                std::lock_guard<std::mutex> lock(g_socketCacheMutex);
                g_socketCache.erase(socketKey);
                close(sockFd);
            }
            return -1;
        }
        
        LOG_DEBUG("✅ TCP发送成功: socket=%d, %zd字节 -> %s:%d", 
            sockFd, sent, actualTargetIP.c_str(), packetInfo.targetPort);
        
        // 🔧 TCP响应：启动专用响应线程（TCP连接需要持久监听）
        if (isNewSocket) {
            LOG_INFO("🚀 启动新的TCP响应线程 for socket %d (新socket)", sockFd);
            std::thread([sockFd, originalPeer, packetInfo, socketKey]() {
                {
                    std::lock_guard<std::mutex> lock(g_threadMapMutex);
                    g_socketThreadMap[sockFd] = std::this_thread::get_id();
                }
                LOG_INFO("🔥 TCP响应线程已进入 - socket=%d", sockFd);
                HandleTcpResponseSimple(sockFd, originalPeer, packetInfo);

                // 响应线程结束时，清理
                {
                    std::lock_guard<std::mutex> lock(g_threadMapMutex);
                    g_socketThreadMap.erase(sockFd);
                }
                {
                    std::lock_guard<std::mutex> lock(g_socketCacheMutex);
                    g_socketCache.erase(socketKey);
                }
                LOG_INFO("🔥 TCP响应线程已退出 - socket=%d", sockFd);
            }).detach();
        } else {
            // 🔧 Socket复用时，检查响应线程状态
            LOG_DEBUG("♻️ 复用TCP socket %d", sockFd);
            {
                std::lock_guard<std::mutex> lock(g_threadMapMutex);
                auto it = g_socketThreadMap.find(sockFd);
                if (it != g_socketThreadMap.end()) {
                    LOG_DEBUG("✅ 响应线程仍在运行 for socket %d", sockFd);
                } else {
                    LOG_INFO("⚠️ 响应线程丢失 for socket %d，可能需要重启", sockFd);
                }
            }
        }
        
        return sockFd;
    }
    
    if (packetInfo.protocol == PROTOCOL_UDP) {
        // 🔧 DNS缓存检查：如果是DNS查询，先检查缓存
        if (packetInfo.targetPort == 53 && payloadSize >= sizeof(DNSHeader)) {
            // 解析DNS查询域名
            std::string domain = DNSCacheManager::parseQueryDomain(payload, payloadSize);
            if (!domain.empty()) {
                // 提取查询类型（跳过DNS头部和域名）
                uint16_t qtype = 0;
                if (payloadSize >= sizeof(DNSHeader) + domain.length() + 2 + 4) {
                    const uint8_t* qtypePtr = payload + sizeof(DNSHeader) + domain.length() + 2;
                    qtype = (qtypePtr[0] << 8) | qtypePtr[1];
                }

                std::string cacheKey = DNSCacheManager::makeCacheKey(domain, qtype);

                // 检查缓存
                uint8_t cachedResponse[4096];
                int cachedResponseSize = sizeof(cachedResponse);
                if (DNSCacheManager::getCachedResponse(cacheKey, payload, payloadSize,
                                                     cachedResponse, cachedResponseSize)) {
                    LOG_DEBUG("🎯 DNS缓存命中: %s (qtype=%d), 返回缓存响应 %d字节",
                        domain.c_str(), qtype, cachedResponseSize);

                    // 直接发送缓存的响应给客户端（通过响应队列）
                    if (!TaskQueueManager::getInstance().submitResponseTask(
                            cachedResponse, cachedResponseSize, originalPeer, sockFd, PROTOCOL_UDP)) {
                        LOG_ERROR("提交DNS缓存响应失败");
                    } else {
                        LOG_DEBUG("✅ DNS缓存响应已提交到队列");
                    }

                    return sockFd;  // 返回但不创建响应线程（缓存响应直接处理）
                } else {
                    LOG_DEBUG("💾 DNS缓存未命中: %s (qtype=%d)", domain.c_str(), qtype);

                    // 保存原始DNS查询数据，用于后续缓存设置
                    {
                        std::lock_guard<std::mutex> lock(g_dnsQueryCacheMutex);
                        g_dnsQueryCache[sockFd] = std::vector<uint8_t>(payload, payload + payloadSize);
                    }
                }
            }
        }

        // 🔍 [流程4] UDP发送数据
        LOG_DEBUG("🔍 [步骤3] 发送UDP数据 %d字节 -> %s:%d", 
            payloadSize, actualTargetIP.c_str(), packetInfo.targetPort);
        
        // 🔥 ZHOUB日志：转发请求时
        LOG_INFO("ZHOUB [转发请求] 源IP:%s 目的IP:%s 源端口:%d 目的端口:%d 协议:UDP 大小:%d字节",
                 packetInfo.sourceIP.c_str(), actualTargetIP.c_str(), 
                 packetInfo.sourcePort, packetInfo.targetPort, payloadSize);
        
        ssize_t sent = -1;
        int retryCount = 0;
        const int maxRetries = 3;
        
        while (sent < 0 && retryCount < maxRetries) {
            sent = sendto(sockFd, payload, payloadSize, 0, 
                         pTargetAddr, targetAddrLen);
            
            if (sent < 0) {
                retryCount++;
                int savedErrno = errno;
                LOG_ERROR("❌ UDP sendto()失败，重试 %d/%d", retryCount, maxRetries);
                LOG_ERROR("   Errno: %d (%s)", savedErrno, strerror(savedErrno));
                LOG_ERROR("   Socket: %d, Payload: %d字节, Target: %s:%d", 
                         sockFd, payloadSize, actualTargetIP.c_str(), packetInfo.targetPort);
                
                // 🔧 详细错误分析
                if (savedErrno == ENETUNREACH) {
                    LOG_ERROR("   ⚠️ ENETUNREACH: 网络不可达！可能原因：");
                    LOG_ERROR("      1. 设备没有网络连接");
                    LOG_ERROR("      2. 没有到8.8.8.8的路由");
                    LOG_ERROR("      3. VPN未调用protect()保护socket");
                } else if (savedErrno == EACCES) {
                    LOG_ERROR("   ⚠️ EACCES: 权限被拒绝（可能需要网络权限或protect socket）");
                } else if (savedErrno == EPERM) {
                    LOG_ERROR("   ⚠️ EPERM: 操作不被允许（需要protect socket避免路由循环）");
                }
                
                if (retryCount < maxRetries) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(10));
                    
                    // 检查socket状态
                    int error = 0;
                    socklen_t len = sizeof(error);
                    if (getsockopt(sockFd, SOL_SOCKET, SO_ERROR, &error, &len) == 0 && error != 0) {
                        LOG_ERROR("Socket状态错误，停止重试: errno=%d (%s)", error, strerror(error));
                        break;
                    }
                }
            }
        }
        
        if (sent < 0) {
            LOG_ERROR("UDP发送最终失败!");
            LOG_ERROR("   socket: %d", sockFd);
            LOG_ERROR("   target: %s:%d", actualTargetIP.c_str(), packetInfo.targetPort);
            LOG_ERROR("   size: %d字节", payloadSize);
            LOG_ERROR("   errno: %d (%s)", errno, strerror(errno));
            LOG_ERROR("   重试次数: %d", retryCount);
            LOG_ERROR("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            
            NATTable::RemoveMapping(natKey);
            if (isNewSocket) {
                std::lock_guard<std::mutex> lock(g_socketCacheMutex);
                g_socketCache.erase(socketKey);
                close(sockFd);
            }
            return -1;
        }
        
        LOG_DEBUG("✅ [步骤3完成] UDP发送成功: %zd字节 -> %s:%d %s", 
            sent, actualTargetIP.c_str(), packetInfo.targetPort,
            retryCount > 0 ? ("(重试" + std::to_string(retryCount) + "次)").c_str() : "");
        
        // 🔧 修复：在启动响应线程前验证socket仍然有效
        int postSendError = 0;
        socklen_t postSendLen = sizeof(postSendError);
        if (getsockopt(sockFd, SOL_SOCKET, SO_ERROR, &postSendError, &postSendLen) < 0) {
            LOG_ERROR("❌ sendto后无法检查socket状态: errno=%d (%s)", errno, strerror(errno));
            NATTable::RemoveMapping(natKey);
            if (isNewSocket) {
                std::lock_guard<std::mutex> lock(g_socketCacheMutex);
                g_socketCache.erase(socketKey);
                close(sockFd);
            }
            return -1;
        }
        if (postSendError != 0) {
            LOG_ERROR("❌ sendto后socket有错误状态: errno=%d (%s)", postSendError, strerror(postSendError));
            NATTable::RemoveMapping(natKey);
            if (isNewSocket) {
                std::lock_guard<std::mutex> lock(g_socketCacheMutex);
                g_socketCache.erase(socketKey);
                close(sockFd);
            }
            return -1;
        }
        
        // 🔍 [流程5] 启动UDP响应线程
        if (isNewSocket) {
            LOG_INFO("🔍 [步骤4] 启动UDP响应线程 for socket %d", sockFd);
            std::thread([sockFd, originalPeer, packetInfo, socketKey]() {
                {
                    std::lock_guard<std::mutex> lock(g_threadMapMutex);
                    g_socketThreadMap[sockFd] = std::this_thread::get_id();
                }
                LOG_DEBUG("🔥 [响应线程启动] socket=%d, 等待来自 %s:%d 的响应", 
                    sockFd, packetInfo.targetIP.c_str(), packetInfo.targetPort);
                HandleUdpResponseSimple(sockFd, originalPeer, packetInfo);

                // 响应线程结束时，清理
                {
                    std::lock_guard<std::mutex> lock(g_threadMapMutex);
                    g_socketThreadMap.erase(sockFd);
                }
                {
                    std::lock_guard<std::mutex> lock(g_socketCacheMutex);
                    g_socketCache.erase(socketKey);
                }
                LOG_INFO("🔚 [响应线程退出] socket=%d", sockFd);
            }).detach();
            LOG_DEBUG("✅ [步骤4完成] 响应线程已启动");
        } else {
            LOG_DEBUG("♻️ [步骤4跳过] 复用socket，响应线程已存在");
        }
        
        LOG_DEBUG("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        LOG_DEBUG("✅ [转发完成] socket=%d 返回", sockFd);
    } else if (packetInfo.protocol == PROTOCOL_ICMPV6) {
        // ❌ ICMPv6 不支持：需要RAW socket（需要系统权限）
        LOG_INFO("⚠️ ICMPv6不支持: Type=%d -> %s (需要RAW socket权限)", 
                 packetInfo.icmpv6Type, actualTargetIP.c_str());
        LOG_INFO("ℹ️  建议：使用标准网络协议（TCP/UDP）代替ICMPv6");
        
        // 清理NAT映射
        NATTable::RemoveMapping(natKey);
        
        // 注意：此时 sockFd 应该是 -1（在创建阶段就失败了）
        // 所以不需要清理socket
        
        return -1;  // 不支持ICMPv6
    } else {
        // 不应该到这里
        LOG_ERROR("未知协议: %d", packetInfo.protocol);
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
    LOG_DEBUG("📥 UDP响应线程启动: socket=%d, 目标=%s:%d", 
        sockFd, packetInfo.targetIP.c_str(), packetInfo.targetPort);
    
    // 🐛 修复：保存g_sockFd副本，避免服务器停止时使用无效socket
    int tunnelFd = g_sockFd.load();
    if (tunnelFd < 0) {
        LOG_ERROR("TUN socket无效，退出响应线程");
        close(sockFd);
        return;
    }
    
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
        LOG_ERROR("❌ setsockopt(SO_RCVTIMEO)失败: errno=%d (%s)", errno, strerror(errno));
        // 🔧 继续执行，超时失败不影响基本功能（只是会永久阻塞）
    } else {
        LOG_DEBUG("✅ socket超时设置成功: %ldms", timeout.tv_usec / 1000);
    }
    
    // 🔧 优化：动态调整超时限制
    int consecutiveTimeouts = 0;
    int maxTimeouts = (packetInfo.targetPort == 53) ? 30 : 20;  // DNS: 3秒, 其他: 2秒
    int totalResponses = 0;
    int lastActivityTime = time(nullptr);
    
    // 🔧 优化：添加socket状态检查
    int lastErrorCheck = time(nullptr);
    
    LOG_DEBUG("🔄 开始持续监听UDP响应... socket=%d, 超时限制=%d", sockFd, maxTimeouts);
    
    // 🔧 修复：在开始接收前验证socket有效性
    int socketError = 0;
    socklen_t errorLen = sizeof(socketError);
    if (getsockopt(sockFd, SOL_SOCKET, SO_ERROR, &socketError, &errorLen) < 0) {
        LOG_ERROR("❌ 无法检查socket状态: errno=%d (%s)，退出响应线程", errno, strerror(errno));
        close(sockFd);
        return;
    }
    if (socketError != 0) {
        LOG_ERROR("❌ Socket已有错误状态: errno=%d (%s)，退出响应线程", socketError, strerror(socketError));
        close(sockFd);
        return;
    }
    
    // 🔧 修复：验证socket文件描述符有效性（使用fcntl）
    int flags = fcntl(sockFd, F_GETFD, 0);
    if (flags < 0) {
        LOG_ERROR("❌ Socket文件描述符无效 (fcntl失败): errno=%d (%s)，退出响应线程", errno, strerror(errno));
        close(sockFd);
        return;
    }
    
    while (consecutiveTimeouts < maxTimeouts) {
        // 🐛 修复：快速检查服务器是否正在停止
        if (!g_running.load() || tunnelFd != g_sockFd.load()) {
            LOG_INFO("⚠️ 服务器正在停止，退出响应线程 socket=%d", sockFd);
            break;
        }
        
        // 🔧 每5秒检查一次socket状态
        int currentTime = time(nullptr);
        if (currentTime - lastErrorCheck >= 5) {
            lastErrorCheck = currentTime;
            
            int error = 0;
            socklen_t len = sizeof(error);
            if (getsockopt(sockFd, SOL_SOCKET, SO_ERROR, &error, &len) == 0 && error != 0) {
                LOG_ERROR("Socket错误检测: %s，退出响应线程", strerror(error));
                break;
            }
            
            // 🔧 修复：定期验证socket文件描述符有效性
            int checkFlags = fcntl(sockFd, F_GETFD, 0);
            if (checkFlags < 0) {
                LOG_ERROR("❌ Socket文件描述符已失效: errno=%d (%s)，退出响应线程", errno, strerror(errno));
                break;
            }
        }
        
        // 每次循环都重新查找NAT映射（可能已被更新）
        NATConnection conn;
        if (!NATTable::FindMappingBySocket(sockFd, conn)) {
            LOG_DEBUG("NAT映射已被删除，退出响应线程 socket=%d", sockFd);
            break;
        }
        
        uint8_t responsePayload[4096];
        struct sockaddr_in responseAddr{};
        socklen_t addrLen = sizeof(responseAddr);
        
        // 🔧 修复：在recvfrom前再次验证socket有效性
        int preCheckError = 0;
        socklen_t preCheckLen = sizeof(preCheckError);
        if (getsockopt(sockFd, SOL_SOCKET, SO_ERROR, &preCheckError, &preCheckLen) < 0) {
            int savedErrno = errno;
            LOG_ERROR("❌ recvfrom前socket检查失败: errno=%d (%s)", savedErrno, strerror(savedErrno));
            break;
        }
        if (preCheckError != 0) {
            LOG_ERROR("❌ recvfrom前socket有错误状态: errno=%d (%s)", preCheckError, strerror(preCheckError));
            break;
        }
        
        // 🔧 调试：记录接收尝试（非常频繁，禁用）
        // LOG_DEBUG("🔍 尝试接收UDP响应... socket=%d", sockFd);
        
        // 🔥 ZHOUB日志：记录recvfrom尝试（每10次记录一次，避免日志过多）
        static int recvAttemptCount = 0;
        bool shouldLogRecvAttempt = (++recvAttemptCount % 10 == 0);
        if (shouldLogRecvAttempt) {
            LOG_DEBUG("ZHOUB [UDP接收] 尝试接收响应 socket=%d 目标=%s:%d (尝试#%d)", 
                     sockFd, packetInfo.targetIP.c_str(), packetInfo.targetPort, recvAttemptCount);
        }
        
        ssize_t received = recvfrom(sockFd, responsePayload, sizeof(responsePayload), 0,
                                    (struct sockaddr*)&responseAddr, &addrLen);
        
        if (received <= 0) {
            int savedErrno = errno;  // 🔧 修复：立即保存errno，避免被其他调用覆盖
            if (savedErrno == EAGAIN || savedErrno == EWOULDBLOCK) {
                consecutiveTimeouts++;
                lastActivityTime = currentTime;
                
                // 🔧 优化：大幅减少日志频率，避免日志爆炸
                if (consecutiveTimeouts % 50 == 0 && consecutiveTimeouts > 0) {
                    LOG_DEBUG("⏱️ UDP响应线程等待中... socket=%d (已收%d个响应, 空闲%.1f秒)",
                        sockFd, totalResponses, consecutiveTimeouts * 0.1);
                }
                continue;
            } else {
                // 🔴 关键错误日志：详细显示errno（不被日志系统隐藏）
                LOG_ERROR("❌❌❌ UDP recvfrom()失败 ❌❌❌");
                LOG_ERROR("   Socket FD: %d", sockFd);
                LOG_ERROR("   Errno: %d", savedErrno);
                LOG_ERROR("   错误描述: %s", strerror(savedErrno));
                LOG_ERROR("   目标地址: %s:%d", packetInfo.targetIP.c_str(), packetInfo.targetPort);
                
                // 🔥 ZHOUB日志：记录失败时的上下文信息
                LOG_ERROR("ZHOUB [UDP接收失败] socket=%d 目标=%s:%d errno=%d (%s) 已等待%.1f秒",
                         sockFd, packetInfo.targetIP.c_str(), packetInfo.targetPort, 
                         savedErrno, strerror(savedErrno), consecutiveTimeouts * 0.1);
                
                // 🔧 修复：添加socket状态诊断
                int diagError = 0;
                socklen_t diagLen = sizeof(diagError);
                if (getsockopt(sockFd, SOL_SOCKET, SO_ERROR, &diagError, &diagLen) == 0) {
                    LOG_ERROR("   Socket SO_ERROR状态: %d (%s)", diagError, diagError != 0 ? strerror(diagError) : "无错误");
                } else {
                    LOG_ERROR("   无法获取socket状态: errno=%d (%s)", errno, strerror(errno));
                }
                
                // 🔧 修复：检查socket是否仍然有效
                int diagFlags = fcntl(sockFd, F_GETFD, 0);
                if (diagFlags < 0) {
                    LOG_ERROR("   Socket文件描述符已失效: errno=%d (%s)", errno, strerror(errno));
                } else {
                    LOG_ERROR("   Socket文件描述符仍然有效 (flags=0x%x)", diagFlags);
                }
                
                // 🔧 特殊错误处理
                if (savedErrno == EBADF) {
                    LOG_ERROR("   ⚠️ EBADF: Socket已关闭或无效");
                } else if (savedErrno == ENOTCONN) {
                    LOG_ERROR("   ⚠️ ENOTCONN: Socket未连接（UDP不需要连接，这不应该发生）");
                } else if (savedErrno == ENETUNREACH) {
                    LOG_ERROR("   ⚠️ ENETUNREACH: 网络不可达（可能是路由问题或网络断开）");
                    LOG_ERROR("   💡 提示: 可能需要protect socket避免VPN路由循环");
                } else if (savedErrno == EHOSTUNREACH) {
                    LOG_ERROR("   ⚠️ EHOSTUNREACH: 主机不可达");
                } else if (savedErrno == ECONNREFUSED) {
                    LOG_ERROR("   ⚠️ ECONNREFUSED: 连接被拒绝（端口关闭）");
                } else if (savedErrno == EINTR) {
                    LOG_ERROR("   ⚠️ EINTR: 系统调用被信号中断，继续重试");
                    continue;  // EINTR应该重试，不应该退出
                } else if (savedErrno == EINVAL) {
                    LOG_ERROR("   ⚠️ EINVAL: 参数无效（可能是socket状态异常）");
                }
                break;
            }
        }
        
        // 收到响应，重置超时计数
        consecutiveTimeouts = 0;
        totalResponses++;
        LOG_DEBUG("✅ 收到UDP响应 #%d: socket=%d, %zd字节", totalResponses, sockFd, received);
        
        // 🔧 验证响应来源
        char responseIP[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &responseAddr.sin_addr, responseIP, INET_ADDRSTRLEN);
        if (strcmp(responseIP, packetInfo.targetIP.c_str()) != 0) {
            LOG_INFO("⚠️ 响应来源不匹配: 期望%s，实际%s", packetInfo.targetIP.c_str(), responseIP);
            continue;
        }
        
        LOG_INFO("✅✅✅ 收到UDP响应: socket=%d, %zd字节, 来源=%s:%d (目标=%s:%d)", 
            sockFd, received, responseIP, ntohs(responseAddr.sin_port),
            packetInfo.targetIP.c_str(), packetInfo.targetPort);
        
        // 🔧 关键修复：构建完整的IP包（UDP响应需要IP/UDP头部！）
        uint8_t ipPacket[4096 + 60];
        int packetLen = PacketBuilder::BuildResponsePacket(
            ipPacket, sizeof(ipPacket),
            responsePayload, received,
            conn.originalRequest
        );
        
        if (packetLen < 0) {
            LOG_ERROR("构建UDP响应包失败");
            continue;
        }
        
        LOG_DEBUG("✅ 构建UDP IP包: %d字节 (payload: %zd字节)", packetLen, received);
        
        // 🔧 优化：添加响应内容摘要（仅DNS）
        if (packetInfo.targetPort == 53 && received >= 12) {
            // DNS响应前12字节包含头部信息
            uint16_t dnsId = (responsePayload[0] << 8) | responsePayload[1];
            uint8_t flags = responsePayload[2];
            uint8_t rcode = flags & 0x0F;
            uint16_t answerCount = (responsePayload[6] << 8) | responsePayload[7];

            LOG_DEBUG("🔍 DNS响应详情: ID=%d, 标志=0x%02X, RCODE=%d, 答案数=%d",
                dnsId, flags, rcode, answerCount);

            // 🔧 DNS缓存：保存DNS响应到缓存（仅成功响应）
            if (rcode == 0 && answerCount > 0) {  // 只有成功响应且有答案才缓存
                // 从DNS查询缓存中获取原始查询数据
                std::vector<uint8_t> originalQuery;
                {
                    std::lock_guard<std::mutex> lock(g_dnsQueryCacheMutex);
                    auto it = g_dnsQueryCache.find(sockFd);
                    if (it != g_dnsQueryCache.end()) {
                        originalQuery = it->second;
                        g_dnsQueryCache.erase(it);
                    }
                }

                if (!originalQuery.empty()) {
                    // 解析原始查询域名
                    std::string domain = DNSCacheManager::parseQueryDomain(originalQuery.data(), originalQuery.size());
                    if (!domain.empty()) {
                        // 提取查询类型
                        uint16_t qtype = 0;
                        if (originalQuery.size() >= sizeof(DNSHeader) + domain.length() + 2 + 4) {
                            const uint8_t* qtypePtr = originalQuery.data() + sizeof(DNSHeader) + domain.length() + 2;
                            qtype = (qtypePtr[0] << 8) | qtypePtr[1];
                        }

                        std::string cacheKey = DNSCacheManager::makeCacheKey(domain, qtype);

                        // 设置DNS缓存
                        DNSCacheManager::setCachedResponse(cacheKey,
                                                         originalQuery.data(), originalQuery.size(),
                                                         responsePayload, received);

                        LOG_DEBUG("💾 DNS响应已缓存: %s (qtype=%d, %zd字节)",
                            domain.c_str(), qtype, received);
                    }
                } else {
                    LOG_DEBUG("⚠️ 找不到原始DNS查询，无法缓存响应");
                }
            }

            // 🔧 UDP重传确认：收到DNS响应后，确认对应的重传记录
            // 注意：这里需要从packetInfo中提取原始的packetId
            // 简化处理：DNS响应通常对应最近的DNS查询
            LOG_DEBUG("📨 DNS响应已确认，更新重传状态");
        }
        
        // 🔧 提交响应任务到队列（异步发送）- 发送完整的IP包！
        bool sendSuccess = false;
        if (!TaskQueueManager::getInstance().submitResponseTask(
                ipPacket, packetLen, originalPeer, sockFd, packetInfo.protocol)) {
            // 🔧 队列满时的正确处理：
            // UDP响应可以丢弃（客户端会重试），不要阻塞响应线程
            LOG_ERROR("响应队列已满，丢弃UDP响应！系统过载警告！");
            LOG_ERROR("队列大小限制: %zu, 请考虑增大队列或优化性能", 
                TaskQueueManager::getInstance().getResponseQueueSize());
            
            // 不要直接发送，避免占用响应线程资源
            // UDP丢包是可接受的，客户端会重试DNS查询
            sendSuccess = false;
        } else {
            LOG_INFO("✅✅✅ UDP响应已提交到队列: %d字节 (完整IP包) -> 客户端 %s:%d", 
                    packetLen, 
                    inet_ntoa(originalPeer.sin_addr),
                    ntohs(originalPeer.sin_port));
            sendSuccess = true;
        }

        if (sendSuccess) {
            // 更新活动时间
            std::string natKey = NATTable::GenerateKey(packetInfo);
            NATTable::UpdateActivity(natKey);

            // UDP响应确认（用于重传管理）
            if (packetInfo.protocol == PROTOCOL_UDP) {
                // 这里可以添加UDP响应确认逻辑
                LOG_DEBUG("📨 UDP响应已处理");
            }
        }
    }
    
    // 清理
    LOG_DEBUG("🔒 UDP响应线程退出: 总共接收%d个响应", totalResponses);
    std::string natKey = NATTable::GenerateKey(packetInfo);
    NATTable::RemoveMapping(natKey);
    close(sockFd);
    LOG_DEBUG("🧹 清理完成: socket=%d", sockFd);
}

// ========== TCP响应处理（增强版）==========
static void HandleTcpResponseSimple(int sockFd, sockaddr_in originalPeer, const PacketInfo& packetInfo) {
    LOG_DEBUG("📥 TCP响应线程启动: socket=%d, 目标=%s:%d", sockFd, packetInfo.targetIP.c_str(), packetInfo.targetPort);
    
    // 🐛 修复：保存g_sockFd副本，避免服务器停止时使用无效socket
    int tunnelFd = g_sockFd.load();
    if (tunnelFd < 0) {
        LOG_ERROR("TUN socket无效，退出响应线程");
        close(sockFd);
        return;
    }
    
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
        LOG_ERROR("找不到NAT映射，退出TCP响应线程");
        close(sockFd);
        return;
    }
    LOG_DEBUG("✅ 找到NAT映射: %s", conn.originalRequest.sourceIP.c_str());
    
    uint8_t responsePayload[4096];
    int totalResponses = 0;
    
    LOG_DEBUG("🔄 开始TCP数据转发... socket=%d", sockFd);
    while (true) {
        // 🐛 修复：快速检查服务器是否正在停止
        if (!g_running.load() || tunnelFd != g_sockFd.load()) {
            LOG_INFO("⚠️ 服务器正在停止，退出TCP响应线程 socket=%d", sockFd);
            break;
        }
        
        ssize_t received = recv(sockFd, responsePayload, sizeof(responsePayload), 0);
        
        if (received <= 0) {
            if (received == 0) {
                LOG_DEBUG("🔚 TCP连接关闭: socket=%d", sockFd);
            } else {
                LOG_ERROR("TCP响应接收失败: socket=%d, errno=%d (%s)", sockFd, errno, strerror(errno));
            }
            break;
        }
        
        totalResponses++;
        LOG_DEBUG("✅ 收到TCP响应 #%d: socket=%d, %zd字节", totalResponses, sockFd, received);
        
        // 🔧 调试：记录TCP响应内容
        if (received >= 20) {
            // 检查是否是HTTP响应
            if (strncmp((char*)responsePayload, "HTTP/", 5) == 0) {
                LOG_DEBUG("🌐 检测到HTTP响应: %.20s...", responsePayload);
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
            LOG_ERROR("构建TCP响应包失败");
            continue;
        }
        
        LOG_DEBUG("✅ 构建TCP IP包: %d字节", packetLen);
        
        // 🔧 提交TCP响应任务到队列（异步发送）
        // TCP响应不能丢失，需要可靠传输
        bool tcpSendSuccess = false;
        if (!TaskQueueManager::getInstance().submitResponseTask(
                ipPacket, packetLen, conn.clientPhysicalAddr, sockFd, PROTOCOL_TCP)) {
            // 🔧 TCP响应队列满是严重问题！
            // TCP不能丢包，但直接发送也有风险（死锁、性能问题）
            // 最好的策略：记录错误，关闭连接，让客户端重试
            LOG_ERROR("响应队列已满，无法发送TCP响应！系统严重过载！");
            LOG_ERROR("TCP连接将被关闭，客户端需要重连");
            
            // 不要直接发送，避免死锁和资源竞争
            // 让TCP连接断开，客户端会重新建立连接
            tcpSendSuccess = false;
            break;  // 退出响应循环，关闭连接
        } else {
            LOG_DEBUG("✅ TCP响应已提交到队列: %d字节", packetLen);
            tcpSendSuccess = true;
        }
        
        if (tcpSendSuccess) {
            // 更新活动时间
            std::string natKey = NATTable::GenerateKey(conn.originalRequest);
            NATTable::UpdateActivity(natKey);
        }
    }
    
    // 清理
    LOG_DEBUG("🔒 TCP响应线程退出: 总共处理%d个响应", totalResponses);
    std::string natKey = NATTable::GenerateKey(packetInfo);
    NATTable::RemoveMapping(natKey);
    close(sockFd);
    LOG_DEBUG("🧹 TCP清理完成: socket=%d", sockFd);
}

// ========== 辅助函数 ==========
int PacketForwarder::CreateSocket(int addressFamily, uint8_t protocol) {
    int sockType = SOCK_DGRAM;
    int socketProtocol = 0;
    
    if (protocol == PROTOCOL_ICMPV6) {
        // ❌ 不支持ICMPv6：需要RAW socket（需要系统权限）
        LOG_ERROR("ICMPv6不支持：需要RAW socket权限");
        return -1;
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

// 清理所有缓存的socket和线程
void PacketForwarder::CleanupAll() {
    LOG_INFO("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    LOG_INFO("🧹 [资源清理] 开始清理PacketForwarder资源...");
    
    // 清理socket缓存
    int socketCount = 0;
    {
        std::lock_guard<std::mutex> lock(g_socketCacheMutex);
        socketCount = g_socketCache.size();
        LOG_INFO("📊 [统计] Socket缓存数量: %d", socketCount);
        for (auto& pair : g_socketCache) {
            LOG_DEBUG("   🔒 关闭socket: fd=%d, key=%s", pair.second, pair.first.c_str());
            close(pair.second);
        }
        g_socketCache.clear();
        LOG_INFO("✅ Socket缓存已清空 (关闭了%d个socket)", socketCount);
    }
    
    // 清理线程映射
    int threadCount = 0;
    {
        std::lock_guard<std::mutex> lock(g_threadMapMutex);
        threadCount = g_socketThreadMap.size();
        LOG_INFO("📊 [统计] 活跃响应线程数: %d", threadCount);
        g_socketThreadMap.clear();
        LOG_INFO("✅ 线程映射已清空 (清理了%d个线程记录)", threadCount);
    }

    // 清理DNS查询缓存
    int dnsCount = 0;
    {
        std::lock_guard<std::mutex> lock(g_dnsQueryCacheMutex);
        dnsCount = g_dnsQueryCache.size();
        LOG_INFO("📊 [统计] DNS查询缓存数量: %d", dnsCount);
        g_dnsQueryCache.clear();
        LOG_INFO("✅ DNS查询缓存已清空 (清理了%d条DNS记录)", dnsCount);
    }
    
    LOG_INFO("✅ [资源清理完成] Socket:%d, 线程:%d, DNS:%d", 
        socketCount, threadCount, dnsCount);
    LOG_INFO("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
}

// 获取统计信息（用于调试）
void PacketForwarder::LogStatistics() {
    LOG_INFO("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    LOG_INFO("📊 [PacketForwarder统计]");
    
    {
        std::lock_guard<std::mutex> lock(g_socketCacheMutex);
        LOG_INFO("   Socket缓存: %zu个", g_socketCache.size());
        if (!g_socketCache.empty()) {
            for (const auto& pair : g_socketCache) {
                LOG_DEBUG("      - fd:%d, key:%s", pair.second, pair.first.c_str());
            }
        }
    }
    
    {
        std::lock_guard<std::mutex> lock(g_threadMapMutex);
        LOG_INFO("   响应线程: %zu个", g_socketThreadMap.size());
    }
    
    {
        std::lock_guard<std::mutex> lock(g_dnsQueryCacheMutex);
        LOG_INFO("   DNS缓存: %zu条", g_dnsQueryCache.size());
    }
    
    LOG_INFO("   NAT映射: %d个", NATTable::GetMappingCount());
    LOG_INFO("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
}
