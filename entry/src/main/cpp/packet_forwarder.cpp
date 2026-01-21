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

// 🔧 调试开关：启用转发器日志（默认启用，用于排查问题）
// 生产环境可以设置为 0 减少日志
#define ENABLE_FORWARDER_LOG 1

#if ENABLE_FORWARDER_LOG
  #define LOG(fmt, ...) \
    OH_LOG_Print(LOG_APP, LOG_INFO, 0x15b1, "VpnServer", "ZBQ [Forwarder] [%{public}s:%{public}d] " fmt, MAKE_FILE_NAME, __LINE__, ##__VA_ARGS__)
  #define LOG_ERROR(fmt, ...) \
    OH_LOG_Print(LOG_APP, LOG_ERROR, 0x15b1, "VpnServer", "ZBQ [Forwarder] [%{public}s:%{public}d] ❌ " fmt, MAKE_FILE_NAME, __LINE__, ##__VA_ARGS__)
#else
  #define LOG(fmt, ...) /* 转发器日志已禁用 */
  #define LOG_ERROR(fmt, ...) /* 转发器错误日志已禁用 */
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
    // 🔍 [流程1] 转发开始
    LOG("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    LOG("📦 [开始转发] %s:%d -> %s:%d (%s, %d字节)",
        packetInfo.sourceIP.c_str(), packetInfo.sourcePort,
        packetInfo.targetIP.c_str(), packetInfo.targetPort,
        ProtocolHandler::GetProtocolName(packetInfo.protocol).c_str(),
        dataSize);
    
    // ✅ 路由循环已通过 vpnConnection.protect(tunnelFd) 防止
    // 无需额外的重复数据包检测，让所有合法请求正常转发
    
    // 🔍 [流程2] 提取payload
    const uint8_t* payload = nullptr;
    int payloadSize = 0;
    LOG("🔍 [步骤1] 开始提取payload (数据包大小: %d)", dataSize);
    if (!PacketBuilder::ExtractPayload(data, dataSize, packetInfo, &payload, &payloadSize)) {
        LOG_ERROR("提取payload失败 - 数据包可能损坏或格式错误");
        LOG_ERROR("   原因: 数据包大小=%d, 协议=%s", dataSize, 
                  ProtocolHandler::GetProtocolName(packetInfo.protocol).c_str());
        return -1;
    }
    
    if (payloadSize <= 0) {
        LOG("⚠️ payload为空(size=%d)，跳过转发", payloadSize);
        return 0;
    }
    
    LOG("✅ [步骤1完成] 提取payload: %d字节", payloadSize);
    
    // 🔧 3. Socket复用：检查是否已有可用socket
    std::string socketKey = packetInfo.targetIP + ":" + std::to_string(packetInfo.targetPort);
    int sockFd = -1;
    bool isNewSocket = true;  // 🔧 默认是新socket
    
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
                isNewSocket = false;  // 🔧 标记为复用socket
            } else {
                LOG("⚠️ 缓存的socket无效，将创建新socket");
                close(sockFd);
                g_socketCache.erase(it);
                sockFd = -1;
            }
        }
    }
    
    // 🔍 [流程3] 创建或复用socket
    if (sockFd < 0) {
        LOG("🔍 [步骤2] 创建新socket...");
        // 根据协议选择socket类型和地址族
        int addressFamily = packetInfo.addressFamily;
        int sockType = SOCK_DGRAM;
        int protocol = 0;
        
        if (packetInfo.protocol == PROTOCOL_ICMPV6) {
            addressFamily = AF_INET6;
            sockType = SOCK_RAW;
            protocol = IPPROTO_ICMPV6;
            LOG("   类型: ICMPv6 RAW socket");
        } else if (packetInfo.protocol == PROTOCOL_UDP) {
            sockType = SOCK_DGRAM;
            LOG("   类型: UDP DGRAM socket");
        } else if (packetInfo.protocol == PROTOCOL_TCP) {
            sockType = SOCK_STREAM;
            LOG("   类型: TCP STREAM socket");
        }
        
        sockFd = socket(addressFamily, sockType, protocol);
        if (sockFd < 0) {
            LOG_ERROR("创建socket失败!");
            LOG_ERROR("   errno: %d (%s)", errno, strerror(errno));
            LOG_ERROR("   family: %d, type: %d, protocol: %d", 
                     addressFamily, sockType, protocol);
            LOG_ERROR("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            return -1;
        }
        isNewSocket = true;
        
        // 添加到缓存
        {
            std::lock_guard<std::mutex> lock(g_socketCacheMutex);
            g_socketCache[socketKey] = sockFd;
        }
        LOG("✅ [步骤2完成] 创建socket成功: fd=%d, key=%s", sockFd, socketKey.c_str());
    } else {
        LOG("♻️ [步骤2跳过] 复用已有socket: fd=%d", sockFd);
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
        
        // 🔧 TCP响应：启动专用响应线程（TCP连接需要持久监听）
        if (isNewSocket) {
            LOG("🚀 启动新的TCP响应线程 for socket %d (新socket)", sockFd);
            std::thread([sockFd, originalPeer, packetInfo, socketKey]() {
                {
                    std::lock_guard<std::mutex> lock(g_threadMapMutex);
                    g_socketThreadMap[sockFd] = std::this_thread::get_id();
                }
                LOG("🔥🔥🔥 TCP响应线程已进入 - socket=%d 🔥🔥🔥", sockFd);
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
                LOG("🔥🔥🔥 TCP响应线程已退出 - socket=%d 🔥🔥🔥", sockFd);
            }).detach();
        } else {
            // 🔧 Socket复用时，检查响应线程状态
            LOG("♻️ 复用TCP socket %d", sockFd);
            {
                std::lock_guard<std::mutex> lock(g_threadMapMutex);
                auto it = g_socketThreadMap.find(sockFd);
                if (it != g_socketThreadMap.end()) {
                    LOG("✅ 响应线程仍在运行 for socket %d", sockFd);
                } else {
                    LOG("⚠️ 响应线程丢失 for socket %d，可能需要重启", sockFd);
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
                    LOG("🎯 DNS缓存命中: %s (qtype=%d), 返回缓存响应 %d字节",
                        domain.c_str(), qtype, cachedResponseSize);

                    // 直接发送缓存的响应给客户端（通过响应队列）
                    if (!TaskQueueManager::getInstance().submitResponseTask(
                            cachedResponse, cachedResponseSize, originalPeer, sockFd, PROTOCOL_UDP)) {
                        LOG("❌ 提交DNS缓存响应失败");
                    } else {
                        LOG("✅ DNS缓存响应已提交到队列");
                    }

                    return sockFd;  // 返回但不创建响应线程（缓存响应直接处理）
                } else {
                    LOG("💾 DNS缓存未命中: %s (qtype=%d)", domain.c_str(), qtype);

                    // 保存原始DNS查询数据，用于后续缓存设置
                    {
                        std::lock_guard<std::mutex> lock(g_dnsQueryCacheMutex);
                        g_dnsQueryCache[sockFd] = std::vector<uint8_t>(payload, payload + payloadSize);
                    }
                }
            }
        }

        // 🔍 [流程4] UDP发送数据
        LOG("🔍 [步骤3] 发送UDP数据 %d字节 -> %s:%d", 
            payloadSize, actualTargetIP.c_str(), packetInfo.targetPort);
        
        ssize_t sent = -1;
        int retryCount = 0;
        const int maxRetries = 3;
        
        while (sent < 0 && retryCount < maxRetries) {
            sent = sendto(sockFd, payload, payloadSize, 0, 
                         pTargetAddr, targetAddrLen);
            
            if (sent < 0) {
                retryCount++;
                LOG("⚠️ UDP发送失败，重试 %d/%d: errno=%d (%s)", 
                    retryCount, maxRetries, errno, strerror(errno));
                
                if (retryCount < maxRetries) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(10));
                    
                    // 检查socket状态
                    int error = 0;
                    socklen_t len = sizeof(error);
                    if (getsockopt(sockFd, SOL_SOCKET, SO_ERROR, &error, &len) == 0 && error != 0) {
                        LOG_ERROR("Socket状态错误，停止重试: %s", strerror(error));
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
        
        LOG("✅ [步骤3完成] UDP发送成功: %zd字节 -> %s:%d %s", 
            sent, actualTargetIP.c_str(), packetInfo.targetPort,
            retryCount > 0 ? ("(重试" + std::to_string(retryCount) + "次)").c_str() : "");
        
        // 🔍 [流程5] 启动UDP响应线程
        if (isNewSocket) {
            LOG("🔍 [步骤4] 启动UDP响应线程 for socket %d", sockFd);
            std::thread([sockFd, originalPeer, packetInfo, socketKey]() {
                {
                    std::lock_guard<std::mutex> lock(g_threadMapMutex);
                    g_socketThreadMap[sockFd] = std::this_thread::get_id();
                }
                LOG("🔥 [响应线程启动] socket=%d, 等待来自 %s:%d 的响应", 
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
                LOG("🔚 [响应线程退出] socket=%d", sockFd);
            }).detach();
            LOG("✅ [步骤4完成] 响应线程已启动");
        } else {
            LOG("♻️ [步骤4跳过] 复用socket，响应线程已存在");
        }
        
        LOG("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        LOG("✅ [转发完成] socket=%d 返回", sockFd);
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
    
    // 🐛 修复：保存g_sockFd副本，避免服务器停止时使用无效socket
    int tunnelFd = g_sockFd;
    if (tunnelFd < 0) {
        LOG("❌ TUN socket无效，退出响应线程");
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
        // 🐛 修复：快速检查服务器是否正在停止
        if (!g_running.load() || tunnelFd != g_sockFd) {
            LOG("⚠️ 服务器正在停止，退出响应线程 socket=%d", sockFd);
            break;
        }
        
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
        
        // 🔧 关键修复：构建完整的IP包（UDP响应需要IP/UDP头部！）
        uint8_t ipPacket[4096 + 60];
        int packetLen = PacketBuilder::BuildResponsePacket(
            ipPacket, sizeof(ipPacket),
            responsePayload, received,
            conn.originalRequest
        );
        
        if (packetLen < 0) {
            LOG("❌ 构建UDP响应包失败");
            continue;
        }
        
        LOG("✅ 构建UDP IP包: %d字节 (payload: %zd字节)", packetLen, received);
        
        // 🔧 优化：添加响应内容摘要（仅DNS）
        if (packetInfo.targetPort == 53 && received >= 12) {
            // DNS响应前12字节包含头部信息
            uint16_t dnsId = (responsePayload[0] << 8) | responsePayload[1];
            uint8_t flags = responsePayload[2];
            uint8_t rcode = flags & 0x0F;
            uint16_t answerCount = (responsePayload[6] << 8) | responsePayload[7];

            LOG("🔍 DNS响应详情: ID=%d, 标志=0x%02X, RCODE=%d, 答案数=%d",
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

                        LOG("💾 DNS响应已缓存: %s (qtype=%d, %zd字节)",
                            domain.c_str(), qtype, received);
                    }
                } else {
                    LOG("⚠️ 找不到原始DNS查询，无法缓存响应");
                }
            }

            // 🔧 UDP重传确认：收到DNS响应后，确认对应的重传记录
            // 注意：这里需要从packetInfo中提取原始的packetId
            // 简化处理：DNS响应通常对应最近的DNS查询
            LOG("📨 DNS响应已确认，更新重传状态");
        }
        
        // 🔧 提交响应任务到队列（异步发送）- 发送完整的IP包！
        bool sendSuccess = false;
        if (!TaskQueueManager::getInstance().submitResponseTask(
                ipPacket, packetLen, originalPeer, sockFd, packetInfo.protocol)) {
            // 🔧 队列满时的正确处理：
            // UDP响应可以丢弃（客户端会重试），不要阻塞响应线程
            LOG("❌❌❌ 响应队列已满，丢弃UDP响应！系统过载警告！");
            LOG("⚠️ 队列大小限制: %zu, 请考虑增大队列或优化性能", 
                TaskQueueManager::getInstance().getResponseQueueSize());
            
            // 不要直接发送，避免占用响应线程资源
            // UDP丢包是可接受的，客户端会重试DNS查询
            sendSuccess = false;
        } else {
            LOG("✅ UDP响应已提交到队列: %d字节 (完整IP包)", packetLen);
            sendSuccess = true;
        }

        if (sendSuccess) {
            // 更新活动时间
            std::string natKey = NATTable::GenerateKey(packetInfo);
            NATTable::UpdateActivity(natKey);

            // UDP响应确认（用于重传管理）
            if (packetInfo.protocol == PROTOCOL_UDP) {
                // 这里可以添加UDP响应确认逻辑
                LOG("📨 UDP响应已处理");
            }
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
    
    // 🐛 修复：保存g_sockFd副本，避免服务器停止时使用无效socket
    int tunnelFd = g_sockFd;
    if (tunnelFd < 0) {
        LOG("❌ TUN socket无效，退出响应线程");
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
        LOG("❌ 找不到NAT映射，退出TCP响应线程");
        close(sockFd);
        return;
    }
    LOG("✅ 找到NAT映射: %s", conn.originalRequest.sourceIP.c_str());
    
    uint8_t responsePayload[4096];
    int totalResponses = 0;
    
    LOG("🔄 开始TCP数据转发... socket=%d", sockFd);
    while (true) {
        // 🐛 修复：快速检查服务器是否正在停止
        if (!g_running.load() || tunnelFd != g_sockFd) {
            LOG("⚠️ 服务器正在停止，退出TCP响应线程 socket=%d", sockFd);
            break;
        }
        
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
        
        // 🔧 提交TCP响应任务到队列（异步发送）
        // TCP响应不能丢失，需要可靠传输
        bool tcpSendSuccess = false;
        if (!TaskQueueManager::getInstance().submitResponseTask(
                ipPacket, packetLen, conn.clientPhysicalAddr, sockFd, PROTOCOL_TCP)) {
            // 🔧 TCP响应队列满是严重问题！
            // TCP不能丢包，但直接发送也有风险（死锁、性能问题）
            // 最好的策略：记录错误，关闭连接，让客户端重试
            LOG("❌❌❌ 响应队列已满，无法发送TCP响应！系统严重过载！");
            LOG("⚠️ TCP连接将被关闭，客户端需要重连");
            
            // 不要直接发送，避免死锁和资源竞争
            // 让TCP连接断开，客户端会重新建立连接
            tcpSendSuccess = false;
            break;  // 退出响应循环，关闭连接
        } else {
            LOG("✅ TCP响应已提交到队列: %d字节", packetLen);
            tcpSendSuccess = true;
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

// 清理所有缓存的socket和线程
void PacketForwarder::CleanupAll() {
    LOG("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    LOG("🧹 [资源清理] 开始清理PacketForwarder资源...");
    
    // 清理socket缓存
    int socketCount = 0;
    {
        std::lock_guard<std::mutex> lock(g_socketCacheMutex);
        socketCount = g_socketCache.size();
        LOG("📊 [统计] Socket缓存数量: %d", socketCount);
        for (auto& pair : g_socketCache) {
            LOG("   🔒 关闭socket: fd=%d, key=%s", pair.second, pair.first.c_str());
            close(pair.second);
        }
        g_socketCache.clear();
        LOG("✅ Socket缓存已清空 (关闭了%d个socket)", socketCount);
    }
    
    // 清理线程映射
    int threadCount = 0;
    {
        std::lock_guard<std::mutex> lock(g_threadMapMutex);
        threadCount = g_socketThreadMap.size();
        LOG("📊 [统计] 活跃响应线程数: %d", threadCount);
        g_socketThreadMap.clear();
        LOG("✅ 线程映射已清空 (清理了%d个线程记录)", threadCount);
    }

    // 清理DNS查询缓存
    int dnsCount = 0;
    {
        std::lock_guard<std::mutex> lock(g_dnsQueryCacheMutex);
        dnsCount = g_dnsQueryCache.size();
        LOG("📊 [统计] DNS查询缓存数量: %d", dnsCount);
        g_dnsQueryCache.clear();
        LOG("✅ DNS查询缓存已清空 (清理了%d条DNS记录)", dnsCount);
    }
    
    LOG("✅ [资源清理完成] Socket:%d, 线程:%d, DNS:%d", 
        socketCount, threadCount, dnsCount);
    LOG("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
}

// 获取统计信息（用于调试）
void PacketForwarder::LogStatistics() {
    LOG("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    LOG("📊 [PacketForwarder统计]");
    
    {
        std::lock_guard<std::mutex> lock(g_socketCacheMutex);
        LOG("   Socket缓存: %zu个", g_socketCache.size());
        if (!g_socketCache.empty()) {
            for (const auto& pair : g_socketCache) {
                LOG("      - fd:%d, key:%s", pair.second, pair.first.c_str());
            }
        }
    }
    
    {
        std::lock_guard<std::mutex> lock(g_threadMapMutex);
        LOG("   响应线程: %zu个", g_socketThreadMap.size());
    }
    
    {
        std::lock_guard<std::mutex> lock(g_dnsQueryCacheMutex);
        LOG("   DNS缓存: %zu条", g_dnsQueryCache.size());
    }
    
    LOG("   NAT映射: %d个", NATTable::GetMappingCount());
    LOG("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
}
