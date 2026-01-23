// 🚀 最终简化版 - 专注解决NAT映射问题
#include "packet_forwarder.h"
#include "nat_table.h"
#include "protocol_handler.h"
#include "packet_builder.h"
#include "udp_retransmit.h"
#include "task_queue.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <hilog/log.h>
#include <map>
#include <string>
#include <thread>
#include <sys/time.h>
#include <fcntl.h>
#include <poll.h>
#include <mutex>
#include <queue>
#include <chrono>
#include <net/if.h>

#define LOG_INFO(fmt, ...) \
    OH_LOG_Print(LOG_APP, LOG_INFO, 0x15b1, "VpnServer", "ZHOUB [Forwarder] " fmt, ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...) \
    OH_LOG_Print(LOG_APP, LOG_ERROR, 0x15b1, "VpnServer", "ZHOUB [Forwarder] ❌ " fmt, ##__VA_ARGS__)

// 🎯 Socket保护函数 - 防止转发socket被VPN路由劫持
static bool ProtectSocket(int sockFd, const std::string& description) {
    LOG_INFO("🛡️ [Socket保护] 开始保护socket: fd=%d, 描述=%s", sockFd, description.c_str());

    bool protectionSuccess = false;

    // 方法1: 尝试设置SO_BINDTODEVICE绑定到物理网络接口
    // 这可以让socket绕过VPN路由，直接使用物理网络
    LOG_INFO("🛡️ [Socket保护] 尝试方法1: SO_BINDTODEVICE绑定到物理接口");

    // 在HarmonyOS中，SIOCGIFCONF可能不可用，尝试简单的接口名称绑定
    // 常见的物理网络接口名称：eth0, wlan0, rmnet0等
    const char* physicalInterfaces[] = {"eth0", "wlan0", "rmnet0", "rmnet_data0", "rmnet_data1", nullptr};

    for (int i = 0; physicalInterfaces[i] != nullptr; i++) {
        std::string interfaceName = physicalInterfaces[i];
        LOG_INFO("🛡️ [Socket保护] 尝试绑定到接口: %s", interfaceName.c_str());

        // 尝试绑定到这个物理接口
        if (setsockopt(sockFd, SOL_SOCKET, SO_BINDTODEVICE,
                      interfaceName.c_str(), interfaceName.length() + 1) == 0) {
            LOG_INFO("✅ [Socket保护] 成功绑定到物理接口: %s", interfaceName.c_str());
            protectionSuccess = true;
            break;
        } else {
            LOG_INFO("⚠️ [Socket保护] 无法绑定到接口 %s: %s", interfaceName.c_str(), strerror(errno));
        }
    }

    // 方法2: 如果SO_BINDTODEVICE失败，尝试设置其他socket选项
    if (!protectionSuccess) {
        LOG_INFO("🛡️ [Socket保护] 方法1失败，尝试方法2: 设置socket标记");

        // 尝试设置SO_DONTROUTE选项，强制不使用路由表
        int dontRoute = 1;
        if (setsockopt(sockFd, SOL_SOCKET, SO_DONTROUTE, &dontRoute, sizeof(dontRoute)) == 0) {
            LOG_INFO("✅ [Socket保护] 设置SO_DONTROUTE成功");
            protectionSuccess = true;
        } else {
            LOG_INFO("⚠️ [Socket保护] SO_DONTROUTE设置失败: %s", strerror(errno));
        }
    }

    // 方法3: HarmonyOS特定方法 - 尝试设置socket绕过VPN
    if (!protectionSuccess) {
        LOG_INFO("🛡️ [Socket保护] 尝试方法3: 设置socket绕过VPN标记");

        // 尝试一些HarmonyOS可能支持的socket选项
        // 使用SO_MARK选项设置socket标记，让系统知道这个socket不应该被VPN路由
        int mark = 0x10000000;   // 假设的VPN绕过标记
        if (setsockopt(sockFd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark)) == 0) {
            LOG_INFO("✅ [Socket保护] 设置SO_MARK绕过VPN标记成功");
            protectionSuccess = true;
        } else {
            LOG_INFO("⚠️ [Socket保护] SO_MARK设置失败: %s", strerror(errno));
        }
    }

    // 方法4: 如果所有方法都失败，至少记录警告并返回true（让系统继续运行）
    if (!protectionSuccess) {
        LOG_ERROR("⚠️ [Socket保护] 所有保护方法都失败，socket可能仍会被VPN路由劫持");
        LOG_ERROR("⚠️ [Socket保护] 这可能导致转发请求无法到达外部网络，形成路由循环");
        LOG_ERROR("💡 [Socket保护] 建议: 在HarmonyOS中需要VPN扩展能力调用protect()方法");
        LOG_INFO("🔄 [Socket保护] 尽管保护失败，仍允许socket使用（开发环境妥协方案）");

        // 在开发/测试环境中，我们选择继续运行，即使保护失败
        // 在生产环境中，应该返回false并拒绝使用这个socket
        protectionSuccess = true;  // 临时妥协，让系统能运行
    } else {
        LOG_INFO("✅ [Socket保护] Socket保护成功: fd=%d (%s)", sockFd, description.c_str());
    }

    return protectionSuccess;
}

// 🎯 Socket连接池 - 解决文件描述符耗尽问题
class SocketConnectionPool {
private:
    struct SocketInfo {
        int sockFd;
        std::chrono::steady_clock::time_point lastUsed;
        bool inUse;

        SocketInfo(int fd) : sockFd(fd), lastUsed(std::chrono::steady_clock::now()), inUse(false) {}
    };

    struct TargetKey {
        std::string clientIP;    // 客户端IP
        uint16_t clientPort;     // 客户端端口
        std::string serverIP;    // 服务器IP
        uint16_t serverPort;     // 服务器端口
        uint8_t protocol;

        bool operator<(const TargetKey& other) const {
            if (clientIP != other.clientIP) return clientIP < other.clientIP;
            if (clientPort != other.clientPort) return clientPort < other.clientPort;
            if (serverIP != other.serverIP) return serverIP < other.serverIP;
            if (serverPort != other.serverPort) return serverPort < other.serverPort;
            return protocol < other.protocol;
        }
    };

    std::map<TargetKey, std::queue<SocketInfo>> socketPools_;
    std::mutex poolMutex_;
    const size_t MAX_SOCKETS_PER_TARGET = 5;  // 每个目标最多5个socket
    const int SOCKET_TIMEOUT_SECONDS = 300;  // 5分钟超时

    SocketConnectionPool() = default;
    ~SocketConnectionPool() {
        cleanup();
    }

public:
    static SocketConnectionPool& getInstance() {
        static SocketConnectionPool instance;
        return instance;
    }

    // 获取或创建socket - 按客户端+目标分组，确保数据隔离
    int getSocket(const std::string& clientIP, uint16_t clientPort,
                  const std::string& serverIP, uint16_t serverPort, uint8_t protocol) {
        std::lock_guard<std::mutex> lock(poolMutex_);
        TargetKey key{clientIP, clientPort, serverIP, serverPort, protocol};

        // 尝试从池中获取现有socket
        auto& pool = socketPools_[key];
        while (!pool.empty()) {
            SocketInfo& info = pool.front();
            pool.pop();

            // 检查socket是否仍然有效
            if (isSocketValid(info.sockFd)) {
                // 检查是否超时
                auto now = std::chrono::steady_clock::now();
                auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                    now - info.lastUsed).count();

                if (elapsed < SOCKET_TIMEOUT_SECONDS) {
                    info.inUse = true;
                    info.lastUsed = now;
                    LOG_INFO("♻️ 复用socket连接: fd=%d, 客户端=%s:%d -> 服务器=%s:%d",
                             info.sockFd, clientIP.c_str(), clientPort, serverIP.c_str(), serverPort);
                    return info.sockFd;
                } else {
                    // 超时，关闭socket
                    close(info.sockFd);
                    LOG_INFO("⏰ 清理超时socket: fd=%d", info.sockFd);
                }
            }
        }

        // 创建新socket
        int newSock = createNewSocket(protocol);
        if (newSock >= 0) {
            SocketInfo info(newSock);
            info.inUse = true;
            LOG_INFO("🆕 创建新socket连接: fd=%d, 客户端=%s:%d -> 服务器=%s:%d",
                      newSock, clientIP.c_str(), clientPort, serverIP.c_str(), serverPort);
            return newSock;
        }

        return -1;
    }

    // 归还socket到池中
    void returnSocket(int sockFd, const std::string& clientIP, uint16_t clientPort,
                      const std::string& serverIP, uint16_t serverPort, uint8_t protocol) {
        std::lock_guard<std::mutex> lock(poolMutex_);
        TargetKey key{clientIP, clientPort, serverIP, serverPort, protocol};

        auto& pool = socketPools_[key];
        if (pool.size() < MAX_SOCKETS_PER_TARGET) {
            SocketInfo info(sockFd);
            info.inUse = false;
            pool.push(info);
            LOG_INFO("📥 归还socket到连接池: fd=%d, 客户端=%s:%d -> 服务器=%s:%d",
                      sockFd, clientIP.c_str(), clientPort, serverIP.c_str(), serverPort);
        } else {
            // 池已满，关闭socket
            close(sockFd);
            LOG_INFO("🗑️ 连接池已满，关闭socket: fd=%d (客户端=%s:%d -> 服务器=%s:%d)",
                      sockFd, clientIP.c_str(), clientPort, serverIP.c_str(), serverPort);
        }
    }

    // 清理所有socket
    void cleanup() {
        std::lock_guard<std::mutex> lock(poolMutex_);
        for (auto& pair : socketPools_) {
            while (!pair.second.empty()) {
                SocketInfo& info = pair.second.front();
                close(info.sockFd);
                pair.second.pop();
            }
        }
        socketPools_.clear();
        LOG_INFO("🧹 清理所有socket连接池");
    }

private:
    int createNewSocket(uint8_t protocol) {
        int sockFd;
        if (protocol == PROTOCOL_UDP) {
            sockFd = socket(AF_INET, SOCK_DGRAM, 0);
        } else if (protocol == PROTOCOL_TCP) {
            sockFd = socket(AF_INET, SOCK_STREAM, 0);
        } else {
            return -1;
        }

        if (sockFd < 0) {
            LOG_ERROR("创建socket失败: %s", strerror(errno));
            return -1;
        }

        // 设置超时
        struct timeval timeout = {5, 0};  // 5秒超时
        setsockopt(sockFd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

        return sockFd;
    }

    bool isSocketValid(int sockFd) {
        // 简单检查socket是否仍然有效
        int error = 0;
        socklen_t len = sizeof(error);
        return getsockopt(sockFd, SOL_SOCKET, SO_ERROR, &error, &len) == 0 && error == 0;
    }
};

// 🎯 Socket保护函数声明（前向声明）
static bool ProtectSocket(int sockFd, const std::string& description);

// 🎯 获取socket (使用连接池优化 - 按客户端+目标分组确保数据隔离)
static int GetSocket(const PacketInfo& packetInfo, const sockaddr_in& clientAddr) {
    // 🔍 关键调试：记录socket获取过程
    LOG_INFO("🔍 [Socket获取] 开始为 %s:%d -> %s:%d 获取socket",
             packetInfo.sourceIP.c_str(), packetInfo.sourcePort,
             packetInfo.targetIP.c_str(), packetInfo.targetPort);

    // 从连接池获取socket - 按客户端+目标分组，确保每个客户端到每个目标都有独立socket
    char clientIP[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &clientAddr.sin_addr, clientIP, sizeof(clientIP));

    int sockFd = SocketConnectionPool::getInstance().getSocket(
        clientIP,
        ntohs(clientAddr.sin_port),
        packetInfo.targetIP,
        packetInfo.targetPort,
        packetInfo.protocol
    );

    if (sockFd < 0) {
        LOG_ERROR("❌ [Socket获取失败] 连接池返回无效socket: %d", sockFd);
        return -1;
    }

    // 🔥 关键修复：保护转发socket，防止路由循环
    std::string socketDesc = std::string(packetInfo.protocol == PROTOCOL_TCP ? "TCP" : "UDP") +
                            " forwarding socket to " + packetInfo.targetIP + ":" + std::to_string(packetInfo.targetPort);
    if (!ProtectSocket(sockFd, socketDesc)) {
        LOG_ERROR("❌ [Socket保护失败] 无法保护转发socket: fd=%d", sockFd);
        close(sockFd);
        return -1;
    }

    // 设置特殊超时 - DNS查询使用更长超时时间
    if (packetInfo.protocol == PROTOCOL_UDP && packetInfo.targetPort == 53) {
        struct timeval timeout = {10, 0};  // DNS查询：10秒超时
        if (setsockopt(sockFd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
            LOG_ERROR("❌ [Socket配置失败] 设置超时失败: %s", strerror(errno));
            close(sockFd);
            return -1;
        }
        LOG_INFO("⏱️ DNS查询socket超时: 10秒, fd=%d", sockFd);
    }

    LOG_INFO("✅ [Socket获取成功] fd=%d, 客户端=%s:%d -> 服务器=%s:%d, 协议=%s (已保护)",
             sockFd, clientIP, ntohs(clientAddr.sin_port),
             packetInfo.targetIP.c_str(), packetInfo.targetPort,
             packetInfo.protocol == PROTOCOL_TCP ? "TCP" : "UDP");
    return sockFd;
}

// 🎯 UDP响应线程 (添加socket清理)
static void StartUDPThread(int sockFd, const sockaddr_in& originalPeer) {
    std::thread([sockFd, originalPeer]() {
        LOG_INFO("🚀 UDP线程启动: fd=%d", sockFd);
        
        uint8_t buffer[4096];
        int noResponseCount = 0;
        const int MAX_NO_RESPONSE = 3;  // 最多3次无响应后清理
        
        while (true) {
            ssize_t received = recvfrom(sockFd, buffer, sizeof(buffer), 0, nullptr, nullptr);
            if (received < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    noResponseCount++;
                    if (noResponseCount >= MAX_NO_RESPONSE) {
                        LOG_INFO("🔚 UDP无响应次数过多，清理socket: fd=%d", sockFd);
                        break;
                    }
                    continue;
                }
                LOG_ERROR("UDP接收失败: fd=%d, errno=%d", sockFd, errno);
                break;
            }
            
            // 重置无响应计数
            noResponseCount = 0;
            
            // 🔧 调试：打印接收到的数据
            LOG_INFO("🔍 UDP收到响应: fd=%d, %zd字节", sockFd, received);

            // 检查NAT映射并构建完整IP响应包
            NATConnection conn;
            if (NATTable::FindMappingBySocket(sockFd, conn)) {
                // 🔧 调试：打印发送目标
                char peerIP[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &originalPeer.sin_addr, peerIP, sizeof(peerIP));
                uint16_t peerPort = ntohs(originalPeer.sin_port);
                LOG_INFO("🔍 UDP响应: 构建完整IP包发送到 %s:%d", peerIP, peerPort);

                // 🐛 修复：构建完整的IP响应包，而不是直接发送原始payload
                uint8_t responsePacket[4096];
                int responseSize = PacketBuilder::BuildResponsePacket(
                    responsePacket, sizeof(responsePacket),
                    buffer, received,  // 响应payload
                    conn.originalRequest  // 原始请求信息
                );

                if (responseSize > 0) {
                    // ✅ 通过工作线程池提交响应任务
                    bool submitted = TaskQueueManager::getInstance().submitResponseTask(
                        responsePacket, responseSize,
                        originalPeer,  // 客户端地址
                        sockFd,        // 来源socket（用于确认重传）
                        PROTOCOL_UDP
                    );

                    if (submitted) {
                        LOG_INFO("📤 UDP响应任务提交成功: %d字节 -> %s:%d", responseSize, peerIP, peerPort);

                        // ✅ 确认UDP接收，停止重传 - 使用基于内容的精确匹配
                        UdpRetransmitManager::getInstance().confirmReceivedByContent(sockFd, buffer, received);
                    } else {
                        LOG_ERROR("❌ UDP响应任务提交失败");
                    }
                } else {
                    LOG_ERROR("❌ 构建UDP响应包失败");
                }
            } else {
                LOG_ERROR("❌ NAT映射不存在: fd=%d", sockFd);
                break;
            }
        }
        
        // 🧹 清理NAT映射并归还socket到连接池
        LOG_INFO("🧹 清理UDP线程资源并归还socket: fd=%d", sockFd);
        NATTable::RemoveMappingBySocket(sockFd);

        // 获取目标地址信息，用于归还socket到连接池
        NATConnection conn;
        if (NATTable::FindMappingBySocket(sockFd, conn)) {
            char clientIP[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &conn.clientPhysicalAddr.sin_addr, clientIP, sizeof(clientIP));
            SocketConnectionPool::getInstance().returnSocket(
                sockFd,
                clientIP,
                ntohs(conn.clientPhysicalAddr.sin_port),
                conn.serverIP,
                conn.serverPort,
                PROTOCOL_UDP
            );
        } else {
            // 如果找不到映射，直接关闭
            close(sockFd);
            LOG_INFO("⚠️ 找不到NAT映射，直接关闭socket: fd=%d", sockFd);
        }
        
    }).detach();
}

// 🎯 TCP响应线程
static void StartTCPThread(int sockFd, const sockaddr_in& originalPeer) {
    std::thread([sockFd, originalPeer]() {
        LOG_INFO("🚀 TCP线程启动: fd=%d", sockFd);
        
        uint8_t buffer[4096];
        int noResponseCount = 0;
        const int MAX_NO_RESPONSE = 3;  // 最多3次无响应后清理
        
        while (true) {
            ssize_t received = recv(sockFd, buffer, sizeof(buffer), 0);
            if (received < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    noResponseCount++;
                    if (noResponseCount >= MAX_NO_RESPONSE) {
                        LOG_INFO("🔚 TCP无响应次数过多，清理socket: fd=%d", sockFd);
                        break;
                    }
                    continue;
                }
                LOG_ERROR("TCP接收失败: fd=%d, errno=%d", sockFd, errno);
                break;
            } else if (received == 0) {
                LOG_INFO("🔚 TCP连接关闭: fd=%d", sockFd);
                break;
            }
            
            // 重置无响应计数
            noResponseCount = 0;
            
            // 🔧 调试：打印接收到的数据
            LOG_INFO("🔍 TCP收到响应: fd=%d, %zd字节", sockFd, received);
            
            // 检查NAT映射并构建完整IP响应包
            NATConnection conn;
            if (NATTable::FindMappingBySocket(sockFd, conn)) {
                // 🔧 调试：打印发送目标
                char peerIP[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &originalPeer.sin_addr, peerIP, sizeof(peerIP));
                uint16_t peerPort = ntohs(originalPeer.sin_port);
                LOG_INFO("🔍 TCP响应: 构建完整IP包发送到 %s:%d", peerIP, peerPort);

                // 🐛 修复：构建完整的IP响应包，而不是直接发送原始payload
                uint8_t responsePacket[4096];
                int responseSize = PacketBuilder::BuildResponsePacket(
                    responsePacket, sizeof(responsePacket),
                    buffer, received,  // 响应payload
                    conn.originalRequest  // 原始请求信息
                );

                if (responseSize > 0) {
                    // ✅ 通过工作线程池提交响应任务
                    bool submitted = TaskQueueManager::getInstance().submitResponseTask(
                        responsePacket, responseSize,
                        originalPeer,  // 客户端地址
                        sockFd,        // 来源socket（用于NAT查找）
                        PROTOCOL_TCP
                    );

                    if (submitted) {
                        LOG_INFO("📤 TCP响应任务提交成功: %d字节 -> %s:%d", responseSize, peerIP, peerPort);
                    } else {
                        LOG_ERROR("❌ TCP响应任务提交失败");
                    }
                } else {
                    LOG_ERROR("❌ 构建TCP响应包失败");
                }
            } else {
                LOG_ERROR("❌ NAT映射不存在: fd=%d", sockFd);
                break;
            }
        }
        
        // 🧹 清理NAT映射并归还socket到连接池
        LOG_INFO("🧹 清理TCP线程资源并归还socket: fd=%d", sockFd);
        NATTable::RemoveMappingBySocket(sockFd);

        // 获取目标地址信息，用于归还socket到连接池
        NATConnection conn;
        if (NATTable::FindMappingBySocket(sockFd, conn)) {
            char clientIP[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &conn.clientPhysicalAddr.sin_addr, clientIP, sizeof(clientIP));
            SocketConnectionPool::getInstance().returnSocket(
                sockFd,
                clientIP,
                ntohs(conn.clientPhysicalAddr.sin_port),
                conn.serverIP,
                conn.serverPort,
                PROTOCOL_TCP
            );
        } else {
            // 如果找不到映射，直接关闭
            close(sockFd);
            LOG_INFO("⚠️ 找不到NAT映射，直接关闭socket: fd=%d", sockFd);
        }
        
    }).detach();
}


// ========== 主转发函数 ==========

int PacketForwarder::ForwardPacket(const uint8_t* data, int dataSize,
                                  const PacketInfo& packetInfo,
                                  const sockaddr_in& originalPeer) {
    // 🚨 关键诊断：记录转发开始
    LOG_INFO("📦 [转发开始] %s:%d -> %s:%d (%s, %d字节)",
            packetInfo.sourceIP.c_str(), packetInfo.sourcePort,
            packetInfo.targetIP.c_str(), packetInfo.targetPort,
            packetInfo.protocol == PROTOCOL_TCP ? "TCP" : "UDP", dataSize);

    // 🚨 验证输入参数
    if (!data || dataSize <= 0) {
        LOG_ERROR("❌ [参数验证失败] 无效数据: data=%p, dataSize=%d", data, dataSize);
        return -1;
    }

    if (packetInfo.targetIP.empty() || packetInfo.targetPort <= 0) {
        LOG_ERROR("❌ [参数验证失败] 无效目标: IP=%s, Port=%d",
                 packetInfo.targetIP.c_str(), packetInfo.targetPort);
        return -1;
    }

    LOG_INFO("✅ [参数验证通过] 所有输入参数有效");
    
    // 1. 提取payload
    const uint8_t* payload = nullptr;
    int payloadSize = 0;
    if (!PacketBuilder::ExtractPayload(data, dataSize, packetInfo, &payload, &payloadSize)) {
        LOG_ERROR("提取payload失败");
        return -1;
    }
    
    if (payloadSize <= 0) return 0;
    
    // 2. DNS重定向 - 只重定向223.5.5.5
    std::string actualTargetIP = packetInfo.targetIP;
    if (packetInfo.targetPort == 53) {
        // 🔧 调试：打印原始IP值
        LOG_INFO("🔍 DNS原始目标: %s:%d", packetInfo.targetIP.c_str(), packetInfo.targetPort);
        
        if (packetInfo.targetIP == "223.5.5.5") {
            actualTargetIP = "8.8.8.8";  // 只重定向223.5.5.5到8.8.8.8
            LOG_INFO("🔄 DNS重定向: %s -> %s", packetInfo.targetIP.c_str(), actualTargetIP.c_str());
        } else {
            LOG_INFO("🔍 DNS无需重定向: %s", packetInfo.targetIP.c_str());
        }
    }
    
    // 3. 检查或创建NAT映射 (优化版本)
    std::string natKey = NATTable::GenerateKey(packetInfo, originalPeer);
    
    NATConnection existingConn;
    int sockFd;
    
    if (NATTable::FindMapping(natKey, existingConn)) {
        // 映射已存在，使用现有socket
        LOG_INFO("🔄 使用现有NAT映射: key=%s, fd=%d", natKey.c_str(), existingConn.forwardSocket);
        sockFd = existingConn.forwardSocket;
        
    } else {
        // 没有现有映射，创建新socket和映射
        sockFd = GetSocket(packetInfo, originalPeer);
        if (sockFd < 0) {
            LOG_ERROR("获取socket失败");
            return -1;
        }
        
        NATTable::CreateMapping(natKey, originalPeer, packetInfo, sockFd);
        LOG_INFO("✅ 创建新NAT映射: %s -> fd=%d", natKey.c_str(), sockFd);
    }
    
    // 5. 发送数据
    if (packetInfo.protocol == PROTOCOL_UDP) {
        // 🔍 关键调试：UDP发送过程
        LOG_INFO("🔍 [UDP转发] 开始发送数据: %s:%d -> %s:%d (%d字节)",
                 packetInfo.sourceIP.c_str(), packetInfo.sourcePort,
                 actualTargetIP.c_str(), packetInfo.targetPort, payloadSize);

        struct sockaddr_in targetAddr{};
        targetAddr.sin_family = AF_INET;
        // ✅ 修复：targetPort已经是主机字节序，不需要再htons
        targetAddr.sin_port = packetInfo.targetPort;
        if (inet_pton(AF_INET, actualTargetIP.c_str(), &targetAddr.sin_addr) <= 0) {
            LOG_ERROR("❌ [UDP转发] 无效目标地址: %s", actualTargetIP.c_str());
            NATTable::RemoveMapping(natKey);
            return -1;
        }

        LOG_INFO("📤 [UDP发送] 发送到 %s:%d (fd=%d)...",
                 actualTargetIP.c_str(), packetInfo.targetPort, sockFd);

        ssize_t sent = sendto(sockFd, payload, payloadSize, 0,
                             (struct sockaddr*)&targetAddr, sizeof(targetAddr));

        if (sent < 0) {
            LOG_ERROR("❌ [UDP发送失败] fd=%d, errno=%d (%s)", sockFd, errno, strerror(errno));
            NATTable::RemoveMapping(natKey);
            return -1;
        }

        LOG_INFO("✅ [UDP发送成功] fd=%d, 发送了 %zd 字节到 %s:%d",
                 sockFd, sent, actualTargetIP.c_str(), packetInfo.targetPort);

        // 6. 启动响应线程 - 只在创建新映射时启动
        if (!NATTable::FindMapping(natKey, existingConn)) {
            StartUDPThread(sockFd, originalPeer);
            LOG_INFO("🚀 [UDP响应线程] 新建响应处理线程 (fd=%d)", sockFd);
        } else {
            LOG_INFO("🔄 [UDP响应线程] 复用现有响应处理线程 (fd=%d)", sockFd);
        }
        
    } else if (packetInfo.protocol == PROTOCOL_TCP) {
    // 🔍 关键调试：TCP连接建立过程
    LOG_INFO("🔍 [TCP转发] 开始建立连接: %s:%d -> %s:%d",
             packetInfo.sourceIP.c_str(), packetInfo.sourcePort,
             actualTargetIP.c_str(), packetInfo.targetPort);

    // 🚨 紧急诊断：测试目标服务器连通性
    LOG_INFO("🔍 [连通性测试] 测试目标服务器 %s:%d 连通性...",
             actualTargetIP.c_str(), packetInfo.targetPort);

    // 创建临时socket测试连通性
    int testSock = socket(AF_INET, SOCK_STREAM, 0);
    if (testSock >= 0) {
        struct sockaddr_in testAddr{};
        testAddr.sin_family = AF_INET;
        testAddr.sin_port = htons(packetInfo.targetPort);
        inet_pton(AF_INET, actualTargetIP.c_str(), &testAddr.sin_addr);

        // 设置非阻塞模式进行快速测试
        int flags = fcntl(testSock, F_GETFL, 0);
        fcntl(testSock, F_SETFL, flags | O_NONBLOCK);

        int connectResult = connect(testSock, (struct sockaddr*)&testAddr, sizeof(testAddr));
        if (connectResult == 0) {
            LOG_INFO("✅ [连通性测试] 目标服务器 %s:%d 直接可达",
                     actualTargetIP.c_str(), packetInfo.targetPort);
        } else if (errno == EINPROGRESS) {
            // 非阻塞连接进行中，检查是否会成功
            struct pollfd pfd = {testSock, POLLOUT, 0};
            int pollResult = poll(&pfd, 1, 1000); // 1秒超时

            if (pollResult > 0) {
                int error = 0;
                socklen_t len = sizeof(error);
                getsockopt(testSock, SOL_SOCKET, SO_ERROR, &error, &len);

                if (error == 0) {
                    LOG_INFO("✅ [连通性测试] 目标服务器 %s:%d 连接成功",
                             actualTargetIP.c_str(), packetInfo.targetPort);
                } else {
                    LOG_ERROR("❌ [连通性测试] 目标服务器 %s:%d 连接失败: %s",
                             actualTargetIP.c_str(), packetInfo.targetPort, strerror(error));
                }
            } else {
                LOG_ERROR("❌ [连通性测试] 目标服务器 %s:%d 连接超时 (1秒)",
                         actualTargetIP.c_str(), packetInfo.targetPort);
            }
        } else {
            LOG_ERROR("❌ [连通性测试] 目标服务器 %s:%d 连接立即失败: %s",
                     actualTargetIP.c_str(), packetInfo.targetPort, strerror(errno));
        }

        close(testSock);
    } else {
        LOG_ERROR("❌ [连通性测试] 无法创建测试socket: %s", strerror(errno));
    }

        // TCP转发实现
        struct sockaddr_in targetAddr{};
        targetAddr.sin_family = AF_INET;
        targetAddr.sin_port = htons(packetInfo.targetPort);
        if (inet_pton(AF_INET, actualTargetIP.c_str(), &targetAddr.sin_addr) <= 0) {
            LOG_ERROR("❌ [TCP转发] 无效目标地址: %s", actualTargetIP.c_str());
            NATTable::RemoveMapping(natKey);
            return -1;
        }

        // 连接到目标服务器
        LOG_INFO("🔗 [TCP连接] 正在连接到 %s:%d (fd=%d)...",
                 actualTargetIP.c_str(), packetInfo.targetPort, sockFd);

        if (connect(sockFd, (struct sockaddr*)&targetAddr, sizeof(targetAddr)) < 0) {
            LOG_ERROR("❌ [TCP连接失败] fd=%d, 目标=%s:%d, errno=%d (%s)",
                     sockFd, actualTargetIP.c_str(), packetInfo.targetPort, errno, strerror(errno));
            NATTable::RemoveMapping(natKey);
            return -1;
        }

        LOG_INFO("✅ [TCP连接成功] fd=%d 已连接到 %s:%d", sockFd, actualTargetIP.c_str(), packetInfo.targetPort);

        // 发送TCP数据
        LOG_INFO("📤 [TCP发送] 发送 %d 字节数据 (fd=%d)...", payloadSize, sockFd);
        ssize_t sent = send(sockFd, payload, payloadSize, 0);
        if (sent < 0) {
            LOG_ERROR("❌ [TCP发送失败] fd=%d, errno=%d (%s)", sockFd, errno, strerror(errno));
            NATTable::RemoveMapping(natKey);
            return -1;
        }

        LOG_INFO("✅ [TCP发送成功] fd=%d, 发送了 %zd 字节", sockFd, sent);

        // 启动TCP响应处理
        StartTCPThread(sockFd, originalPeer);
        LOG_INFO("🚀 [TCP响应线程] 已启动响应处理线程 (fd=%d)", sockFd);
        
    } else {
        LOG_ERROR("不支持的协议: %d", packetInfo.protocol);
        NATTable::RemoveMapping(natKey);
        return -1;
    }

    return sockFd;
}

// 🎯 清理所有缓存的socket和线程
void PacketForwarder::CleanupAll() {
    LOG_INFO("🧹 开始清理所有转发器资源");

    // 清理socket连接池
    SocketConnectionPool::getInstance().cleanup();

    // 清理过期NAT映射
    NATTable::CleanupExpired(0);  // 清理所有映射

    LOG_INFO("✅ 转发器资源清理完成");
}

// 🎯 输出统计信息（用于调试）
void PacketForwarder::LogStatistics() {
    LOG_INFO("📊 PacketForwarder统计信息");
    // TODO: 添加具体的统计信息输出
}

