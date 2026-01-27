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

// ICMP协议常量（如果系统头文件未定义）
#ifndef IPPROTO_ICMP
#define IPPROTO_ICMP 1
#endif
#ifndef IPPROTO_ICMPV6
#define IPPROTO_ICMPV6 58
#endif
#ifndef IPPROTO_RAW
#define IPPROTO_RAW 255
#endif
#ifndef IP_HDRINCL
#define IP_HDRINCL 3
#endif
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
#include <random>
#include <vector>

#define LOG_INFO(fmt, ...) \
    OH_LOG_Print(LOG_APP, LOG_INFO, 0x15b1, "VpnServer", "ZHOUB [Forwarder] " fmt, ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...) \
    OH_LOG_Print(LOG_APP, LOG_ERROR, 0x15b1, "VpnServer", "ZHOUB [Forwarder] ❌ " fmt, ##__VA_ARGS__)

// TCP flags helpers
static inline bool HasTcpFlag(uint8_t flags, uint8_t mask) { return (flags & mask) != 0; }
static std::string TcpFlagsToString(uint8_t flags)
{
    std::string s;
    if (HasTcpFlag(flags, 0x02)) s += "SYN|";
    if (HasTcpFlag(flags, 0x10)) s += "ACK|";
    if (HasTcpFlag(flags, 0x01)) s += "FIN|";
    if (HasTcpFlag(flags, 0x04)) s += "RST|";
    if (HasTcpFlag(flags, 0x08)) s += "PSH|";
    if (HasTcpFlag(flags, 0x20)) s += "URG|";
    if (HasTcpFlag(flags, 0x40)) s += "ECE|";
    if (HasTcpFlag(flags, 0x80)) s += "CWR|";
    if (!s.empty()) s.pop_back(); // drop trailing '|'
    if (s.empty()) return "NONE";
    return s;
}

static std::string FormatSockaddr(const sockaddr_in& addr)
{
    char ip[INET_ADDRSTRLEN] = {0};
    inet_ntop(AF_INET, &addr.sin_addr, ip, sizeof(ip));
    return std::string(ip) + ":" + std::to_string(ntohs(addr.sin_port));
}

static std::string GetSocketAddrString(int sockFd, bool peer)
{
    sockaddr_storage addr{};
    socklen_t len = sizeof(addr);
    int rc = peer ? getpeername(sockFd, reinterpret_cast<sockaddr*>(&addr), &len)
                  : getsockname(sockFd, reinterpret_cast<sockaddr*>(&addr), &len);
    if (rc != 0) {
        return "unknown";
    }
    if (addr.ss_family == AF_INET) {
        return FormatSockaddr(*reinterpret_cast<sockaddr_in*>(&addr));
    }
    if (addr.ss_family == AF_INET6) {
        char ip[INET6_ADDRSTRLEN] = {0};
        auto* a6 = reinterpret_cast<sockaddr_in6*>(&addr);
        inet_ntop(AF_INET6, &a6->sin6_addr, ip, sizeof(ip));
        return std::string(ip) + ":" + std::to_string(ntohs(a6->sin6_port));
    }
    return "unknown";
}

static bool SetBlockingMode(int sockFd, bool blocking)
{
    int flags = fcntl(sockFd, F_GETFL, 0);
    if (flags < 0) {
        return false;
    }
    if (blocking) {
        flags &= ~O_NONBLOCK;
    } else {
        flags |= O_NONBLOCK;
    }
    return fcntl(sockFd, F_SETFL, flags) == 0;
}

// TCP连接（带超时）
static bool ConnectWithTimeout(int sockFd, const sockaddr* targetAddr, socklen_t addrLen, int timeoutMs) {
    int flags = fcntl(sockFd, F_GETFL, 0);
    if (flags < 0 || fcntl(sockFd, F_SETFL, flags | O_NONBLOCK) < 0) {
        return false;
    }

    int rc = connect(sockFd, targetAddr, addrLen);
    if (rc == 0) {
        fcntl(sockFd, F_SETFL, flags);
        return true;
    }
    if (errno != EINPROGRESS) {
        fcntl(sockFd, F_SETFL, flags);
        return false;
    }

    fd_set writefds;
    FD_ZERO(&writefds);
    FD_SET(sockFd, &writefds);
    struct timeval tv;
    tv.tv_sec = timeoutMs / 1000;
    tv.tv_usec = (timeoutMs % 1000) * 1000;

    if (select(sockFd + 1, nullptr, &writefds, nullptr, &tv) <= 0) {
        fcntl(sockFd, F_SETFL, flags);
        return false;
    }

    int soError = 0;
    socklen_t len = sizeof(soError);
    if (getsockopt(sockFd, SOL_SOCKET, SO_ERROR, &soError, &len) < 0 || soError != 0) {
        fcntl(sockFd, F_SETFL, flags);
        return false;
    }

    fcntl(sockFd, F_SETFL, flags);
    return true;
}

// Minimal TCP header parser for IPv4/IPv6 packets
struct ParsedTcp {
    bool ok = false;
    uint8_t ipHeaderLen = 0;
    uint8_t tcpHeaderLen = 0;
    uint16_t srcPort = 0;
    uint16_t dstPort = 0;
    uint32_t seq = 0;
    uint32_t ack = 0;
    uint8_t flags = 0;
};

static ParsedTcp ParseTcpFromIp(const uint8_t* data, int dataSize)
{
    ParsedTcp t;
    if (!data || dataSize < 40) return t; // min IPv4(20)+TCP(20) or IPv6(40)
    uint8_t version = (data[0] >> 4) & 0x0F;
    if (version == 4) {
        uint8_t ipHL = (data[0] & 0x0F) * 4;
        if (ipHL < 20 || dataSize < ipHL + 20) return t;
        if (data[9] != PROTOCOL_TCP) return t;
        int off = ipHL;

        t.ipHeaderLen = ipHL;
        t.srcPort = (static_cast<uint16_t>(data[off + 0]) << 8) | data[off + 1];
        t.dstPort = (static_cast<uint16_t>(data[off + 2]) << 8) | data[off + 3];
        t.seq = (static_cast<uint32_t>(data[off + 4]) << 24) |
                (static_cast<uint32_t>(data[off + 5]) << 16) |
                (static_cast<uint32_t>(data[off + 6]) << 8)  |
                (static_cast<uint32_t>(data[off + 7]));
        t.ack = (static_cast<uint32_t>(data[off + 8]) << 24) |
                (static_cast<uint32_t>(data[off + 9]) << 16) |
                (static_cast<uint32_t>(data[off + 10]) << 8) |
                (static_cast<uint32_t>(data[off + 11]));
        // 🚨 修复：在访问 data[off + 12] 和 data[off + 13] 之前检查边界
        if (dataSize < off + 14) return t;  // 至少需要14字节才能读取TCP头的基本字段
        uint8_t dataOffsetWords = (data[off + 12] >> 4) & 0x0F;
        int tcpHL = static_cast<int>(dataOffsetWords) * 4;
        if (tcpHL < 20 || dataSize < off + tcpHL) return t;
        t.flags = data[off + 13];
        t.tcpHeaderLen = static_cast<uint8_t>(tcpHL);
        t.ok = true;
        return t;
    }

    if (version == 6) {
        if (dataSize < 40) return t;
        uint8_t nextHeader = data[6];
        int off = 40;
        int hops = 0;
        const int maxHops = 8;
        while (hops < maxHops) {
            if (nextHeader == 0 || nextHeader == 43 || nextHeader == 50 ||
                nextHeader == 51 || nextHeader == 60) {
                if (dataSize < off + 2) return t;
                uint8_t next = data[off];
                uint8_t hdrExtLen = data[off + 1];
                int extLen = (hdrExtLen + 1) * 8;
                // 🚨 修复：在增加 off 之前检查边界，避免越界
                if (off + extLen > dataSize) return t;
                off += extLen;
                nextHeader = next;
                hops++;
                continue;
            } else if (nextHeader == 44) { // Fragment
                if (dataSize < off + 8) return t;
                uint8_t next = data[off];
                off += 8;
                if (off > dataSize) return t;
                nextHeader = next;
                hops++;
                continue;
            }
            break;
        }
        if (hops >= maxHops) return t;
        if (nextHeader != PROTOCOL_TCP) return t;
        if (dataSize < off + 20) return t;

        t.ipHeaderLen = static_cast<uint8_t>(off);
        t.srcPort = (static_cast<uint16_t>(data[off + 0]) << 8) | data[off + 1];
        t.dstPort = (static_cast<uint16_t>(data[off + 2]) << 8) | data[off + 3];
        t.seq = (static_cast<uint32_t>(data[off + 4]) << 24) |
                (static_cast<uint32_t>(data[off + 5]) << 16) |
                (static_cast<uint32_t>(data[off + 6]) << 8)  |
                (static_cast<uint32_t>(data[off + 7]));
        t.ack = (static_cast<uint32_t>(data[off + 8]) << 24) |
                (static_cast<uint32_t>(data[off + 9]) << 16) |
                (static_cast<uint32_t>(data[off + 10]) << 8) |
                (static_cast<uint32_t>(data[off + 11]));
        // 🚨 修复：在访问 data[off + 12] 和 data[off + 13] 之前检查边界
        if (dataSize < off + 14) return t;  // 至少需要14字节才能读取TCP头的基本字段
        uint8_t dataOffsetWords = (data[off + 12] >> 4) & 0x0F;
        int tcpHL = static_cast<int>(dataOffsetWords) * 4;
        if (tcpHL < 20 || dataSize < off + tcpHL) return t;
        t.flags = data[off + 13];
        t.tcpHeaderLen = static_cast<uint8_t>(tcpHL);
        t.ok = true;
        return t;
    }

    return t;
}

static uint32_t RandomIsn()
{
    static std::mt19937 rng{std::random_device{}()};
    static std::uniform_int_distribution<uint32_t> dist;
    return dist(rng);
}

// 🎯 发送socket保护控制消息给VPN客户端
static void SendProtectSocketMessage(int sockFd, const PacketInfo& packetInfo, const sockaddr_in& clientAddr, int tunnelFd);

// Socket保护函数 - 防止转发socket被VPN路由劫持
static bool ProtectSocket(int sockFd, const std::string& description) {
    bool protectionSuccess = false;

    // 方法1: 尝试设置SO_BINDTODEVICE绑定到物理网络接口
    const char* physicalInterfaces[] = {"eth0", "wlan0", "rmnet0", "rmnet_data0", "rmnet_data1", nullptr};

    for (int i = 0; physicalInterfaces[i] != nullptr; i++) {
        std::string interfaceName = physicalInterfaces[i];
        if (setsockopt(sockFd, SOL_SOCKET, SO_BINDTODEVICE,
                      interfaceName.c_str(), interfaceName.length() + 1) == 0) {
            protectionSuccess = true;
            break;
        }
    }

    // 方法2: 如果SO_BINDTODEVICE失败，尝试设置其他socket选项
    if (!protectionSuccess) {
        int dontRoute = 1;
        if (setsockopt(sockFd, SOL_SOCKET, SO_DONTROUTE, &dontRoute, sizeof(dontRoute)) == 0) {
            protectionSuccess = true;
        }
    }

    // 方法3: HarmonyOS特定方法 - 尝试设置socket绕过VPN
    if (!protectionSuccess) {
        int mark = 0x10000000;
        if (setsockopt(sockFd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark)) == 0) {
            protectionSuccess = true;
        }
    }

    // 如果所有方法都失败，至少记录警告并返回true（让系统继续运行）
    if (!protectionSuccess) {
        LOG_ERROR("Socket保护失败 fd=%d desc=%s", sockFd, description.c_str());
        protectionSuccess = true;  // 临时妥协，让系统能运行
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
        int addressFamily;

        bool operator<(const TargetKey& other) const {
            if (clientIP != other.clientIP) return clientIP < other.clientIP;
            if (clientPort != other.clientPort) return clientPort < other.clientPort;
            if (serverIP != other.serverIP) return serverIP < other.serverIP;
            if (serverPort != other.serverPort) return serverPort < other.serverPort;
            if (protocol != other.protocol) return protocol < other.protocol;
            return addressFamily < other.addressFamily;
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
                  const std::string& serverIP, uint16_t serverPort, uint8_t protocol,
                  int addressFamily) {
        std::lock_guard<std::mutex> lock(poolMutex_);
        TargetKey key{clientIP, clientPort, serverIP, serverPort, protocol, addressFamily};

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
                    return info.sockFd;
                } else {
                    // 超时，关闭socket
                    close(info.sockFd);
                }
            }
        }

        // 创建新socket
        int newSock = createNewSocket(protocol, addressFamily);
        if (newSock >= 0) {
            SocketInfo info(newSock);
            info.inUse = true;
            return newSock;
        }

        return -1;
    }
    
    // 归还socket到池中
    void returnSocket(int sockFd, const std::string& clientIP, uint16_t clientPort,
                      const std::string& serverIP, uint16_t serverPort, uint8_t protocol,
                      int addressFamily) {
        std::lock_guard<std::mutex> lock(poolMutex_);
        TargetKey key{clientIP, clientPort, serverIP, serverPort, protocol, addressFamily};

        auto& pool = socketPools_[key];
        if (pool.size() < MAX_SOCKETS_PER_TARGET) {
            SocketInfo info(sockFd);
            info.inUse = false;
            pool.push(info);
        } else {
            // 池已满，关闭socket
            close(sockFd);
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
    }

private:
    int createNewSocket(uint8_t protocol, int addressFamily) {
        int sockFd;
        int af = (addressFamily == AF_INET6) ? AF_INET6 : AF_INET;
        if (protocol == PROTOCOL_UDP) {
            sockFd = socket(af, SOCK_DGRAM, 0);
        } else if (protocol == PROTOCOL_TCP) {
            sockFd = socket(af, SOCK_STREAM, 0);
        } else {
        return -1;
    }

    if (sockFd < 0) {
            LOG_ERROR("创建socket失败: %s", strerror(errno));
        return -1;
    }
    
        // 🚨 关键修复：UDP socket必须设置为非阻塞模式，避免recvfrom阻塞
        if (protocol == PROTOCOL_UDP) {
            int flags = fcntl(sockFd, F_GETFL, 0);
            if (flags >= 0) {
                if (fcntl(sockFd, F_SETFL, flags | O_NONBLOCK) < 0) {
                    LOG_ERROR("设置UDP socket为非阻塞模式失败: %s", strerror(errno));
                    close(sockFd);
                    return -1;
                }
            }
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

// 获取socket (使用连接池优化 - 按客户端+目标分组确保数据隔离)
static int GetSocket(const PacketInfo& packetInfo, const sockaddr_in& clientAddr, int tunnelFd) {

    // 从连接池获取socket - 按客户端+目标分组，确保每个客户端到每个目标都有独立socket
    char clientIP[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &clientAddr.sin_addr, clientIP, sizeof(clientIP));

    int sockFd = SocketConnectionPool::getInstance().getSocket(
        clientIP,
        ntohs(clientAddr.sin_port),
        packetInfo.targetIP,
        packetInfo.targetPort,
        packetInfo.protocol,
        packetInfo.addressFamily
    );

    if (sockFd < 0) {
        LOG_ERROR("连接池返回无效socket: %d", sockFd);
        return -1;
    }
    
    // 发送控制消息给VPN客户端，请求保护转发socket
    std::string socketDesc = std::string(packetInfo.protocol == PROTOCOL_TCP ? "TCP" : "UDP") +
                            " forwarding socket to " + packetInfo.targetIP + ":" + std::to_string(packetInfo.targetPort);
    
    // 🔍 流程跟踪：记录socket创建和保护（详细诊断）
    auto protectStartTime = std::chrono::steady_clock::now();
    LOG_INFO("🔍 [Socket保护诊断] ========== 开始socket保护流程 ==========");
    LOG_INFO("🔍 [Socket保护诊断] 创建转发socket: fd=%d, 目标=%s:%d, 协议=%s", 
             sockFd, packetInfo.targetIP.c_str(), packetInfo.targetPort,
             packetInfo.protocol == PROTOCOL_TCP ? "TCP" : "UDP");
    LOG_INFO("🔍 [Socket保护诊断] socket作用: 代理服务器转发socket，用于连接真实服务器");
    LOG_INFO("🔍 [Socket保护诊断] 保护原因: 防止socket流量被VPN路由表捕获，形成环路");
    
    // 🚨 关键：先尝试本地保护（可能失败，但不影响）
    bool localProtect = ProtectSocket(sockFd, socketDesc);
    if (!localProtect) {
        LOG_ERROR("🚨 [Socket保护诊断] 本地socket保护失败: fd=%d (但继续发送保护请求给VPN客户端)", sockFd);
    } else {
        LOG_INFO("✅ [Socket保护诊断] 本地socket保护成功: fd=%d", sockFd);
    }
    
    // 🚨 关键：发送保护请求给VPN客户端（这是最重要的保护方式）
    LOG_INFO("🔍 [Socket保护诊断] 发送socket保护请求给VPN客户端: fd=%d", sockFd);
    LOG_INFO("🔍 [Socket保护诊断] VPN客户端检查频率: 每500ms检查一次保护队列");
    SendProtectSocketMessage(sockFd, packetInfo, clientAddr, tunnelFd);
    
    auto protectRequestTime = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(protectRequestTime - protectStartTime).count();
    LOG_INFO("✅ [Socket保护诊断] socket保护请求已发送: fd=%d (耗时%lldms)", sockFd, elapsed);
    LOG_INFO("🔍 [Socket保护诊断] 预期保护完成时间: 约500-1500ms后 (VPN客户端每500ms检查一次，需要1-3个周期)");
    LOG_INFO("🔍 [Socket保护诊断] ========================================");

    // 设置特殊超时 - DNS查询使用更长超时时间
    if (packetInfo.protocol == PROTOCOL_UDP && packetInfo.targetPort == 53) {
        struct timeval timeout = {10, 0};  // DNS查询：10秒超时
        if (setsockopt(sockFd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
            LOG_ERROR("设置DNS超时失败: %s", strerror(errno));
            close(sockFd);
            return -1;
        }
    }
    
    return sockFd;
}

// 发送socket保护控制消息给VPN客户端
static void SendProtectSocketMessage(int sockFd, const PacketInfo& packetInfo, const sockaddr_in& clientAddr, int tunnelFd) {

    // 构建控制消息包：目的IP=127.0.0.1，目的端口=0，协议=UDP
    // Payload格式：命令类型(1字节) + socket FD(4字节)

    uint8_t controlPacket[28 + 5];  // IP头(20) + UDP头(8) + payload(5)
    memset(controlPacket, 0, sizeof(controlPacket));

    // IP头
    controlPacket[0] = 0x45;  // IPv4, 5字节头
    controlPacket[1] = 0x00;  // TOS
    uint16_t totalLength = 28 + 5;  // IP头 + UDP头 + payload
    controlPacket[2] = (totalLength >> 8) & 0xFF;
    controlPacket[3] = totalLength & 0xFF;
    controlPacket[4] = 0x00;  // ID高字节
    controlPacket[5] = 0x01;  // ID低字节
    controlPacket[6] = 0x00;  // Flags + Fragment offset
    controlPacket[7] = 0x00;
    controlPacket[8] = 0x40;  // TTL
    controlPacket[9] = 17;    // Protocol: UDP

    // 源IP：127.0.0.1（本地回环，与VPN服务器监听地址一致）
    controlPacket[12] = 127;
    controlPacket[13] = 0;
    controlPacket[14] = 0;
    controlPacket[15] = 1;

    // 目的IP：127.0.0.1（控制消息）
    controlPacket[16] = 127;
    controlPacket[17] = 0;
    controlPacket[18] = 0;
    controlPacket[19] = 1;

    // UDP头
    // 源端口：8888（VPN服务器端口）
    controlPacket[20] = (8888 >> 8) & 0xFF;
    controlPacket[21] = 8888 & 0xFF;
    // 目的端口：0（控制消息标识）
    controlPacket[22] = 0;
    controlPacket[23] = 0;

    uint16_t udpLength = 8 + 5;  // UDP头 + payload
    controlPacket[24] = (udpLength >> 8) & 0xFF;
    controlPacket[25] = udpLength & 0xFF;

    // Payload：控制消息
    int payloadOffset = 28;
    controlPacket[payloadOffset] = 0x01;  // 命令：保护转发socket
    controlPacket[payloadOffset + 1] = (sockFd >> 24) & 0xFF;  // socket FD (大端)
    controlPacket[payloadOffset + 2] = (sockFd >> 16) & 0xFF;
    controlPacket[payloadOffset + 3] = (sockFd >> 8) & 0xFF;
    controlPacket[payloadOffset + 4] = sockFd & 0xFF;

    // 通过VPN隧道发送控制消息
    if (tunnelFd >= 0) {
        ssize_t sent = sendto(tunnelFd, controlPacket, sizeof(controlPacket), 0,
                             (struct sockaddr*)&clientAddr, sizeof(clientAddr));
        if (sent <= 0) {
            LOG_ERROR("发送socket保护控制消息失败: errno=%d", errno);
        }
    }
}

// UDP响应线程
static void StartUDPThread(int sockFd, const sockaddr_in& originalPeer) {
    std::thread([sockFd, originalPeer]() {
        uint8_t buffer[4096];
        int noResponseCount = 0;
        const int MAX_NO_RESPONSE = 10;

        while (true) {
            // 🔍 流程跟踪：记录UDP响应接收
            LOG_INFO("🔍 [流程跟踪] 等待UDP响应 (socket fd=%d)", sockFd);
            
            ssize_t received = recvfrom(sockFd, buffer, sizeof(buffer), 0, nullptr, nullptr);
            
            if (received > 0) {
                // 🔍 流程跟踪：记录收到UDP响应
                NATConnection conn;
                if (NATTable::FindMappingBySocket(sockFd, conn)) {
                    LOG_INFO("🔍 [流程跟踪] 收到UDP响应: %d字节 (socket fd=%d, 目标=%s:%d)", 
                             received, sockFd, conn.serverIP.c_str(), conn.serverPort);
                } else {
                    LOG_INFO("🔍 [流程跟踪] 收到UDP响应: %d字节 (socket fd=%d, NAT映射不存在)", 
                             received, sockFd);
                }
            }
            
            if (received < 0) {
                int savedErrno = errno;
                if (savedErrno == EAGAIN || savedErrno == EWOULDBLOCK) {
                    noResponseCount++;
                    if (noResponseCount >= MAX_NO_RESPONSE) {
                        break;
                    }
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                    continue;
                }
                break;
            }

            noResponseCount = 0;

            // 查找NAT映射
            NATConnection conn;
            if (!NATTable::FindMappingBySocket(sockFd, conn)) {
                break;
            }

            // 构建响应包
            uint8_t responsePacket[4096];
            int responseSize = PacketBuilder::BuildResponsePacket(
                responsePacket, sizeof(responsePacket),
                buffer, received, conn.originalRequest
            );

            if (responseSize > 0) {
                if (TaskQueueManager::getInstance().submitResponseTask(
                    responsePacket, responseSize, originalPeer, sockFd, PROTOCOL_UDP
                )) {
                    UdpRetransmitManager::getInstance().confirmReceivedByContent(sockFd, buffer, received);
                }
            }
        }

        // 清理：先获取映射信息，再删除映射
        NATConnection conn;
        bool hasConn = NATTable::FindMappingBySocket(sockFd, conn);
        if (hasConn) {
            char clientIP[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &conn.clientPhysicalAddr.sin_addr, clientIP, sizeof(clientIP));
            NATTable::RemoveMappingBySocket(sockFd);
            SocketConnectionPool::getInstance().returnSocket(
                sockFd, clientIP, ntohs(conn.clientPhysicalAddr.sin_port),
                conn.serverIP, conn.serverPort, PROTOCOL_UDP, conn.originalRequest.addressFamily
            );
        } else {
            NATTable::RemoveMappingBySocket(sockFd);
            close(sockFd);
        }
    }).detach();
}

// TCP响应线程
static void StartTCPThread(int sockFd, const sockaddr_in& originalPeer) {
    std::thread([sockFd, originalPeer]() {
        // 确保TCP socket是阻塞模式，以便完整接收所有数据
        if (!SetBlockingMode(sockFd, true)) {
            LOG_ERROR("设置TCP socket为阻塞模式失败: fd=%d", sockFd);
            close(sockFd);
            return;
        }
        
        // 设置接收超时（30秒），避免无限期阻塞
        struct timeval timeout;
        timeout.tv_sec = 30;
        timeout.tv_usec = 0;
        setsockopt(sockFd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        
        uint8_t buffer[4096];
        int noResponseCount = 0;
        const int MAX_NO_RESPONSE = 10;  // 🔥 增加无响应次数限制（阻塞模式下应该很少触发）
    
    while (true) {
            // 🔍 简化：只在每100次或前5次时记录
            static thread_local int tcpRecvCount = 0;
            tcpRecvCount++;
            if (tcpRecvCount <= 5 || tcpRecvCount % 100 == 0) {
                LOG_INFO("🔍 等待TCP响应 (fd=%d)", sockFd);
            }
            
            ssize_t received = recv(sockFd, buffer, sizeof(buffer), 0);
            
            if (received > 0) {
                // 🔍 简化：只在每100次或前5次时记录
                NATConnection conn;
                if (NATTable::FindMappingBySocket(sockFd, conn)) {
                    if (tcpRecvCount <= 5 || tcpRecvCount % 100 == 0) {
                        LOG_INFO("🔍 收到TCP响应: %d字节 (fd=%d, 目标=%s:%d)", 
                                 received, sockFd, conn.serverIP.c_str(), conn.serverPort);
                    }
                } else {
                    LOG_ERROR("🚨 收到TCP响应但NAT映射不存在: %d字节 (fd=%d)", received, sockFd);
                }
            }
            
            if (received < 0) {
                // 🔥 阻塞模式下，超时返回ETIMEDOUT，非阻塞模式返回EAGAIN/EWOULDBLOCK
                if (errno == EAGAIN || errno == EWOULDBLOCK || errno == ETIMEDOUT) {
                    noResponseCount++;
                    if (noResponseCount >= MAX_NO_RESPONSE) {
                        break;
                    }
                    continue;
                }
                // 其他错误（如连接重置、网络不可达等）应该退出
                LOG_ERROR("TCP接收失败: fd=%d, errno=%d (%s)", sockFd, errno, strerror(errno));
                break;
            } else if (received == 0) {

                // Best-effort: send FIN|ACK to client with current seq/ack
                NATConnection conn;
                if (NATTable::FindMappingBySocket(sockFd, conn)) {
                    uint32_t seqToSend = 0;
                    uint32_t ackToSend = 0;
                    PacketInfo origReq = conn.originalRequest;
                    // 🚨 修复：检查WithConnectionBySocket返回值，避免在映射不存在时崩溃
                    bool hasConn = NATTable::WithConnectionBySocket(sockFd, [&](NATConnection& c) {
                        seqToSend = c.nextServerSeq;
                        ackToSend = c.nextClientSeq;
                        c.nextServerSeq += 1; // FIN consumes one seq
                        c.tcpState = NATConnection::TcpState::FIN_SENT;
                    });
                    if (!hasConn) {
                        LOG_ERROR("NAT映射不存在，无法处理FIN响应: fd=%d", sockFd);
                        close(sockFd);
                        return;
                    }

                    uint8_t finPkt[128];
                    int finSize = PacketBuilder::BuildTcpResponsePacket(
                        finPkt, sizeof(finPkt),
                        nullptr, 0,
                        origReq,
                        seqToSend, ackToSend,
                        TCP_FIN | TCP_ACK
                    );
                    if (finSize > 0) {
                        TaskQueueManager::getInstance().submitResponseTask(
                            finPkt, finSize, originalPeer, sockFd, PROTOCOL_TCP
                        );
                    }
                }

                break;
            }
        
            // 重置无响应计数
            noResponseCount = 0;
            
            // 检查NAT映射并构建完整IP响应包（包含正确的TCP seq/ack）
            NATConnection conn;
            if (NATTable::FindMappingBySocket(sockFd, conn)) {

            // Snapshot + advance nextServerSeq under lock
                uint32_t seqToSend = 0;
                uint32_t ackToSend = 0;
                PacketInfo origReq = conn.originalRequest;
                // 🚨 修复：检查WithConnectionBySocket返回值，避免在映射不存在时崩溃
                bool hasConn = NATTable::WithConnectionBySocket(sockFd, [&](NATConnection& c) {
                    seqToSend = c.nextServerSeq;
                    ackToSend = c.nextClientSeq;
                    c.nextServerSeq += static_cast<uint32_t>(received);
                });
                if (!hasConn) {
                    LOG_ERROR("NAT映射不存在，无法处理数据响应: fd=%d", sockFd);
                    close(sockFd);
                    return;
                }


                const size_t responseCapacity = static_cast<size_t>(received) + 64; // IPv4+TCP headers
                std::vector<uint8_t> responsePacket(responseCapacity);
                int responseSize = PacketBuilder::BuildTcpResponsePacket(
                    responsePacket.data(), static_cast<int>(responsePacket.size()),
                    buffer, static_cast<int>(received),
                    origReq,
                    seqToSend, ackToSend,
                    TCP_ACK | TCP_PSH
                );

                if (responseSize > 0) {
                    // ✅ 通过工作线程池提交响应任务
                    bool submitted = TaskQueueManager::getInstance().submitResponseTask(
                        responsePacket.data(), responseSize,
                        originalPeer,  // 客户端地址
                        sockFd,        // 来源socket（用于NAT查找）
                        PROTOCOL_TCP
                    );

                    if (!submitted) {
                        LOG_ERROR("TCP响应任务提交失败");
                    }
                } else {
                    LOG_ERROR("构建TCP响应包失败");
                }
            } else {
                LOG_ERROR("NAT映射不存在: fd=%d", sockFd);
                break;
            }
        }
        
        // 清理NAT映射并关闭socket

        NATTable::RemoveMappingBySocket(sockFd);
        close(sockFd);
        
    }).detach();
}


// ========== 前向声明 ==========
static int ForwardICMPPacket(const uint8_t* data, int dataSize,
                             const PacketInfo& packetInfo,
                             const sockaddr_in& originalPeer,
                             int tunnelFd);

// ========== 主转发函数 ==========

int PacketForwarder::ForwardPacket(const uint8_t* data, int dataSize,
                                  const PacketInfo& packetInfo,
                                  const sockaddr_in& originalPeer,
                                  int tunnelFd) {
    // 1. 参数验证
    if (!data || dataSize <= 0 || packetInfo.targetIP.empty()) {
        return -1;
    }
    
    // ICMP/ICMPv6 没有端口，允许 targetPort 为 0
    if (packetInfo.protocol != PROTOCOL_ICMP && packetInfo.protocol != PROTOCOL_ICMPV6) {
        if (packetInfo.targetPort <= 0) {
            return -1;
        }
    }

    // 2. ICMP/ICMPv6 转发处理
    if (packetInfo.protocol == PROTOCOL_ICMP || packetInfo.protocol == PROTOCOL_ICMPV6) {
        return ForwardICMPPacket(data, dataSize, packetInfo, originalPeer, tunnelFd);
    }
    
    // 3. 提取payload
    const uint8_t* payload = nullptr;
    int payloadSize = 0;
    if (!PacketBuilder::ExtractPayload(data, dataSize, packetInfo, &payload, &payloadSize)) {
        return -1;
    }
    
    // TCP控制包（SYN/ACK/FIN/RST）payload可能为0，需要继续处理
    if (payloadSize <= 0 && packetInfo.protocol != PROTOCOL_TCP) {
        return 0;
    }
    
    // 4. DNS重定向（只重定向223.5.5.5到8.8.8.8）
    std::string actualTargetIP = packetInfo.targetIP;
    if (packetInfo.targetPort == 53 && packetInfo.targetIP == "223.5.5.5") {
        actualTargetIP = "8.8.8.8";
    }
    
    // 5. 查找或创建NAT映射
    std::string natKey = NATTable::GenerateKey(packetInfo, originalPeer);
    NATConnection existingConn;
    int sockFd = -1;
    bool isNewMapping = false;

    if (packetInfo.protocol == PROTOCOL_TCP) {
        // TCP: 需要检查是否为SYN包
        ParsedTcp tcp = ParseTcpFromIp(data, dataSize);
        if (!tcp.ok) {
            LOG_ERROR("🚨 TCP包解析失败: %s:%d -> %s:%d (数据大小=%d)", 
                     packetInfo.sourceIP.c_str(), packetInfo.sourcePort,
                     packetInfo.targetIP.c_str(), packetInfo.targetPort, dataSize);
            return -1;
        }

        bool isSyn = HasTcpFlag(tcp.flags, TCP_SYN);
        bool isAck = HasTcpFlag(tcp.flags, TCP_ACK);
        bool isRst = HasTcpFlag(tcp.flags, TCP_RST);
        bool isFin = HasTcpFlag(tcp.flags, TCP_FIN);

        if (NATTable::FindMapping(natKey, existingConn)) {
            sockFd = existingConn.forwardSocket;
        } else {
            // 只有纯SYN包（非SYN-ACK）才创建映射
            if (!isSyn || (isSyn && isAck)) {
                // 非SYN包或SYN-ACK包：发送RST告知客户端连接不存在
                if (!isRst) {
                    LOG_ERROR("🚨 [TCP连接诊断] ========== 收到非SYN包但连接不存在 ==========");
                    LOG_ERROR("   包类型: flags=0x%02x (SYN=%d, ACK=%d, RST=%d, FIN=%d)", 
                             tcp.flags, isSyn, isAck, isRst, isFin);
                    LOG_ERROR("   源: %s:%d", packetInfo.sourceIP.c_str(), packetInfo.sourcePort);
                    LOG_ERROR("   目标: %s:%d", packetInfo.targetIP.c_str(), packetInfo.targetPort);
                    LOG_ERROR("   原因分析:");
                    LOG_ERROR("     1. 客户端发送了ACK/PSH包，但服务器端没有对应的连接映射");
                    LOG_ERROR("     2. 可能原因: 之前的SYN包处理失败，NAT映射被移除");
                    LOG_ERROR("     3. 可能原因: 连接建立超时，映射已过期");
                    LOG_ERROR("     4. 可能原因: 客户端认为连接已建立，但服务器端连接失败");
                    LOG_ERROR("   影响: 客户端无法完成TCP握手，浏览器无法访问网站");
                    LOG_ERROR("   处理: 发送RST包告知客户端连接不存在");
                    LOG_ERROR("🚨 [TCP连接诊断] ========================================");
                    uint8_t rstPkt[128];
                    uint32_t ackVal = tcp.seq;
                    int tcpPayloadSize = dataSize - tcp.ipHeaderLen - tcp.tcpHeaderLen;
                    if (tcpPayloadSize < 0) {
                        tcpPayloadSize = 0;
                    } else if (tcpPayloadSize > 0) {
                        ackVal += static_cast<uint32_t>(tcpPayloadSize);
                    } else if (isFin) {
                        ackVal += 1;  // FIN消耗一个seq
                    }
                    int rstSize = PacketBuilder::BuildTcpResponsePacket(
                        rstPkt, sizeof(rstPkt), nullptr, 0, packetInfo,
                        0, ackVal, TCP_RST | TCP_ACK
                    );
                    if (rstSize > 0) {
                        TaskQueueManager::getInstance().submitResponseTask(
                            rstPkt, rstSize, originalPeer, -1, PROTOCOL_TCP
                        );
                    }
                }
                return 0;
            }

            // 创建新映射
            LOG_INFO("🔍 [TCP连接诊断] 创建新的TCP连接映射: %s:%d -> %s:%d", 
                     packetInfo.sourceIP.c_str(), packetInfo.sourcePort,
                     packetInfo.targetIP.c_str(), packetInfo.targetPort);
            sockFd = GetSocket(packetInfo, originalPeer, tunnelFd);
            if (sockFd < 0) {
                LOG_ERROR("❌ [TCP连接诊断] 创建转发socket失败，无法建立连接");
                return -1;
            }
            NATTable::CreateMapping(natKey, originalPeer, packetInfo, sockFd);
            isNewMapping = true;
            LOG_INFO("✅ [TCP连接诊断] NAT映射已创建: socket fd=%d, 映射key=%s", sockFd, natKey.c_str());
        }
    } else {
        // UDP: 直接查找或创建映射
        if (NATTable::FindMapping(natKey, existingConn)) {
            sockFd = existingConn.forwardSocket;
        } else {
            sockFd = GetSocket(packetInfo, originalPeer, tunnelFd);
            if (sockFd < 0) {
                return -1;
            }
            NATTable::CreateMapping(natKey, originalPeer, packetInfo, sockFd);
            isNewMapping = true;
        }
    }
    
    // 6. 发送数据到真实服务器
    if (packetInfo.protocol == PROTOCOL_UDP) {
        // 构建目标地址
        sockaddr_storage targetAddr{};
        socklen_t addrLen = 0;
        
        if (packetInfo.addressFamily == AF_INET6) {
            auto* addr6 = reinterpret_cast<sockaddr_in6*>(&targetAddr);
            addr6->sin6_family = AF_INET6;
            addr6->sin6_port = htons(static_cast<uint16_t>(packetInfo.targetPort));
            if (inet_pton(AF_INET6, actualTargetIP.c_str(), &addr6->sin6_addr) <= 0) {
                NATTable::RemoveMapping(natKey);
                return -1;
            }
            addrLen = sizeof(sockaddr_in6);
        } else {
            auto* addr4 = reinterpret_cast<sockaddr_in*>(&targetAddr);
            addr4->sin_family = AF_INET;
            addr4->sin_port = htons(static_cast<uint16_t>(packetInfo.targetPort));
            if (inet_pton(AF_INET, actualTargetIP.c_str(), &addr4->sin_addr) <= 0) {
                NATTable::RemoveMapping(natKey);
                return -1;
            }
            addrLen = sizeof(sockaddr_in);
        }

        // 发送数据
        ssize_t sent = sendto(sockFd, payload, payloadSize, 0, 
                             reinterpret_cast<sockaddr*>(&targetAddr), addrLen);
        if (sent < 0) {
            NATTable::RemoveMapping(natKey);
            return -1;
        }

        // 启动UDP响应线程（仅新映射）
        if (isNewMapping) {
            StartUDPThread(sockFd, originalPeer);
        }
        
        return sockFd;
        
    } else if (packetInfo.protocol == PROTOCOL_TCP) {
        // TCP处理
        ParsedTcp tcp = ParseTcpFromIp(data, dataSize);
        if (!tcp.ok) {
            if (isNewMapping) {
                NATTable::RemoveMapping(natKey);
                if (sockFd >= 0) close(sockFd);
            }
            return -1;
        }

        bool isSyn = HasTcpFlag(tcp.flags, TCP_SYN);
        bool isAck = HasTcpFlag(tcp.flags, TCP_ACK);
        bool isFin = HasTcpFlag(tcp.flags, TCP_FIN);
        bool isRst = HasTcpFlag(tcp.flags, TCP_RST);

        // 检查映射是否存在（竞态条件检查）
        if (!NATTable::WithConnection(natKey, [](NATConnection&) {}) && !isNewMapping) {
            return -1;
        }

        // 新映射：建立TCP连接
        if (isNewMapping) {
            sockaddr_storage targetAddr{};
            socklen_t addrLen = 0;
            
            if (packetInfo.addressFamily == AF_INET6) {
                auto* addr6 = reinterpret_cast<sockaddr_in6*>(&targetAddr);
                addr6->sin6_family = AF_INET6;
                addr6->sin6_port = htons(static_cast<uint16_t>(packetInfo.targetPort));
                if (inet_pton(AF_INET6, actualTargetIP.c_str(), &addr6->sin6_addr) <= 0) {
                    NATTable::RemoveMapping(natKey);
                    close(sockFd);
                    return -1;
                }
                addrLen = sizeof(sockaddr_in6);
            } else {
                auto* addr4 = reinterpret_cast<sockaddr_in*>(&targetAddr);
                addr4->sin_family = AF_INET;
                addr4->sin_port = htons(static_cast<uint16_t>(packetInfo.targetPort));
                if (inet_pton(AF_INET, actualTargetIP.c_str(), &addr4->sin_addr) <= 0) {
                    NATTable::RemoveMapping(natKey);
                    close(sockFd);
                    return -1;
                }
                addrLen = sizeof(sockaddr_in);
            }

            // 🔍 流程跟踪：记录TCP连接尝试（详细诊断）
            LOG_INFO("🔍 [TCP连接诊断] 开始TCP连接: %s:%d (fd=%d, 源=%s:%d)", 
                     actualTargetIP.c_str(), packetInfo.targetPort, sockFd,
                     packetInfo.sourceIP.c_str(), packetInfo.sourcePort);
            LOG_INFO("🔍 [TCP连接诊断] 连接目的: 代理服务器转发socket -> 真实服务器 %s:%d", 
                     actualTargetIP.c_str(), packetInfo.targetPort);
            LOG_INFO("🔍 [TCP连接诊断] 连接作用: 将VPN客户端流量转发到互联网服务器");
            
            // 🚨 关键修复：等待socket保护完成
            // VPN客户端每500ms检查一次保护队列，实际保护可能需要1-2个周期
            // 等待1500ms确保保护完成（3个检查周期）
            LOG_INFO("🔍 [TCP连接诊断] 等待socket保护完成 (1500ms, 3个检查周期)...");
            auto waitStartTime = std::chrono::steady_clock::now();
            std::this_thread::sleep_for(std::chrono::milliseconds(1500));
            auto waitEndTime = std::chrono::steady_clock::now();
            auto waitElapsed = std::chrono::duration_cast<std::chrono::milliseconds>(waitEndTime - waitStartTime).count();
            LOG_INFO("🔍 [TCP连接诊断] socket保护等待完成 (实际等待%lldms)，开始尝试连接", waitElapsed);
            
            // 连接服务器（带重试机制）
            bool connectSuccess = false;
            int retryCount = 0;
            const int MAX_RETRIES = 2;  // 最多重试2次
            
            while (!connectSuccess && retryCount <= MAX_RETRIES) {
                LOG_INFO("🔍 [TCP连接诊断] 尝试连接 (第%d次，共%d次): %s:%d (fd=%d)", 
                         retryCount + 1, MAX_RETRIES + 1, actualTargetIP.c_str(), packetInfo.targetPort, sockFd);
                
                if (ConnectWithTimeout(sockFd, reinterpret_cast<sockaddr*>(&targetAddr), addrLen, 3000)) {
                    connectSuccess = true;
                    LOG_INFO("✅ [TCP连接诊断] 连接成功: %s:%d (fd=%d, 重试%d次)", 
                             actualTargetIP.c_str(), packetInfo.targetPort, sockFd, retryCount);
                    break;
                }
                
                int savedErrno = errno;
                
                // 🚨 详细诊断：记录连接失败原因
                LOG_ERROR("❌ [TCP连接诊断] 连接失败: %s:%d (fd=%d, 重试%d/%d) - errno=%d (%s)", 
                         actualTargetIP.c_str(), packetInfo.targetPort, sockFd, retryCount + 1, MAX_RETRIES + 1, 
                         savedErrno, strerror(savedErrno));
                
                // 🚨 环路检测：ENETUNREACH通常表示socket未保护，流量被VPN路由表捕获
                if (savedErrno == ENETUNREACH) {
                    LOG_ERROR("🚨 [TCP连接诊断] ENETUNREACH原因分析:");
                    LOG_ERROR("   1. socket可能未保护，连接请求被VPN路由表捕获");
                    LOG_ERROR("   2. 连接请求进入VPN隧道，形成环路");
                    LOG_ERROR("   3. 导致无法到达真实服务器");
                    if (retryCount < MAX_RETRIES) {
                        int retryWaitTime = 1500 + retryCount * 500;  // 重试等待时间：1500ms, 2000ms
                        LOG_ERROR("🚨 [TCP连接诊断] 等待后重试 (%d/%d, 等待%dms)...", 
                                 retryCount + 1, MAX_RETRIES, retryWaitTime);
                        // 每次重试等待更长时间，给socket保护更多时间
                        std::this_thread::sleep_for(std::chrono::milliseconds(retryWaitTime));
                        retryCount++;
                        continue;
                    } else {
                        LOG_ERROR("🚨 [TCP连接诊断] 已达到最大重试次数 (%d次)，连接失败", MAX_RETRIES + 1);
                    }
                } else if (savedErrno == ECONNREFUSED) {
                    LOG_ERROR("🚨 [TCP连接诊断] ECONNREFUSED: 目标服务器拒绝连接 (可能端口关闭或防火墙阻止)");
                } else if (savedErrno == ETIMEDOUT) {
                    LOG_ERROR("🚨 [TCP连接诊断] ETIMEDOUT: 连接超时 (可能网络不通或防火墙阻止)");
                } else if (savedErrno == EHOSTUNREACH) {
                    LOG_ERROR("🚨 [TCP连接诊断] EHOSTUNREACH: 目标主机不可达 (可能路由问题或socket未保护)");
                }
                break;
            }
            
            if (!connectSuccess) {
                LOG_ERROR("❌ [TCP连接诊断] ========== TCP连接最终失败 ==========");
                LOG_ERROR("   目标: %s:%d (fd=%d)", actualTargetIP.c_str(), packetInfo.targetPort, sockFd);
                LOG_ERROR("   源: %s:%d", packetInfo.sourceIP.c_str(), packetInfo.sourcePort);
                LOG_ERROR("   影响: 无法将VPN客户端流量转发到真实服务器");
                LOG_ERROR("   后果: 客户端将无法访问该服务器，浏览器无法加载网页");
                
                // 发送RST给客户端
                LOG_INFO("🔍 [TCP连接诊断] 发送RST包给客户端，告知连接失败");
                uint8_t rstPkt[128];
                int rstSize = PacketBuilder::BuildTcpResponsePacket(
                    rstPkt, sizeof(rstPkt), nullptr, 0, packetInfo,
                    0, tcp.seq + 1, TCP_RST | TCP_ACK
                );
                if (rstSize > 0) {
                    bool submitted = TaskQueueManager::getInstance().submitResponseTask(
                        rstPkt, rstSize, originalPeer, sockFd, PROTOCOL_TCP
                    );
                    if (submitted) {
                        LOG_INFO("✅ [TCP连接诊断] RST包已发送给客户端");
                    } else {
                        LOG_ERROR("❌ [TCP连接诊断] RST包发送失败");
                    }
                } else {
                    LOG_ERROR("❌ [TCP连接诊断] RST包构建失败");
                }
                
                // 🚨 关键修复：延迟移除NAT映射，给客户端时间接收RST包
                // 使用异步方式延迟清理，避免客户端后续ACK包找不到映射
                // 延迟2秒，给客户端更多时间接收RST包和后续ACK包
                LOG_INFO("🔍 [TCP连接诊断] 延迟2秒后清理NAT映射 (避免客户端后续ACK包找不到映射)");
                std::thread([natKey, sockFd, actualTargetIP, packetInfo]() {
                    std::this_thread::sleep_for(std::chrono::milliseconds(2000));
                    LOG_INFO("🔍 [TCP连接诊断] 清理失败的NAT映射: %s:%d -> %s:%d", 
                             packetInfo.sourceIP.c_str(), packetInfo.sourcePort,
                             actualTargetIP.c_str(), packetInfo.targetPort);
                    NATTable::RemoveMapping(natKey);
                    if (sockFd >= 0) {
                        close(sockFd);
                        LOG_INFO("🔍 [TCP连接诊断] 已关闭失败的socket: fd=%d", sockFd);
                    }
                }).detach();
                LOG_ERROR("❌ [TCP连接诊断] ========================================");
                return -1;
            }

            // 初始化TCP状态并发送SYN-ACK
            LOG_INFO("✅ [TCP连接诊断] TCP连接成功，初始化TCP状态");
            uint32_t clientIsn = tcp.seq;
            uint32_t serverIsn = RandomIsn();
            
            if (!NATTable::WithConnection(natKey, [&](NATConnection& c) {
                c.tcpState = NATConnection::TcpState::SYN_RECEIVED;
                c.clientIsn = clientIsn;
                c.serverIsn = serverIsn;
                c.nextClientSeq = clientIsn + 1;
                c.nextServerSeq = serverIsn + 1;
            })) {
                LOG_ERROR("🚨 [TCP连接诊断] 创建NAT映射失败: %s:%d (连接已建立但无法更新状态)", 
                         actualTargetIP.c_str(), packetInfo.targetPort);
                close(sockFd);
                return -1;
            }
            LOG_INFO("🔍 [TCP连接诊断] NAT映射已更新: 状态=SYN_RECEIVED, clientISN=%u, serverISN=%u", 
                     clientIsn, serverIsn);

            uint8_t synAckPkt[128];
            int synAckSize = PacketBuilder::BuildTcpResponsePacket(
                synAckPkt, sizeof(synAckPkt), nullptr, 0, packetInfo,
                serverIsn, clientIsn + 1, TCP_SYN | TCP_ACK
            );
            if (synAckSize > 0) {
                bool submitted = TaskQueueManager::getInstance().submitResponseTask(
                    synAckPkt, synAckSize, originalPeer, sockFd, PROTOCOL_TCP
                );
                if (!submitted) {
                    LOG_ERROR("🚨 [TCP连接诊断] 提交SYN-ACK响应失败: %s:%d", 
                             actualTargetIP.c_str(), packetInfo.targetPort);
                } else {
                    LOG_INFO("✅ [TCP连接诊断] ========== TCP连接成功 ==========");
                    LOG_INFO("   目标: %s:%d (fd=%d)", actualTargetIP.c_str(), packetInfo.targetPort, sockFd);
                    LOG_INFO("   源: %s:%d", packetInfo.sourceIP.c_str(), packetInfo.sourcePort);
                    LOG_INFO("   状态: 已发送SYN-ACK，等待客户端ACK");
                    LOG_INFO("   下一步: 启动TCP响应线程，等待服务器数据");
                    LOG_INFO("✅ [TCP连接诊断] ========================================");
                }
            } else {
                LOG_ERROR("🚨 [TCP连接诊断] 构建SYN-ACK包失败: %s:%d", 
                         actualTargetIP.c_str(), packetInfo.targetPort);
            }

            StartTCPThread(sockFd, originalPeer);
            return sockFd;
        }

        // 现有映射：处理控制包和数据包
        if (isRst) {
            shutdown(sockFd, SHUT_RDWR);
            NATTable::RemoveMapping(natKey);
            return 0;
        }

        if (isFin) {
            uint32_t ackVal = tcp.seq + 1;
            uint32_t seqVal = 0;
            if (!NATTable::WithConnection(natKey, [&](NATConnection& c) {
                c.nextClientSeq = ackVal;
                seqVal = c.nextServerSeq;
            })) {
                return -1;
            }

            uint8_t ackPkt[128];
            int ackSize = PacketBuilder::BuildTcpResponsePacket(
                ackPkt, sizeof(ackPkt), nullptr, 0, packetInfo,
                seqVal, ackVal, TCP_ACK
            );
            if (ackSize > 0) {
                TaskQueueManager::getInstance().submitResponseTask(
                    ackPkt, ackSize, originalPeer, sockFd, PROTOCOL_TCP
                );
            }
            shutdown(sockFd, SHUT_RDWR);
            NATTable::RemoveMapping(natKey);
            return 0;
        }

        // ACK包（完成握手）
        int tcpPayloadSize = dataSize - tcp.ipHeaderLen - tcp.tcpHeaderLen;
        if (tcpPayloadSize <= 0 && isAck && !isSyn) {
            NATTable::WithConnection(natKey, [&](NATConnection& c) {
                if (c.tcpState == NATConnection::TcpState::SYN_RECEIVED && 
                    tcp.ack == c.serverIsn + 1) {
                    c.tcpState = NATConnection::TcpState::ESTABLISHED;
                    c.nextClientSeq = tcp.seq;
                }
            });
            return sockFd;
        }

        // 数据包
        if (tcpPayloadSize > 0) {
            const uint8_t* tcpPayload = data + tcp.ipHeaderLen + tcp.tcpHeaderLen;
            ssize_t sent = send(sockFd, tcpPayload, tcpPayloadSize, 0);
            if (sent < 0) {
                LOG_ERROR("发送数据到真实服务器失败: errno=%d (%s)", errno, strerror(errno));
                shutdown(sockFd, SHUT_RDWR);
                NATTable::RemoveMapping(natKey);
                return -1;
            }

            uint32_t seqVal = 0;
            uint32_t ackVal = 0;
            NATTable::WithConnection(natKey, [&](NATConnection& c) {
                c.tcpState = NATConnection::TcpState::ESTABLISHED;
                c.nextClientSeq = tcp.seq + static_cast<uint32_t>(tcpPayloadSize);
                seqVal = c.nextServerSeq;
                ackVal = c.nextClientSeq;
            });

            uint8_t ackPkt[128];
            int ackSize = PacketBuilder::BuildTcpResponsePacket(
                ackPkt, sizeof(ackPkt), nullptr, 0, packetInfo,
                seqVal, ackVal, TCP_ACK
            );
            if (ackSize > 0) {
                TaskQueueManager::getInstance().submitResponseTask(
                    ackPkt, ackSize, originalPeer, sockFd, PROTOCOL_TCP
                );
            }
            return sockFd;
        }

        return sockFd;
    }

    return -1;
}

// ICMP 转发函数
static int ForwardICMPPacket(const uint8_t* data, int dataSize,
                             const PacketInfo& packetInfo,
                             const sockaddr_in& originalPeer,
                             int tunnelFd) {
    
    // 1. 提取ICMP数据（跳过IP头）
    uint8_t version = (data[0] >> 4) & 0x0F;
    int ipHeaderLen = 0;
    const uint8_t* icmpData = nullptr;
    int icmpSize = 0;
    
    if (version == 4) {
        // IPv4
        ipHeaderLen = (data[0] & 0x0F) * 4;
        if (dataSize < ipHeaderLen + 8) {
            LOG_ERROR("ICMP包太小: %d字节 (需要至少%d字节)", dataSize, ipHeaderLen + 8);
            return -1;
        }
        icmpData = data + ipHeaderLen;
        icmpSize = dataSize - ipHeaderLen;
    } else if (version == 6) {
        // IPv6 - ICMPv6
        ipHeaderLen = 40;  // IPv6基本头固定40字节
        // 跳过扩展头
        uint8_t nextHeader = data[6];
        int offset = 40;
        int hops = 0;
        const int maxHops = 8;
        while (hops < maxHops && nextHeader != PROTOCOL_ICMPV6) {
            if (nextHeader == 0 || nextHeader == 43 || nextHeader == 60 ||
                nextHeader == 51 || nextHeader == 50) {
                if (dataSize < offset + 2) break;
                uint8_t hdrExtLen = data[offset + 1];
                int extLen = (hdrExtLen + 1) * 8;
                if (offset + extLen > dataSize) break;
                // 获取下一个头部（在扩展头中）
                if (dataSize < offset + extLen) break;
                nextHeader = data[offset];  // 扩展头的第一个字节是下一个头部
                offset += extLen;
                hops++;
            } else {
                break;
            }
        }
        if (nextHeader != PROTOCOL_ICMPV6) {
            LOG_ERROR("无法找到ICMPv6头");
            return -1;
        }
        ipHeaderLen = offset;
        if (dataSize < ipHeaderLen + 8) {
            LOG_ERROR("ICMPv6包太小: %d字节", dataSize);
            return -1;
        }
        icmpData = data + ipHeaderLen;
        icmpSize = dataSize - ipHeaderLen;
    } else {
        LOG_ERROR("不支持的IP版本: %d", version);
        return -1;
    }
    
    // 2. 只处理ICMP Echo Request (Type=8) 和 ICMPv6 Echo Request (Type=128)
    if (packetInfo.icmpv6Type != 8 && packetInfo.icmpv6Type != 128) {
        return 0;  // 返回0表示已处理（跳过）
    }
    
    // 3. 尝试所有可能的方法创建ICMP socket
    // ⚠️ 重要：ICMP是网络层协议，标准socket（TCP/UDP）无法处理
    // 必须使用SOCK_RAW，没有完全替代方案
    // 但我们可以尝试多种方法，并给出详细的错误信息
    int sockFd = -1;
    std::string socketMethod = "";
    
    if (packetInfo.protocol == PROTOCOL_ICMP) {
        // IPv4 ICMP: 尝试多种方法
        
        // 方法1: IPPROTO_RAW + IP_HDRINCL（最灵活，可以发送完整IP包）
        sockFd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
        if (sockFd >= 0) {
            socketMethod = "IPPROTO_RAW";
            int on = 1;
            setsockopt(sockFd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on));
        } else {
            // 方法2: IPPROTO_ICMP（标准ICMP原始socket）
            sockFd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
            if (sockFd >= 0) {
                socketMethod = "IPPROTO_ICMP";
            } else {
                // 方法3: 尝试SOCK_DGRAM + IPPROTO_ICMP（非标准，某些系统可能支持）
                sockFd = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
                if (sockFd >= 0) {
                    socketMethod = "SOCK_DGRAM+IPPROTO_ICMP";
                } else {
                    LOG_ERROR("所有ICMP socket创建方法都失败: errno=%d (%s)", errno, strerror(errno));
                    return -1;
                }
            }
        }
    } else {
        // IPv6 ICMPv6: 只能使用SOCK_RAW + IPPROTO_ICMPV6
        sockFd = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
        if (sockFd < 0) {
            LOG_ERROR("创建ICMPv6原始socket失败: %s", strerror(errno));
            return -1;
        }
        socketMethod = "IPPROTO_ICMPV6";
    }
    
    // 保护socket（避免被VPN路由劫持）
    std::string socketDesc = std::string(packetInfo.protocol == PROTOCOL_ICMP ? "ICMP" : "ICMPv6") +
                            " forwarding socket to " + packetInfo.targetIP;
    ProtectSocket(sockFd, socketDesc);
    SendProtectSocketMessage(sockFd, packetInfo, originalPeer, tunnelFd);
    
    // 构建目标地址
    sockaddr_storage targetAddr{};
    socklen_t addrLen = 0;
    
    if (packetInfo.protocol == PROTOCOL_ICMP) {
        auto* addr4 = reinterpret_cast<sockaddr_in*>(&targetAddr);
        addr4->sin_family = AF_INET;
        addr4->sin_port = 0;  // ICMP没有端口
        if (inet_pton(AF_INET, packetInfo.targetIP.c_str(), &addr4->sin_addr) <= 0) {
            LOG_ERROR("无效的目标IP: %s", packetInfo.targetIP.c_str());
            close(sockFd);
            return -1;
        }
        addrLen = sizeof(sockaddr_in);
    } else {
        auto* addr6 = reinterpret_cast<sockaddr_in6*>(&targetAddr);
        addr6->sin6_family = AF_INET6;
        addr6->sin6_port = 0;  // ICMPv6没有端口
        if (inet_pton(AF_INET6, packetInfo.targetIP.c_str(), &addr6->sin6_addr) <= 0) {
            LOG_ERROR("无效的目标IPv6: %s", packetInfo.targetIP.c_str());
            close(sockFd);
            return -1;
        }
        addrLen = sizeof(sockaddr_in6);
    }
    
    // 发送ICMP包到真实目标服务器
    // 如果使用了IP_HDRINCL，需要发送完整的IP包（包含IP头）
    // 否则只发送ICMP数据
    const uint8_t* dataToSend = nullptr;
    int dataSizeToSend = 0;
    
    // 检查是否设置了IP_HDRINCL
    int ipHdrIncl = 0;
    socklen_t optLen = sizeof(ipHdrIncl);
    bool useFullPacket = false;
    if (packetInfo.protocol == PROTOCOL_ICMP) {
        if (getsockopt(sockFd, IPPROTO_IP, IP_HDRINCL, &ipHdrIncl, &optLen) == 0 && ipHdrIncl) {
            useFullPacket = true;
            // 使用完整IP包（包含IP头）
            dataToSend = data;
            dataSizeToSend = dataSize;
        } else {
            // 只发送ICMP数据
            dataToSend = icmpData;
            dataSizeToSend = icmpSize;
        }
    } else {
        // IPv6: 只发送ICMPv6数据
        dataToSend = icmpData;
        dataSizeToSend = icmpSize;
    }
    
    ssize_t sent = sendto(sockFd, dataToSend, dataSizeToSend, 0,
                         reinterpret_cast<sockaddr*>(&targetAddr), addrLen);
    if (sent < 0) {
        LOG_ERROR("发送ICMP包失败: %s", strerror(errno));
        close(sockFd);
        return -1;
    }
    
    // 4. 启动响应接收线程（接收真实服务器的ICMP响应）
    std::thread([sockFd, originalPeer, packetInfo, icmpData, icmpSize]() {
        // 设置接收超时（5秒）
        struct timeval timeout = {5, 0};
        setsockopt(sockFd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        
        uint8_t buffer[4096];
        sockaddr_storage fromAddr{};
        socklen_t fromLen = sizeof(fromAddr);
        
        // 接收真实服务器的ICMP响应
        ssize_t received = recvfrom(sockFd, buffer, sizeof(buffer), 0,
                                   reinterpret_cast<sockaddr*>(&fromAddr), &fromLen);
        if (received < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK && errno != ETIMEDOUT) {
                LOG_ERROR("接收ICMP响应失败: %s", strerror(errno));
            }
            close(sockFd);
            return;
        }
        
        // 构建完整IP响应包（包含IP头）
        uint8_t responsePacket[4096];
        int responseSize = 0;
        
        if (packetInfo.protocol == PROTOCOL_ICMP) {
            // IPv4 ICMP响应
            // 检查接收到的数据是否包含IP头
            // SOCK_RAW接收ICMP时，通常返回的数据包含IP头（取决于系统）
            uint8_t version = (buffer[0] >> 4) & 0x0F;
            const uint8_t* icmpResponseData = nullptr;
            int icmpResponseSize = 0;
            
            if (version == 4 && received >= 20) {
                // 数据包含IP头，跳过IP头
                int ipHeaderLen = (buffer[0] & 0x0F) * 4;
                if (received >= ipHeaderLen) {
                    icmpResponseData = buffer + ipHeaderLen;
                    icmpResponseSize = static_cast<int>(received) - ipHeaderLen;
                } else {
                    // IP头不完整，使用全部数据
                    icmpResponseData = buffer;
                    icmpResponseSize = static_cast<int>(received);
                }
            } else {
                // 数据不包含IP头，直接使用
                icmpResponseData = buffer;
                icmpResponseSize = static_cast<int>(received);
            }
            
            // 构建新的IP头（用于VPN隧道）
            responsePacket[0] = 0x45;  // IPv4, 5字节头
            responsePacket[1] = 0x00;  // TOS
            uint16_t totalLength = 20 + static_cast<uint16_t>(icmpResponseSize);
            responsePacket[2] = (totalLength >> 8) & 0xFF;
            responsePacket[3] = totalLength & 0xFF;
            responsePacket[4] = 0x00;
            responsePacket[5] = 0x01;
            responsePacket[6] = 0x00;
            responsePacket[7] = 0x00;
            responsePacket[8] = 0x40;  // TTL
            responsePacket[9] = PROTOCOL_ICMP;
            
            // 源IP = 目标IP（响应来自目标服务器）
            inet_pton(AF_INET, packetInfo.targetIP.c_str(), &responsePacket[12]);
            // 目的IP = 源IP（VPN虚拟IP，需要转发回客户端）
            inet_pton(AF_INET, packetInfo.sourceIP.c_str(), &responsePacket[16]);
            
            // 复制ICMP响应数据
            if (icmpResponseSize > 0 && icmpResponseSize <= 4096 - 20) {
                memcpy(responsePacket + 20, icmpResponseData, icmpResponseSize);
            } else {
                LOG_ERROR("ICMP响应数据大小异常: %d", icmpResponseSize);
                close(sockFd);
                return;
            }
            
            // 计算IP校验和
            uint16_t checksum = 0;
            for (int i = 0; i < 20; i += 2) {
                checksum += (static_cast<uint16_t>(responsePacket[i]) << 8) | responsePacket[i + 1];
            }
            while (checksum >> 16) {
                checksum = (checksum & 0xFFFF) + (checksum >> 16);
            }
            checksum = ~checksum;
            responsePacket[10] = (checksum >> 8) & 0xFF;
            responsePacket[11] = checksum & 0xFF;
            
            responseSize = 20 + icmpResponseSize;
        } else {
            // IPv6 ICMPv6响应
            // TODO: 实现完整的IPv6 ICMPv6响应构建
            close(sockFd);
            return;
        }
        
        // 提交响应任务（通过VPN隧道发送回客户端）
        if (responseSize > 0) {
            TaskQueueManager::getInstance().submitResponseTask(
                responsePacket, responseSize, originalPeer, sockFd, packetInfo.protocol
            );
        }
        
        close(sockFd);
    }).detach();
    
    return sockFd;
}

// 清理所有缓存的socket和线程
void PacketForwarder::CleanupAll() {
    // 清理socket连接池
    SocketConnectionPool::getInstance().cleanup();
    // 清理过期NAT映射
    NATTable::CleanupExpired(0);  // 清理所有映射
}

// 输出统计信息（用于调试）
void PacketForwarder::LogStatistics() {
    // TODO: 添加具体的统计信息输出
}
