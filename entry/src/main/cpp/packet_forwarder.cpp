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

static bool ConnectWithTimeout(int sockFd, const sockaddr* targetAddr, socklen_t addrLen, int timeoutMs)
{
    int flags = fcntl(sockFd, F_GETFL, 0);
    if (flags < 0) {
        LOG_ERROR("TCP connect: failed to get socket flags: fd=%d errno=%d", sockFd, errno);
        return false;
    }
    if (fcntl(sockFd, F_SETFL, flags | O_NONBLOCK) < 0) {
        LOG_ERROR("TCP connect: failed to set O_NONBLOCK: fd=%d errno=%d", sockFd, errno);
        return false;
    }

    int rc = connect(sockFd, targetAddr, addrLen);
    if (rc == 0) {
        // Connected immediately
        fcntl(sockFd, F_SETFL, flags);
        return true;
    }
    if (errno != EINPROGRESS) {
        LOG_ERROR("TCP connect: immediate failure: fd=%d errno=%d (%s)", sockFd, errno, strerror(errno));
        fcntl(sockFd, F_SETFL, flags);
        return false;
    }

    fd_set writefds;
    FD_ZERO(&writefds);
    FD_SET(sockFd, &writefds);
    struct timeval tv;
    tv.tv_sec = timeoutMs / 1000;
    tv.tv_usec = (timeoutMs % 1000) * 1000;

    int sel = select(sockFd + 1, nullptr, &writefds, nullptr, &tv);
    if (sel <= 0) {
        LOG_ERROR("TCP_CONNECT_TIMEOUT fd=%d timeoutMs=%d", sockFd, timeoutMs);
        fcntl(sockFd, F_SETFL, flags);
        return false;
    }

    int soError = 0;
    socklen_t len = sizeof(soError);
    if (getsockopt(sockFd, SOL_SOCKET, SO_ERROR, &soError, &len) < 0 || soError != 0) {
        LOG_ERROR("TCP connect: failed after select: fd=%d errno=%d (%s)", sockFd,
                  soError ? soError : errno, strerror(soError ? soError : errno));
        fcntl(sockFd, F_SETFL, flags);
        return false;
    }

    // Restore original flags
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
        t.flags = data[off + 13];
        uint8_t dataOffsetWords = (data[off + 12] >> 4) & 0x0F;
        int tcpHL = static_cast<int>(dataOffsetWords) * 4;
        if (tcpHL < 20 || dataSize < off + tcpHL) return t;
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
                off += extLen;
                if (off > dataSize) return t;
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
        t.flags = data[off + 13];
        uint8_t dataOffsetWords = (data[off + 12] >> 4) & 0x0F;
        int tcpHL = static_cast<int>(dataOffsetWords) * 4;
        if (tcpHL < 20 || dataSize < off + tcpHL) return t;
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
        LOG_ERROR("SOCKET_PROTECT_EFFECTIVE=0 fd=%d desc=%s", sockFd, description.c_str());
    } else {
        LOG_INFO("✅ [Socket保护] Socket保护成功: fd=%d (%s)", sockFd, description.c_str());
        LOG_INFO("SOCKET_PROTECT_EFFECTIVE=1 fd=%d desc=%s", sockFd, description.c_str());
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
        int newSock = createNewSocket(protocol, addressFamily);
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
                      const std::string& serverIP, uint16_t serverPort, uint8_t protocol,
                      int addressFamily) {
        std::lock_guard<std::mutex> lock(poolMutex_);
        TargetKey key{clientIP, clientPort, serverIP, serverPort, protocol, addressFamily};

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
static int GetSocket(const PacketInfo& packetInfo, const sockaddr_in& clientAddr, int tunnelFd) {
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
        packetInfo.protocol,
        packetInfo.addressFamily
    );

    if (sockFd < 0) {
        LOG_ERROR("❌ [Socket获取失败] 连接池返回无效socket: %d", sockFd);
        return -1;
    }
    
    // 🔥 关键修复：发送控制消息给VPN客户端，请求保护转发socket
    std::string socketDesc = std::string(packetInfo.protocol == PROTOCOL_TCP ? "TCP" : "UDP") +
                            " forwarding socket to " + packetInfo.targetIP + ":" + std::to_string(packetInfo.targetPort);
    LOG_INFO("🛡️ [Socket保护] 发送控制消息请求保护socket: fd=%d (%s)", sockFd, socketDesc.c_str());

    // 本地尝试保护socket（避免服务器自身流量被VPN劫持形成回环）
    ProtectSocket(sockFd, socketDesc);

    // 🛡️ Socket保护策略
    // NOTE:
    // - 这里“保护”仅指：通知VPN客户端/扩展能力做 bypass（如果机制可用）
    // - 即便保护机制不可用，也不应影响基本转发逻辑
    bool shouldProtect = true;

    if (shouldProtect) {
        // 发送控制消息给VPN客户端请求保护socket
        SendProtectSocketMessage(sockFd, packetInfo, clientAddr, tunnelFd);
    } else {
        LOG_INFO("🛡️ [Socket保护] 使用普通socket (fd=%d)", sockFd);
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
    
    LOG_INFO("✅ [Socket获取成功] fd=%d, 客户端=%s:%d -> 服务器=%s:%d, 协议=%s",
             sockFd, clientIP, ntohs(clientAddr.sin_port),
             packetInfo.targetIP.c_str(), packetInfo.targetPort,
             packetInfo.protocol == PROTOCOL_TCP ? "TCP" : "UDP");
    return sockFd;
}

// 🎯 发送socket保护控制消息给VPN客户端
static void SendProtectSocketMessage(int sockFd, const PacketInfo& packetInfo, const sockaddr_in& clientAddr, int tunnelFd) {
    LOG_INFO("📤 [控制消息] 发送socket保护请求: fd=%d, tunnelFd=%d", sockFd, tunnelFd);

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
        if (sent > 0) {
            LOG_INFO("✅ [控制消息] socket保护请求已发送: fd=%d -> 客户端 %{public}s:%{public}d",
                     sockFd, inet_ntoa(clientAddr.sin_addr), ntohs(clientAddr.sin_port));
        } else {
            LOG_ERROR("❌ [控制消息] 发送失败: errno=%d", errno);
        }
    } else {
        LOG_ERROR("❌ [控制消息] tunnelFd无效，无法发送控制消息");
    }
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

        // 先抓取映射信息（用于归还连接池），再删除映射，避免信息丢失
        NATConnection conn;
        bool hasConn = NATTable::FindMappingBySocket(sockFd, conn);
        if (hasConn) {
            char clientIP[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &conn.clientPhysicalAddr.sin_addr, clientIP, sizeof(clientIP));

            NATTable::RemoveMappingBySocket(sockFd);
            SocketConnectionPool::getInstance().returnSocket(
                sockFd,
                clientIP,
                ntohs(conn.clientPhysicalAddr.sin_port),
                conn.serverIP,
                conn.serverPort,
                PROTOCOL_UDP,
                conn.originalRequest.addressFamily
            );
        } else {
            NATTable::RemoveMappingBySocket(sockFd);
            // 如果找不到映射，直接关闭
            close(sockFd);
            LOG_INFO("⚠️ 找不到NAT映射，直接关闭socket: fd=%d", sockFd);
        }
        
    }).detach();
}

// 🎯 TCP响应线程
static void StartTCPThread(int sockFd, const sockaddr_in& originalPeer) {
    std::thread([sockFd, originalPeer]() {
        LOG_ERROR("TCP_THREAD_STARTED fd=%d", sockFd);
        
        uint8_t buffer[4096];
        int noResponseCount = 0;
        const int MAX_NO_RESPONSE = 3;  // 最多3次无响应后清理
    
    while (true) {
            ssize_t received = recv(sockFd, buffer, sizeof(buffer), 0);
            if (received < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    noResponseCount++;
                    if (noResponseCount == 1 || noResponseCount == MAX_NO_RESPONSE) {
                        std::string localAddr = GetSocketAddrString(sockFd, false);
                        std::string peerAddr = GetSocketAddrString(sockFd, true);
                        LOG_ERROR("TCP_RECV_TIMEOUT fd=%d count=%d local=%s peer=%s",
                                  sockFd, noResponseCount, localAddr.c_str(), peerAddr.c_str());
                    }
                    if (noResponseCount >= MAX_NO_RESPONSE) {
                        LOG_INFO("🔚 TCP无响应次数过多，清理socket: fd=%d", sockFd);
                        break;
                    }
                    continue;
                }
                LOG_ERROR("TCP接收失败: fd=%d, errno=%d", sockFd, errno);
                break;
            } else if (received == 0) {
                LOG_INFO("🔚 TCP连接关闭(远端FIN): fd=%d", sockFd);

                // Best-effort: send FIN|ACK to client with current seq/ack
                NATConnection conn;
                if (NATTable::FindMappingBySocket(sockFd, conn)) {
                    uint32_t seqToSend = 0;
                    uint32_t ackToSend = 0;
                    PacketInfo origReq = conn.originalRequest;
                    NATTable::WithConnectionBySocket(sockFd, [&](NATConnection& c) {
                        seqToSend = c.nextServerSeq;
                        ackToSend = c.nextClientSeq;
                        c.nextServerSeq += 1; // FIN consumes one seq
                        c.tcpState = NATConnection::TcpState::FIN_SENT;
                    });

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
                        LOG_INFO("📤 [TCP] 已回FIN-ACK给客户端: seq=%u ack=%u", seqToSend, ackToSend);
                    }
                }

                break;
            }
        
            // 重置无响应计数
            noResponseCount = 0;
            
            // 🔧 调试：打印接收到的数据
            LOG_INFO("🔍 TCP收到响应: fd=%d, %zd字节", sockFd, received);
            
            // 检查NAT映射并构建完整IP响应包（包含正确的TCP seq/ack）
            NATConnection conn;
            if (NATTable::FindMappingBySocket(sockFd, conn)) {
                // 🔧 调试：打印发送目标
                char peerIP[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &originalPeer.sin_addr, peerIP, sizeof(peerIP));
                uint16_t peerPort = ntohs(originalPeer.sin_port);
                LOG_INFO("🔍 TCP响应: 构建完整IP包发送到 %s:%d", peerIP, peerPort);

            // Snapshot + advance nextServerSeq under lock
                uint32_t seqToSend = 0;
                uint32_t ackToSend = 0;
                PacketInfo origReq = conn.originalRequest;
                NATTable::WithConnectionBySocket(sockFd, [&](NATConnection& c) {
                    seqToSend = c.nextServerSeq;
                    ackToSend = c.nextClientSeq;
                    c.nextServerSeq += static_cast<uint32_t>(received);
                });

            LOG_INFO("TCP_SERVER_DATA fd=%d len=%zd seq=%u ack=%u",
                     sockFd, received, seqToSend, ackToSend);

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
        
        // 🧹 清理NAT映射并关闭socket (TCP不复用连接池，避免复用到已关闭/半关闭的连接)
        LOG_ERROR("TCP_THREAD_EXIT fd=%d", sockFd);
        LOG_INFO("🧹 清理TCP线程资源并关闭socket: fd=%d", sockFd);

        NATTable::RemoveMappingBySocket(sockFd);
        close(sockFd);
        
    }).detach();
}


// ========== 主转发函数 ==========

int PacketForwarder::ForwardPacket(const uint8_t* data, int dataSize,
                                  const PacketInfo& packetInfo,
                                  const sockaddr_in& originalPeer,
                                  int tunnelFd) {
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

    if (packetInfo.protocol == PROTOCOL_ICMPV6) {
        LOG_INFO("ℹ️ [ICMPv6转发] 当前未实现ICMPv6转发，已跳过: Type=%d (%s) -> %s",
                 packetInfo.icmpv6Type,
                 ProtocolHandler::GetICMPv6TypeName(packetInfo.icmpv6Type).c_str(),
                 packetInfo.targetIP.c_str());
        return 0;
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
    
    // TCP control packets often have payloadSize==0 (SYN/ACK/FIN/RST). We must NOT drop them.
    if (packetInfo.protocol == PROTOCOL_TCP && payloadSize <= 0) {
        ParsedTcp tcp = ParseTcpFromIp(data, dataSize);
        if (tcp.ok) {
            LOG_ERROR("TCP_ZERO_PAYLOAD %s:%u -> %s:%u dataSize=%d payloadSize=%d flags=0x%02x(%s) seq=%u ack=%u ipHL=%u tcpHL=%u",
                      packetInfo.sourceIP.c_str(), static_cast<unsigned>(tcp.srcPort),
                      packetInfo.targetIP.c_str(), static_cast<unsigned>(tcp.dstPort),
                      dataSize, payloadSize,
                      tcp.flags, TcpFlagsToString(tcp.flags).c_str(),
                      tcp.seq, tcp.ack, tcp.ipHeaderLen, tcp.tcpHeaderLen);
        }
        // continue into TCP handling below (do not return)
    } else if (payloadSize <= 0) {
        return 0;
    }
    
    // 2. DNS重定向 - 只重定向223.5.5.5
    std::string actualTargetIP = packetInfo.targetIP;
    if (packetInfo.targetPort == 53) {
        // 🔧 调试：打印原始IP值 (强制输出)
        LOG_ERROR("🔍 DNS原始目标: %s:%d", packetInfo.targetIP.c_str(), packetInfo.targetPort);

        if (packetInfo.targetIP == "223.5.5.5") {
            actualTargetIP = "8.8.8.8";  // 只重定向223.5.5.5到8.8.8.8
            LOG_ERROR("🔄 DNS重定向: %s -> %s", packetInfo.targetIP.c_str(), actualTargetIP.c_str());
        } else {
            LOG_ERROR("🔍 DNS无需重定向: %s", packetInfo.targetIP.c_str());
        }
    }
    
    // 3. 检查或创建NAT映射 (优化版本)
    std::string natKey = NATTable::GenerateKey(packetInfo, originalPeer);
    
    NATConnection existingConn;
    int sockFd;
    bool isNewMapping = false;
    
    if (NATTable::FindMapping(natKey, existingConn)) {
        // 映射已存在，使用现有socket
        LOG_INFO("🔄 使用现有NAT映射: key=%s, fd=%d", natKey.c_str(), existingConn.forwardSocket);
        sockFd = existingConn.forwardSocket;
        
        } else {
        // 没有现有映射，创建新socket和映射
        sockFd = GetSocket(packetInfo, originalPeer, tunnelFd);
        if (sockFd < 0) {
            LOG_ERROR("获取socket失败");
            return -1;
        }
        
        NATTable::CreateMapping(natKey, originalPeer, packetInfo, sockFd);
        LOG_INFO("✅ 创建新NAT映射: %s -> fd=%d", natKey.c_str(), sockFd);
        isNewMapping = true;
    }
    
    // 5. 发送数据
    if (packetInfo.protocol == PROTOCOL_UDP) {
        // 🔍 关键调试：UDP发送过程
        LOG_INFO("🔍 [UDP转发] 开始发送数据: %s:%d -> %s:%d (%d字节)",
                 packetInfo.sourceIP.c_str(), packetInfo.sourcePort,
                 actualTargetIP.c_str(), packetInfo.targetPort, payloadSize);

        if (packetInfo.addressFamily == AF_INET6) {
            struct sockaddr_in6 targetAddr{};
            targetAddr.sin6_family = AF_INET6;
            targetAddr.sin6_port = htons(static_cast<uint16_t>(packetInfo.targetPort));
            if (inet_pton(AF_INET6, actualTargetIP.c_str(), &targetAddr.sin6_addr) <= 0) {
                LOG_ERROR("❌ [UDP转发] 无效目标IPv6地址: %s", actualTargetIP.c_str());
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
        } else {
            struct sockaddr_in targetAddr{};
            targetAddr.sin_family = AF_INET;
            // sockaddr_in 端口必须是网络字节序
            targetAddr.sin_port = htons(static_cast<uint16_t>(packetInfo.targetPort));
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
        }

        // 6. 启动响应线程 - 只在创建新映射时启动
        if (isNewMapping) {
            StartUDPThread(sockFd, originalPeer);
            LOG_INFO("🚀 [UDP响应线程] 新建响应处理线程 (fd=%d)", sockFd);
        } else {
            LOG_INFO("🔄 [UDP响应线程] 复用现有响应处理线程 (fd=%d)", sockFd);
        }
        
    } else if (packetInfo.protocol == PROTOCOL_TCP) {
    // Minimal TCP state machine: handle SYN/ACK/FIN control packets from client, and translate payload to a stream socket.
    ParsedTcp tcp = ParseTcpFromIp(data, dataSize);
    if (!tcp.ok) {
        LOG_ERROR("❌ [TCP解析失败] 非IPv4/TCP或头部不完整: dataSize=%d", dataSize);
        NATTable::RemoveMapping(natKey);
        return -1;
    }

    const bool isSyn = HasTcpFlag(tcp.flags, TCP_SYN);
    const bool isAck = HasTcpFlag(tcp.flags, TCP_ACK);
    const bool isFin = HasTcpFlag(tcp.flags, TCP_FIN);
    const bool isRst = HasTcpFlag(tcp.flags, TCP_RST);

    // 🔍 关键诊断：记录客户端TCP包的seq/ack与当前状态
    NATTable::WithConnection(natKey, [&](NATConnection& c) {
        LOG_INFO("TCP_CLIENT_PKT key=%s flags=%s seq=%u ack=%u state=%d nextClientSeq=%u nextServerSeq=%u",
                 natKey.c_str(), TcpFlagsToString(tcp.flags).c_str(), tcp.seq, tcp.ack,
                 static_cast<int>(c.tcpState), c.nextClientSeq, c.nextServerSeq);
    });

    // New mapping should only start on SYN (no ACK)
    if (isNewMapping) {
        if (!isSyn || isAck) {
            LOG_ERROR("❌ [TCP] 收到非SYN的新连接包，丢弃: flags=%s", TcpFlagsToString(tcp.flags).c_str());
            NATTable::RemoveMapping(natKey);
            return -1;
        }
    }

    // Establish outgoing TCP connection once for new mapping
    sockaddr_storage targetAddr{};
    socklen_t targetAddrLen = 0;
    if (packetInfo.addressFamily == AF_INET6) {
        auto* addr6 = reinterpret_cast<sockaddr_in6*>(&targetAddr);
        addr6->sin6_family = AF_INET6;
        addr6->sin6_port = htons(static_cast<uint16_t>(packetInfo.targetPort));
        if (inet_pton(AF_INET6, actualTargetIP.c_str(), &addr6->sin6_addr) <= 0) {
            LOG_ERROR("❌ [TCP转发] 无效目标IPv6地址: %s", actualTargetIP.c_str());
            NATTable::RemoveMapping(natKey);
            return -1;
        }
        targetAddrLen = sizeof(sockaddr_in6);
    } else {
        auto* addr4 = reinterpret_cast<sockaddr_in*>(&targetAddr);
        addr4->sin_family = AF_INET;
        addr4->sin_port = htons(static_cast<uint16_t>(packetInfo.targetPort));
        if (inet_pton(AF_INET, actualTargetIP.c_str(), &addr4->sin_addr) <= 0) {
            LOG_ERROR("❌ [TCP转发] 无效目标地址: %s", actualTargetIP.c_str());
            NATTable::RemoveMapping(natKey);
            return -1;
        }
        targetAddrLen = sizeof(sockaddr_in);
    }

    if (isNewMapping) {
        LOG_INFO("🔗 [TCP连接] 正在连接到 %s:%d (fd=%d)...",
                 actualTargetIP.c_str(), packetInfo.targetPort, sockFd);
        if (!ConnectWithTimeout(sockFd, reinterpret_cast<sockaddr*>(&targetAddr), targetAddrLen, 3000)) {
            LOG_ERROR("❌ [TCP连接失败/超时] fd=%d, 目标=%s:%d", sockFd, actualTargetIP.c_str(), packetInfo.targetPort);
            LOG_ERROR("TCP_CONNECT_FAIL fd=%d", sockFd);

            // Best-effort: send RST back to client to avoid hanging
            uint8_t rstPkt[128];
            uint32_t ackVal = tcp.seq + 1; // SYN consumes one seq
            int rstSize = PacketBuilder::BuildTcpResponsePacket(
                rstPkt, sizeof(rstPkt),
                nullptr, 0,
                packetInfo,
                0, ackVal,
                TCP_RST | TCP_ACK
            );
            if (rstSize > 0) {
                TaskQueueManager::getInstance().submitResponseTask(
                    rstPkt, rstSize, originalPeer, sockFd, PROTOCOL_TCP
                );
                LOG_INFO("📤 [TCP失败] 已回RST给客户端: ack=%u", ackVal);
            }

            NATTable::RemoveMapping(natKey);
            close(sockFd);
            return -1;
        }
        LOG_INFO("✅ [TCP连接成功] fd=%d 已连接到 %s:%d", sockFd, actualTargetIP.c_str(), packetInfo.targetPort);

        // Initialize TCP state and reply SYN-ACK to client
        uint32_t clientIsn = tcp.seq;
        uint32_t serverIsn = RandomIsn();
        NATTable::WithConnection(natKey, [&](NATConnection& c) {
            c.tcpState = NATConnection::TcpState::SYN_RECEIVED;
            c.clientIsn = clientIsn;
            c.serverIsn = serverIsn;
            c.nextClientSeq = clientIsn + 1;
            c.nextServerSeq = serverIsn + 1;
        });

        uint8_t synAckPkt[128];
        int synAckSize = PacketBuilder::BuildTcpResponsePacket(
            synAckPkt, sizeof(synAckPkt),
            nullptr, 0,
            packetInfo,
            serverIsn, clientIsn + 1,
            TCP_SYN | TCP_ACK
        );
        if (synAckSize > 0) {
            TaskQueueManager::getInstance().submitResponseTask(
                synAckPkt, synAckSize, originalPeer, sockFd, PROTOCOL_TCP
            );
            LOG_INFO("📤 [TCP握手] 已回SYN-ACK给客户端: seq=%u ack=%u", serverIsn, clientIsn + 1);
        } else {
            LOG_ERROR("❌ [TCP握手] 构建SYN-ACK失败");
        }

        LOG_ERROR("TCP_THREAD_LAUNCH fd=%d", sockFd);
        StartTCPThread(sockFd, originalPeer);
        LOG_INFO("🚀 [TCP响应线程] 新建响应处理线程 (fd=%d)", sockFd);

        return sockFd;
    }

    // Existing mapping: handle control packets & data
    if (isRst) {
        LOG_INFO("🔚 [TCP] RST received from client, closing (fd=%d) seq=%u ack=%u",
                 sockFd, tcp.seq, tcp.ack);
        shutdown(sockFd, SHUT_RDWR);
        NATTable::RemoveMapping(natKey);
        return 0;
    }

    // ACK-only / FIN handling updates minimal state
    if (isFin) {
        LOG_INFO("🔚 [TCP] FIN received from client (fd=%d) seq=%u ack=%u",
                 sockFd, tcp.seq, tcp.ack);
        // ACK FIN
        uint32_t clientFinSeq = tcp.seq;
        uint32_t ackVal = clientFinSeq + 1;
        uint32_t seqVal = 0;
        NATTable::WithConnection(natKey, [&](NATConnection& c) {
            c.nextClientSeq = ackVal;
            seqVal = c.nextServerSeq;
        });

        uint8_t ackPkt[128];
        int ackSize = PacketBuilder::BuildTcpResponsePacket(
            ackPkt, sizeof(ackPkt),
            nullptr, 0, packetInfo,
            seqVal, ackVal, TCP_ACK
        );
        if (ackSize > 0) {
            TaskQueueManager::getInstance().submitResponseTask(ackPkt, ackSize, originalPeer, sockFd, PROTOCOL_TCP);
        }
        shutdown(sockFd, SHUT_RDWR);
        NATTable::RemoveMapping(natKey);
        return 0;
    }

    // If this is the ACK completing handshake, mark established
    if (payloadSize <= 0 && isAck && !isSyn) {
        bool transitioned = false;
        uint32_t serverIsn = 0;
        uint32_t expectedServerSeq = 0;
        NATTable::WithConnection(natKey, [&](NATConnection& c) {
            expectedServerSeq = c.nextServerSeq;
            serverIsn = c.serverIsn;
            if (c.nextServerSeq != 0 && tcp.ack != c.nextServerSeq) {
                LOG_ERROR("TCP_ACK_MISMATCH key=%s clientAck=%u expectedServerSeq=%u state=%d",
                          natKey.c_str(), tcp.ack, c.nextServerSeq, static_cast<int>(c.tcpState));
            }
            if (c.tcpState == NATConnection::TcpState::SYN_RECEIVED) {
                // best-effort check: client should ACK our SYN-ACK (ack==serverIsn+1)
                if (tcp.ack == c.serverIsn + 1) {
                    c.tcpState = NATConnection::TcpState::ESTABLISHED;
                    c.nextClientSeq = tcp.seq; // should be clientIsn+1
                    transitioned = true;
                }
            } else if (c.tcpState == NATConnection::TcpState::ESTABLISHED) {
                // ACKs for server->client data: nothing required for our minimal model
            }
        });
        if (transitioned) {
            LOG_INFO("TCP_ESTABLISHED key=%s clientAck=%u serverIsn=%u expectedServerSeq=%u",
                     natKey.c_str(), tcp.ack, serverIsn, expectedServerSeq);
        }
        return sockFd;
    }

    // Data packet from client
    if (payloadSize > 0) {
        // forward to remote stream socket
        LOG_INFO("📤 [TCP发送] key=%s 发送 %d 字节数据 (fd=%d) seq=%u ack=%u",
                 natKey.c_str(), payloadSize, sockFd, tcp.seq, tcp.ack);
        ssize_t sent = send(sockFd, payload, payloadSize, 0);
        if (sent < 0) {
            LOG_ERROR("❌ [TCP发送失败] fd=%d, errno=%d (%s)", sockFd, errno, strerror(errno));
            shutdown(sockFd, SHUT_RDWR);
            NATTable::RemoveMapping(natKey);
            return -1;
        }

        // advance expected client seq and ACK it
        uint32_t seqVal = 0;
        uint32_t ackVal = 0;
        NATTable::WithConnection(natKey, [&](NATConnection& c) {
            c.tcpState = NATConnection::TcpState::ESTABLISHED;
            // best-effort: accept sender seq, then advance by payload
            c.nextClientSeq = tcp.seq + static_cast<uint32_t>(payloadSize);
            seqVal = c.nextServerSeq;
            ackVal = c.nextClientSeq;
        });

        uint8_t ackPkt[128];
        int ackSize = PacketBuilder::BuildTcpResponsePacket(
            ackPkt, sizeof(ackPkt),
            nullptr, 0, packetInfo,
            seqVal, ackVal, TCP_ACK
        );
        if (ackSize > 0) {
            TaskQueueManager::getInstance().submitResponseTask(ackPkt, ackSize, originalPeer, sockFd, PROTOCOL_TCP);
        }

        LOG_INFO("✅ [TCP发送成功] fd=%d, 发送了 %zd 字节", sockFd, sent);
        return sockFd;
    }

    return sockFd;

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
}// 🎯 输出统计信息（用于调试）
void PacketForwarder::LogStatistics() {
    LOG_INFO("📊 PacketForwarder统计信息");
    // TODO: 添加具体的统计信息输出
}