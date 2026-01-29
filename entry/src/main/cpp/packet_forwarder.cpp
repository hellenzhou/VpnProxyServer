// 🚀 最终简化版 - 专注解决NAT映射问题
#include "packet_forwarder.h"
#include "nat_table.h"
#include "nat_connection_manager.h"  // 🚀 新的NAT连接管理器
#include "protocol_handler.h"
#include "packet_builder.h"
#include "udp_retransmit.h"
#include "traffic_stats.h"
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
#include <unordered_set>
#include <condition_variable>
#include <atomic>

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

static const char* TcpStateToString(NATConnection::TcpState s)
{
    switch (s) {
        case NATConnection::TcpState::NONE:
            return "NONE";
        case NATConnection::TcpState::CONNECTING:
            return "CONNECTING";
        case NATConnection::TcpState::SYN_RECEIVED:
            return "SYN_RECEIVED";
        case NATConnection::TcpState::ESTABLISHED:
            return "ESTABLISHED";
        case NATConnection::TcpState::FIN_SENT:
            return "FIN_SENT";
        case NATConnection::TcpState::CLOSED:
            return "CLOSED";
        default:
            return "UNKNOWN";
    }
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
        LOG_INFO("🔍 [ConnectWithTimeout] connect立即成功: fd=%{public}d", sockFd);
        fcntl(sockFd, F_SETFL, flags);
        return true;
    }
    if (errno != EINPROGRESS) {
        LOG_ERROR("🔍 [ConnectWithTimeout] connect立即失败: fd=%{public}d, errno=%{public}d (%{public}s)", 
                 sockFd, errno, strerror(errno));
        fcntl(sockFd, F_SETFL, flags);
        return false;
    }
    
    LOG_INFO("🔍 [ConnectWithTimeout] connect返回EINPROGRESS: fd=%{public}d, 等待select...", sockFd);

    fd_set writefds;
    FD_ZERO(&writefds);
    FD_SET(sockFd, &writefds);
    struct timeval tv;
    tv.tv_sec = timeoutMs / 1000;
    tv.tv_usec = (timeoutMs % 1000) * 1000;

    auto selectStartTime = std::chrono::steady_clock::now();
    LOG_INFO("🔍 [ConnectWithTimeout] 开始select等待: fd=%{public}d, timeout=%{public}dms", sockFd, timeoutMs);
    int sel = select(sockFd + 1, nullptr, &writefds, nullptr, &tv);
    auto selectEndTime = std::chrono::steady_clock::now();
    auto selectCostMs = std::chrono::duration_cast<std::chrono::milliseconds>(selectEndTime - selectStartTime).count();
    LOG_INFO("🔍 [ConnectWithTimeout] select返回: sel=%{public}d, 耗时=%{public}lldms, fd=%{public}d", 
             sel, (long long)selectCostMs, sockFd);
    
    if (sel <= 0) {
        if (sel == 0) {
            errno = ETIMEDOUT;
            LOG_ERROR("🔍 [ConnectWithTimeout] select超时: timeout=%{public}dms, 实际等待=%{public}lldms, fd=%{public}d", 
                     timeoutMs, (long long)selectCostMs, sockFd);
        } else {
            LOG_ERROR("🔍 [ConnectWithTimeout] select失败: sel=%{public}d, errno=%{public}d (%{public}s), 耗时=%{public}lldms, fd=%{public}d", 
                     sel, errno, strerror(errno), (long long)selectCostMs, sockFd);
        }
        fcntl(sockFd, F_SETFL, flags);
        return false;
    }
    
    LOG_INFO("🔍 [ConnectWithTimeout] select成功: sel=%{public}d, fd=%{public}d (准备检查SO_ERROR)", sel, sockFd);

    int soError = 0;
    socklen_t len = sizeof(soError);
    if (getsockopt(sockFd, SOL_SOCKET, SO_ERROR, &soError, &len) < 0) {
        LOG_ERROR("🔍 [ConnectWithTimeout] getsockopt(SO_ERROR)调用失败: errno=%{public}d (%{public}s)", 
                 errno, strerror(errno));
        fcntl(sockFd, F_SETFL, flags);
        return false;
    }
    
    if (soError != 0) {
        errno = soError;
        // 🚨 详细诊断：记录SO_ERROR的具体值
        LOG_ERROR("🔍 [ConnectWithTimeout] getsockopt(SO_ERROR)返回错误: soError=%{public}d, errno=%{public}d (%{public}s)", 
                 soError, errno, strerror(errno));
        fcntl(sockFd, F_SETFL, flags);
        return false;
    }

    // ✅ 连接成功：恢复socket阻塞模式并记录日志
    LOG_INFO("✅ [ConnectWithTimeout] 连接成功: fd=%{public}d, 恢复阻塞模式", sockFd);
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

static void LogTcpTrace(const char* stage,
                        const PacketInfo& info,
                        const ParsedTcp& tcp,
                        int dataSize,
                        const std::string& natKey,
                        int sockFd)
{
    int payload = dataSize - tcp.ipHeaderLen - tcp.tcpHeaderLen;
    if (payload < 0) {
        payload = 0;
    }
    LOG_INFO("🧭 [TCP-TRACE] %s key=%{public}s fd=%{public}d %s:%d -> %s:%d flags=%{public}s seq=%{public}u ack=%{public}u payload=%{public}d",
             stage, natKey.c_str(), sockFd,
             info.sourceIP.c_str(), info.sourcePort,
             info.targetIP.c_str(), info.targetPort,
             TcpFlagsToString(tcp.flags).c_str(), tcp.seq, tcp.ack, payload);
}

static uint32_t RandomIsn()
{
    static std::mt19937 rng{std::random_device{}()};
    static std::uniform_int_distribution<uint32_t> dist;
    return dist(rng);
}

// Socket保护函数 - 防止转发socket被VPN路由劫持
static bool ProtectSocket(int sockFd, const std::string& description) {
    bool protectionSuccess = false;
    std::string successfulInterface;

    // 方法1: 尝试设置SO_BINDTODEVICE绑定到物理网络接口
    const char* physicalInterfaces[] = {"eth0", "wlan0", "rmnet0", "rmnet_data0", "rmnet_data1", nullptr};

    for (int i = 0; physicalInterfaces[i] != nullptr; i++) {
        std::string interfaceName = physicalInterfaces[i];
        if (setsockopt(sockFd, SOL_SOCKET, SO_BINDTODEVICE,
                      interfaceName.c_str(), interfaceName.length() + 1) == 0) {
            protectionSuccess = true;
            successfulInterface = interfaceName;
            LOG_INFO("✅ [Socket保护] SO_BINDTODEVICE成功: fd=%d, 接口=%s, desc=%s", 
                     sockFd, interfaceName.c_str(), description.c_str());
            break;
        } else {
            int savedErrno = errno;
            LOG_INFO("🔍 [Socket保护] SO_BINDTODEVICE尝试失败: fd=%d, 接口=%s, errno=%d (%s)", 
                     sockFd, interfaceName.c_str(), savedErrno, strerror(savedErrno));
        }
    }

    // ⚠️ 注意：
    // SO_DONTROUTE/SO_MARK 可能导致无法到达外网（绕过路由表或被系统忽略）。
    // 在已通过 blockedApplications 绕过 VPN 的情况下，这些选项反而容易引发连接失败。

    // 如果所有方法都失败，至少记录警告并返回true（让系统继续运行）
    if (!protectionSuccess) {
        LOG_ERROR("⚠️ [Socket保护] 所有接口绑定失败: fd=%d, desc=%s (将依赖blockedApplications绕过VPN)", 
                  sockFd, description.c_str());
        LOG_ERROR("⚠️ [Socket保护] 如果连接失败，可能是socket被VPN路由表捕获");
        protectionSuccess = true;  // 不中断业务逻辑，依赖blockedApplications
    } else {
        LOG_INFO("✅ [Socket保护] Socket已绑定到物理接口: fd=%d, 接口=%s", sockFd, successfulInterface.c_str());
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

        // TCP 是面向连接的，不能复用旧 socket
        if (protocol == PROTOCOL_TCP) {
            int newSock = createNewSocket(protocol, addressFamily);
            if (newSock >= 0) {
                return newSock;
            }
            return -1;
        }

        TargetKey key{clientIP, clientPort, serverIP, serverPort, protocol, addressFamily};

        // 尝试从池中获取现有socket (UDP可复用)
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
        // TCP 不复用，直接关闭
        if (protocol == PROTOCOL_TCP) {
            close(sockFd);
            return;
        }

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
        // ✅ Socket保持阻塞模式（默认就是阻塞）。
        // 之前设置成 O_NONBLOCK 会导致 recvfrom/recv 频繁 EAGAIN + 100ms 轮询，
        // 在高并发 DNS/UDP 场景下会造成线程/日志/CPU 风暴，进而"卡住"Forward worker，
        // 表现为 TCP 任务持续入队但几乎不被处理。
        // 我们用 SO_RCVTIMEO 和 SO_SNDTIMEO 控制阻塞时长即可。
    
        // 🚨 关键修复：设置发送和接收超时，防止send/sendto/recv/recvfrom无限阻塞worker线程
        // TCP需要更长的超时时间（10秒），因为TCP是可靠协议，需要等待ACK
        // UDP可以使用较短的超时时间（5秒），因为UDP是无状态协议
        struct timeval timeout;
        if (protocol == PROTOCOL_TCP) {
            timeout.tv_sec = 10;  // TCP: 10秒超时（考虑网络延迟和ACK等待）
            timeout.tv_usec = 0;
        } else {
            timeout.tv_sec = 5;   // UDP: 5秒超时
            timeout.tv_usec = 0;
        }
        
        if (setsockopt(sockFd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
            LOG_ERROR("设置接收超时失败: %s", strerror(errno));
        }
        // 🔧 关键修复：设置发送超时，防止send/sendto阻塞worker线程
        // 这是防止worker线程卡住的关键：如果发送缓冲区满，send()会阻塞直到超时
        if (setsockopt(sockFd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) < 0) {
            LOG_ERROR("设置发送超时失败: %s", strerror(errno));
        }

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
    // 🚨 强制记录：TCP任务进入GetSocket（用于诊断TCP任务是否到达socket创建阶段）
    if (packetInfo.protocol == PROTOCOL_TCP) {
        LOG_INFO("🚀 [TCP转发线程] ========== TCP任务进入GetSocket ==========");
        LOG_INFO("🚀 [TCP转发线程] 准备创建转发socket: 目标=%s:%d", 
                 packetInfo.targetIP.c_str(), packetInfo.targetPort);
    }
    
    auto protectStartTime = std::chrono::steady_clock::now();
    LOG_INFO("🔍 [Socket保护诊断] ========== 开始socket保护流程 ==========");
    LOG_INFO("🔍 [Socket保护诊断] 创建转发socket: fd=%d, 目标=%s:%d, 协议=%s", 
             sockFd, packetInfo.targetIP.c_str(), packetInfo.targetPort,
             packetInfo.protocol == PROTOCOL_TCP ? "TCP" : "UDP");
    LOG_INFO("🔍 [Socket保护诊断] socket作用: 代理服务器转发socket，用于连接真实服务器");
    LOG_INFO("🔍 [Socket保护诊断] 保护原因: 防止socket流量被VPN路由表捕获，形成环路");
    
    // 🚨 强制记录：TCP socket保护开始
    if (packetInfo.protocol == PROTOCOL_TCP) {
        LOG_INFO("🚀 [TCP转发线程] TCP socket保护开始: fd=%d, 目标=%s:%d", 
                 sockFd, packetInfo.targetIP.c_str(), packetInfo.targetPort);
    }
    
    // 🚨 关键：先尝试本地保护（可能失败，但不影响）
    bool localProtect = ProtectSocket(sockFd, socketDesc);
    if (!localProtect) {
        LOG_ERROR("🚨 [Socket保护诊断] 本地socket保护失败: fd=%d (但继续发送保护请求给VPN客户端)", sockFd);
    } else {
        LOG_INFO("✅ [Socket保护诊断] 本地socket保护成功: fd=%d", sockFd);
    }
    
    auto protectRequestTime = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(protectRequestTime - protectStartTime).count();
    LOG_INFO("✅ [Socket保护诊断] 本地socket保护完成: fd=%d (耗时%lldms)", sockFd, elapsed);
    LOG_INFO("🔍 [Socket保护诊断] ========================================");
    
    // 🚨 强制记录：TCP socket保护完成
    if (packetInfo.protocol == PROTOCOL_TCP) {
        LOG_INFO("🚀 [TCP转发线程] TCP socket保护完成: fd=%d, 耗时%lldms", sockFd, elapsed);
        LOG_INFO("🚀 [TCP转发线程] ========================================");
    }

    // 设置特殊超时 - DNS查询使用更长超时时间
    if (packetInfo.protocol == PROTOCOL_UDP && packetInfo.targetPort == 53) {
        struct timeval timeout = {10, 0};  // DNS查询：10秒超时
        if (setsockopt(sockFd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
            LOG_ERROR("设置DNS接收超时失败: %s", strerror(errno));
            close(sockFd);
            return -1;
        }
        // 🔧 修复：DNS查询也需要设置发送超时，防止sendto阻塞
        if (setsockopt(sockFd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) < 0) {
            LOG_ERROR("设置DNS发送超时失败: %s", strerror(errno));
            close(sockFd);
            return -1;
        }
    }
    
    return sockFd;
}


// UDP响应线程
// ==========================
// ✅ UDP Socket Pump（关键重写）
// 之前：每个UDP NAT映射启动一个 StartUDPThread()，DNS高频时会产生成百上千线程，
//      导致调度/内存/日志风暴，Forward worker 被饿死 -> TCP任务只入队不处理。
// 现在：用一个全局线程 poll() 监听所有UDP sockFd，统一收包并投递 response task。
// ==========================
class UdpSocketPump {
public:
    static UdpSocketPump& getInstance()
    {
        static UdpSocketPump inst;
        return inst;
    }

    void registerSocket(int sockFd)
    {
        if (sockFd < 0) return;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (fdsSet_.find(sockFd) != fdsSet_.end()) {
                return;
            }
            pollfd p{};
            p.fd = sockFd;
            p.events = POLLIN;
            fds_.push_back(p);
            fdsSet_.insert(sockFd);
        }
        ensureStarted();
        cv_.notify_one();
    }

private:
    UdpSocketPump() = default;
    ~UdpSocketPump()
    {
        running_.store(false);
        cv_.notify_all();
        // worker_ 使用 detach：不 join，交给进程结束清理
    }

    void ensureStarted()
    {
        bool expected = false;
        if (running_.compare_exchange_strong(expected, true)) {
            worker_ = std::thread([this]() { this->loop(); });
            worker_.detach();
        }
    }

    void loop()
    {
        uint8_t buffer[4096];
        int iter = 0;
        while (running_.load()) {
            std::vector<pollfd> localFds;
            {
                std::unique_lock<std::mutex> lock(mutex_);
                if (fds_.empty()) {
                    cv_.wait_for(lock, std::chrono::milliseconds(500), [this]() {
                        return !running_.load() || !fds_.empty();
                    });
                }
                if (!running_.load()) {
                    break;
                }
                localFds = fds_;
            }

            if (localFds.empty()) {
                continue;
            }

            int rc = poll(localFds.data(), static_cast<nfds_t>(localFds.size()), 200);
            if (rc <= 0) {
                continue;
            }

            iter++;
            for (auto& p : localFds) {
                if (!(p.revents & POLLIN)) {
                    continue;
                }

                // 🔍 [排查点4] 服务端从真实服务器接收响应 (UDP)
                ssize_t received = recvfrom(p.fd, buffer, sizeof(buffer), 0, nullptr, nullptr);
                if (received <= 0) {
                    if (received < 0 && (errno != EAGAIN && errno != EWOULDBLOCK)) {
                        LOG_ERROR("❌ [排查点4] 服务端<-真实服务器(UDP)失败: fd=%{public}d, errno=%{public}d (%{public}s)",
                                 p.fd, errno, strerror(errno));
                    }
                    continue;
                }

                NATConnection conn;
                if (!NATTable::FindMappingBySocket(p.fd, conn)) {
                    // 映射可能刚被清理/覆盖；不在这里close，交给NAT清理逻辑
                    if (iter <= 10 || (iter % 200 == 0)) {
                        LOG_ERROR("❌ [排查点4] 服务端<-真实服务器(UDP): 收到%{public}zd字节但NAT映射不存在 (fd=%{public}d)", received, p.fd);
                    }
                    continue;
                }
                
                // 🔍 [排查点4] 服务端从真实服务器接收响应成功
                static int udpRecvSuccessCount = 0;
                udpRecvSuccessCount++;
                if (iter <= 10 || udpRecvSuccessCount % 50 == 0) {
                    LOG_INFO("✅ [排查点4] 服务端<-真实服务器(UDP): %{public}s:%{public}d -> %{public}s:%{public}d (收到%{public}zd字节, fd=%{public}d)",
                            conn.serverIP.c_str(), conn.serverPort,
                            conn.clientVirtualIP.c_str(), conn.clientVirtualPort,
                            received, p.fd);
                }

                uint8_t responsePacket[4096];
                int responseSize = PacketBuilder::BuildResponsePacket(
                    responsePacket, sizeof(responsePacket),
                    buffer, (int)received, conn.originalRequest
                );

                if (responseSize > 0) {
                    if (TaskQueueManager::getInstance().submitResponseTask(
                        responsePacket, responseSize, conn.clientPhysicalAddr, p.fd, PROTOCOL_UDP
                    )) {
                        UdpRetransmitManager::getInstance().confirmReceivedByContent(p.fd, buffer, (int)received);
                    }
                }
            }
        }
    }

private:
    std::mutex mutex_;
    std::condition_variable cv_;
    std::vector<pollfd> fds_;
    std::unordered_set<int> fdsSet_;
    std::thread worker_;
    std::atomic<bool> running_{false};
};

static void StartUDPThread(int sockFd, const sockaddr_in& originalPeer) {
    std::thread([sockFd, originalPeer]() {
        uint8_t buffer[4096];
        int noResponseCount = 0;
        const int MAX_NO_RESPONSE = 10;
        int loopCount = 0;

        while (true) {
            loopCount++;
            // 限流日志：只记录前3次以及之后每50次，避免日志洪泛拖垮调度
            if (loopCount <= 3 || (loopCount % 50 == 0)) {
                LOG_INFO("🔍 [流程跟踪] 等待UDP响应 (socket fd=%d, loop=%d)", sockFd, loopCount);
            }
            
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
                    // SO_RCVTIMEO 会让 recvfrom 阻塞到超时再返回 EAGAIN，
                    // 这里不需要再 100ms 轮询睡眠；直接继续下一轮即可。
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
            SocketConnectionPool::getInstance().returnSocket(sockFd, "", 0, "", 0, PROTOCOL_UDP, AF_INET);
        }
    }).detach();
}

// TCP响应线程
static void StartTCPThread(int sockFd, const sockaddr_in& originalPeer) {
    std::thread([sockFd, originalPeer]() {
        // ✅ 关键：TCP 是字节流，后端 recv() 返回的大小不等于“一个IP包/一个TCP段”。
        // 如果把 3KB+ payload 直接封装成一个 TCP 段回写 TUN，极易超过 MTU（IPv6 常见 1280 / IPv4 1500），
        // 系统 TCP 栈会直接丢弃，表现为“日志显示已回包/已写入TUN，但网页打不开”。
        // 因此必须做分段（按保守 MSS 切片）。
        constexpr int kMaxTcpPayloadPerSegment = 1200; // 保守值，兼容 IPv6/UDP隧道/不同MTU

        // 确保TCP socket是阻塞模式，以便完整接收所有数据
        if (!SetBlockingMode(sockFd, true)) {
            LOG_ERROR("设置TCP socket为阻塞模式失败: fd=%d", sockFd);
            SocketConnectionPool::getInstance().returnSocket(sockFd, "", 0, "", 0, PROTOCOL_TCP, AF_INET);
            return;
        }

        // 🔍 追踪：线程启动时记录key与目标信息
        std::string natKey;
        NATTable::GetKeyBySocket(sockFd, natKey);
        NATConnection startConn;
        if (NATTable::FindMappingBySocket(sockFd, startConn)) {
            LOG_INFO("🧭 [TCP-TRACE] RECV_THREAD_START key=%{public}s fd=%{public}d target=%{public}s:%{public}d client=%{public}s:%{public}d state=%{public}s",
                     natKey.c_str(), sockFd,
                     startConn.serverIP.c_str(), startConn.serverPort,
                     startConn.clientVirtualIP.c_str(), startConn.clientVirtualPort,
                     TcpStateToString(startConn.tcpState));
        } else {
            LOG_INFO("🧭 [TCP-TRACE] RECV_THREAD_START key=%{public}s fd=%{public}d (no mapping yet)", natKey.c_str(), sockFd);
        }
        
        // 设置接收超时（30秒），避免无限期阻塞
        struct timeval timeout;
        timeout.tv_sec = 30;
        timeout.tv_usec = 0;
        setsockopt(sockFd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        
        // 🚨 关键修复：TCP接收线程也需要设置发送超时
        // 虽然这个线程主要用于接收，但在某些错误处理路径中可能会调用send()
        // 设置发送超时防止意外阻塞
        timeout.tv_sec = 10;  // TCP发送超时：10秒
        timeout.tv_usec = 0;
        if (setsockopt(sockFd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) < 0) {
            LOG_ERROR("设置TCP接收线程发送超时失败: fd=%d, %s", sockFd, strerror(errno));
        }
        
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
            
            // 🔍 [排查点4] 服务端从真实服务器接收响应 (TCP)
            ssize_t received = recv(sockFd, buffer, sizeof(buffer), 0);
            
            if (received > 0) {
                // 🔍 [排查点4] 服务端从真实服务器接收响应成功
                NATConnection conn;
                if (NATTable::FindMappingBySocket(sockFd, conn)) {
                    static int tcpRecvSuccessCount = 0;
                    tcpRecvSuccessCount++;
                    if (tcpRecvCount <= 10 || tcpRecvSuccessCount % 50 == 0) {
                        LOG_INFO("✅ [排查点4] 服务端<-真实服务器(TCP): %{public}s:%{public}d -> %{public}s:%{public}d (收到%{public}zd字节, fd=%{public}d)",
                                conn.serverIP.c_str(), conn.serverPort,
                                conn.clientVirtualIP.c_str(), conn.clientVirtualPort,
                                received, sockFd);
                    }
                } else {
                    LOG_ERROR("❌ [排查点4] 服务端<-真实服务器(TCP): 收到%{public}zd字节但NAT映射不存在 (fd=%{public}d)", received, sockFd);
                }
                LOG_INFO("🧭 [TCP-TRACE] RECV_BACKEND key=%{public}s fd=%{public}d bytes=%{public}d",
                         natKey.c_str(), sockFd, static_cast<int>(received));
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
                        SocketConnectionPool::getInstance().returnSocket(sockFd, "", 0, "", 0, PROTOCOL_TCP, AF_INET);
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
                        bool submitted = TaskQueueManager::getInstance().submitResponseTask(
                            finPkt, finSize, originalPeer, sockFd, PROTOCOL_TCP
                        );
                        LOG_INFO("🧭 [TCP-TRACE] ENQ_FIN key=%{public}s fd=%{public}d size=%{public}d ok=%{public}d",
                                 natKey.c_str(), sockFd, finSize, submitted ? 1 : 0);
                    }
                    
                    // 🚀 使用统一的NAT清理接口（自动延迟5秒，等待客户端ACK）
                    // Socket将在NAT映射删除后自动归还到连接池
                    LOG_INFO("⏰ [TCP-TRACE] DELAY_DELETE key=%{public}s fd=%{public}d",
                             natKey.c_str(), sockFd);
                    
                    NATConnectionManager::getInstance().scheduleRemoveBySocket(sockFd, CleanupReason::TCP_SERVER_FIN);
                    
                    return;  // 不要继续循环，让延迟线程处理清理
                }

                break;
            }
        
            // 重置无响应计数
            noResponseCount = 0;
            
            // 检查NAT映射并构建完整IP响应包（包含正确的TCP seq/ack）
            NATConnection conn;
            if (NATTable::FindMappingBySocket(sockFd, conn)) {
                // ✅ 分段回写：按保守 MSS 切片，避免超过 MTU 被系统丢弃
                int remaining = static_cast<int>(received);
                int offset = 0;
                while (remaining > 0) {
                    int chunk = remaining > kMaxTcpPayloadPerSegment ? kMaxTcpPayloadPerSegment : remaining;

                    // Snapshot + advance nextServerSeq under lock（按 chunk 推进）
                    uint32_t seqToSend = 0;
                    uint32_t ackToSend = 0;
                    PacketInfo origReq = conn.originalRequest;
                    bool hasConn = NATTable::WithConnectionBySocket(sockFd, [&](NATConnection& c) {
                        seqToSend = c.nextServerSeq;
                        ackToSend = c.nextClientSeq;
                        origReq = c.originalRequest;
                        c.nextServerSeq += static_cast<uint32_t>(chunk);
                    });
                    if (!hasConn) {
                        LOG_ERROR("NAT映射不存在，无法处理数据响应(分段): fd=%d", sockFd);
                        SocketConnectionPool::getInstance().returnSocket(sockFd, "", 0, "", 0, PROTOCOL_TCP, AF_INET);
                        return;
                    }

                    const size_t responseCapacity = static_cast<size_t>(chunk) + 96; // IPv6(40)+TCP(20)+余量
                    std::vector<uint8_t> responsePacket(responseCapacity);
                    uint8_t flags = TCP_ACK;
                    if (remaining == chunk) {
                        // 最后一段可带 PSH，语义更接近真实栈
                        flags |= TCP_PSH;
                    }
                    int responseSize = PacketBuilder::BuildTcpResponsePacket(
                        responsePacket.data(), static_cast<int>(responsePacket.size()),
                        buffer + offset, chunk,
                        origReq,
                        seqToSend, ackToSend,
                        flags
                    );

                    if (responseSize > 0) {
                        bool submitted = TaskQueueManager::getInstance().submitResponseTask(
                            responsePacket.data(), responseSize,
                            originalPeer,
                            sockFd,
                            PROTOCOL_TCP
                        );
                        if (!submitted) {
                            LOG_ERROR("TCP响应任务提交失败(分段): fd=%d", sockFd);
                        } else {
                            LOG_INFO("🧭 [TCP-TRACE] ENQ_DATA key=%{public}s fd=%{public}d size=%{public}d chunk=%{public}d off=%{public}d/%{public}d",
                                     natKey.c_str(), sockFd, responseSize, chunk, offset, static_cast<int>(received));
                        }
                    } else {
                        LOG_ERROR("构建TCP响应包失败(分段): fd=%d chunk=%d", sockFd, chunk);
                    }

                    offset += chunk;
                    remaining -= chunk;
                }
            } else {
                LOG_ERROR("NAT映射不存在: fd=%d", sockFd);
                break;
            }
        }
        
        // 🚀 使用统一的NAT清理接口（自动延迟2秒）
        // Socket将在NAT映射删除后自动归还到连接池
        LOG_INFO("🧹 [TCP-TRACE] ERROR_CLEAN_SCHEDULED key=%{public}s fd=%{public}d",
                 natKey.c_str(), sockFd);
        NATConnectionManager::getInstance().scheduleRemoveBySocket(sockFd, CleanupReason::TCP_TIMEOUT);
        
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
    // 🚨 强制记录：TCP任务进入ForwardPacket（用于诊断TCP任务是否被处理）
    if (packetInfo.protocol == PROTOCOL_TCP) {
        LOG_INFO("🚀 [TCP转发线程] ========== TCP任务进入ForwardPacket ==========");
        LOG_INFO("🚀 [TCP转发线程] 源: %{public}s:%{public}d -> 目标: %{public}s:%{public}d", 
                 packetInfo.sourceIP.c_str(), packetInfo.sourcePort,
                 packetInfo.targetIP.c_str(), packetInfo.targetPort);
        LOG_INFO("🚀 [TCP转发线程] 数据大小: %{public}d字节, 地址族: %{public}s", 
                 dataSize, packetInfo.addressFamily == AF_INET6 ? "IPv6" : "IPv4");
    }
    
    // 1. 参数验证
    if (!data || dataSize <= 0 || packetInfo.targetIP.empty()) {
        if (packetInfo.protocol == PROTOCOL_TCP) {
            LOG_ERROR("❌ [TCP转发线程] 参数验证失败: data=%p, dataSize=%d, targetIP=%s", 
                     data, dataSize, packetInfo.targetIP.c_str());
        }
        return -1;
    }
    
    // ICMP/ICMPv6 没有端口，允许 targetPort 为 0
    if (packetInfo.protocol != PROTOCOL_ICMP && packetInfo.protocol != PROTOCOL_ICMPV6) {
        if (packetInfo.targetPort <= 0) {
            if (packetInfo.protocol == PROTOCOL_TCP) {
                LOG_ERROR("❌ [TCP转发线程] 目标端口无效: %d", packetInfo.targetPort);
            }
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
        if (packetInfo.protocol == PROTOCOL_TCP) {
            LOG_ERROR("❌ [TCP转发线程] ExtractPayload失败: %{public}s:%{public}d -> %{public}s:%{public}d (数据大小=%{public}d)",
                     packetInfo.sourceIP.c_str(), packetInfo.sourcePort,
                     packetInfo.targetIP.c_str(), packetInfo.targetPort, dataSize);
        }
        return -1;
    }
    
    // 🔍 [流程跟踪] 记录payload提取结果
    if (packetInfo.protocol == PROTOCOL_TCP) {
        LOG_INFO("🔍 [TCP转发线程] Payload提取成功: payload大小=%{public}d字节 (总数据=%{public}d字节)",
                 payloadSize, dataSize);
    }
    
    // TCP控制包（SYN/ACK/FIN/RST）payload可能为0，需要继续处理
    if (payloadSize <= 0 && packetInfo.protocol != PROTOCOL_TCP) {
        return 0;
    }
    
    // 4. DNS重定向（只重定向223.5.5.5到8.8.8.8）
    std::string actualTargetIP = packetInfo.targetIP;
    if (packetInfo.targetPort == 53 && packetInfo.targetIP == "223.5.5.5") {
        actualTargetIP = "8.8.8.8";
        LOG_INFO("🔍 [流程跟踪] DNS重定向: %{public}s -> %{public}s (端口=%{public}d)",
                 packetInfo.targetIP.c_str(), actualTargetIP.c_str(), packetInfo.targetPort);
    }
    
    // 5. 查找或创建NAT映射
    std::string natKey = NATTable::GenerateKey(packetInfo, originalPeer);
    NATConnection existingConn;
    int sockFd = -1;
    bool isNewMapping = false;

    // 🐛 修复：移除QUIC丢弃策略，允许HTTP/3流量通过
    // 原因：主动丢弃QUIC导致浏览器无法访问支持HTTP/3的网站
    // 现代浏览器（Chrome/Edge等）默认使用HTTP/3 (QUIC)协议
    // 如果直接丢弃QUIC包而不发送拒绝响应，浏览器会等待超时
    // 而不是快速fallback到TCP，导致用户体验很差
    
    // if (packetInfo.protocol == PROTOCOL_UDP && packetInfo.targetPort == 443) {
    //     UdpProtocolType proto = UdpRetransmitManager::DetectProtocol(payload, payloadSize);
    //     if (proto == UdpProtocolType::QUIC) {
    //         static std::atomic<uint32_t> dropQuicCount{0};
    //         uint32_t n = ++dropQuicCount;
    //         TrafficStats::quicDropped.fetch_add(1, std::memory_order_relaxed);
    //         uint32_t ident = UdpRetransmitManager::ExtractProtocolIdentifier(proto, payload, payloadSize);
    //         if (n <= 3 || (n % 200 == 0)) {
    //             LOG_INFO("🧯 [QUIC] Drop UDP/443(QUIC) to force TCP fallback: src=%{public}s:%{public}d -> dst=%{public}s:%{public}d payload=%{public}d ident=0x%{public}08x (dropped=%{public}u)",
    //                      packetInfo.sourceIP.c_str(), packetInfo.sourcePort,
    //                      packetInfo.targetIP.c_str(), packetInfo.targetPort,
    //                      payloadSize, ident, n);
    //         }
    //         return 0;
    //     }
    //     // 非 QUIC：放行（但仍可按需做采样日志）
    // }

    if (packetInfo.protocol == PROTOCOL_TCP) {
        // TCP: 需要检查是否为SYN包
        ParsedTcp tcp = ParseTcpFromIp(data, dataSize);
        if (!tcp.ok) {
            LOG_ERROR("🚨 TCP包解析失败: %s:%d -> %s:%d (数据大小=%d)", 
                     packetInfo.sourceIP.c_str(), packetInfo.sourcePort,
                     packetInfo.targetIP.c_str(), packetInfo.targetPort, dataSize);
            return -1;
        }
        LogTcpTrace("IN", packetInfo, tcp, dataSize, natKey, sockFd);

        bool isSyn = HasTcpFlag(tcp.flags, TCP_SYN);
        bool isAck = HasTcpFlag(tcp.flags, TCP_ACK);
        bool isRst = HasTcpFlag(tcp.flags, TCP_RST);
        bool isFin = HasTcpFlag(tcp.flags, TCP_FIN);
        if (isSyn && !isAck && !isRst) {
            LOG_INFO("🔍 [TCP连接诊断] 收到SYN: %{public}s:%{public}d -> %{public}s:%{public}d (flags=0x%{public}02x)",
                     packetInfo.sourceIP.c_str(), packetInfo.sourcePort,
                     packetInfo.targetIP.c_str(), packetInfo.targetPort, tcp.flags);
        }

        if (NATTable::FindMapping(natKey, existingConn)) {
            sockFd = existingConn.forwardSocket;
            LOG_INFO("🧭 [TCP-TRACE] MAP_HIT key=%{public}s fd=%{public}d state=%{public}s clientIsn=%{public}u serverIsn=%{public}u",
                     natKey.c_str(), sockFd, TcpStateToString(existingConn.tcpState),
                     existingConn.clientIsn, existingConn.serverIsn);

            // 处理SYN重传：如果SYN-ACK丢失（UDP隧道丢包），需要重发SYN-ACK
            if (isSyn && !isAck && !isRst) {
                if (existingConn.tcpState == NATConnection::TcpState::CONNECTING) {
                    LOG_INFO("🔁 [TCP连接诊断] 收到SYN重传，但后端仍在连接中(暂不回SYN-ACK): %{public}s:%{public}d -> %{public}s:%{public}d (fd=%{public}d)",
                             packetInfo.sourceIP.c_str(), packetInfo.sourcePort,
                             packetInfo.targetIP.c_str(), packetInfo.targetPort, sockFd);
                    LogTcpTrace("SYN_RETRANS_WAIT", packetInfo, tcp, dataSize, natKey, sockFd);
                    return sockFd;
                }
                if (existingConn.tcpState == NATConnection::TcpState::SYN_RECEIVED) {
                    LOG_INFO("🔁 [TCP连接诊断] 收到SYN重传，重发SYN-ACK: %{public}s:%{public}d -> %{public}s:%{public}d (fd=%{public}d)",
                             packetInfo.sourceIP.c_str(), packetInfo.sourcePort,
                             packetInfo.targetIP.c_str(), packetInfo.targetPort, sockFd);
                    LogTcpTrace("SYN_RETRANS_RESEND", packetInfo, tcp, dataSize, natKey, sockFd);

                    // 确保客户端ISN一致
                    NATTable::WithConnection(natKey, [&](NATConnection& c) {
                        if (c.clientIsn != 0 && c.clientIsn != tcp.seq) {
                            LOG_ERROR("⚠️ [TCP连接诊断] SYN重传序号变化: old=%{public}u new=%{public}u (可能是连接复用/重建)",
                                      c.clientIsn, tcp.seq);
                        }
                        c.clientIsn = tcp.seq;
                        c.nextClientSeq = tcp.seq + 1;
                    });

                    uint8_t synAckPkt[128];
                    uint32_t serverIsn = existingConn.serverIsn;
                    int synAckSize = PacketBuilder::BuildTcpResponsePacket(
                        synAckPkt, sizeof(synAckPkt), nullptr, 0,
                        existingConn.originalRequest,
                        serverIsn, tcp.seq + 1, TCP_SYN | TCP_ACK
                    );
                    if (synAckSize > 0) {
                        bool submitted = TaskQueueManager::getInstance().submitResponseTask(
                            synAckPkt, synAckSize, originalPeer, sockFd, PROTOCOL_TCP
                        );
                        LOG_INFO("✅ [TCP连接诊断] SYN-ACK已重发 (seq=%{public}u ack=%{public}u)", serverIsn, tcp.seq + 1);
                        LOG_INFO("🧭 [TCP-TRACE] ENQ_SYNACK_RESEND key=%{public}s fd=%{public}d size=%{public}d ok=%{public}d",
                                 natKey.c_str(), sockFd, synAckSize, submitted ? 1 : 0);
                    } else {
                        LOG_ERROR("❌ [TCP连接诊断] SYN-ACK重发失败：构建失败");
                    }
                    return sockFd;
                }
            }
        } else {
            // 只有纯SYN包（非SYN-ACK）才创建映射
            if (!isSyn || (isSyn && isAck)) {
                // 非SYN包或SYN-ACK包：发送RST告知客户端连接不存在
                if (!isRst) {
                    LOG_ERROR("🚨 [TCP连接诊断] ========== 收到非SYN包但连接不存在 ==========");
                    LOG_ERROR("   包类型: flags=0x%{public}02x (SYN=%{public}d, ACK=%{public}d, RST=%{public}d, FIN=%{public}d)", 
                             tcp.flags, isSyn, isAck, isRst, isFin);
                    LOG_ERROR("   源: %{public}s:%{public}d", packetInfo.sourceIP.c_str(), packetInfo.sourcePort);
                    LOG_ERROR("   目标: %{public}s:%{public}d", packetInfo.targetIP.c_str(), packetInfo.targetPort);
                    LOG_ERROR("   NAT Key: %{public}s", natKey.c_str());
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
            LOG_INFO("🚀 [TCP转发线程] ========== 开始创建TCP新映射 ==========");
            LOG_INFO("🔍 [TCP连接诊断] 创建新的TCP连接映射: %{public}s:%{public}d -> %{public}s:%{public}d", 
                     packetInfo.sourceIP.c_str(), packetInfo.sourcePort,
                     packetInfo.targetIP.c_str(), packetInfo.targetPort);
            LogTcpTrace("MAP_CREATE_START", packetInfo, tcp, dataSize, natKey, sockFd);
            LOG_INFO("🚀 [TCP转发线程] 调用GetSocket创建转发socket...");
            sockFd = GetSocket(packetInfo, originalPeer, tunnelFd);
            if (sockFd < 0) {
                LOG_ERROR("❌ [TCP连接诊断] 创建转发socket失败，无法建立连接");
                LOG_ERROR("🚀 [TCP转发线程] ========================================");
                return -1;
            }
            LOG_INFO("🚀 [TCP转发线程] GetSocket返回成功: fd=%d, 开始创建NAT映射...", sockFd);
            // 🚨 并发修复：可能已有其它worker抢先创建了同key映射（SYN重传/并发处理）
            NATConnection racedConn;
            if (NATTable::FindMapping(natKey, racedConn)) {
                LOG_INFO("⚠️ [TCP连接诊断] NAT映射竞争：已存在fd=%{public}d，归还新fd=%{public}d 并复用已有映射 (key=%{public}s)",
                         racedConn.forwardSocket, sockFd, natKey.c_str());
                char clientIP[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &originalPeer.sin_addr, clientIP, sizeof(clientIP));
                SocketConnectionPool::getInstance().returnSocket(
                    sockFd, clientIP, ntohs(originalPeer.sin_port),
                    packetInfo.targetIP, static_cast<uint16_t>(packetInfo.targetPort),
                    PROTOCOL_TCP, packetInfo.addressFamily
                );
                return racedConn.forwardSocket;
            }

            if (!NATTable::CreateMapping(natKey, originalPeer, packetInfo, sockFd)) {
                // CreateMapping 拒绝覆盖：说明竞争窗口内有人创建了
                if (NATTable::FindMapping(natKey, racedConn)) {
                    LOG_INFO("⚠️ [TCP连接诊断] CreateMapping被拒绝(竞争)：复用已有fd=%{public}d，归还新fd=%{public}d",
                             racedConn.forwardSocket, sockFd);
                    char clientIP[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &originalPeer.sin_addr, clientIP, sizeof(clientIP));
                    SocketConnectionPool::getInstance().returnSocket(
                        sockFd, clientIP, ntohs(originalPeer.sin_port),
                        packetInfo.targetIP, static_cast<uint16_t>(packetInfo.targetPort),
                        PROTOCOL_TCP, packetInfo.addressFamily
                    );
                    return racedConn.forwardSocket;
                }
                LOG_ERROR("🚨 [TCP连接诊断] CreateMapping失败且未找到现存映射: key=%{public}s (fd=%{public}d)", natKey.c_str(), sockFd);
                SocketConnectionPool::getInstance().returnSocket(sockFd, "", 0, "", 0, PROTOCOL_TCP, AF_INET);
                return -1;
            }

            isNewMapping = true;
            LOG_INFO("✅ [TCP连接诊断] NAT映射已创建: socket fd=%{public}d, 映射key=%{public}s", sockFd, natKey.c_str());
            LOG_INFO("🧭 [TCP-TRACE] MAP_CREATE_OK key=%{public}s fd=%{public}d", natKey.c_str(), sockFd);
            
        }
    } else {
        // UDP: 直接查找或创建映射
        // 🔍 [流程跟踪] UDP任务开始处理
        LOG_INFO("🔍 [UDP转发线程] ========== UDP任务开始处理 ==========");
        LOG_INFO("🔍 [UDP转发线程] 源: %{public}s:%{public}d -> 目标: %{public}s:%{public}d, payload=%{public}d字节",
                 packetInfo.sourceIP.c_str(), packetInfo.sourcePort,
                 packetInfo.targetIP.c_str(), packetInfo.targetPort, payloadSize);
        LOG_INFO("🔍 [UDP转发线程] NAT Key: %{public}s", natKey.c_str());
        
        // 🔧 死锁修复：统一锁顺序 - 先获取socket（poolMutex_），再操作NAT表（NATTable::mutex_）
        // 避免与TCP worker形成死锁（TCP先获取poolMutex_，再获取NATTable::mutex_）
        LOG_INFO("🔍 [UDP转发线程] 步骤1: 获取转发socket...");
        sockFd = GetSocket(packetInfo, originalPeer, tunnelFd);
        if (sockFd < 0) {
            LOG_ERROR("❌ [UDP转发线程] GetSocket失败");
            return -1;
        }
        LOG_INFO("🔍 [UDP转发线程] GetSocket成功: fd=%{public}d", sockFd);
        
        // 🔧 修复：先释放socket池锁，再检查NAT映射（避免死锁）
        LOG_INFO("🔍 [UDP转发线程] 步骤2: 查找NAT映射...");
        NATConnection existingConn;
        if (NATTable::FindMapping(natKey, existingConn)) {
            LOG_INFO("🔍 [UDP转发线程] NAT映射已存在: fd=%{public}d, 复用已有socket", existingConn.forwardSocket);
            // 映射已存在，归还新socket，复用已有socket
            char clientIP[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &originalPeer.sin_addr, clientIP, sizeof(clientIP));
            SocketConnectionPool::getInstance().returnSocket(
                sockFd, clientIP, ntohs(originalPeer.sin_port),
                packetInfo.targetIP, static_cast<uint16_t>(packetInfo.targetPort),
                PROTOCOL_UDP, packetInfo.addressFamily
            );
            sockFd = existingConn.forwardSocket;
            isNewMapping = false;
        } else {
            // 🚨 并发修复：多个worker同时处理同一UDP flow 时，可能重复建socket
            LOG_INFO("🔍 [UDP转发线程] NAT映射不存在，创建新映射: fd=%{public}d", sockFd);
            NATConnection racedConn;
            if (!NATTable::CreateMapping(natKey, originalPeer, packetInfo, sockFd)) {
                if (NATTable::FindMapping(natKey, racedConn)) {
                    LOG_INFO("⚠️ [UDP] CreateMapping被拒绝(竞争)：复用已有fd=%{public}d，归还新fd=%{public}d (key=%{public}s)",
                             racedConn.forwardSocket, sockFd, natKey.c_str());
                    char clientIP[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &originalPeer.sin_addr, clientIP, sizeof(clientIP));
                    SocketConnectionPool::getInstance().returnSocket(
                        sockFd, clientIP, ntohs(originalPeer.sin_port),
                        packetInfo.targetIP, static_cast<uint16_t>(packetInfo.targetPort),
                        PROTOCOL_UDP, packetInfo.addressFamily
                    );
                    sockFd = racedConn.forwardSocket;
                    isNewMapping = false;
                } else {
                    LOG_ERROR("🚨 [UDP] CreateMapping失败且未找到现存映射: key=%{public}s (fd=%{public}d)", natKey.c_str(), sockFd);
                    SocketConnectionPool::getInstance().returnSocket(sockFd, "", 0, "", 0, PROTOCOL_UDP, AF_INET);
                    return -1;
                }
            } else {
                isNewMapping = true;
                LOG_INFO("✅ [UDP转发线程] NAT映射创建成功: fd=%{public}d, key=%{public}s", sockFd, natKey.c_str());
            }
        }
        LOG_INFO("🔍 [UDP转发线程] ========================================");
    }
    
    // 6. 发送数据到真实服务器
    if (packetInfo.protocol == PROTOCOL_UDP) {
        // 构建目标地址
        LOG_INFO("🔍 [UDP转发线程] 步骤3: 构建目标地址...");
        sockaddr_storage targetAddr{};
        socklen_t addrLen = 0;
        
        if (packetInfo.addressFamily == AF_INET6) {
            auto* addr6 = reinterpret_cast<sockaddr_in6*>(&targetAddr);
            addr6->sin6_family = AF_INET6;
            addr6->sin6_port = htons(static_cast<uint16_t>(packetInfo.targetPort));
            if (inet_pton(AF_INET6, actualTargetIP.c_str(), &addr6->sin6_addr) <= 0) {
                LOG_ERROR("❌ [UDP转发线程] IPv6地址解析失败: %{public}s", actualTargetIP.c_str());
                // 🚀 使用统一的NAT清理接口
                // Socket将在NAT映射删除后自动归还到连接池
                NATConnectionManager::getInstance().scheduleRemove(natKey, CleanupReason::UDP_ADDRESS_FAIL);
                return -1;
            }
            addrLen = sizeof(sockaddr_in6);
            LOG_INFO("🔍 [UDP转发线程] IPv6地址解析成功: %{public}s:%{public}d", actualTargetIP.c_str(), packetInfo.targetPort);
        } else {
            auto* addr4 = reinterpret_cast<sockaddr_in*>(&targetAddr);
            addr4->sin_family = AF_INET;
            addr4->sin_port = htons(static_cast<uint16_t>(packetInfo.targetPort));
            if (inet_pton(AF_INET, actualTargetIP.c_str(), &addr4->sin_addr) <= 0) {
                LOG_ERROR("❌ [UDP转发线程] IPv4地址解析失败: %{public}s", actualTargetIP.c_str());
                // 🚀 使用统一的NAT清理接口
                // Socket将在NAT映射删除后自动归还到连接池
                NATConnectionManager::getInstance().scheduleRemove(natKey, CleanupReason::UDP_ADDRESS_FAIL);
                return -1;
            }
            addrLen = sizeof(sockaddr_in);
            LOG_INFO("🔍 [UDP转发线程] IPv4地址解析成功: %{public}s:%{public}d", actualTargetIP.c_str(), packetInfo.targetPort);
        }

        // 🔍 [排查点3] 服务端转发到真实服务器 (UDP)
        LOG_INFO("🔍 [UDP转发线程] 步骤4: 发送数据到真实服务器 (fd=%{public}d, payload=%{public}d字节)...", sockFd, payloadSize);
        auto sendStartTime = std::chrono::steady_clock::now();
        ssize_t sent = sendto(sockFd, payload, payloadSize, 0, 
                             reinterpret_cast<sockaddr*>(&targetAddr), addrLen);
        auto sendEndTime = std::chrono::steady_clock::now();
        auto sendCostMs = std::chrono::duration_cast<std::chrono::milliseconds>(sendEndTime - sendStartTime).count();
        LOG_INFO("🔍 [UDP转发线程] sendto返回: sent=%{public}zd, 耗时=%{public}lldms, errno=%{public}d (fd=%{public}d)",
                 sent, (long long)sendCostMs, (sent < 0 ? errno : 0), sockFd);
        
        if (sendCostMs > 100) {
            WORKER_LOGE("⏱️ [UDP转发线程] sendto耗时过长: %{public}lldms (fd=%{public}d, payload=%{public}d字节)",
                       (long long)sendCostMs, sockFd, payloadSize);
        }
        
        if (sent < 0) {
            LOG_ERROR("❌ [排查点3] 服务端->真实服务器(UDP)失败: %{public}s:%{public}d, errno=%{public}d (%{public}s), fd=%{public}d",
                     actualTargetIP.c_str(), packetInfo.targetPort, errno, strerror(errno), sockFd);
            // 🚀 使用统一的NAT清理接口（自动延迟2秒，允许UDP重传）
            // Socket将在NAT映射删除后自动归还到连接池
            NATConnectionManager::getInstance().scheduleRemove(natKey, CleanupReason::UDP_SEND_FAIL);
            return -1;
        } else{
            static int udpSendCount = 0;
            udpSendCount++;
            if (udpSendCount <= 10 || udpSendCount % 50 == 0) {
                LOG_INFO("✅ [排查点3] 服务端->真实服务器(UDP): %{public}s:%{public}d -> %{public}s:%{public}d (payload=%{public}zd字节, fd=%{public}d)",
                        packetInfo.sourceIP.c_str(), packetInfo.sourcePort,
                        actualTargetIP.c_str(), packetInfo.targetPort, sent, sockFd);
            }
        }

        // ✅ 重写：不要为每个UDP映射启动一个线程（会线程爆炸）
        // 统一交给 UdpSocketPump poll() 监听
        if (isNewMapping) {
            UdpSocketPump::getInstance().registerSocket(sockFd);
        }
        
        return sockFd;
        
    } else if (packetInfo.protocol == PROTOCOL_TCP) {
        // TCP处理
        ParsedTcp tcp = ParseTcpFromIp(data, dataSize);
        if (!tcp.ok) {
            if (isNewMapping) {
                NATTable::RemoveMapping(natKey);
                if (sockFd >= 0) {
                    SocketConnectionPool::getInstance().returnSocket(sockFd, "", 0, "", 0, PROTOCOL_TCP, AF_INET);
                }
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

        // 🚀 修复：新映射 - 异步建立TCP连接，不阻塞worker线程
        // 关键点：必须“后端connect成功后再回SYN-ACK”，否则客户端会立刻发ACK/数据，
        // 但sockFd尚未connect完成，导致send()失败 -> NAT被移除 -> 后续包报“连接不存在”。
        if (isNewMapping) {
            uint32_t clientIsn = tcp.seq;
            uint32_t serverIsn = RandomIsn();
            
            if (!NATTable::WithConnection(natKey, [&](NATConnection& c) {
                c.tcpState = NATConnection::TcpState::CONNECTING;
                c.clientIsn = clientIsn;
                c.serverIsn = serverIsn;
                c.nextClientSeq = clientIsn + 1;
                c.nextServerSeq = serverIsn + 1;
            })) {
                LOG_ERROR("❌ [TCP] 更新NAT映射失败: %{public}s:%{public}d",
                         actualTargetIP.c_str(), packetInfo.targetPort);
                SocketConnectionPool::getInstance().returnSocket(sockFd, "", 0, "", 0, PROTOCOL_TCP, AF_INET);
                return -1;
            }
            
            // 1) 在后台线程中异步建立连接（不阻塞worker线程）
            sockaddr_storage targetAddr{};
            socklen_t addrLen = 0;
            
            LOG_INFO("🔍 [TCP转发线程] 步骤3: 构建目标地址并解析...");
            if (packetInfo.addressFamily == AF_INET6) {
                auto* addr6 = reinterpret_cast<sockaddr_in6*>(&targetAddr);
                addr6->sin6_family = AF_INET6;
                addr6->sin6_port = htons(static_cast<uint16_t>(packetInfo.targetPort));
                if (inet_pton(AF_INET6, actualTargetIP.c_str(), &addr6->sin6_addr) <= 0) {
                    LOG_ERROR("❌ [TCP] IPv6地址解析失败: %s", actualTargetIP.c_str());
                    // 🚀 使用统一的NAT清理接口
                    // Socket将在NAT映射删除后自动归还到连接池
                    NATConnectionManager::getInstance().scheduleRemove(natKey, CleanupReason::TCP_ADDRESS_FAIL);
                    return -1;
                }
                addrLen = sizeof(sockaddr_in6);
                LOG_INFO("🔍 [TCP转发线程] IPv6地址解析成功: %{public}s:%{public}d", actualTargetIP.c_str(), packetInfo.targetPort);
            } else {
                auto* addr4 = reinterpret_cast<sockaddr_in*>(&targetAddr);
                addr4->sin_family = AF_INET;
                addr4->sin_port = htons(static_cast<uint16_t>(packetInfo.targetPort));
                if (inet_pton(AF_INET, actualTargetIP.c_str(), &addr4->sin_addr) <= 0) {
                    LOG_ERROR("❌ [TCP] IPv4地址解析失败: %s", actualTargetIP.c_str());
                    // 🚀 使用统一的NAT清理接口
                    // Socket将在NAT映射删除后自动归还到连接池
                    NATConnectionManager::getInstance().scheduleRemove(natKey, CleanupReason::TCP_ADDRESS_FAIL);
                    return -1;
                }
                addrLen = sizeof(sockaddr_in);
                LOG_INFO("🔍 [TCP转发线程] IPv4地址解析成功: %{public}s:%{public}d", actualTargetIP.c_str(), packetInfo.targetPort);
            }
            
            // 2) 异步连接（不阻塞worker线程）
            LOG_INFO("🔍 [TCP转发线程] 步骤4: 启动异步连接线程 (目标=%{public}s:%{public}d, fd=%{public}d)...",
                     actualTargetIP.c_str(), packetInfo.targetPort, sockFd);
            std::thread([natKey, sockFd, targetAddr, addrLen, actualTargetIP, packetInfo, originalPeer, clientIsn, serverIsn]() mutable {
                // 等待socket保护完成（在后台线程中等待，不阻塞worker）
                LOG_INFO("🔍 [TCP异步连接] 等待socket保护完成 (fd=%{public}d)...", sockFd);
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                LOG_INFO("🔍 [TCP异步连接] Socket保护等待完成，开始连接 (fd=%{public}d)...", sockFd);
                
                // 尝试连接（快速超时，避免长时间阻塞）
                LOG_INFO("🧭 [TCP-TRACE] CONNECT_START key=%{public}s fd=%{public}d target=%{public}s:%{public}d",
                         natKey.c_str(), sockFd, actualTargetIP.c_str(), packetInfo.targetPort);
                auto connectStartTime = std::chrono::steady_clock::now();
                bool connectResult = ConnectWithTimeout(sockFd, reinterpret_cast<sockaddr*>(&targetAddr), addrLen, 2000);
                auto connectEndTime = std::chrono::steady_clock::now();
                auto connectCostMs = std::chrono::duration_cast<std::chrono::milliseconds>(connectEndTime - connectStartTime).count();
                LOG_INFO("🔍 [TCP异步连接] ConnectWithTimeout返回: result=%{public}d, 耗时=%{public}lldms (fd=%{public}d)",
                         connectResult ? 1 : 0, (long long)connectCostMs, sockFd);
                
                if (connectResult) {
                    LOG_INFO("✅ [TCP] 后台连接成功: %{public}s:%{public}d (fd=%{public}d)",
                             actualTargetIP.c_str(), packetInfo.targetPort, sockFd);
                    LOG_INFO("✅ [TCP] 后端已连通，准备回SYN-ACK: client=%{public}s:%{public}d -> target=%{public}s:%{public}d key=%{public}s local=%{public}s peer=%{public}s",
                             packetInfo.sourceIP.c_str(), packetInfo.sourcePort,
                             actualTargetIP.c_str(), packetInfo.targetPort, natKey.c_str(),
                             GetSocketAddrString(sockFd, false).c_str(), GetSocketAddrString(sockFd, true).c_str());

                    // 后端已连通：此时再给客户端回SYN-ACK，避免ACK/数据早到导致send失败
                    uint8_t synAckPkt[128];
                    int synAckSize = PacketBuilder::BuildTcpResponsePacket(
                        synAckPkt, sizeof(synAckPkt), nullptr, 0, packetInfo,
                        serverIsn, clientIsn + 1, TCP_SYN | TCP_ACK
                    );
                    if (synAckSize > 0) {
                        bool submitted = TaskQueueManager::getInstance().submitResponseTask(
                            synAckPkt, synAckSize, originalPeer, sockFd, PROTOCOL_TCP
                        );
                        LOG_INFO("✅ [TCP] SYN-ACK(延后)已发送: %{public}s:%{public}d -> %{public}s:%{public}d (fd=%{public}d)",
                                 packetInfo.sourceIP.c_str(), packetInfo.sourcePort,
                                 actualTargetIP.c_str(), packetInfo.targetPort, sockFd);
                        LOG_INFO("🧭 [TCP-TRACE] ENQ_SYNACK key=%{public}s fd=%{public}d size=%{public}d ok=%{public}d",
                                 natKey.c_str(), sockFd, synAckSize, submitted ? 1 : 0);
                    } else {
                        LOG_ERROR("❌ [TCP] SYN-ACK构建失败(延后发送): fd=%{public}d", sockFd);
                    }

                    // 更新状态为 SYN_RECEIVED，等待客户端ACK完成握手
                    NATTable::WithConnection(natKey, [&](NATConnection& c) {
                        c.tcpState = NATConnection::TcpState::SYN_RECEIVED;
                    });

                    // 启动TCP响应线程
                    StartTCPThread(sockFd, originalPeer);
                } else {
                    int savedErr = errno;
                    LOG_ERROR("❌ [TCP] 后台连接失败: %{public}s:%{public}d (fd=%{public}d) - errno=%{public}d (%{public}s)",
                             actualTargetIP.c_str(), packetInfo.targetPort, sockFd, savedErr, strerror(savedErr));
                    LOG_ERROR("❌ [TCP] 后端连接失败，准备回RST: client=%{public}s:%{public}d -> target=%{public}s:%{public}d key=%{public}s",
                             packetInfo.sourceIP.c_str(), packetInfo.sourcePort,
                             actualTargetIP.c_str(), packetInfo.targetPort, natKey.c_str());

                    // 发送 RST|ACK 告知客户端连接失败（ack=clientIsn+1）
                    uint8_t rstPkt[128];
                    int rstSize = PacketBuilder::BuildTcpResponsePacket(
                        rstPkt, sizeof(rstPkt), nullptr, 0, packetInfo,
                        0, clientIsn + 1, TCP_RST | TCP_ACK
                    );
                    if (rstSize > 0) {
                        bool submitted = TaskQueueManager::getInstance().submitResponseTask(
                            rstPkt, rstSize, originalPeer, sockFd, PROTOCOL_TCP
                        );
                        LOG_INFO("🧭 [TCP-TRACE] ENQ_RST key=%{public}s fd=%{public}d size=%{public}d ok=%{public}d",
                                 natKey.c_str(), sockFd, rstSize, submitted ? 1 : 0);
                    } else {
                        LOG_ERROR("❌ [TCP] RST构建失败: fd=%{public}d", sockFd);
                    }
                    // 🚀 使用统一的NAT清理接口
                    // Socket将在NAT映射删除后自动归还到连接池
                    NATConnectionManager::getInstance().scheduleRemove(natKey, CleanupReason::TCP_CONNECT_FAIL);
                }
            }).detach();
            
            // 3) 立即返回，不等待连接建立（worker线程继续处理其他任务）
            return sockFd;
        }

        // 现有映射：处理控制包和数据包
        if (isRst) {
            shutdown(sockFd, SHUT_RDWR);
            
            // 🚀 使用统一的NAT清理接口（自动延迟1秒）
            // Socket将在NAT映射删除后自动归还到连接池
            LOG_INFO("⏰ [TCP-TRACE] RST_DELAY key=%{public}s fd=%{public}d",
                     natKey.c_str(), sockFd);
            NATConnectionManager::getInstance().scheduleRemove(natKey, CleanupReason::TCP_RST_RECEIVED);
            
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
                bool submitted = TaskQueueManager::getInstance().submitResponseTask(
                    ackPkt, ackSize, originalPeer, sockFd, PROTOCOL_TCP
                );
                LOG_INFO("🧭 [TCP-TRACE] ENQ_FIN_ACK key=%{public}s fd=%{public}d size=%{public}d ok=%{public}d",
                         natKey.c_str(), sockFd, ackSize, submitted ? 1 : 0);
            }
            shutdown(sockFd, SHUT_RDWR);
            
            // 🚀 使用统一的NAT清理接口（自动延迟2秒）
            // Socket将在NAT映射删除后自动归还到连接池
            LOG_INFO("⏰ [TCP-TRACE] CLIENT_FIN_DELAY key=%{public}s fd=%{public}d",
                     natKey.c_str(), sockFd);
            NATConnectionManager::getInstance().scheduleRemove(natKey, CleanupReason::TCP_CLIENT_FIN);
            
            return 0;
        }

        // ACK包（完成握手）
        int tcpPayloadSize = dataSize - tcp.ipHeaderLen - tcp.tcpHeaderLen;
        // ✅ 关键修复：
        // 浏览器/系统TCP栈经常在第三次握手直接发送 ACK+PSH(带首个HTTP数据段)。
        // 之前代码只在“纯ACK且无payload”时才进入 ESTABLISHED，导致 ACK+数据被误判为“握手未完成”并丢弃，
        // 表现就是“连接看似成功但网页永远打不开”。
        if (isAck && !isSyn) {
            NATTable::WithConnection(natKey, [&](NATConnection& c) {
                if (c.tcpState == NATConnection::TcpState::SYN_RECEIVED &&
                    tcp.ack == c.serverIsn + 1) {
                    c.tcpState = NATConnection::TcpState::ESTABLISHED;
                    if (tcpPayloadSize > 0) {
                        LOG_INFO("✅ [TCP] 第三次握手ACK携带数据：SYN_RECEIVED -> ESTABLISHED (fd=%{public}d flags=%{public}s payload=%{public}d ack=%{public}u)",
                                 sockFd, TcpFlagsToString(tcp.flags).c_str(), tcpPayloadSize, tcp.ack);
                    }
                    // 如果是纯ACK，下一段期望seq就是当前tcp.seq；若带payload，会在数据分支里推进。
                    if (tcpPayloadSize <= 0) {
                        c.nextClientSeq = tcp.seq;
                    }
                }
            });
            // 纯ACK：握手完成即可返回；ACK+payload 继续走数据分支
            if (tcpPayloadSize <= 0) {
                LogTcpTrace("ACK_HANDSHAKE", packetInfo, tcp, dataSize, natKey, sockFd);
                return sockFd;
            }
        }

        // 数据包
        if (tcpPayloadSize > 0) {
            // 若握手未完成，不应发往真实服务器（否则可能 ENOTCONN/EPIPE）
            bool canSend = false;
            NATTable::WithConnection(natKey, [&](NATConnection& c) {
                // ✅ 允许 ACK+payload 的第三次握手：在这里也做一次兜底升级
                if (c.tcpState == NATConnection::TcpState::SYN_RECEIVED &&
                    isAck && !isSyn && (tcp.ack == c.serverIsn + 1)) {
                    c.tcpState = NATConnection::TcpState::ESTABLISHED;
                }
                canSend = (c.tcpState == NATConnection::TcpState::ESTABLISHED);
            });
            if (!canSend) {
                LOG_ERROR("⚠️ [TCP] 收到数据但握手未完成，丢弃该段并等待ACK建立: %{public}s:%{public}d -> %{public}s:%{public}d (fd=%{public}d flags=%{public}s payload=%{public}d)",
                          packetInfo.sourceIP.c_str(), packetInfo.sourcePort,
                          actualTargetIP.c_str(), packetInfo.targetPort, sockFd,
                          TcpFlagsToString(tcp.flags).c_str(), tcpPayloadSize);
                LogTcpTrace("DATA_DROP_NO_ESTABLISH", packetInfo, tcp, dataSize, natKey, sockFd);
                return sockFd;
            }
            const uint8_t* tcpPayload = data + tcp.ipHeaderLen + tcp.tcpHeaderLen;
            LogTcpTrace("SEND_BACKEND", packetInfo, tcp, dataSize, natKey, sockFd);
            // 🔍 [排查点3] 服务端转发到真实服务器 (TCP)
            ssize_t sent = send(sockFd, tcpPayload, tcpPayloadSize, 0);
            if (sent < 0) {
                int savedErr = errno;
                LOG_ERROR("❌ [排查点3] 服务端->真实服务器(TCP)失败: %{public}s:%{public}d -> %{public}s:%{public}d, fd=%{public}d, errno=%{public}d (%{public}s), payload=%{public}d字节",
                         packetInfo.sourceIP.c_str(), packetInfo.sourcePort,
                         actualTargetIP.c_str(), packetInfo.targetPort, sockFd, savedErr, strerror(savedErr), tcpPayloadSize);
                // 🚀 先发送RST给客户端，告知连接失败
                uint8_t rstPkt[128];
                int rstSize = PacketBuilder::BuildTcpResponsePacket(
                    rstPkt, sizeof(rstPkt), nullptr, 0, packetInfo,
                    0, tcp.seq + (tcpPayloadSize > 0 ? static_cast<uint32_t>(tcpPayloadSize) : 1), TCP_RST | TCP_ACK
                );
                if (rstSize > 0) {
                    TaskQueueManager::getInstance().submitResponseTask(
                        rstPkt, rstSize, originalPeer, sockFd, PROTOCOL_TCP
                    );
                }
                // 🚀 使用统一的NAT清理接口（自动延迟2秒，确保RST能发出）
                // Socket将在NAT映射删除后自动归还到连接池
                NATConnectionManager::getInstance().scheduleRemove(natKey, CleanupReason::TCP_SEND_FAIL);
                return -1;
            } else {
                static int tcpSendCount = 0;
                tcpSendCount++;
                if (tcpSendCount <= 10 || tcpSendCount % 50 == 0) {
                    LOG_INFO("✅ [排查点3] 服务端->真实服务器(TCP): %{public}s:%{public}d -> %{public}s:%{public}d (payload=%{public}zd字节, fd=%{public}d, seq=%{public}u)",
                            packetInfo.sourceIP.c_str(), packetInfo.sourcePort,
                            actualTargetIP.c_str(), packetInfo.targetPort, sent, sockFd, tcp.seq);
                }
            }
            LOG_INFO("🧭 [TCP-TRACE] SEND_BACKEND_OK key=%{public}s fd=%{public}d bytes=%{public}d",
                     natKey.c_str(), sockFd, static_cast<int>(sent));

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
                bool submitted = TaskQueueManager::getInstance().submitResponseTask(
                    ackPkt, ackSize, originalPeer, sockFd, PROTOCOL_TCP
                );
                LOG_INFO("🧭 [TCP-TRACE] ENQ_DATA_ACK key=%{public}s fd=%{public}d size=%{public}d ok=%{public}d",
                         natKey.c_str(), sockFd, ackSize, submitted ? 1 : 0);
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
