// 🚀 最终简化版 - 专注解决NAT映射问题
#include "packet_forwarder.h"
#include "nat_table.h"
#include "nat_connection_manager.h"
#include "protocol_handler.h"
#include "packet_builder.h"
#include "udp_retransmit.h"
#include "traffic_stats.h"
#include "task_queue.h"
#include "network_diagnostics.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <cstdlib>
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
    if (!s.empty()) s.pop_back(); 
    if (s.empty()) return "NONE";
    return s;
}

static const char* TcpStateToString(NATConnection::TcpState s)
{
    switch (s) {
        case NATConnection::TcpState::NONE: return "NONE";
        case NATConnection::TcpState::CONNECTING: return "CONNECTING";
        case NATConnection::TcpState::SYN_RECEIVED: return "SYN_RECEIVED";
        case NATConnection::TcpState::ESTABLISHED: return "ESTABLISHED";
        case NATConnection::TcpState::FIN_SENT: return "FIN_SENT";
        case NATConnection::TcpState::CLOSED: return "CLOSED";
        default: return "UNKNOWN";
    }
}

static std::string GetSocketAddrString(int sockFd, bool peer)
{
    sockaddr_storage addr{};
    socklen_t len = sizeof(addr);
    int rc = peer ? getpeername(sockFd, reinterpret_cast<sockaddr*>(&addr), &len)
                  : getsockname(sockFd, reinterpret_cast<sockaddr*>(&addr), &len);
    if (rc != 0) return "unknown";
    if (addr.ss_family == AF_INET) {
        char ip[INET_ADDRSTRLEN] = {0};
        auto* a4 = reinterpret_cast<sockaddr_in*>(&addr);
        inet_ntop(AF_INET, &a4->sin_addr, ip, sizeof(ip));
        return std::string(ip) + ":" + std::to_string(ntohs(a4->sin_port));
    }
    if (addr.ss_family == AF_INET6) {
        char ip[INET6_ADDRSTRLEN] = {0};
        auto* a6 = reinterpret_cast<sockaddr_in6*>(&addr);
        inet_ntop(AF_INET6, &a6->sin6_addr, ip, sizeof(ip));
        return std::string(ip) + ":" + std::to_string(ntohs(a6->sin6_port));
    }
    return "unknown";
}

// ✅ TCP Socket Pump
class TcpSocketPump {
public:
    static TcpSocketPump& getInstance() {
        static TcpSocketPump inst;
        return inst;
    }
    void registerSocket(int sockFd) {
        if (sockFd < 0) return;
        int flags = fcntl(sockFd, F_GETFL, 0);
        fcntl(sockFd, F_SETFL, flags | O_NONBLOCK);
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (fdsSet_.find(sockFd) != fdsSet_.end()) return;
            pollfd p{}; p.fd = sockFd; p.events = POLLIN;
            fds_.push_back(p);
            fdsSet_.insert(sockFd);
            LOG_INFO("➕ [TcpSocketPump] 注册TCP socket: fd=%d, 总数=%zu", sockFd, fds_.size());
        }
        ensureStarted();
        cv_.notify_one();
    }
    void unregisterSocket(int sockFd) {
        if (sockFd < 0) return;
        std::lock_guard<std::mutex> lock(mutex_);
        if (fdsSet_.find(sockFd) == fdsSet_.end()) return;
        for (auto it = fds_.begin(); it != fds_.end(); ++it) {
            if (it->fd == sockFd) { fds_.erase(it); break; }
        }
        fdsSet_.erase(sockFd);
        LOG_INFO("➖ [TcpSocketPump] 注销TCP socket: fd=%d, 剩余=%zu", sockFd, fds_.size());
    }
private:
    TcpSocketPump() = default;
    void ensureStarted() {
        bool expected = false;
        if (running_.compare_exchange_strong(expected, true)) {
            worker_ = std::thread([this]() { this->loop(); });
            worker_.detach();
        }
    }
    void loop() {
        uint8_t buffer[4096];
        constexpr int kMaxTcpPayloadPerSegment = 1200;
        while (running_.load()) {
            std::vector<pollfd> localFds;
            {
                std::unique_lock<std::mutex> lock(mutex_);
                if (fds_.empty()) {
                    cv_.wait_for(lock, std::chrono::milliseconds(500), [this]() {
                        return !running_.load() || !fds_.empty();
                    });
                }
                if (!running_.load()) break;
                localFds = fds_;
            }
            if (localFds.empty()) continue;
            int ret = poll(localFds.data(), localFds.size(), 100);
            if (ret <= 0) continue;
            bool hasInvalidFds = false;
            for (const auto& p : localFds) {
                if (p.revents & (POLLERR | POLLHUP | POLLNVAL)) {
                    hasInvalidFds = true;
                    if (!(p.revents & POLLIN)) { handleClose(p.fd); continue; }
                }
                if (!(p.revents & POLLIN)) continue;
                ssize_t received = recv(p.fd, buffer, sizeof(buffer), 0);
                if (received > 0) handleData(p.fd, buffer, received, kMaxTcpPayloadPerSegment);
                else if (received == 0) handleClose(p.fd);
                else if (errno != EAGAIN && errno != EWOULDBLOCK) { handleClose(p.fd); }
            }
            if (hasInvalidFds) {
                std::lock_guard<std::mutex> lock(mutex_);
                for (auto it = fds_.begin(); it != fds_.end(); ) {
                    int err = 0; socklen_t len = sizeof(err);
                    if (getsockopt(it->fd, SOL_SOCKET, SO_ERROR, &err, &len) < 0 || err != 0) {
                        fdsSet_.erase(it->fd); it = fds_.erase(it);
                    } else ++it;
                }
            }
        }
    }
    void handleData(int sockFd, uint8_t* buffer, ssize_t received, int maxMSS) {
        NATConnection conn;
        if (!NATTable::FindMappingBySocket(sockFd, conn)) return;
        int remaining = static_cast<int>(received);
        int offset = 0;
        while (remaining > 0) {
            int chunk = (remaining > maxMSS) ? maxMSS : remaining;
            uint32_t seqToSend = 0, ackToSend = 0;
            PacketInfo origReq = conn.originalRequest;
            bool hasConn = NATTable::WithConnectionBySocket(sockFd, [&](NATConnection& c) {
                seqToSend = c.nextServerSeq; ackToSend = c.nextClientSeq;
                c.nextServerSeq += static_cast<uint32_t>(chunk);
                c.lastActivity = std::chrono::steady_clock::now();
            });
            if (!hasConn) break;
            uint8_t flags = TCP_ACK; if (remaining == chunk) flags |= TCP_PSH;
            std::vector<uint8_t> responsePacket(chunk + 128);
            int size = PacketBuilder::BuildTcpResponsePacket(responsePacket.data(), responsePacket.size(), buffer + offset, chunk, origReq, seqToSend, ackToSend, flags);
            if (size > 0) TaskQueueManager::getInstance().submitResponseTask(responsePacket.data(), size, conn.clientPhysicalAddr, sockFd, PROTOCOL_TCP);
            offset += chunk; remaining -= chunk;
        }
    }
    void handleClose(int sockFd) {
        NATConnection conn;
        if (NATTable::FindMappingBySocket(sockFd, conn)) {
            uint32_t seqToSend = 0, ackToSend = 0;
            PacketInfo origReq = conn.originalRequest;
            NATTable::WithConnectionBySocket(sockFd, [&](NATConnection& c) {
                seqToSend = c.nextServerSeq; ackToSend = c.nextClientSeq;
                c.nextServerSeq += 1; c.tcpState = NATConnection::TcpState::FIN_SENT;
            });
            uint8_t finPkt[128];
            int finSize = PacketBuilder::BuildTcpResponsePacket(finPkt, sizeof(finPkt), nullptr, 0, origReq, seqToSend, ackToSend, TCP_FIN | TCP_ACK);
            if (finSize > 0) TaskQueueManager::getInstance().submitResponseTask(finPkt, finSize, conn.clientPhysicalAddr, sockFd, PROTOCOL_TCP);
            NATConnectionManager::getInstance().scheduleRemoveBySocket(sockFd, CleanupReason::TCP_SERVER_FIN);
        }
        unregisterSocket(sockFd);
    }
    std::mutex mutex_; std::condition_variable cv_; std::vector<pollfd> fds_; std::unordered_set<int> fdsSet_; std::thread worker_; std::atomic<bool> running_{false};
};

// ✅ UDP Socket Pump
class UdpSocketPump {
public:
    static UdpSocketPump& getInstance() { static UdpSocketPump inst; return inst; }
    void registerSocket(int sockFd) {
        if (sockFd < 0) return;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (fdsSet_.find(sockFd) != fdsSet_.end()) return;
            pollfd p{}; p.fd = sockFd; p.events = POLLIN;
            fds_.push_back(p); fdsSet_.insert(sockFd);
            LOG_INFO("➕ [UdpSocketPump] 注册socket: fd=%d, 当前总数=%zu", sockFd, fds_.size());
        }
        ensureStarted();
        cv_.notify_one();
    }
    void unregisterSocket(int sockFd) {
        if (sockFd < 0) return;
        std::lock_guard<std::mutex> lock(mutex_);
        if (fdsSet_.find(sockFd) == fdsSet_.end()) return;
        for (auto it = fds_.begin(); it != fds_.end(); ++it) {
            if (it->fd == sockFd) { fds_.erase(it); break; }
        }
        fdsSet_.erase(sockFd);
        LOG_INFO("➖ [UdpSocketPump] 注销socket: fd=%d, 剩余总数=%zu", sockFd, fds_.size());
    }
private:
    UdpSocketPump() = default;
    void ensureStarted() {
        bool expected = false;
        if (running_.compare_exchange_strong(expected, true)) {
            worker_ = std::thread([this]() { this->loop(); });
            worker_.detach();
        }
    }
    void loop() {
        uint8_t buffer[4096];
        while (running_.load()) {
            std::vector<pollfd> localFds;
            {
                std::unique_lock<std::mutex> lock(mutex_);
                if (fds_.empty()) {
                    cv_.wait_for(lock, std::chrono::milliseconds(500), [this]() { return !running_.load() || !fds_.empty(); });
                }
                if (!running_.load()) break;
                localFds = fds_;
            }
            if (localFds.empty()) continue;
            int rc = poll(localFds.data(), static_cast<nfds_t>(localFds.size()), 200);
            if (rc <= 0) continue;
            bool hasInvalidFds = false;
            for (auto& p : localFds) {
                if (p.revents & POLLNVAL) { hasInvalidFds = true; continue; }
                if (!(p.revents & POLLIN)) continue;
                ssize_t received = recvfrom(p.fd, buffer, sizeof(buffer), 0, nullptr, nullptr);
                if (received <= 0) {
                    if (received < 0 && errno == EBADF) hasInvalidFds = true;
                    continue;
                }
                NATConnection conn;
                if (!NATTable::FindMappingBySocket(p.fd, conn)) continue;
                uint8_t responsePacket[4096];
                int responseSize = PacketBuilder::BuildResponsePacket(responsePacket, sizeof(responsePacket), buffer, (int)received, conn.originalRequest);
                if (responseSize > 0) {
                    if (TaskQueueManager::getInstance().submitResponseTask(responsePacket, responseSize, conn.clientPhysicalAddr, p.fd, PROTOCOL_UDP)) {
                        UdpRetransmitManager::getInstance().confirmReceivedByContent(p.fd, buffer, (int)received);
                    }
                }
            }
            if (hasInvalidFds) {
                std::lock_guard<std::mutex> lock(mutex_);
                for (auto it = fds_.begin(); it != fds_.end(); ) {
                    int err = 0; socklen_t len = sizeof(err);
                    if (getsockopt(it->fd, SOL_SOCKET, SO_ERROR, &err, &len) < 0 || errno == EBADF) {
                        fdsSet_.erase(it->fd); it = fds_.erase(it);
                    } else ++it;
                }
            }
        }
    }
    std::mutex mutex_; std::condition_variable cv_; std::vector<pollfd> fds_; std::unordered_set<int> fdsSet_; std::thread worker_; std::atomic<bool> running_{false};
};

static bool ProtectSocket(int sockFd, const std::string& description);

class SocketConnectionPool {
private:
    struct SocketInfo {
        int sockFd;
        std::chrono::steady_clock::time_point lastUsed;
        bool inUse;
        SocketInfo(int fd) : sockFd(fd), lastUsed(std::chrono::steady_clock::now()), inUse(false) {}
    };
    struct TargetKey {
        std::string clientIP, serverIP; uint16_t clientPort, serverPort; uint8_t protocol; int addressFamily;
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
    const size_t MAX_SOCKETS_PER_TARGET = 5;
    const int SOCKET_TIMEOUT_SECONDS = 300;
    SocketConnectionPool() = default;
public:
    static SocketConnectionPool& getInstance() { static SocketConnectionPool instance; return instance; }
    int getSocket(const std::string& clientIP, uint16_t clientPort, const std::string& serverIP, uint16_t serverPort, uint8_t protocol, int addressFamily) {
        std::lock_guard<std::mutex> lock(poolMutex_);
        if (protocol == PROTOCOL_TCP) return createNewSocket(protocol, addressFamily);
        TargetKey key{clientIP, clientPort, serverIP, serverPort, protocol, addressFamily};
        auto& pool = socketPools_[key];
        while (!pool.empty()) {
            SocketInfo info = pool.front(); pool.pop();
            int err = 0; socklen_t len = sizeof(err);
            if (getsockopt(info.sockFd, SOL_SOCKET, SO_ERROR, &err, &len) == 0 && err == 0) {
                if (std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - info.lastUsed).count() < SOCKET_TIMEOUT_SECONDS) {
                    return info.sockFd;
                }
            }
            close(info.sockFd);
        }
        return createNewSocket(protocol, addressFamily);
    }
    void returnSocket(int sockFd, const std::string& clientIP, uint16_t clientPort, const std::string& serverIP, uint16_t serverPort, uint8_t protocol, int addressFamily) {
        if (protocol == PROTOCOL_TCP) { TcpSocketPump::getInstance().unregisterSocket(sockFd); close(sockFd); return; }
        UdpSocketPump::getInstance().unregisterSocket(sockFd);
        std::lock_guard<std::mutex> lock(poolMutex_);
        TargetKey key{clientIP, clientPort, serverIP, serverPort, protocol, addressFamily};
        auto& pool = socketPools_[key];
        if (pool.size() < MAX_SOCKETS_PER_TARGET) {
            pool.push(SocketInfo(sockFd));
        } else close(sockFd);
    }
    void cleanup() {
        std::lock_guard<std::mutex> lock(poolMutex_);
        for (auto& p : socketPools_) { while(!p.second.empty()) { close(p.second.front().sockFd); p.second.pop(); } }
        socketPools_.clear();
    }
private:
    int createNewSocket(uint8_t protocol, int addressFamily) {
        int af = (addressFamily == AF_INET6) ? AF_INET6 : AF_INET;
        int sockFd = socket(af, (protocol == PROTOCOL_UDP ? SOCK_DGRAM : SOCK_STREAM), 0);
        if (sockFd < 0) return -1;
        struct timeval tv; tv.tv_sec = (protocol == PROTOCOL_TCP ? 10 : 5); tv.tv_usec = 0;
        setsockopt(sockFd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(sockFd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        return sockFd;
    }
};

static bool ProtectSocket(int sockFd, const std::string& description) {
    const char* ifs[] = {"eth0", "wlan0", "rmnet0", "rmnet_data0", "rmnet_data1", nullptr};
    for (int i = 0; ifs[i]; i++) {
        if (setsockopt(sockFd, SOL_SOCKET, SO_BINDTODEVICE, ifs[i], strlen(ifs[i]) + 1) == 0) return true;
    }
    return true; 
}

static bool ConnectWithTimeout(int sockFd, const sockaddr* addr, socklen_t len, int timeoutMs) {
    int flags = fcntl(sockFd, F_GETFL, 0);
    fcntl(sockFd, F_SETFL, flags | O_NONBLOCK);
    if (connect(sockFd, addr, len) == 0) { fcntl(sockFd, F_SETFL, flags); return true; }
    if (errno != EINPROGRESS) { fcntl(sockFd, F_SETFL, flags); return false; }
    pollfd pfd{sockFd, POLLOUT, 0};
    if (poll(&pfd, 1, timeoutMs) > 0) {
        int err = 0; socklen_t elen = sizeof(err);
        if (getsockopt(sockFd, SOL_SOCKET, SO_ERROR, &err, &elen) == 0 && err == 0) {
            fcntl(sockFd, F_SETFL, flags); return true;
        }
    }
    fcntl(sockFd, F_SETFL, flags); return false;
}

struct ParsedTcp {
    bool ok = false; uint8_t ipHeaderLen = 0, tcpHeaderLen = 0; uint16_t srcPort = 0, dstPort = 0; uint32_t seq = 0, ack = 0; uint8_t flags = 0;
};
static ParsedTcp ParseTcpFromIp(const uint8_t* data, int dataSize) {
    ParsedTcp t; if (dataSize < 40) return t;
    uint8_t ver = (data[0] >> 4) & 0x0F;
    if (ver == 4) {
        t.ipHeaderLen = (data[0] & 0x0F) * 4;
        if (dataSize < t.ipHeaderLen + 20) return t;
        int off = t.ipHeaderLen;
        t.srcPort = ntohs(*(uint16_t*)&data[off]); t.dstPort = ntohs(*(uint16_t*)&data[off+2]);
        t.seq = ntohl(*(uint32_t*)&data[off+4]); t.ack = ntohl(*(uint32_t*)&data[off+8]);
        t.tcpHeaderLen = ((data[off+12] >> 4) & 0x0F) * 4; t.flags = data[off+13];
        t.ok = (t.tcpHeaderLen >= 20); return t;
    } else if (ver == 6) {
        t.ipHeaderLen = 40; // simplified
        if (dataSize < 60) return t;
        int off = 40;
        t.srcPort = ntohs(*(uint16_t*)&data[off]); t.dstPort = ntohs(*(uint16_t*)&data[off+2]);
        t.seq = ntohl(*(uint32_t*)&data[off+4]); t.ack = ntohl(*(uint32_t*)&data[off+8]);
        t.tcpHeaderLen = ((data[off+12] >> 4) & 0x0F) * 4; t.flags = data[off+13];
        t.ok = (t.tcpHeaderLen >= 20); return t;
    }
    return t;
}

static int ForwardICMPPacket(const uint8_t* data, int dataSize, const PacketInfo& pi, const sockaddr_in& peer, int tunnelFd) {
    int af = (pi.addressFamily == AF_INET6) ? AF_INET6 : AF_INET;
    int proto = (pi.addressFamily == AF_INET6) ? IPPROTO_ICMPV6 : IPPROTO_ICMP;
    int sockFd = socket(af, SOCK_RAW, proto);
    if (sockFd < 0) return -1;
    ProtectSocket(sockFd, "ICMP");
    sockaddr_storage target{}; socklen_t tlen = 0;
    if (af == AF_INET) {
        auto* a4 = reinterpret_cast<sockaddr_in*>(&target); a4->sin_family = AF_INET;
        inet_pton(AF_INET, pi.targetIP.c_str(), &a4->sin_addr); tlen = sizeof(sockaddr_in);
    } else {
        auto* a6 = reinterpret_cast<sockaddr_in6*>(&target); a6->sin_family = AF_INET6;
        inet_pton(AF_INET6, pi.targetIP.c_str(), &a6->sin6_addr); tlen = sizeof(sockaddr_in6);
    }
    int ipHL = (af == AF_INET) ? (data[0] & 0x0F) * 4 : 40;
    sendto(sockFd, data + ipHL, dataSize - ipHL, 0, (sockaddr*)&target, tlen);
    std::thread([sockFd, peer, pi]() {
        struct timeval tv{5, 0}; setsockopt(sockFd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        uint8_t buf[4096]; ssize_t r = recv(sockFd, buf, sizeof(buf), 0);
        if (r > 0) {
            uint8_t resp[4096]; int rSize = PacketBuilder::BuildResponsePacket(resp, sizeof(resp), buf, (int)r, pi);
            if (rSize > 0) TaskQueueManager::getInstance().submitResponseTask(resp, rSize, peer, sockFd, pi.protocol);
        }
        close(sockFd);
    }).detach();
    return sockFd;
}

int PacketForwarder::ForwardPacket(const uint8_t* data, int dataSize, const PacketInfo& pi, const sockaddr_in& peer, int tunnelFd) {
    if (!data || dataSize <= 0) return -1;
    if (pi.protocol == PROTOCOL_ICMP || pi.protocol == PROTOCOL_ICMPV6) return ForwardICMPPacket(data, dataSize, pi, peer, tunnelFd);
    
    const uint8_t* payload = nullptr; int payloadSize = 0;
    if (!PacketBuilder::ExtractPayload(data, dataSize, pi, &payload, &payloadSize)) return -1;
    
    std::string natKey = NATTable::GenerateKey(pi, peer);
    NATConnection conn;
    int sockFd = -1;
    bool isNew = false;

    if (pi.protocol == PROTOCOL_TCP) {
        ParsedTcp tcp = ParseTcpFromIp(data, dataSize);
        if (!tcp.ok) return -1;
        if (NATTable::FindMapping(natKey, conn)) {
            sockFd = conn.forwardSocket;
        } else {
            if (!HasTcpFlag(tcp.flags, TCP_SYN) || HasTcpFlag(tcp.flags, TCP_ACK)) return -1;
            sockFd = SocketConnectionPool::getInstance().getSocket(pi.sourceIP, pi.sourcePort, pi.targetIP, pi.targetPort, pi.protocol, pi.addressFamily);
            if (sockFd < 0) return -1;
            ProtectSocket(sockFd, "TCP");
            if (!NATTable::CreateMapping(natKey, peer, pi, sockFd)) { close(sockFd); return -1; }
            isNew = true;
            uint32_t serverIsn = (uint32_t)rand();
            NATTable::WithConnection(natKey, [&](NATConnection& c) {
                c.tcpState = NATConnection::TcpState::CONNECTING; c.clientIsn = tcp.seq; c.serverIsn = serverIsn;
                c.nextClientSeq = tcp.seq + 1; c.nextServerSeq = serverIsn + 1;
            });
            std::thread([natKey, sockFd, pi, peer, serverIsn, tcp]() {
                sockaddr_storage target{}; socklen_t tlen = 0;
                if (pi.addressFamily == AF_INET6) {
                    auto* a6 = reinterpret_cast<sockaddr_in6*>(&target); a6->sin6_family = AF_INET6; a6->sin6_port = htons(pi.targetPort);
                    inet_pton(AF_INET6, pi.targetIP.c_str(), &a6->sin6_addr); tlen = sizeof(sockaddr_in6);
                } else {
                    auto* a4 = reinterpret_cast<sockaddr_in*>(&target); a4->sin_family = AF_INET; a4->sin_port = htons(pi.targetPort);
                    inet_pton(AF_INET, pi.targetIP.c_str(), &a4->sin_addr); tlen = sizeof(sockaddr_in);
                }
                if (ConnectWithTimeout(sockFd, (sockaddr*)&target, tlen, 2000)) {
                    uint8_t saPkt[128]; int saSize = PacketBuilder::BuildTcpResponsePacket(saPkt, sizeof(saPkt), nullptr, 0, pi, serverIsn, tcp.seq + 1, TCP_SYN | TCP_ACK);
                    if (saSize > 0) TaskQueueManager::getInstance().submitResponseTask(saPkt, saSize, peer, sockFd, PROTOCOL_TCP);
                    NATTable::WithConnection(natKey, [&](NATConnection& c) { c.tcpState = NATConnection::TcpState::SYN_RECEIVED; });
                    TcpSocketPump::getInstance().registerSocket(sockFd);
                } else {
                    uint8_t rst[128]; int rSize = PacketBuilder::BuildTcpResponsePacket(rst, sizeof(rst), nullptr, 0, pi, 0, tcp.seq + 1, TCP_RST | TCP_ACK);
                    if (rSize > 0) TaskQueueManager::getInstance().submitResponseTask(rst, rSize, peer, sockFd, PROTOCOL_TCP);
                    NATConnectionManager::getInstance().scheduleRemove(natKey, CleanupReason::TCP_CONNECT_FAIL);
                }
            }).detach();
            return sockFd;
        }
        if (HasTcpFlag(tcp.flags, TCP_RST)) { NATConnectionManager::getInstance().scheduleRemove(natKey, CleanupReason::TCP_RST_RECEIVED); return 0; }
        if (HasTcpFlag(tcp.flags, TCP_FIN)) {
            NATTable::WithConnection(natKey, [&](NATConnection& c) { c.nextClientSeq = tcp.seq + 1; });
            uint8_t aPkt[128]; int aSize = PacketBuilder::BuildTcpResponsePacket(aPkt, sizeof(aPkt), nullptr, 0, pi, conn.nextServerSeq, tcp.seq + 1, TCP_ACK);
            if (aSize > 0) TaskQueueManager::getInstance().submitResponseTask(aPkt, aSize, peer, sockFd, PROTOCOL_TCP);
            NATConnectionManager::getInstance().scheduleRemove(natKey, CleanupReason::TCP_CLIENT_FIN);
            return 0;
        }
        if (payloadSize > 0) {
            bool established = false;
            NATTable::WithConnection(natKey, [&](NATConnection& c) {
                if (c.tcpState == NATConnection::TcpState::SYN_RECEIVED) c.tcpState = NATConnection::TcpState::ESTABLISHED;
                established = (c.tcpState == NATConnection::TcpState::ESTABLISHED);
            });
            if (established) {
                if (send(sockFd, payload, payloadSize, 0) > 0) {
                    NATTable::WithConnection(natKey, [&](NATConnection& c) { c.nextClientSeq = tcp.seq + payloadSize; });
                    uint8_t aPkt[128]; int aSize = PacketBuilder::BuildTcpResponsePacket(aPkt, sizeof(aPkt), nullptr, 0, pi, conn.nextServerSeq, tcp.seq + payloadSize, TCP_ACK);
                    if (aSize > 0) TaskQueueManager::getInstance().submitResponseTask(aPkt, aSize, peer, sockFd, PROTOCOL_TCP);
                }
            }
        }
    } else {
        if (!NATTable::FindMapping(natKey, conn)) {
            sockFd = SocketConnectionPool::getInstance().getSocket(pi.sourceIP, pi.sourcePort, pi.targetIP, pi.targetPort, pi.protocol, pi.addressFamily);
            if (sockFd < 0) return -1;
            ProtectSocket(sockFd, "UDP");
            if (!NATTable::CreateMapping(natKey, peer, pi, sockFd)) { close(sockFd); return -1; }
        } else sockFd = conn.forwardSocket;
        sockaddr_storage target{}; socklen_t tlen = 0;
        if (pi.addressFamily == AF_INET6) {
            auto* a6 = reinterpret_cast<sockaddr_in6*>(&target); a6->sin6_family = AF_INET6; a6->sin6_port = htons(pi.targetPort);
            inet_pton(AF_INET6, pi.targetIP.c_str(), &a6->sin6_addr); tlen = sizeof(sockaddr_in6);
        } else {
            auto* a4 = reinterpret_cast<sockaddr_in*>(&target); a4->sin_family = AF_INET; a4->sin_port = htons(pi.targetPort);
            inet_pton(AF_INET, pi.targetIP.c_str(), &a4->sin_addr); tlen = sizeof(sockaddr_in);
        }
        sendto(sockFd, payload, payloadSize, 0, (sockaddr*)&target, tlen);
        UdpSocketPump::getInstance().registerSocket(sockFd);
    }
    return sockFd;
}

void PacketForwarder::CleanupAll() { SocketConnectionPool::getInstance().cleanup(); NATTable::CleanupExpired(0); }
void PacketForwarder::LogStatistics() {}
