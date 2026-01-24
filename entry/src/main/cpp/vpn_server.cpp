#include <napi/native_api.h>
#include <hilog/log.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <inttypes.h>
#include <sys/select.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <thread>
#include <unistd.h>
#include <map>
#include <vector>
#include <mutex>
#include <ctime>
#include <netdb.h>
#include <fcntl.h>
#include <sys/select.h>
#include <hilog/log.h>
#include <chrono>
#include "vpn_server_globals.h"
#include "worker_thread_pool.h"
#include "udp_retransmit.h"
#include "network_diagnostics.h"
#include "thread_pool.h"  // 🔄 添加线程池支持
#include "protocol_handler.h"
#include "packet_forwarder.h"
#include "nat_table.h"  // NATTable

// 🔄 线程池管理函数声明
bool InitializeThreadPool(int forwardWorkers, int responseWorkers, int networkWorkers);
VPNThreadPool* GetThreadPool();
void CleanupThreadPool();

#define MAKE_FILE_NAME (strrchr(__FILE__, '/') ? (strrchr(__FILE__, '/') + 1) : __FILE__)

#define VPN_SERVER_LOGE(fmt, ...) \
  OH_LOG_Print(LOG_APP, LOG_INFO, 0x15b1, "VpnServer", "ZHOUB server [%{public}s %{public}d] " fmt, MAKE_FILE_NAME, __LINE__, ##__VA_ARGS__)
#define VPN_SERVER_LOGI(fmt, ...) \
  OH_LOG_Print(LOG_APP, LOG_INFO, 0x15b1, "VpnServer", "ZHOUB server [%{public}s %{public}d] " fmt, MAKE_FILE_NAME, __LINE__, ##__VA_ARGS__)
#define VPN_SERVER_LOGW(fmt, ...) \
  OH_LOG_Print(LOG_APP, LOG_INFO, 0x15b1, "VpnServer", "ZHOUB server [%{public}s %{public}d] " fmt, MAKE_FILE_NAME, __LINE__, ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...) \
  OH_LOG_Print(LOG_APP, LOG_ERROR, 0x15b1, "VpnServer", "ZHOUB [%{public}s:%{public}d] " fmt, MAKE_FILE_NAME, __LINE__, ##__VA_ARGS__)

namespace {
constexpr int BUFFER_SIZE = 2048;  // 🔧 减少缓冲区大小，避免内存不足
}

// 全局变量定义
std::atomic<bool> g_running{false};
std::atomic<int> g_sockFd{-1};  // 🔧 使用atomic确保线程安全
std::thread g_worker;
// std::thread g_udpRetransmitThread;  // 🔄 替换为线程池管理

// Statistics
std::atomic<uint64_t> g_packetsReceived{0};
std::atomic<uint64_t> g_packetsSent{0};
std::atomic<uint64_t> g_bytesReceived{0};
std::atomic<uint64_t> g_bytesSent{0};
std::string g_lastActivity;
std::mutex g_lastActivityMutex;  // 🔧 保护 g_lastActivity 的互斥锁
std::mutex g_statsMutex;

// Client tracking
struct ClientInfo {
  std::string ip;
  int port;
  std::string lastSeen;
  uint64_t packetsCount;
  uint64_t totalBytes;
};
std::map<std::string, ClientInfo> g_clients;
std::mutex g_clientsMutex;

// Data buffer for UI
std::vector<std::string> g_dataBuffer;
std::mutex g_dataBufferMutex;
const size_t MAX_DATA_BUFFER = 100;

// Forwarding related globals
std::map<std::string, int> g_forwardSockets;  // 目标服务器socket映射
std::mutex g_forwardSocketsMutex;

// 处理UDP响应
void HandleUdpResponse(int sockFd, const sockaddr_in& originalPeer);

// 处理转发响应
void HandleForwardResponse(int sockFd, const sockaddr_in& originalPeer);

// 测试百度连接
void TestBaiduConnection();

// 转发数据到真实目标服务器
int ForwardToRealServer(const uint8_t* data, int dataSize, const std::string& targetIP, int targetPort, uint8_t protocol, int addressFamily, const sockaddr_in& originalPeer);

// 解析IP数据包获取目标IP和端�?(支持IPv4和IPv6)
bool ParseIPPacket(const uint8_t* data, int dataSize, std::string& targetIP, int& targetPort, uint8_t& protocol, int& addressFamily) {
    uint8_t version = (data[0] >> 4);

    if (version == 4) {  // IPv4
        if (dataSize < 20) {
            VPN_SERVER_LOGW("IPv4 packet too small: %{public}d bytes (minimum 20 required)", dataSize);
            return false;
        }

        // 获取IP头长度
        uint8_t ipHeaderLen = (data[0] & 0x0F) * 4;
        if (ipHeaderLen < 20 || ipHeaderLen > dataSize) {
            VPN_SERVER_LOGW("Invalid IPv4 header length: %{public}d bytes", ipHeaderLen);
            return false;
        }

        // 获取协议类型
        protocol = data[9];

        // 只处理TCP (protocol=6) �?UDP (protocol=17)
        if (protocol != PROTOCOL_TCP && protocol != PROTOCOL_UDP) {
            VPN_SERVER_LOGW("Unsupported IPv4 protocol: %{public}d (only TCP=6, UDP=17 supported)", protocol);
            return false;
        }

        // 获取目标IP
        char dstIP[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &data[16], dstIP, INET_ADDRSTRLEN);

        // 获取端口 (TCP/UDP头部)
        int payloadOffset = ipHeaderLen;
        if (protocol == PROTOCOL_TCP) {  // TCP
            if (dataSize < payloadOffset + 20) {
                VPN_SERVER_LOGW("TCP packet too small: %{public}d bytes (header=%{public}d, need at least %{public}d)",
                                dataSize, payloadOffset, payloadOffset + 20);
                return false;
            }
            targetPort = (data[payloadOffset + 2] << 8) | data[payloadOffset + 3];  // 目标端口
            VPN_SERVER_LOGI("IPv4 TCP: src_port=%{public}d, dst_port=%{public}d",
                            (data[payloadOffset + 0] << 8) | data[payloadOffset + 1], targetPort);
        } else if (protocol == PROTOCOL_UDP) {  // UDP
            if (dataSize < payloadOffset + 8) {
                VPN_SERVER_LOGW("UDP packet too small: %{public}d bytes (header=%{public}d, need at least %{public}d)",
                                dataSize, payloadOffset, payloadOffset + 8);
                return false;
            }
            targetPort = (data[payloadOffset + 2] << 8) | data[payloadOffset + 3];  // 目标端口
            VPN_SERVER_LOGI("IPv4 UDP: src_port=%{public}d, dst_port=%{public}d",
                            (data[payloadOffset + 0] << 8) | data[payloadOffset + 1], targetPort);
        }

        targetIP = dstIP;
        addressFamily = AF_INET;
        VPN_SERVER_LOGI("Parsed IPv4 packet: protocol=%{public}d, target=%{public}s:%{public}d",
                        protocol, targetIP.c_str(), targetPort);
        return true;

    } else if (version == 6) {  // IPv6
        if (dataSize < 40) {
            VPN_SERVER_LOGW("IPv6 packet too small: %{public}d bytes (minimum 40 required)", dataSize);
            return false;
        }

        // IPv6头部固定40字节
        uint8_t nextHeader = data[6];

        // 只处理TCP (nextHeader=6) �?UDP (nextHeader=17)
        if (nextHeader != 6 && nextHeader != 17) {
            VPN_SERVER_LOGW("Unsupported IPv6 next header: %{public}d (only TCP=6, UDP=17 supported)", nextHeader);
            return false;
        }

        // 获取目标IPv6地址 (16字节，从偏移24开�?
        char dstIP[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &data[24], dstIP, INET6_ADDRSTRLEN);

        // 获取端口 (TCP/UDP头部，IPv6有效载荷从偏�?0开�?
        int payloadOffset = 40;
        if (nextHeader == 6) {  // TCP
            if (dataSize < payloadOffset + 20) {
                VPN_SERVER_LOGW("IPv6 TCP packet too small: %{public}d bytes (need at least %{public}d)",
                                dataSize, payloadOffset + 20);
                return false;
            }
            targetPort = (data[payloadOffset + 2] << 8) | data[payloadOffset + 3];  // 目标端口
            VPN_SERVER_LOGI("IPv6 TCP: src_port=%{public}d, dst_port=%{public}d",
                            (data[payloadOffset + 0] << 8) | data[payloadOffset + 1], targetPort);
        } else if (nextHeader == 17) {  // UDP
            if (dataSize < payloadOffset + 8) {
                VPN_SERVER_LOGW("IPv6 UDP packet too small: %{public}d bytes (need at least %{public}d)",
                                dataSize, payloadOffset + 8);
                return false;
            }
            targetPort = (data[payloadOffset + 2] << 8) | data[payloadOffset + 3];  // 目标端口
            VPN_SERVER_LOGI("IPv6 UDP: src_port=%{public}d, dst_port=%{public}d",
                            (data[payloadOffset + 0] << 8) | data[payloadOffset + 1], targetPort);
        }

        targetIP = dstIP;
        addressFamily = AF_INET6;
        VPN_SERVER_LOGI("Parsed IPv6 packet: nextHeader=%{public}d, target=%{public}s:%{public}d",
                        nextHeader, targetIP.c_str(), targetPort);
        return true;

    } else {
        VPN_SERVER_LOGW("Unsupported IP version: %{public}d (only IPv4=4, IPv6=6 supported)", version);
        return false;
    }
}

// 转发数据到真实目标服务器 (支持IPv4和IPv6)
int ForwardToRealServer(const uint8_t* data, int dataSize, const std::string& targetIP, int targetPort, uint8_t protocol, int addressFamily, const sockaddr_in& originalPeer) {
    VPN_SERVER_LOGI("ForwardToRealServer called with target %{public}s:%{public}d", targetIP.c_str(), targetPort);
    
    // 检查是否是VPN客户端网段（根据实际配置调整）
    if (targetIP.find("192.168.0.") == 0) {
        VPN_SERVER_LOGE("Detected routing loop: target %{public}s is VPN client subnet, rejecting", targetIP.c_str());
        return -1;
    }

    // 检查是否是DNS查询，重定向到公共DNS服务器
    std::string actualTargetIP = targetIP;
    if (targetPort == 53) {
        // 强制重定向到公共DNS服务器
        if (actualTargetIP != "8.8.8.8") {
            VPN_SERVER_LOGI("Redirecting DNS query from %{public}s to public DNS 8.8.8.8", actualTargetIP.c_str());
            actualTargetIP = "8.8.8.8";
        }
        VPN_SERVER_LOGI("Using public DNS: %{public}s:%{public}d", actualTargetIP.c_str(), targetPort);
    }
    
    int sockFd;
    socklen_t addrLen;

    if (addressFamily == AF_INET6) {
        addrLen = sizeof(struct sockaddr_in6);
        VPN_SERVER_LOGI("Processing IPv6 address: %{public}s", actualTargetIP.c_str());
    } else if (addressFamily == AF_INET) {
        addrLen = sizeof(struct sockaddr_in);
        VPN_SERVER_LOGI("Processing IPv4 address: %{public}s", actualTargetIP.c_str());
    } else {
        VPN_SERVER_LOGE("Unsupported address family: %{public}d", addressFamily);
        return -1;
    }

    // 根据协议选择socket类型
    if (protocol == PROTOCOL_UDP) {  // UDP
        sockFd = socket(addressFamily, SOCK_DGRAM, 0);
        VPN_SERVER_LOGI("Using UDP socket for DNS query");
    } else {  // TCP
        sockFd = socket(addressFamily, SOCK_STREAM, 0);
        VPN_SERVER_LOGI("Using TCP socket for HTTP/HTTPS");
    }

    if (sockFd < 0) {
        VPN_SERVER_LOGE("Failed to create socket for forwarding: %{public}s", strerror(errno));
        return -1;
    }

    // 在HarmonyOS 沙盒环境中，使用标准绑定
    if (addressFamily == AF_INET6) {
        struct sockaddr_in6 bindAddr{};
        bindAddr.sin6_family = AF_INET6;
        bindAddr.sin6_addr = in6addr_any;
        bindAddr.sin6_port = htons(0);

        if (bind(sockFd, (struct sockaddr*)&bindAddr, sizeof(bindAddr)) < 0) {
            VPN_SERVER_LOGW("⚠️  Failed to bind IPv6 socket: %{public}s", strerror(errno));
            VPN_SERVER_LOGI("🔄 Using default socket binding");
        } else {
            VPN_SERVER_LOGI("Successfully bound IPv6 socket");
        }
    } else {
        struct sockaddr_in bindAddr{};
        bindAddr.sin_family = AF_INET;
        bindAddr.sin_addr.s_addr = htonl(INADDR_ANY);
        bindAddr.sin_port = htons(0);

        if (bind(sockFd, (struct sockaddr*)&bindAddr, sizeof(bindAddr)) < 0) {
            VPN_SERVER_LOGW("⚠️  Failed to bind IPv4 socket: %{public}s", strerror(errno));
            VPN_SERVER_LOGI("🔄 Using default socket binding");
        } else {
            VPN_SERVER_LOGI("Successfully bound IPv4 socket");
        }
    }

    // 设置 socket 选项
    int sockopt = 1;
    if (setsockopt(sockFd, SOL_SOCKET, SO_REUSEADDR, &sockopt, sizeof(sockopt)) < 0) {
        VPN_SERVER_LOGW("Failed to set SO_REUSEADDR: %{public}s", strerror(errno));
    }

    VPN_SERVER_LOGI("Socket created successfully for forwarding");

    // 设置目标服务器地址
    if (addressFamily == AF_INET6) {
        struct sockaddr_in6 serverAddr{};
        serverAddr.sin6_family = AF_INET6;
        serverAddr.sin6_port = htons(targetPort);

        if (inet_pton(AF_INET6, actualTargetIP.c_str(), &serverAddr.sin6_addr) <= 0) {
            VPN_SERVER_LOGE("Invalid target IPv6 address: %{public}s", actualTargetIP.c_str());
            close(sockFd);
            return -1;
        }

        // IPv6 连接逻辑
        if (protocol == 17) {  // UDP
            // UDP 直接发送数据
            int sent = sendto(sockFd, data, dataSize, 0, (struct sockaddr*)&serverAddr, sizeof(serverAddr));
            if (sent < 0) {
                VPN_SERVER_LOGE("Failed to send IPv6 UDP data: %{public}s", strerror(errno));
                close(sockFd);
                return -1;
            }

            VPN_SERVER_LOGI("IPv6 UDP data sent successfully: %{public}d bytes", sent);

            // 等待响应
            uint8_t response[BUFFER_SIZE];
            struct timeval timeout;
            timeout.tv_sec = 5;
            timeout.tv_usec = 0;
            setsockopt(sockFd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

            int received = recvfrom(sockFd, response, sizeof(response), 0, nullptr, nullptr);
            if (received > 0) {
                VPN_SERVER_LOGI("IPv6 UDP response received: %{public}d bytes", received);

                // 发送响应回客户端
                int sentBack = sendto(g_sockFd, response, received, 0, (struct sockaddr*)&originalPeer, sizeof(originalPeer));
                if (sentBack > 0) {
                    VPN_SERVER_LOGI("IPv6 UDP response sent back to client: %{public}d bytes", sentBack);
                } else {
                    VPN_SERVER_LOGE("Failed to send IPv6 UDP response back to client: %{public}s", strerror(errno));
                }
            } else {
                VPN_SERVER_LOGW("No IPv6 UDP response received or timeout");
            }
            
            close(sockFd);
            return received > 0 ? received : -1;
        } else {  // TCP
            // TCP 连接并发送数据
            if (connect(sockFd, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
                VPN_SERVER_LOGE("Failed to connect to IPv6 server %{public}s:%{public}d: %{public}s",
                               actualTargetIP.c_str(), targetPort, strerror(errno));
                close(sockFd);
                return -1;
            }

            VPN_SERVER_LOGI("Connected to IPv6 server %{public}s:%{public}d", actualTargetIP.c_str(), targetPort);

            // 发送数据
            int sent = send(sockFd, data, dataSize, 0);
            if (sent < 0) {
                VPN_SERVER_LOGE("Failed to send IPv6 TCP data: %{public}s", strerror(errno));
                close(sockFd);
                return -1;
            }

            VPN_SERVER_LOGI("IPv6 TCP data sent successfully: %{public}d bytes", sent);

            // 对于TCP，返回socket fd，让调用者启动线程处理响应
            return sockFd;
        }

    } else {
        // IPv4 逻辑
        struct sockaddr_in serverAddr{};
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_port = htons(targetPort);

        if (inet_pton(AF_INET, actualTargetIP.c_str(), &serverAddr.sin_addr) <= 0) {
            VPN_SERVER_LOGE("Invalid target IPv4 address: %{public}s", actualTargetIP.c_str());
            close(sockFd);
            return -1;
        }

        // 记录当前时间戳（使用steady_clock保持一致性）
        auto now = std::chrono::steady_clock::now();
        auto timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
        VPN_SERVER_LOGI("Network request started at: %{public}lld", timestamp);

        // 根据协议类型进行连接
        if (protocol == PROTOCOL_UDP) {  // UDP
            // 计算IP头长度
            int ipHeaderLen = (data[0] & 0x0F) * 4;  // IP头长度 = (IHL字段) * 4字节
            int udpHeaderLen = 8;  // UDP头固�?字节
            int payloadOffset = ipHeaderLen + udpHeaderLen;
            int payloadSize = dataSize - payloadOffset;
            
            if (payloadSize <= 0) {
                VPN_SERVER_LOGE("Invalid UDP packet: no payload data");
                close(sockFd);
                return -1;
            }
            
            // 只发送UDP载荷数据（不包含IP头和UDP头）
            const uint8_t* payloadData = data + payloadOffset;
            int sent = sendto(sockFd, payloadData, payloadSize, 0, (struct sockaddr*)&serverAddr, sizeof(serverAddr));
            if (sent < 0) {
                VPN_SERVER_LOGE("Failed to send IPv4 UDP data: %{public}s", strerror(errno));
                close(sockFd);
                return -1;
            }

            VPN_SERVER_LOGI("IPv4 UDP payload sent successfully: %{public}d bytes (total packet: %{public}d)", sent, dataSize);

            // 等待响应
            uint8_t response[BUFFER_SIZE];
            struct timeval timeout;
            timeout.tv_sec = 1;  // 减少超时时间到1秒
            timeout.tv_usec = 0;
            setsockopt(sockFd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
            
            VPN_SERVER_LOGI("Waiting for UDP response from %{public}s:%{public}d", actualTargetIP.c_str(), targetPort);

            int received = recvfrom(sockFd, response, sizeof(response), 0, nullptr, nullptr);
            if (received > 0) {
                VPN_SERVER_LOGI("IPv4 UDP response received: %{public}d bytes", received);

                // 发送响应回客户端
                int sentBack = sendto(g_sockFd, response, received, 0, (struct sockaddr*)&originalPeer, sizeof(originalPeer));
                if (sentBack > 0) {
                    VPN_SERVER_LOGI("IPv4 UDP response sent back to client: %{public}d bytes", sentBack);
                } else {
                    VPN_SERVER_LOGE("Failed to send IPv4 UDP response back to client: %{public}s", strerror(errno));
                }
            } else {
                VPN_SERVER_LOGW("No IPv4 UDP response received: %{public}s", strerror(errno));
            }

            close(sockFd);
            return received > 0 ? received : -1;

        } else {  // TCP
            // 设置socket为非阻塞模式
            int flags = fcntl(sockFd, F_GETFL, 0);
            fcntl(sockFd, F_SETFL, flags | O_NONBLOCK);
            
            VPN_SERVER_LOGI("Attempting non-blocking TCP connection to %{public}s:%{public}d", actualTargetIP.c_str(), targetPort);
            
            // 尝试连接
            int connectResult = connect(sockFd, (struct sockaddr*)&serverAddr, sizeof(serverAddr));
            if (connectResult < 0) {
                if (errno == EINPROGRESS) {
                    // 连接正在进行中，使用select等待连接完成
                    VPN_SERVER_LOGI("TCP connection in progress, waiting for completion...");
                    
                    fd_set writefds;
                    struct timeval timeout;
                    timeout.tv_sec = 3;  // 🔧 减少超时时间�?秒，提高响应速度
                    timeout.tv_usec = 0;
                    
                    FD_ZERO(&writefds);
                    FD_SET(sockFd, &writefds);
                    
                    int selectResult = select(sockFd + 1, nullptr, &writefds, nullptr, &timeout);
                    if (selectResult > 0) {
                        // 检查连接是否成功
                        int error = 0;
                        socklen_t len = sizeof(error);
                        if (getsockopt(sockFd, SOL_SOCKET, SO_ERROR, &error, &len) == 0 && error == 0) {
                            VPN_SERVER_LOGI("IPv4 TCP connection established successfully");
                        } else {
                            VPN_SERVER_LOGE("TCP connection failed: %{public}s", strerror(error));
                            close(sockFd);
                            return -1;
                        }
                    } else {
                        VPN_SERVER_LOGE("TCP connection timeout or failed: %{public}s", strerror(errno));
                        close(sockFd);
                        return -1;
                    }
                } else {
                    VPN_SERVER_LOGE("Failed to connect IPv4 TCP socket: %{public}s", strerror(errno));
                    close(sockFd);
                    return -1;
                }
            } else {
                VPN_SERVER_LOGI("IPv4 TCP connection established successfully immediately");
            }

            // 计算IP头长度
            int ipHeaderLen = (data[0] & 0x0F) * 4;  // IP头长度 = (IHL字段) * 4字节
            int tcpHeaderLen = (data[ipHeaderLen + 12] & 0xF0) >> 4;  // TCP头长度 = (偏移字段) * 4字节
            tcpHeaderLen *= 4;
            int payloadOffset = ipHeaderLen + tcpHeaderLen;
            int payloadSize = dataSize - payloadOffset;
            
            if (payloadSize <= 0) {
                VPN_SERVER_LOGE("Invalid TCP packet: no payload data");
                close(sockFd);
                return -1;
            }
            
            // 只发送TCP载荷数据（不包含IP头和TCP头）
            const uint8_t* payloadData = data + payloadOffset;
            int sent = send(sockFd, payloadData, payloadSize, 0);
            if (sent < 0) {
                VPN_SERVER_LOGE("Failed to send IPv4 TCP data: %{public}s", strerror(errno));
                close(sockFd);
                return -1;
            }

            VPN_SERVER_LOGI("IPv4 TCP payload sent successfully: %{public}d bytes (total packet: %{public}d)", sent, dataSize);

            // TCP响应现在由单独的线程处理，这里不关闭socket
            return sockFd;
        }
    }
}

// 处理UDP响应
void HandleUdpResponse(int sockFd, const sockaddr_in& originalPeer) {
    VPN_SERVER_LOGI("Handling UDP response");
    
    uint8_t response[BUFFER_SIZE];
    struct timeval timeout;
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;
    setsockopt(sockFd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    
    int received = recvfrom(sockFd, response, sizeof(response), 0, nullptr, nullptr);
    if (received > 0) {
        VPN_SERVER_LOGI("UDP response received: %{public}d bytes", received);
        
        // 发送响应回客户端
        int sentBack = sendto(g_sockFd, response, received, 0, (struct sockaddr*)&originalPeer, sizeof(originalPeer));
        if (sentBack > 0) {
            VPN_SERVER_LOGI("UDP response sent back to client: %{public}d bytes", sentBack);
        } else {
            VPN_SERVER_LOGE("Failed to send UDP response back to client: %{public}s", strerror(errno));
        }
    } else {
        VPN_SERVER_LOGW("No UDP response received: %{public}s", strerror(errno));
    }
    
    close(sockFd);
}

// 处理TCP响应
void HandleTcpResponse(int sockFd, const sockaddr_in& originalPeer) {
    VPN_SERVER_LOGI("Handling TCP response");
    
    uint8_t response[BUFFER_SIZE];
    struct timeval timeout;
    timeout.tv_sec = 10;  // 增加超时时间
    timeout.tv_usec = 0;
    setsockopt(sockFd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    
    while (true) {
        int received = recv(sockFd, response, sizeof(response), 0);
        if (received > 0) {
            VPN_SERVER_LOGI("TCP response received: %{public}d bytes", received);
            
            // 发送响应回客户端
            int sentBack = sendto(g_sockFd, response, received, 0, (struct sockaddr*)&originalPeer, sizeof(originalPeer));
            if (sentBack > 0) {
                VPN_SERVER_LOGI("TCP response sent back to client: %{public}d bytes", sentBack);
            } else {
                VPN_SERVER_LOGE("Failed to send TCP response back to client: %{public}s", strerror(errno));
                break;
            }
        } else if (received == 0) {
            VPN_SERVER_LOGI("TCP connection closed by peer");
            break;
        } else {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                VPN_SERVER_LOGW("TCP response timeout");
            } else {
                VPN_SERVER_LOGW("No TCP response received: %{public}s", strerror(errno));
            }
            break;
        }
    }
    
    close(sockFd);
    VPN_SERVER_LOGI("TCP response handler finished");
}

// 处理转发响应
void HandleForwardResponse(int sockFd, const sockaddr_in& originalPeer) {
    VPN_SERVER_LOGI("Handling forward response");
    
    uint8_t response[BUFFER_SIZE];
    int received = recv(sockFd, response, sizeof(response), 0);
    if (received > 0) {
        VPN_SERVER_LOGI("Forward response received: %{public}d bytes", received);
        
        // 发送响应回客户端
        int sentBack = sendto(g_sockFd, response, received, 0, (struct sockaddr*)&originalPeer, sizeof(originalPeer));
        if (sentBack > 0) {
            VPN_SERVER_LOGI("Forward response sent back to client: %{public}d bytes", sentBack);
        } else {
            VPN_SERVER_LOGE("Failed to send forward response back to client: %{public}s", strerror(errno));
        }
    } else {
        VPN_SERVER_LOGW("No forward response received: %{public}s", strerror(errno));
    }
    
    close(sockFd);
}

// 测试UDP连通性
void TestUDPConnectivity() {
    VPN_SERVER_LOGI("=== Testing UDP Connectivity ===");

    int testSock = socket(AF_INET, SOCK_DGRAM, 0);
    if (testSock < 0) {
        VPN_SERVER_LOGE("Failed to create UDP test socket: %{public}s", strerror(errno));
        return;
    }

    // 绑定到本地端口
    struct sockaddr_in localAddr{};
    localAddr.sin_family = AF_INET;
    localAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    localAddr.sin_port = htons(0);

    if (bind(testSock, (struct sockaddr*)&localAddr, sizeof(localAddr)) < 0) {
        VPN_SERVER_LOGE("Failed to bind UDP test socket: %{public}s", strerror(errno));
        close(testSock);
        return;
    }

    VPN_SERVER_LOGI("UDP test socket bound successfully");
    
    // 测试发送到公共DNS服务器
    struct sockaddr_in dnsAddr{};
    dnsAddr.sin_family = AF_INET;
    dnsAddr.sin_port = htons(53);
    inet_pton(AF_INET, "8.8.8.8", &dnsAddr.sin_addr);
    
    const char* testData = "ping";
    int sent = sendto(testSock, testData, strlen(testData), 0, (struct sockaddr*)&dnsAddr, sizeof(dnsAddr));
    if (sent < 0) {
        VPN_SERVER_LOGE("Failed to send UDP test: %{public}s", strerror(errno));
        close(testSock);
        return;
    }
    
    VPN_SERVER_LOGI("�?UDP test data sent: %{public}d bytes", sent);
    
    // 设置超时
    struct timeval timeout;
    timeout.tv_sec = 2;
    timeout.tv_usec = 0;
    setsockopt(testSock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    
    // 尝试接收响应
    char buffer[1024];
    int received = recvfrom(testSock, buffer, sizeof(buffer), 0, nullptr, nullptr);
    if (received > 0) {
        VPN_SERVER_LOGI("�?UDP response received: %{public}d bytes", received);
    } else {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            VPN_SERVER_LOGI("ℹ️  UDP test timeout (expected for invalid data)");
        } else {
            VPN_SERVER_LOGE("�?UDP test recv error: %{public}s", strerror(errno));
        }
    }
    
    close(testSock);
    VPN_SERVER_LOGI("=== UDP Connectivity Test Complete ===");
}

// 更新客户端信息
void UpdateClientInfo(const std::string& ip, int port, int bytesReceived)
{
  std::lock_guard<std::mutex> lock(g_clientsMutex);
  std::string clientKey = ip + ":" + std::to_string(port);
  
  auto it = g_clients.find(clientKey);
  if (it != g_clients.end()) {
    it->second.packetsCount++;
    it->second.totalBytes += bytesReceived;
    it->second.lastSeen = std::to_string(std::time(nullptr));
  } else {
    ClientInfo newClient;
    newClient.ip = ip;
    newClient.port = port;
    newClient.packetsCount = 1;
    newClient.totalBytes = bytesReceived;
    newClient.lastSeen = std::to_string(std::time(nullptr));
    g_clients[clientKey] = newClient;
  }
}

std::string EscapeJsonString(const std::string& str)
{
  std::string escaped;
  escaped.reserve(str.length() + 10);
  for (char c : str) {
    switch (c) {
      case '"':  escaped += "\\\""; break;
      case '\\': escaped += "\\\\"; break;
      case '\b': escaped += "\\b"; break;
      case '\f': escaped += "\\f"; break;
      case '\n': escaped += "\\n"; break;
      case '\r': escaped += "\\r"; break;
      case '\t': escaped += "\\t"; break;
      default:
        if (c >= 0x00 && c < 0x20) {
          // 控制字符转义�?\uXXXX
          char hex[7];
          snprintf(hex, sizeof(hex), "\\u%04x", static_cast<unsigned char>(c));
          escaped += hex;
        } else {
          escaped += c;
        }
        break;
    }
  }
  return escaped;
}

void AddDataPacket(const std::string& data, const std::string& client, const std::string& dataType = "data")
{
  std::lock_guard<std::mutex> lock(g_dataBufferMutex);
  
  // Create packet info
  time_t now = std::time(nullptr);
  std::string timestamp = std::to_string(now);
  
  // Truncate data if too long
  std::string truncatedData = data;
  if (truncatedData.length() > 100) {
    truncatedData = truncatedData.substr(0, 100) + "...";
  }
  
  // 转义JSON特殊字符
  std::string escapedData = EscapeJsonString(truncatedData);
  std::string escapedClient = EscapeJsonString(client);
  std::string escapedType = EscapeJsonString(dataType);
  
  std::string packetEntry = "{\"timestamp\":\"" + timestamp + "\",\"client\":\"" + escapedClient + "\",\"data\":\"" + escapedData + "\",\"type\":\"" + escapedType + "\"}";
  
  g_dataBuffer.insert(g_dataBuffer.begin(), packetEntry);
  
  // Keep buffer size limited
  if (g_dataBuffer.size() > MAX_DATA_BUFFER) {
    g_dataBuffer.resize(MAX_DATA_BUFFER);
  }
}

std::string FormatTime(const std::string& timestamp)
{
  try {
    time_t rawtime = static_cast<time_t>(std::stoul(timestamp));
    // 使用线程安全�?localtime_r() 替代 localtime()，避免多线程环境下的死锁问题
    struct tm timeinfo;
    struct tm * result = localtime_r(&rawtime, &timeinfo);
    if (result == nullptr) {
      // localtime_r 失败时返回原始时间戳
      return timestamp;
    }
    char buffer[80];
    strftime(buffer, sizeof(buffer), "%H:%M:%S", &timeinfo);
    return std::string(buffer);
  } catch (...) {
    return timestamp;
  }
}

std::string BytesToHex(const uint8_t* data, size_t len, size_t maxBytes = 32)
{
  std::string hexStr;
  std::string asciiStr;
  size_t displayLen = std::min(len, maxBytes);
  
  for (size_t i = 0; i < displayLen; ++i) {
    char hex[4];
    snprintf(hex, sizeof(hex), "%02x ", data[i]);
    hexStr += hex;
    
    // 添加ASCII可打印字符预览（不可打印字符显示为.）
    if (data[i] >= 32 && data[i] < 127) {
      asciiStr += static_cast<char>(data[i]);
    } else {
      asciiStr += '.';
    }
  }
  
  std::string result = hexStr;
  if (len > maxBytes) {
    result += "...";
  }
  result += " (" + asciiStr;
  if (len > maxBytes) {
    result += "...";
  }
  result += ")";
  
  return result;
}

std::string IdentifyPacketType(const uint8_t* data, size_t len)
{
  if (len < 1) {
    return "Unknown";
  }
  
  // 检查IPv4 (第一个字节的�?位通常�?x4，但需要检查IP头长�?
  if (len >= 20 && (data[0] & 0xF0) == 0x40) {
    uint8_t ipHeaderLen = (data[0] & 0x0F) * 4;
    if (ipHeaderLen >= 20 && len >= ipHeaderLen) {
      uint8_t protocol = data[9];
      std::string protoStr;
      switch (protocol) {
        case 1: protoStr = "ICMP"; break;
        case 6: protoStr = "TCP"; break;
        case 17: protoStr = "UDP"; break;
        case 41: protoStr = "IPv6"; break;
        case 47: protoStr = "GRE"; break;
        default: protoStr = "IPv4(proto=" + std::to_string(protocol) + ")";
      }
      return "IPv4/" + protoStr;
    }
  }
  
  // 检查IPv6 (第一个字节的�?位是0x6)
  if (len >= 40 && (data[0] & 0xF0) == 0x60) {
    uint8_t nextHeader = data[6];
    std::string nextStr;
    switch (nextHeader) {
      case 1: nextStr = "ICMP"; break;
      case 6: nextStr = "TCP"; break;
      case 17: nextStr = "UDP"; break;
      case 58: 
        if (len >= 48) {
          // 检查ICMPv6类型
          uint8_t icmpv6Type = data[40];
          switch (icmpv6Type) {
            case 133: nextStr = "ICMPv6(Router Solicitation)"; break;
            case 134: nextStr = "ICMPv6(Router Advertisement)"; break;
            case 135: nextStr = "ICMPv6(Neighbor Solicitation)"; break;
            case 136: nextStr = "ICMPv6(Neighbor Advertisement)"; break;
            case 128: nextStr = "ICMPv6(Echo Request)"; break;
            case 129: nextStr = "ICMPv6(Echo Reply)"; break;
            default: nextStr = "ICMPv6(type=" + std::to_string(icmpv6Type) + ")";
          }
        } else {
          nextStr = "ICMPv6";
        }
        break;
      default: nextStr = "NextHeader=" + std::to_string(nextHeader);
    }
    return "IPv6/" + nextStr;
  }
  
  // 检查ARP (以太网类�?x0806，但这里可能是裸ARP)
  if (len >= 28 && (data[0] == 0x00 && data[1] == 0x01)) {
    return "ARP";
  }
  
  // 检查是否是文本数据
  bool isText = true;
  for (size_t i = 0; i < std::min(len, size_t(100)); ++i) {
    if (data[i] < 32 && data[i] != 9 && data[i] != 10 && data[i] != 13) {
      isText = false;
      break;
    }
  }
  if (isText) {
    return "Text";
  }
  
  return "Binary";
}

void WorkerLoop()
{
  VPN_SERVER_LOGI("🔄 WorkerLoop started - waiting for client data...");
  VPN_SERVER_LOGI("📡 Socket fd: %{public}d, g_running: %{public}d", g_sockFd.load(), g_running.load() ? 1 : 0);
  
  // 🔍 详细诊断：显示服务器监听信息
  sockaddr_in serverAddr {};
  socklen_t serverAddrLen = sizeof(serverAddr);
  if (getsockname(g_sockFd.load(), reinterpret_cast<sockaddr*>(&serverAddr), &serverAddrLen) == 0) {
    char serverIP[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &serverAddr.sin_addr, serverIP, sizeof(serverIP));
    VPN_SERVER_LOGI("🔍🔍🔍 服务器监听详�? IP=%{public}s, Port=%{public}d, Socket=%{public}d", 
                   serverIP, ntohs(serverAddr.sin_port), g_sockFd.load());
    VPN_SERVER_LOGI("🔍🔍🔍 VPN客户端应该连接到: 127.0.0.1:8888");
  } else {
    VPN_SERVER_LOGE("�?无法获取服务器监听地址: %{public}s", strerror(errno));
  }
  
  uint8_t buf[BUFFER_SIZE];
  int loopCount = 0;
  while (g_running.load()) {
    loopCount++;
    // 🔍 每1000次循环记录一次，确认循环在运行
    if (loopCount % 1000 == 0) {
      VPN_SERVER_LOGI("🔍 WorkerLoop运行中... (循环#%{public}d, socket=%{public}d)", 
                     loopCount, g_sockFd.load());
    }
    
    // 🔧 获取当前socket fd（atomic变量需要load）
    int currentSockFd = g_sockFd.load();
    
    if (currentSockFd < 0) {
      VPN_SERVER_LOGE("❌ Socket无效，等待...");
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
      continue;
    }
    
    // 使用select检查socket是否有数据可读，避免无限期阻塞
    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(currentSockFd, &readfds);
    
    struct timeval timeout;
    timeout.tv_sec = 0;
    timeout.tv_usec = 100000;  // 100ms超时，快速响应停止信号
    
    // 🔍 诊断：检查socket是否仍然有效
    int socketError = 0;
    socklen_t errorLen = sizeof(socketError);
    if (getsockopt(currentSockFd, SOL_SOCKET, SO_ERROR, &socketError, &errorLen) == 0) {
      if (socketError != 0) {
        VPN_SERVER_LOGE("�?Socket错误: errno=%{public}d (%{public}s)", socketError, strerror(socketError));
      }
    }
    
    // 🔍 诊断：在select之前尝试非阻塞recvfrom，检查是否有数据
    static int preCheckCount = 0;
    if (++preCheckCount % 1000 == 0) {
      uint8_t preCheckBuf[1];
      sockaddr_in preCheckPeer {};
      socklen_t preCheckPeerLen = sizeof(preCheckPeer);
      int preCheckRecv = recvfrom(currentSockFd, preCheckBuf, sizeof(preCheckBuf), MSG_DONTWAIT | MSG_PEEK,
                                 reinterpret_cast<sockaddr*>(&preCheckPeer), &preCheckPeerLen);
      if (preCheckRecv > 0) {
        VPN_SERVER_LOGI("🔍🔍🔍 发现数据！recvfrom(MSG_PEEK)返回 %{public}d字节", preCheckRecv);
      } else if (preCheckRecv < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
        VPN_SERVER_LOGE("�?recvfrom(MSG_PEEK)错误: errno=%{public}d (%{public}s)", errno, strerror(errno));
      }
    }
    
    int selectResult = select(currentSockFd + 1, &readfds, nullptr, nullptr, &timeout);
    
    if (selectResult < 0) {
      if (!g_running.load()) {
        VPN_SERVER_LOGI("🛑 Server stopping, breaking loop");
        break;
      }
      if (errno == EINTR) {
        continue;  // 被信号中断，继续
      }
      VPN_SERVER_LOGE("�?select error: %{public}s", strerror(errno));
      continue;
    }
    
    if (selectResult == 0) {
      // 超时，检查是否应该停止
      if (!g_running.load()) {
        VPN_SERVER_LOGI("🛑 Server stopping (timeout check), breaking loop");
        break;
      }
      // 🔍 每100次超时记录一次，便于诊断
      static int timeoutCount = 0;
      if (++timeoutCount % 100 == 0) {
        VPN_SERVER_LOGI("🔍 select timeout #%{public}d (等待数据中... socket=%{public}d, 监听127.0.0.1:8888)", 
                       timeoutCount, currentSockFd);
      }
      continue;  // 超时但没有数据，继续循环
    }
    
    // 🔍 有数据可读 - 必须检查FD_ISSET
    if (!FD_ISSET(currentSockFd, &readfds)) {
      // select返回>0但当前socket不在readfds中，可能是其他socket有数据
      VPN_SERVER_LOGE("⚠️ select返回>0但socket不在readfds中，跳过");
      continue;
    }
    
    VPN_SERVER_LOGI("🔍🔍🔍 select检测到数据可读 (socket=%{public}d) - 准备接收", currentSockFd);
    
    sockaddr_in peer {};
    socklen_t peerLen = sizeof(peer);
    
    if (!g_running.load()) {
      VPN_SERVER_LOGI("ZHOUB [STOP] Loop exit requested");
      break;
    }
    
    int n = recvfrom(currentSockFd, buf, sizeof(buf), 0, reinterpret_cast<sockaddr *>(&peer), &peerLen);

    if (n < 0) {
      // 检查是否是因为服务器正在停止
      if (!g_running.load()) {
        VPN_SERVER_LOGI("ZHOUB [STOP] recvfrom interrupted by server shutdown");
        break;
      }
      
      // 🔧 关键修复：非阻塞socket在没有数据时返回EAGAIN/EWOULDBLOCK，这是正常的，应该继续循环
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        // 🔥 调试：每1000次超时记录一次，确认循环在运行
        static int eagainCount = 0;
        if (++eagainCount % 1000 == 0) {
          VPN_SERVER_LOGI("ZHOUB [DEBUG] recvfrom EAGAIN #%{public}d (等待数据中...)", eagainCount);
        }
        // 非阻塞模式下没有数据是正常的，继续等待
        std::this_thread::sleep_for(std::chrono::milliseconds(10));  // 避免CPU占用过高
        continue;
      }
      
      // 其他错误处理
      int savedErrno = errno;
      if (savedErrno == ENOMEM) {
        // 🔧 修复：内存不足不应该导致服务器退出，应该记录并继续
        VPN_SERVER_LOGE("ZHOUB [ERROR] recvfrom内存不足: errno=%{public}d (%{public}s) - 继续运行", 
                       savedErrno, strerror(savedErrno));
        std::this_thread::sleep_for(std::chrono::milliseconds(100));  // 等待内存释放
        continue;  // 继续循环，不退出
      } else {
        // 其他严重错误才退出
        VPN_SERVER_LOGE("ZHOUB [ERROR] recvfrom failed: errno=%{public}d (%{public}s)",
                        savedErrno, strerror(savedErrno));
        VPN_SERVER_LOGI("ZHOUB [STOP] Loop exit on error");
        break;
      }
    }
    
    if (n == 0) {
      VPN_SERVER_LOGI("⚠️ Received empty packet, ignoring");
      continue;
    }

    // Update statistics
    g_packetsReceived.fetch_add(1);
    g_bytesReceived.fetch_add(n);
    
    std::string peerAddr = inet_ntoa(peer.sin_addr);
    int peerPort = ntohs(peer.sin_port);
    
    std::string clientKey = peerAddr + ":" + std::to_string(peerPort);
    
    std::string dataStr(reinterpret_cast<char*>(buf), std::min(n, BUFFER_SIZE));
    std::string hexData = BytesToHex(buf, n, 64);
    std::string packetType = IdentifyPacketType(buf, n);
    
    // 🔥 ZHOUB调试日志：记录所有接收到的数据包（包括测试包）
    VPN_SERVER_LOGI("ZHOUB [RX] %{public}d bytes from %{public}s (前16字节: %{public}s)", 
                   n, clientKey.c_str(), hexData.substr(0, 32).c_str());
    
    // 🔥 版本识别日志：IPv4/IPv6/非IP
    uint8_t ipVersion = (n >= 1) ? ((buf[0] >> 4) & 0x0F) : 0;
    if (ipVersion == 4) {
        VPN_SERVER_LOGI("ZHOUB [VER] IPv4 packet: %{public}d bytes", n);
    } else if (ipVersion == 6) {
        VPN_SERVER_LOGI("ZHOUB [VER] IPv6 packet: %{public}d bytes", n);
    } else {
        VPN_SERVER_LOGI("ZHOUB [VER] Non-IP packet: ver=%{public}u size=%{public}d", ipVersion, n);
    }

    // 🔥 检查是否是测试包（非IPv4包）
    if (n < 20 || ipVersion != 4) {
        VPN_SERVER_LOGI("ZHOUB [DEBUG] 跳过非IPv4包: ver=%{public}u size=%{public}d", ipVersion, n);
        continue;  // 仅处理IPv4
    }
    
    // 🔥 检查是否是TestDNSQuery发送的测试包（包含IP头，首位是0x45）
    if (n >= 20 && (buf[0] >> 4) == 4 && buf[9] == 17) {
      // 这是一个IPv4 UDP包，可能是TestDNSQuery发送的完整IP包
      char srcIP[INET_ADDRSTRLEN], dstIP[INET_ADDRSTRLEN];
      inet_ntop(AF_INET, &buf[12], srcIP, sizeof(srcIP));
      inet_ntop(AF_INET, &buf[16], dstIP, sizeof(dstIP));
      VPN_SERVER_LOGI("ZHOUB [DEBUG] 检测到完整IP包: %{public}s -> %{public}s (可能是TestDNSQuery测试包)", 
                     srcIP, dstIP);
    }
    
    // Update last activity and client info (no logging to reduce output)
    {
      std::lock_guard<std::mutex> lock(g_lastActivityMutex);  // 🔧 使用专用锁
      g_lastActivity = clientKey;
    }
    UpdateClientInfo(peerAddr, peerPort, n);

    // 统计信息：每100个包记录一次，避免日志过多
    static uint32_t packetCount = 0;
    packetCount++;
    if (packetCount % 100 == 0) {
        VPN_SERVER_LOGI("📊 处理统计: %{public}u个数据包 (%{public}lu字节发�? %{public}lu字节接收)",
                        packetCount, (unsigned long)g_bytesSent.load(), (unsigned long)g_bytesReceived.load());
    }
    
    // 检查是否是心跳包
    if (n == 4 && dataStr == "ping") {
      VPN_SERVER_LOGI("Heartbeat received from [%{public}s:%{public}d]: ping", peerAddr.c_str(), peerPort);
      
      // 添加心跳包到数据缓冲区
      AddDataPacket("ping", clientKey, "heartbeat");
      
      // 发送pong响应
      const char* pongMsg = "pong";
      int pongLen = strlen(pongMsg);
      int s = sendto(currentSockFd, pongMsg, pongLen, 0, reinterpret_cast<sockaddr *>(&peer), peerLen);
      if (s >= 0) {
        VPN_SERVER_LOGI("Heartbeat response sent to [%{public}s:%{public}d]: pong", peerAddr.c_str(), peerPort);
        g_packetsSent.fetch_add(1);
        g_bytesSent.fetch_add(s);
      } else {
        VPN_SERVER_LOGE("Failed to send pong response to [%{public}s:%{public}d]: %{public}s", 
                        peerAddr.c_str(), peerPort, strerror(errno));
      }
    } else {
      // 使用新的协议处理器解析数据包
      PacketInfo packetInfo = ProtocolHandler::ParseIPPacket(buf, n);
      
      if (!packetInfo.isValid) {
        // 静默丢弃无法解析的数据包，只在调试时需要日志
        AddDataPacket(hexData, clientKey, packetType);
        continue;
      }

      // 解析成功，静默处理避免日志过多
      
      // 添加数据包到缓冲区（用于UI显示）
      std::string targetInfo;
      if (packetInfo.protocol == PROTOCOL_ICMPV6) {
        targetInfo = packetInfo.targetIP + " (ICMPv6:" + ProtocolHandler::GetICMPv6TypeName(packetInfo.icmpv6Type) + ")";
      } else {
        targetInfo = packetInfo.targetIP + ":" + std::to_string(packetInfo.targetPort);
      }
      AddDataPacket(hexData, clientKey + " -> " + targetInfo, packetType);
      
      // 🔥 ZHOUB日志：代理服务器接收到的代理请求
      char clientIP[INET_ADDRSTRLEN];
      inet_ntop(AF_INET, &peer.sin_addr, clientIP, sizeof(clientIP));
      if (packetInfo.protocol == PROTOCOL_ICMPV6) {
        VPN_SERVER_LOGI("ZHOUB [代理接收] 源IP:%{public}s 目的IP:%{public}s 源端�?0 目的端口:0 协议:ICMPv6 大小:%{public}d字节",
                       clientIP, packetInfo.targetIP.c_str(), n);
      } else {
        VPN_SERVER_LOGI("ZHOUB [代理接收] 源IP:%{public}s 目的IP:%{public}s 源端�?%{public}d 目的端口:%{public}d 协议:%{public}s 大小:%{public}d字节",
                       packetInfo.sourceIP.c_str(), packetInfo.targetIP.c_str(), 
                       packetInfo.sourcePort, packetInfo.targetPort,
                       ProtocolHandler::GetProtocolName(packetInfo.protocol).c_str(), n);
      }
      
      // ICMPv6 特殊处理：某些 ICMPv6 消息不需要转发
      if (packetInfo.protocol == PROTOCOL_ICMPV6) {
        // Router Solicitation/Advertisement 和 Neighbor Solicitation/Advertisement 通常不需要转发
        // 这些是本地链路层消息
        if (packetInfo.icmpv6Type == ICMPV6_ROUTER_SOLICITATION ||
            packetInfo.icmpv6Type == ICMPV6_ROUTER_ADVERTISEMENT ||
            packetInfo.icmpv6Type == ICMPV6_NEIGHBOR_SOLICITATION ||
            packetInfo.icmpv6Type == ICMPV6_NEIGHBOR_ADVERTISEMENT) {
          VPN_SERVER_LOGI("ℹ️  ICMPv6 %{public}s 是本地链路消息，不需要转发", 
                          ProtocolHandler::GetICMPv6TypeName(packetInfo.icmpv6Type).c_str());
          continue;
        }
        VPN_SERVER_LOGI("🔄 [ICMPv6转发] ICMPv6 消息: Type=%{public}d (%{public}s) -> %{public}s", 
                        packetInfo.icmpv6Type, 
                        ProtocolHandler::GetICMPv6TypeName(packetInfo.icmpv6Type).c_str(),
                        packetInfo.targetIP.c_str());
      }
      
      // 🔧 提交转发任务到队列（异步处理）
      
      // 🔍 统计接收到的数据包类型
      static std::map<std::string, int> packetStats;
      std::string packetKey = std::string(ProtocolHandler::GetProtocolName(packetInfo.protocol)) + 
                             ":" + packetInfo.targetIP + ":" + std::to_string(packetInfo.targetPort);
      packetStats[packetKey]++;
      
      // 每100个包或每10秒记录一次统计
      static int totalPackets = 0;
      static auto lastLogTime = std::chrono::steady_clock::now();
      totalPackets++;
      auto now = std::chrono::steady_clock::now();
      auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - lastLogTime).count();
      
      if (totalPackets % 100 == 0 || elapsed >= 10) {
        VPN_SERVER_LOGI("📊 [流量统计] 总计接收: %{public}d个数据包", totalPackets);
        for (const auto& stat : packetStats) {
          VPN_SERVER_LOGI("   %{public}s: %{public}d次", stat.first.c_str(), stat.second);
        }
        lastLogTime = now;
      }
      
      VPN_SERVER_LOGI("🔍 [接收] 客户端地址: %{public}s:%{public}d, 数据�? %{public}s -> %{public}s:%{public}d", 
                     clientIP, ntohs(peer.sin_port),
                     ProtocolHandler::GetProtocolName(packetInfo.protocol).c_str(),
                     packetInfo.targetIP.c_str(), packetInfo.targetPort);
      
      if (!TaskQueueManager::getInstance().submitForwardTask(buf, n, packetInfo, peer, currentSockFd)) {
        VPN_SERVER_LOGE("ZHOUB [FWD✗] Failed to submit task (queue full)");
      } else {
        VPN_SERVER_LOGI("ZHOUB [FWD→] %{public}s -> %{public}s:%{public}d (queued) | workerRunning=%{public}d fwdQ=%{public}zu respQ=%{public}zu",
                        ProtocolHandler::GetProtocolName(packetInfo.protocol).c_str(),
                        packetInfo.targetIP.c_str(), packetInfo.targetPort,
                        WorkerThreadPool::getInstance().isRunning() ? 1 : 0,
                        TaskQueueManager::getInstance().getForwardQueueSize(),
                        TaskQueueManager::getInstance().getResponseQueueSize());
      }
    }
  }
}

napi_value StartServer(napi_env env, napi_callback_info info)
{
  // 使用系统日志，确保能看到
  OH_LOG_Print(LOG_APP, LOG_INFO, 0x15b1, "VpnServer", "ZHOUB 🚀🚀🚀 StartServer FUNCTION CALLED - VPN SERVER STARTING NOW 🚀🚀🚀");
  VPN_SERVER_LOGI("🚀🚀🚀 StartServer FUNCTION CALLED - VPN SERVER STARTING NOW 🚀🚀🚀");
  
  size_t argc = 1;
  napi_value args[1] = {nullptr};
  napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);

  int32_t port = 0;
  if (argc >= 1) {
    napi_get_value_int32(env, args[0], &port);
  }

  OH_LOG_Print(LOG_APP, LOG_INFO, 0x15b1, "VpnServer", "ZHOUB 📡 StartServer called with port: %{public}d", port);
  VPN_SERVER_LOGI("📡 StartServer called with port: %{public}d", port);

  if (port <= 0 || port > 65535) {
    napi_value ret;
    napi_create_int32(env, -2, &ret);
    return ret;
  }

  // 如果服务器已经在运行，先停止它
  if (g_running.load()) {
    VPN_SERVER_LOGI("⚠️ Server already running, stopping old instance...");
    g_running.store(false);
    
    // 🔧 atomic 变量不需要锁保护
    int sockFd = g_sockFd.exchange(-1);  // 原子交换
    if (sockFd >= 0) {
      close(sockFd);
    }
    
    // 使用timeout join而不是detach，确保线程正确退出
    // WorkerLoop会在检查g_running时发现为false，然后退出循环
    if (g_worker.joinable()) {
        VPN_SERVER_LOGI("🔄 Waiting for old worker thread to exit...");
        
        // 等待线程自然退出，最多等待2秒
        auto start = std::chrono::steady_clock::now();
        while (g_running.load() && 
               std::chrono::steady_clock::now() - start < std::chrono::seconds(2)) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        
        if (g_worker.joinable()) {
            g_worker.detach();  // 如果超时才detach
            VPN_SERVER_LOGI("⚠️ Worker thread timeout, detached");
        } else {
            VPN_SERVER_LOGI("✅ Worker thread exited cleanly");
        }
    }
    // 给旧线程一点时间退出（非阻塞）
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }

  VPN_SERVER_LOGI("ZHOUB [START] VPN Server on port %{public}d", port);
  
  // 🔄 初始化线程池
  if (!InitializeThreadPool(2, 2, 1)) {
    VPN_SERVER_LOGE("❌ Failed to initialize thread pool");
    napi_value ret;
    napi_create_int32(env, -1, &ret);
    return ret;
  }
  VPN_SERVER_LOGI("✅ Thread pool initialized");

  // 停止旧的工作线程池（如果存在）
  if (WorkerThreadPool::getInstance().isRunning()) {
    VPN_SERVER_LOGI("⚠️ Worker thread pool already running, stopping it...");
    WorkerThreadPool::getInstance().stop();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }
  
  // 清理任务队列
  TaskQueueManager::getInstance().clear();
  VPN_SERVER_LOGI("�?Task queues cleared");
  
  // 启动工作线程�?  VPN_SERVER_LOGI("🚀 Starting worker thread pool with 4 forward and 2 response workers...");
  if (!WorkerThreadPool::getInstance().start(4, 2)) {
    VPN_SERVER_LOGE("�?Failed to start worker thread pool - THIS IS CRITICAL!");
    VPN_SERVER_LOGE("�?Worker thread pool state: isRunning=%d", WorkerThreadPool::getInstance().isRunning() ? 1 : 0);
  } else {
    VPN_SERVER_LOGI("�?Worker thread pool started: 4 forward workers, 2 response workers");
    VPN_SERVER_LOGI("�?Worker thread pool state: isRunning=%d", WorkerThreadPool::getInstance().isRunning() ? 1 : 0);

    // 🔍 显示初始统计信息
    auto stats = WorkerThreadPool::getInstance().getStats();
    VPN_SERVER_LOGI("📊 Initial worker stats: forward_processed=%" PRIu64 ", response_processed=%" PRIu64 ", forward_failed=%" PRIu64 ", response_failed=%" PRIu64,
                   stats.forwardTasksProcessed, stats.responseTasksProcessed,
                   stats.forwardTasksFailed, stats.responseTasksFailed);

    // 🚨 关键诊断：检查是否有任务正在处理
    VPN_SERVER_LOGI("🔍 [诊断开始] 检查工作线程池是否正常工作...");
    VPN_SERVER_LOGI("🔍 [诊断] 工作线程池运行状态: %s", WorkerThreadPool::getInstance().isRunning() ? "正常" : "异常");
    VPN_SERVER_LOGI("🔍 [诊断] 任务队列状态: 待检查");
    VPN_SERVER_LOGI("🔍 [诊断结束] 如果看到'Forward worker received task'日志，说明工作正常");

    // 🧪 添加一个简单的自检测试
    VPN_SERVER_LOGI("🧪 [自检测试] 开始系统自检诊断...");

    // 延迟执行，让系统先运行一会儿
    std::thread([=]() {
        std::this_thread::sleep_for(std::chrono::seconds(3));

        VPN_SERVER_LOGI("🧪 [自检测试] ===== 系统状态检�?=====");

        // check worker thread pool status
        bool isRunning = WorkerThreadPool::getInstance().isRunning();
        VPN_SERVER_LOGI("🧪 [检�?] 工作线程池运行状�? %s", isRunning ? "�?正常" : "�?异常");

        // check stats
        auto stats = WorkerThreadPool::getInstance().getStats();
        VPN_SERVER_LOGI("🧪 [检�?] 任务处理统计:");
        VPN_SERVER_LOGI("   - 转发任务已处理: %" PRIu64, stats.forwardTasksProcessed);
        VPN_SERVER_LOGI("   - 转发任务失败: %" PRIu64, stats.forwardTasksFailed);
        VPN_SERVER_LOGI("   - 响应任务已处理: %" PRIu64, stats.responseTasksProcessed);
        VPN_SERVER_LOGI("   - 响应任务失败: %" PRIu64, stats.responseTasksFailed);

        // 检查任务队�?        VPN_SERVER_LOGI("🧪 [检�?] 任务队列状�? 监控�?..");

        // 诊断建议
        VPN_SERVER_LOGI("🧪 [系统诊断结果]");

        // 详细诊断每个环节
        VPN_SERVER_LOGI("🔍 [诊断1] 工作线程池状�?");
        if (!isRunning) {
            VPN_SERVER_LOGI("  ❌ 工作线程池未运行 - 这是致命问题，请重启应用");
            VPN_SERVER_LOGI("  💡 建议：检查应用是否正常启动，查看系统日志中的崩溃信息");
        } else {
            VPN_SERVER_LOGI("  ✅ 工作线程池正常运行");
        }

        VPN_SERVER_LOGI("🔍 [诊断2] 任务处理状态");
        if (stats.forwardTasksProcessed == 0) {
            VPN_SERVER_LOGI("  ⚠️  没有转发任务被处理 - VPN客户端没有发送数据或数据丢失");
            VPN_SERVER_LOGI("  💡 建议：检查VPN客户端是否正常运行，确认TUN设备流量");
        } else {
            VPN_SERVER_LOGI("  ✅ 已处理 %" PRIu64 " 个转发任务", stats.forwardTasksProcessed);
        }

        VPN_SERVER_LOGI("🔍 [诊断3] 任务成功率");
        if (stats.forwardTasksProcessed > 0) {
            double successRate = (stats.forwardTasksProcessed - stats.forwardTasksFailed) * 100.0 / stats.forwardTasksProcessed;
            if (successRate < 50.0) {
                VPN_SERVER_LOGI("  ⚠️  转发成功率只有 %.1f%% - 网络连接或目标服务器问题", successRate);
                VPN_SERVER_LOGI("  💡 建议：检查网络连通性，测试目标服务器可达性");
            } else {
                VPN_SERVER_LOGI("  ✅ 转发成功率 %.1f%% - 任务处理正常", successRate);
            }
        }

        VPN_SERVER_LOGI("🔍 [诊断4] 响应处理状态");
        if (stats.responseTasksProcessed == 0) {
            VPN_SERVER_LOGI("  ⚠️  没有响应任务被处理 - 可能服务器没有收到响应或响应处理失败");
            VPN_SERVER_LOGI("  💡 建议：检查网络双向连通性，确认响应线程正常启动");
        } else {
            VPN_SERVER_LOGI("  ✅ 已处理 %" PRIu64 " 个响应任务", stats.responseTasksProcessed);
        }

        // 综合判断
        VPN_SERVER_LOGI("🎯 [综合诊断]");
        if (!isRunning) {
            VPN_SERVER_LOGI("🚨 根本问题：工作线程池启动失败 - 需要重启应用");
        } else if (stats.forwardTasksProcessed == 0) {
            VPN_SERVER_LOGI("🚨 根本问题：没有数据流�?- VPN客户端或TUN设备问题");
        } else if (stats.forwardTasksFailed >= stats.forwardTasksProcessed) {
            VPN_SERVER_LOGI("🚨 根本问题：所有转发任务都失败 - 网络连接问题");
        } else if (stats.responseTasksProcessed == 0) {
            VPN_SERVER_LOGI("🚨 根本问题：响应处理中断 - 网络单向可达但双向通信失败");
        } else {
            VPN_SERVER_LOGI("✅ 系统核心功能正常 - 如果网站仍无法访问，检查DNS或应用层问题");
        }

        VPN_SERVER_LOGI("🧪 [自检测试] ===== 自检完成 =====");
    }).detach();
  }
  
  // 清理UDP重传管理器
  UdpRetransmitManager::getInstance().clear();
  
  // DNS缓存已删除
  VPN_SERVER_LOGI("✅ DNS cache cleared");
  
  // 🚨 BUG修复：注释掉错误的NAT表清空调用
  // 这个Clear调用会清空所有NAT映射，导致UDP响应失败
  // NATTable::Clear();
  // VPN_SERVER_LOGI("❌ NAT table cleared");
  LOG_ERROR("ZHOUB 🚨🚨🚨 BUG修复：移除StartServer中的NATTable::Clear()调用");
  
  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd < 0) {
    VPN_SERVER_LOGE("❌ Failed to create socket: %{public}s", strerror(errno));
    napi_value ret;
    napi_create_int32(env, -1, &ret);
    return ret;
  }
  
  VPN_SERVER_LOGI("✅ UDP socket created successfully: fd=%{public}d", fd);

  int opt = 1;
  if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
    VPN_SERVER_LOGE("Failed to set SO_REUSEADDR: %{public}s", strerror(errno));
    close(fd);
    napi_value ret;
    napi_create_int32(env, -1, &ret);
    return ret;
  }

  sockaddr_in addr {};
  addr.sin_family = AF_INET;
  // 绑定到0.0.0.0，确保跨进程/跨应用UDP都能到达
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  addr.sin_port = htons(static_cast<uint16_t>(port));

  VPN_SERVER_LOGI("🔗 Binding to 0.0.0.0:%{public}d (INADDR_ANY) - 接收所有本地数据包", port);

  if (bind(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) < 0) {
    VPN_SERVER_LOGE("❌ Failed to bind socket to port %{public}d: %{public}s", port, strerror(errno));
    close(fd);
    napi_value ret;
    napi_create_int32(env, -3, &ret);
    return ret;
  }

  VPN_SERVER_LOGI("�?Socket bound successfully to port %{public}d", port);
  
  // verify socket bind status  
  sockaddr_in boundAddr {};
  socklen_t boundAddrLen = sizeof(boundAddr);
  if (getsockname(fd, reinterpret_cast<sockaddr*>(&boundAddr), &boundAddrLen) == 0) {
    char boundIP[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &boundAddr.sin_addr, boundIP, sizeof(boundIP));
    VPN_SERVER_LOGI("🔍 Socket验证: 实际绑定�?%{public}s:%{public}d (fd=%{public}d)", 
                   boundIP, ntohs(boundAddr.sin_port), fd);
  } else {
    VPN_SERVER_LOGE("�?无法验证socket绑定状�? %{public}s", strerror(errno));
  }

  // set non-blocking mode (avoid recvfrom blocking forever)
  int flags = fcntl(fd, F_GETFL, 0);
  if (flags < 0) {
    VPN_SERVER_LOGE("Failed to get socket flags: %{public}s", strerror(errno));
    close(fd);
    napi_value ret;
    napi_create_int32(env, -1, &ret);
    return ret;
  }
  if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
    VPN_SERVER_LOGE("Failed to set socket to non-blocking: %{public}s", strerror(errno));
    close(fd);
    napi_value ret;
    napi_create_int32(env, -1, &ret);
    return ret;
  }
  VPN_SERVER_LOGI("�?Socket set to non-blocking mode");

  // 🔧 atomic 变量不需要锁保护
  g_sockFd.store(fd);
  
  // 🔍 立即测试socket是否能接收数据（诊断用）
  VPN_SERVER_LOGI("🔍 测试socket接收能力...");
  uint8_t testBuf[1024];
  sockaddr_in testPeer {};
  socklen_t testPeerLen = sizeof(testPeer);
  int testRecv = recvfrom(fd, testBuf, sizeof(testBuf), MSG_DONTWAIT, 
                         reinterpret_cast<sockaddr*>(&testPeer), &testPeerLen);
  if (testRecv < 0 && errno == EAGAIN) {
    VPN_SERVER_LOGI("�?Socket测试: 非阻塞模式正�?(EAGAIN表示暂无数据，这是正常的)");
  } else if (testRecv >= 0) {
    VPN_SERVER_LOGI("⚠️ Socket测试: 意外收到 %{public}d字节数据", testRecv);
  } else {
    VPN_SERVER_LOGE("�?Socket测试失败: errno=%{public}d (%{public}s)", errno, strerror(errno));
  }
  
  // 🔍 检查socket选项
  int reuseAddr = 0;
  socklen_t reuseLen = sizeof(reuseAddr);
  if (getsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuseAddr, &reuseLen) == 0) {
    VPN_SERVER_LOGI("🔍 Socket选项: SO_REUSEADDR=%{public}d", reuseAddr);
  }
  
  int recvBufSize = 0;
  socklen_t recvBufLen = sizeof(recvBufSize);
  if (getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &recvBufSize, &recvBufLen) == 0) {
    VPN_SERVER_LOGI("🔍 Socket选项: SO_RCVBUF=%{public}d字节", recvBufSize);
  }
  
  g_running.store(true);
  g_worker = std::thread(WorkerLoop);
  
  // 🔍 等待WorkerLoop启动后，发送一个测试包验证通信
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  std::thread([]() {
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    VPN_SERVER_LOGI("🔍 [自测] 发送测试包到服务器...");
    int testSock = socket(AF_INET, SOCK_DGRAM, 0);
    if (testSock >= 0) {
      sockaddr_in testAddr {};
      testAddr.sin_family = AF_INET;
      testAddr.sin_port = htons(8888);
      inet_pton(AF_INET, "127.0.0.1", &testAddr.sin_addr);
      const char* testMsg = "test";
      int sent = sendto(testSock, testMsg, 4, 0, 
                       reinterpret_cast<sockaddr*>(&testAddr), sizeof(testAddr));
      if (sent > 0) {
        VPN_SERVER_LOGI("�?[自测] 测试包发送成�? %{public}d字节", sent);
      } else {
        VPN_SERVER_LOGE("�?[自测] 测试包发送失�? %{public}s", strerror(errno));
      }
      close(testSock);
    }
  }).detach();
  
  // use thread pool to run UDP retransmit timer task  
  auto* threadPool = GetThreadPool();
  if (threadPool) {
    threadPool->submit(VPNThreadPool::NETWORK_WORKER, []() {
      VPN_SERVER_LOGI("🔄 UDP retransmit timer task started");
      
      while (g_running.load()) {
        // 🐛 修复：使用可中断的sleep，避免退出延�?        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        
        if (!g_running.load()) break;  // 双重检�?        
        // 调用UDP重传逻辑 (修改后的代码)
        UdpRetransmitManager::getInstance().checkAndRetransmit();
      }
      
      VPN_SERVER_LOGI("🔄 UDP retransmit timer task stopped");
    });
    VPN_SERVER_LOGI("�?UDP retransmit task submitted to thread pool");
  } else {
    VPN_SERVER_LOGE("�?Failed to get thread pool for UDP retransmit");
  }

  VPN_SERVER_LOGI("🎯 PROXY SERVER STARTED - Ready to accept proxy client connections");
  VPN_SERVER_LOGI("📡 Listening on UDP port %{public}d for proxy tunnel traffic", port);
  VPN_SERVER_LOGI("🌐 All connected clients will have their traffic forwarded through this proxy server");
  
  // run comprehensive network diagnostics in background  
  std::thread([]() {
    VPN_SERVER_LOGI("🔍 Starting comprehensive network diagnostics...");
    NetworkDiagnostics::RunFullDiagnostics();
  }).detach();
  
  // 测试网络连接 - 只保留一次测�?  TestNetworkConnectivity();

  // 等待服务器完全启�?  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  VPN_SERVER_LOGI("�?Server fully initialized and ready for connections");

  // UDP connectivity test - only run once
  static std::atomic<bool> udpTestStarted{false};
  if (!udpTestStarted.exchange(true)) {
    std::thread([]() {
      std::this_thread::sleep_for(std::chrono::seconds(1));      TestUDPConnectivity();
    }).detach();
  }

  // 测试DNS连通�?- 已禁用，避免影响功能逻辑
  // run comprehensive network diagnostics in background  std::thread([]() {
  //   std::this_thread::sleep_for(std::chrono::seconds(2));
  //   TestAllDNSConnectivity();
  // }).detach();

  napi_value ret;
  napi_create_int32(env, 0, &ret);
  return ret;
}

napi_value StopServer(napi_env env, napi_callback_info info)
{
  if (!g_running.load()) {
    napi_value ret;
    napi_create_int32(env, 0, &ret);
    return ret;
  }

  VPN_SERVER_LOGI("ZHOUB [STOP] Stopping server...");
  VPN_SERVER_LOGI("⚠️ 重要提醒：服务器停止后，请手动停止HarmonyOS的VPN连接以避免客户端继续发送数据包");
  g_running.store(false);
  
  // 停止工作线程�?  WorkerThreadPool::getInstance().stop();
  VPN_SERVER_LOGI("�?Worker thread pool stopped");
  
  // 清理任务队列
  TaskQueueManager::getInstance().clear();
  VPN_SERVER_LOGI("�?Task queues cleared");
  
  // 清理UDP重传管理�?  UdpRetransmitManager::getInstance().clear();
  VPN_SERVER_LOGI("�?UDP retransmit manager cleared");
  
  // 🐛 修复：清理PacketForwarder的所有socket和线�?  // PacketForwarder::CleanupAll(); // 已删除，不再需要清�?  
  // 🚨 BUG修复：注释掉StopServer中的NATTable::Clear()调用
  // 这个Clear调用会清空所有NAT映射，导致UDP响应失败
  // NATTable::Clear();
  // VPN_SERVER_LOGI("�?NAT table cleared");
  LOG_ERROR("ZHOUB 🚨🚨🚨 BUG修复：移除StopServer中的NATTable::Clear()调用");

  // broadcast server stop message (best-effort)
  int stopSockFd = g_sockFd.load();
  if (stopSockFd >= 0) {
    // stop message payload
    const char* stopMsg = "SERVER_STOPPED";
    sockaddr_in broadcastAddr {};
    broadcastAddr.sin_family = AF_INET;
    broadcastAddr.sin_addr.s_addr = htonl(INADDR_BROADCAST);
    broadcastAddr.sin_port = htons(8888);

    // enable broadcast option
    int broadcastEnable = 1;
    setsockopt(stopSockFd, SOL_SOCKET, SO_BROADCAST, &broadcastEnable, sizeof(broadcastEnable));

    // send broadcast
    ssize_t sent = sendto(stopSockFd, stopMsg, strlen(stopMsg), 0,
                         (struct sockaddr*)&broadcastAddr, sizeof(broadcastAddr));
    if (sent > 0) {
      VPN_SERVER_LOGI("ZHOUB [STOP] Server stopping broadcast sent to clients");
    }
  }

  // 🔧 atomic 变量不需要锁保护
  // 关闭socket，这会中断recvfrom/select调用
  int sockFd = g_sockFd.exchange(-1);  // 原子交换
  if (sockFd >= 0) {
    close(sockFd);
    VPN_SERVER_LOGI("ZHOUB [STOP] Socket closed");
  }
  
  // 🔄 清理线程�?  CleanupThreadPool();
  VPN_SERVER_LOGI("�?Thread pool cleaned up");

  // 🔧 修复：正确等待线程退出，避免资源泄漏
  // wait for worker thread to exit
  if (g_worker.joinable()) {
    VPN_SERVER_LOGI("�?Waiting for worker thread to exit...");
    g_worker.join();  // 🔧 应该join而不是detach
    VPN_SERVER_LOGI("�?Worker thread stopped");
  }
  
  // 🔄 UDP重传任务已由线程池管理，无需手动join
  // 线程池shutdown时会自动清理所有任�?  VPN_SERVER_LOGI("�?UDP retransmit task will be cleaned up by thread pool");
  
  // Reset statistics
  g_packetsReceived.store(0);
  g_packetsSent.store(0);
  g_bytesReceived.store(0);
  g_bytesSent.store(0);
  {
    std::lock_guard<std::mutex> lock(g_lastActivityMutex);    g_lastActivity.clear();
  }
  
  // Clear client info
  {
    std::lock_guard<std::mutex> lock(g_clientsMutex);
    g_clients.clear();
  }
  
  // Clear data buffer
  {
    std::lock_guard<std::mutex> lock(g_dataBufferMutex);
    g_dataBuffer.clear();
  }

  napi_value ret;
  napi_create_int32(env, 0, &ret);
  return ret;
}

napi_value GetStats(napi_env env, napi_callback_info info)
{
  napi_value statsObj;
  napi_create_object(env, &statsObj);
  
  // Packets received
  napi_value packetsReceived;
  napi_create_uint32(env, g_packetsReceived.load(), &packetsReceived);
  napi_set_named_property(env, statsObj, "packetsReceived", packetsReceived);
  
  // Packets sent
  napi_value packetsSent;
  napi_create_uint32(env, g_packetsSent.load(), &packetsSent);
  napi_set_named_property(env, statsObj, "packetsSent", packetsSent);
  
  // Bytes received
  napi_value bytesReceived;
  napi_create_uint32(env, g_bytesReceived.load(), &bytesReceived);
  napi_set_named_property(env, statsObj, "bytesReceived", bytesReceived);
  
  // Bytes sent
  napi_value bytesSent;
  napi_create_uint32(env, g_bytesSent.load(), &bytesSent);
  napi_set_named_property(env, statsObj, "bytesSent", bytesSent);
  
  // Last activity
  std::string lastActivity;
  {
    std::lock_guard<std::mutex> lock(g_lastActivityMutex);  // 🔧 使用专用互斥锁保护 lastActivity
    lastActivity = g_lastActivity.empty() ? "No activity" : g_lastActivity;
  }
  napi_value lastActivityStr;
  napi_create_string_utf8(env, lastActivity.c_str(), NAPI_AUTO_LENGTH, &lastActivityStr);
  napi_set_named_property(env, statsObj, "lastActivity", lastActivityStr);
  
  return statsObj;
}

napi_value GetClients(napi_env env, napi_callback_info info)
{
  napi_value clientsArray;
  napi_create_array(env, &clientsArray);
  
  std::lock_guard<std::mutex> lock(g_clientsMutex);
  uint32_t index = 0;
  
  for (const auto& pair : g_clients) {
    const ClientInfo& client = pair.second;
    
    napi_value clientObj;
    napi_create_object(env, &clientObj);
    
    // IP
    napi_value ip;
    napi_create_string_utf8(env, client.ip.c_str(), NAPI_AUTO_LENGTH, &ip);
    napi_set_named_property(env, clientObj, "ip", ip);
    
    // Port
    napi_value port;
    napi_create_int32(env, client.port, &port);
    napi_set_named_property(env, clientObj, "port", port);
    
    // Last seen
    napi_value lastSeen;
    std::string formattedTime = FormatTime(client.lastSeen);
    napi_create_string_utf8(env, formattedTime.c_str(), NAPI_AUTO_LENGTH, &lastSeen);
    napi_set_named_property(env, clientObj, "lastSeen", lastSeen);
    
    // Packets count
    napi_value packetsCount;
    napi_create_uint32(env, client.packetsCount, &packetsCount);
    napi_set_named_property(env, clientObj, "packetsCount", packetsCount);
    
    // Total bytes
    napi_value totalBytes;
    napi_create_uint32(env, client.totalBytes, &totalBytes);
    napi_set_named_property(env, clientObj, "totalBytes", totalBytes);
    
    napi_set_element(env, clientsArray, index, clientObj);
    index++;
  }
  
  return clientsArray;
}

// 测试数据缓冲区函数
napi_value TestDataBuffer(napi_env env, napi_callback_info info)
{
  (void)info;
  VPN_SERVER_LOGI("🧪 Testing data buffer functionality");
  
  // 手动添加测试数据
  AddDataPacket("Test data from VPN server", "127.0.0.1:8888", "test");
  AddDataPacket("Another test packet", "127.0.0.1:8889", "test");
  
  VPN_SERVER_LOGI("🧪 Added 2 test packets to buffer");
  
  napi_value ret;
  napi_create_int32(env, 0, &ret);
  return ret;
}

napi_value GetDataBuffer(napi_env env, napi_callback_info info)
{
  napi_value dataArray;
  napi_create_array(env, &dataArray);
  
  std::lock_guard<std::mutex> lock(g_dataBufferMutex);
  
  // 完全禁用日志 - 避免频繁输出
  // if (g_dataBuffer.size() > 0) {
  //   VPN_SERVER_LOGI("📋 GetDataBuffer called: buffer_size=%zu", g_dataBuffer.size());
  // }
  
  for (size_t i = 0; i < g_dataBuffer.size(); i++) {
    napi_value dataStr;
    napi_create_string_utf8(env, g_dataBuffer[i].c_str(), NAPI_AUTO_LENGTH, &dataStr);
    napi_set_element(env, dataArray, i, dataStr);
  }
  
  return dataArray;
}

napi_value SendTestData(napi_env env, napi_callback_info info)
{
  size_t argc = 2;
  napi_value args[2] = {nullptr};
  napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);

  // 检查参数数量
  if (argc < 2 || args[0] == nullptr || args[1] == nullptr) {
    VPN_SERVER_LOGE("SendTestData: Invalid arguments");
    napi_value ret;
    napi_create_int32(env, -1, &ret);
    return ret;
  }

  // 检查服务器是否运行
  if (!g_running.load() || g_sockFd.load() < 0) {
    VPN_SERVER_LOGE("SendTestData: Server is not running");
    napi_value ret;
    napi_create_int32(env, -2, &ret);
    return ret;
  }

  size_t targetLen;
  napi_get_value_string_utf8(env, args[0], nullptr, 0, &targetLen);
  char target[256] = {0};
  napi_get_value_string_utf8(env, args[0], target, sizeof(target), &targetLen);

  size_t msgLen;
  napi_get_value_string_utf8(env, args[1], nullptr, 0, &msgLen);
  char msg[1024] = {0};
  napi_get_value_string_utf8(env, args[1], msg, sizeof(msg), &msgLen);

  std::string targetClient(target);
  std::string testMessage(msg);

  // Parse client address
  size_t colonPos = targetClient.find(':');
  if (colonPos == std::string::npos || colonPos == 0 || colonPos == targetClient.length() - 1) {
    VPN_SERVER_LOGE("Invalid target client format: %{public}s", targetClient.c_str());
    napi_value ret;
    napi_create_int32(env, -1, &ret);
    return ret;
  }

  std::string clientIp = targetClient.substr(0, colonPos);
  std::string portStr = targetClient.substr(colonPos + 1);
  
  // 安全地解析端口号，避免异常
  int clientPort = 0;
  try {
    long portLong = std::stol(portStr);
    if (portLong <= 0 || portLong > 65535) {
      VPN_SERVER_LOGE("Invalid port number: %{public}s", portStr.c_str());
      napi_value ret;
      napi_create_int32(env, -1, &ret);
      return ret;
    }
    clientPort = static_cast<int>(portLong);
  } catch (const std::exception& e) {
    VPN_SERVER_LOGE("Failed to parse port number: %{public}s, error: %{public}s", 
                    portStr.c_str(), e.what());
    napi_value ret;
    napi_create_int32(env, -1, &ret);
    return ret;
  }

  sockaddr_in clientAddr{};
  clientAddr.sin_family = AF_INET;
  clientAddr.sin_port = htons(static_cast<uint16_t>(clientPort));
  
  // 检查 inet_pton 的返回值
  if (inet_pton(AF_INET, clientIp.c_str(), &clientAddr.sin_addr) != 1) {
    VPN_SERVER_LOGE("Invalid IP address: %{public}s", clientIp.c_str());
    napi_value ret;
    napi_create_int32(env, -1, &ret);
    return ret;
  }

  int sent = sendto(g_sockFd.load(), testMessage.c_str(), testMessage.length(), 0,
                   reinterpret_cast<sockaddr*>(&clientAddr), sizeof(clientAddr));
  
  if (sent > 0) {
    // 更新发送统计
    g_packetsSent.fetch_add(1);
    g_bytesSent.fetch_add(sent);
    
    // 添加测试数据到缓冲区
    AddDataPacket(testMessage, targetClient, "test");
    
    VPN_SERVER_LOGI("Test data sent to [%{public}s:%{public}d]: %{public}s", 
                    clientIp.c_str(), clientPort, testMessage.c_str());
  } else {
    VPN_SERVER_LOGE("Failed to send test data to [%{public}s:%{public}d]: %{public}s", 
                    clientIp.c_str(), clientPort, strerror(errno));
  }

  napi_value ret;
  napi_create_int32(env, sent > 0 ? 0 : -3, &ret);
  return ret;
}

napi_value ClearDataBuffer(napi_env env, napi_callback_info info)
{
  std::lock_guard<std::mutex> lock(g_dataBufferMutex);
  g_dataBuffer.clear();
  
  VPN_SERVER_LOGI("Data buffer cleared");
  
  napi_value ret;
  napi_create_int32(env, 0, &ret);
  return ret;
}

 
// 🔧 网络连通性测试：直接测试DNS（不经过VPN隧道）
napi_value TestNetworkConnectivity(napi_env env, napi_callback_info info)
{
  (void)info;
  VPN_SERVER_LOGI("🧪 开始测试网络连通�?..");
  
  std::string result = "🌐 网络连通性测试报告\n\n";
  
  // 测试1: 创建UDP socket
  result += "【测�?】创建UDP Socket\n";
  int udpSock = socket(AF_INET, SOCK_DGRAM, 0);
  if (udpSock < 0) {
    result += "  �?失败: errno=" + std::to_string(errno) + " (" + strerror(errno) + ")\n";
    VPN_SERVER_LOGE("创建UDP socket失败");
  } else {
    result += "  �?成功: socket fd=" + std::to_string(udpSock) + "\n";
    
    // 测试2: 发送到8.8.8.8:53（直接DNS查询，不经过VPN）
    result += "\n【测试2】直接发送DNS查询到 8.8.8.8:53\n";
    result += "  （此测试绕过VPN隧道，直接访问网络）\n";
    
    sockaddr_in dnsAddr{};
    dnsAddr.sin_family = AF_INET;
    dnsAddr.sin_port = htons(53);
    inet_pton(AF_INET, "8.8.8.8", &dnsAddr.sin_addr);
    
    // 简单的DNS查询包（查询 test.com）
    uint8_t dnsQuery[] = {
      0x12, 0x34,  // Transaction ID
      0x01, 0x00,  // Flags: standard query
      0x00, 0x01,  // Questions: 1
      0x00, 0x00,  // Answer RRs: 0
      0x00, 0x00,  // Authority RRs: 0
      0x00, 0x00,  // Additional RRs: 0
      // Query: test.com
      0x04, 't', 'e', 's', 't',
      0x03, 'c', 'o', 'm',
      0x00,        // End of name
      0x00, 0x01,  // Type: A
      0x00, 0x01,  // Class: IN
    };
    
    ssize_t sent = sendto(udpSock, dnsQuery, sizeof(dnsQuery), 0,
                         (struct sockaddr*)&dnsAddr, sizeof(dnsAddr));
    
    if (sent < 0) {
      int savedErrno = errno;
      result += "  �?发送失�? errno=" + std::to_string(savedErrno) + " (" + strerror(savedErrno) + ")\n";
      
      if (savedErrno == ENETUNREACH) {
        result += "\n  🚨 ENETUNREACH: 网络不可达\n";
        result += "  这是最常见的VPN环境错误！\n\n";
        result += "  �?根本原因：\n";
        result += "    服务器创建的socket被路由到VPN隧道，\n";
        result += "    形成循环：socket �?VPN �?服务�?�?socket\n\n";
        result += "  �?解决方法：\n";
        result += "    在VPN客户端调�?protect(socketFd)\n";
        result += "    让socket绕过VPN，直接访问物理网络\n\n";
        result += "  💡 示例代码：\n";
        result += "    // 在服务器创建socket后立即保护\n";
        result += "    vpnConnection.protect(socketFd);\n";
      } else if (savedErrno == EACCES || savedErrno == EPERM) {
        result += "  ⚠️ 权限错误: errno=" + std::to_string(savedErrno) + "\n";
        result += "  可能需要网络权限或socket protection\n";
      }
      
      VPN_SERVER_LOGE("UDP sendto失败: %d (%s)", savedErrno, strerror(savedErrno));
    } else {
      result += "  �?发送成�? " + std::to_string(sent) + " 字节\n";
      
      // 测试3: 尝试接收响应
      result += "\n【测试3】接收DNS响应 (超时2秒)\n";
      struct timeval timeout;
      timeout.tv_sec = 2;
      timeout.tv_usec = 0;
      setsockopt(udpSock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
      
      uint8_t recvBuf[512];
      sockaddr_in fromAddr{};
      socklen_t fromLen = sizeof(fromAddr);
      
      ssize_t received = recvfrom(udpSock, recvBuf, sizeof(recvBuf), 0,
                                 (struct sockaddr*)&fromAddr, &fromLen);
      
      if (received < 0) {
        int savedErrno = errno;
        if (savedErrno == EAGAIN || savedErrno == EWOULDBLOCK) {
          result += "  ⚠️ 超时: 2秒内未收到DNS响应\n";
          result += "  可能原因：\n";
          result += "    1. 8.8.8.8被防火墙阻止（中国大陆常见）\n";
          result += "    2. Socket未被protect，响应无法返回\n";
          result += "    3. 网络连接断开\n";
        } else {
          result += "  �?接收失败: errno=" + std::to_string(savedErrno) + " (" + strerror(savedErrno) + ")\n";
        }
      } else {
        result += "  �?收到DNS响应: " + std::to_string(received) + " 字节\n";
        char fromIP[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &fromAddr.sin_addr, fromIP, INET_ADDRSTRLEN);
        result += "  来源: " + std::string(fromIP) + ":" + std::to_string(ntohs(fromAddr.sin_port)) + "\n";
        result += "\n  🎉🎉🎉 网络连通性测试通过！\n";
        result += "  服务器可以直接访问外部网络！\n";
      }
    }
    
    close(udpSock);
  }
  
  result += "\n" + std::string(50, '=') + "\n";
  result += "📊 测试总结：\n\n";
  result += "1️⃣ 如果 ENETUNREACH（网络不可达）：\n";
  result += "   �?需要实现socket protection机制\n";
  result += "   �?在packet_forwarder.cpp创建socket后调用protect()\n\n";
  result += "2️⃣ 如果 发送成功但超时：\n";
  result += "   �?可能是防火墙阻止8.8.8.8\n";
  result += "   �?或socket未被protect导致响应无法返回\n\n";
  result += "3️⃣ 如果 收到响应：\n";
  result += "   ✅ 网络正常，可以开始测试VPN隧道转发\n";
  
  VPN_SERVER_LOGI("网络连通性测试完成");
  
  napi_value resultValue;
  napi_create_string_utf8(env, result.c_str(), NAPI_AUTO_LENGTH, &resultValue);
  return resultValue;
}

// 注意：超时设置为1秒以避免UI阻塞，如果网络不通会快速失败
napi_value TestDNSQuery(napi_env env, napi_callback_info info)
{
  (void)info;
  VPN_SERVER_LOGI("🧪🧪🧪 TestDNSQuery - Direct UDP test to 8.8.8.8:53");

  // 直接用UDP socket测试DNS，就像网络诊断一样
  int dnsSock = socket(AF_INET, SOCK_DGRAM, 0);
  if (dnsSock < 0) {
    VPN_SERVER_LOGE("�?Failed to create DNS socket: %{public}s", strerror(errno));
    napi_value result;
    napi_create_string_utf8(env, "�?Failed to create DNS socket", NAPI_AUTO_LENGTH, &result);
    return result;
  }

  // IMPORTANT:
  // 之前这里设置了 O_NONBLOCK，导致 recvfrom() 立刻返回 EAGAIN(11)，
  // SO_RCVTIMEO 的 5 秒超时不会生效，从而误判为“UDP 53 被 BLOCKED”。
  // 这里保持阻塞模式 + SO_RCVTIMEO，让测试真正等待并得到可靠结论。

  // DNS服务器地址
  struct sockaddr_in dnsAddr{};
  dnsAddr.sin_family = AF_INET;
  dnsAddr.sin_port = htons(53);
  inet_pton(AF_INET, "8.8.8.8", &dnsAddr.sin_addr);

  // 构造DNS查询（www.baidu.com 的 A 记录）
  uint8_t dnsQuery[] = {
      0x12, 0x34,  // Transaction ID
      0x01, 0x00,  // Flags: standard query
      0x00, 0x01,  // Questions: 1
      0x00, 0x00,  // Answer RRs: 0
      0x00, 0x00,  // Authority RRs: 0
      0x00, 0x00,  // Additional RRs: 0
      // Query: www.baidu.com
      0x03, 'w', 'w', 'w',
      0x05, 'b', 'a', 'i', 'd', 'u',
      0x03, 'c', 'o', 'm',
      0x00,        // End of name
      0x00, 0x01,  // Type: A
      0x00, 0x01   // Class: IN
  };

  // 发送DNS查询
  ssize_t sent = sendto(dnsSock, dnsQuery, sizeof(dnsQuery), 0,
                       (struct sockaddr*)&dnsAddr, sizeof(dnsAddr));

  if (sent < 0) {
    VPN_SERVER_LOGE("�?Failed to send DNS query: %{public}s", strerror(errno));
    close(dnsSock);
    napi_value result;
    napi_create_string_utf8(env, "�?Failed to send DNS query", NAPI_AUTO_LENGTH, &result);
    return result;
  }

  VPN_SERVER_LOGI("�?DNS query sent (%{public}zd bytes) to 8.8.8.8:53", sent);

  // 设置5秒超时
  struct timeval timeout;
  timeout.tv_sec = 5;
  timeout.tv_usec = 0;
  setsockopt(dnsSock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

  VPN_SERVER_LOGI("�?Waiting for DNS response (timeout: 5 seconds)...");

  // 等待响应
  uint8_t responseBuffer[2048];
  ssize_t received = recvfrom(dnsSock, responseBuffer, sizeof(responseBuffer), 0, nullptr, nullptr);

  close(dnsSock);

  if (received > 0) {
    VPN_SERVER_LOGI("�?Received DNS response: %{public}zd bytes", received);

    if (received >= 44 && (responseBuffer[2] & 0x80)) {  // 有效的DNS响应
      VPN_SERVER_LOGI("�?Valid DNS response! 8.8.8.8 is accessible");
      napi_value result;
      napi_create_string_utf8(env, "�?DNS Test SUCCESS!\n\n🎯 8.8.8.8 is accessible!\n\n📊 Response: %{public}zd bytes received\n\n🌐 UDP DNS port 53 is working!\n\n🔥 VPN proxy should work correctly!", NAPI_AUTO_LENGTH, &result);
      return result;
    } else {
      VPN_SERVER_LOGE("�?Invalid DNS response format");
      napi_value result;
      napi_create_string_utf8(env, "�?Invalid DNS response format", NAPI_AUTO_LENGTH, &result);
      return result;
    }
  } else {
    int err = errno;
    VPN_SERVER_LOGE("�?No DNS response yet / timeout: %{public}s (errno=%{public}d)", strerror(err), err);

    if (err == EAGAIN || err == EWOULDBLOCK) {
      VPN_SERVER_LOGE("   DNS response timeout (5s). This does NOT necessarily mean 'blocked'—it means no response was received in time.");
      napi_value result;
      napi_create_string_utf8(env,
                              "�?DNS Test FAILED (Timeout 5s)\n\n"
                              "⚠️ No DNS response received within 5 seconds.\n\n"
                              "Possible reasons:\n"
                              "  �?Network blocks UDP/53 to 8.8.8.8 (common in some regions)\n"
                              "  �?Socket not protected and traffic is routed into VPN loop\n"
                              "  �?DNS server unreachable from the device network\n\n"
                              "💡 Try:\n"
                              "  �?Use domestic DNS (114.114.114.114 / 223.5.5.5)\n"
                              "  �?Switch network (Wi‑Fi/4G) and retest\n",
                              NAPI_AUTO_LENGTH, &result);
      return result;
    } else {
      VPN_SERVER_LOGE("   Socket error");
      napi_value result;
      napi_create_string_utf8(env, "�?Socket error during DNS test", NAPI_AUTO_LENGTH, &result);
      return result;
    }
  }
}


napi_value Init(napi_env env, napi_value exports)
{
  // 模块初始化日�?  OH_LOG_Print(LOG_APP, LOG_INFO, 0x15b1, "VpnServer", "ZHOUB 🎉🎉🎉 NATIVE MODULE INITIALIZED - VPN SERVER MODULE LOADED 🎉🎉🎉");
  VPN_SERVER_LOGI("🎉 Native module initialized successfully");
  
  napi_property_descriptor desc[] = {
    {"startServer", nullptr, StartServer, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"stopServer", nullptr, StopServer, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"getStats", nullptr, GetStats, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"getClients", nullptr, GetClients, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"getDataBuffer", nullptr, GetDataBuffer, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"testDataBuffer", nullptr, TestDataBuffer, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"sendTestData", nullptr, SendTestData, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"clearDataBuffer", nullptr, ClearDataBuffer, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"testDNSQuery", nullptr, TestDNSQuery, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"testNetworkConnectivity", nullptr, TestNetworkConnectivity, nullptr, nullptr, nullptr, napi_default, nullptr},
  };
  napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc);
  
  VPN_SERVER_LOGI("📋 Native module properties defined");
  return exports;
}

static napi_module g_module = {
  .nm_version = 1,
  .nm_flags = 0,
  .nm_filename = nullptr,
  .nm_register_func = Init,
  .nm_modname = "vpn_server",
  .nm_priv = ((void *)0),
  .reserved = {0},
};

extern "C" __attribute__((constructor)) void RegisterEntryModule(void)
{
  napi_module_register(&g_module);
}













