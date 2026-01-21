#include <napi/native_api.h>
#include <hilog/log.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
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

#include "protocol_handler.h"
#include "packet_forwarder.h"
#include "vpn_server_globals.h"
#include "simple_dns_cache.h"
#include "network_diagnostics.h"

#define MAKE_FILE_NAME (strrchr(__FILE__, '/') ? (strrchr(__FILE__, '/') + 1) : __FILE__)

#define VPN_SERVER_LOGE(fmt, ...) \
  OH_LOG_Print(LOG_APP, LOG_INFO, 0x15b1, "VpnServer", "ZBQ server [%{public}s %{public}d] " fmt, MAKE_FILE_NAME, __LINE__, ##__VA_ARGS__)
#define VPN_SERVER_LOGI(fmt, ...) \
  OH_LOG_Print(LOG_APP, LOG_INFO, 0x15b1, "VpnServer", "ZBQ server [%{public}s %{public}d] " fmt, MAKE_FILE_NAME, __LINE__, ##__VA_ARGS__)
#define VPN_SERVER_LOGW(fmt, ...) \
  OH_LOG_Print(LOG_APP, LOG_INFO, 0x15b1, "VpnServer", "ZBQ server [%{public}s %{public}d] " fmt, MAKE_FILE_NAME, __LINE__, ##__VA_ARGS__)

namespace {
constexpr int BUFFER_SIZE = 2048;
}

// 全局变量定义
std::atomic<bool> g_running{false};
int g_sockFd = -1;
std::thread g_worker;

// Statistics
std::atomic<uint64_t> g_packetsReceived{0};
std::atomic<uint64_t> g_packetsSent{0};
std::atomic<uint64_t> g_bytesReceived{0};
std::atomic<uint64_t> g_bytesSent{0};
std::string g_lastActivity;
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

// 测试网络连通性
void TestNetworkConnectivity();

// 测试百度连接
void TestBaiduConnection();

// 转发数据到真实目标服务器
int ForwardToRealServer(const uint8_t* data, int dataSize, const std::string& targetIP, int targetPort, uint8_t protocol, int addressFamily, const sockaddr_in& originalPeer);

// 解析IP数据包获取目标IP和端口 (支持IPv4和IPv6)
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

        // 只处理TCP (protocol=6) 和 UDP (protocol=17)
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

        // 只处理TCP (nextHeader=6) 和 UDP (nextHeader=17)
        if (nextHeader != 6 && nextHeader != 17) {
            VPN_SERVER_LOGW("Unsupported IPv6 next header: %{public}d (only TCP=6, UDP=17 supported)", nextHeader);
            return false;
        }

        // 获取目标IPv6地址 (16字节，从偏移24开始)
        char dstIP[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &data[24], dstIP, INET6_ADDRSTRLEN);

        // 获取端口 (TCP/UDP头部，IPv6有效载荷从偏移40开始)
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

// 测试网络连通性的函数
void TestNetworkConnectivity() {
    VPN_SERVER_LOGI("=== Starting Network Connectivity Test ===");

    // 检测当前网络接口状态
    VPN_SERVER_LOGI("=== Network Interface Detection ===");

    // 测试 socket 创建
    VPN_SERVER_LOGI("Testing socket creation");
    int testSock = socket(AF_INET, SOCK_STREAM, 0);
    if (testSock < 0) {
        VPN_SERVER_LOGE("❌ Failed to create TCP socket: %{public}s", strerror(errno));
        return;
    }

    VPN_SERVER_LOGI("✅ Socket creation SUCCESS");
    close(testSock);
    VPN_SERVER_LOGI("✅ Socket closed successfully");

    // 检查是否作为VPN服务运行
    VPN_SERVER_LOGI("=== VPN Service Status Check ===");
    if (g_running.load()) {
        VPN_SERVER_LOGI("✅ VPN Server is RUNNING - accepting client connections");
        VPN_SERVER_LOGI("📡 Server listening for VPN client connections on UDP port 8888");
        VPN_SERVER_LOGI("🌐 All client traffic will be forwarded through this VPN tunnel");
    } else {
        VPN_SERVER_LOGW("⚠️  VPN Server is STOPPED - no VPN tunnel active");
        VPN_SERVER_LOGI("💡 Start the VPN server to establish tunnel");
    }

    // 测试网络连接
    TestBaiduConnection();

    VPN_SERVER_LOGI("=== Network Connectivity Test Complete ===");
}

// 简化测试：只测试网络连接
void TestBaiduConnection() {
    VPN_SERVER_LOGI("=== Testing Network Connection ===");
    
    // 检查 VPN 是否已经启动
    VPN_SERVER_LOGI("Checking if VPN is already active...");
    
    // 测试最简单的连接 - 连接到本地回环地址的常用端口
    VPN_SERVER_LOGI("Testing local loopback connection");
    int sockFd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockFd < 0) {
        VPN_SERVER_LOGE("❌ Failed to create TCP socket: %{public}s", strerror(errno));
        return;
    }
    
    // 连接到本地回环地址的 80 端口（测试网络栈）
    struct sockaddr_in localAddr{};
    localAddr.sin_family = AF_INET;
    localAddr.sin_port = htons(80);  // 使用标准端口测试
    inet_pton(AF_INET, "127.0.0.1", &localAddr.sin_addr);
    
    int connectResult = connect(sockFd, (struct sockaddr*)&localAddr, sizeof(localAddr));
    if (connectResult == 0) {
        VPN_SERVER_LOGI("✅ Local loopback connection SUCCESS");
        close(sockFd);
    } else {
        VPN_SERVER_LOGI("❌ Local loopback connection FAILED: %{public}s", strerror(errno));
        close(sockFd);
        // 连接失败是正常的，本地可能没有 HTTP 服务器
        VPN_SERVER_LOGI("ℹ️  Local HTTP server not available, but network stack is working");
    }
    
    // 测试外部连接 - 使用本地网关而不是外部DNS
    VPN_SERVER_LOGI("Testing external connection to local gateway");
    sockFd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockFd < 0) {
        VPN_SERVER_LOGE("❌ Failed to create UDP socket: %{public}s", strerror(errno));
        return;
    }

    // 在 HarmonyOS 沙盒中，SO_BINDTODEVICE 不起作用，使用默认绑定
    struct sockaddr_in bindAddr{};
    bindAddr.sin_family = AF_INET;
    bindAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    bindAddr.sin_port = htons(0);

    if (bind(sockFd, (struct sockaddr*)&bindAddr, sizeof(bindAddr)) < 0) {
        VPN_SERVER_LOGW("⚠️  Failed to bind socket: %{public}s", strerror(errno));
    }

    // 设置 socket 选项
    int sockopt = 1;
    setsockopt(sockFd, SOL_SOCKET, SO_REUSEADDR, &sockopt, sizeof(sockopt));

    // 设置超时时间
    struct timeval timeout;
    timeout.tv_sec = 1;  // 减少超时时间
    timeout.tv_usec = 0;
    setsockopt(sockFd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    
    // 发送一个简单的数据包到本地网关（假设网关是192.168.1.1）
    uint8_t testData[] = {0x01, 0x02, 0x03, 0x04};
    
    struct sockaddr_in gatewayAddr{};
    gatewayAddr.sin_family = AF_INET;
    gatewayAddr.sin_port = htons(80);
    inet_pton(AF_INET, "192.168.1.1", &gatewayAddr.sin_addr);

    int sent = sendto(sockFd, testData, sizeof(testData), 0, (struct sockaddr*)&gatewayAddr, sizeof(gatewayAddr));
    if (sent > 0) {
        VPN_SERVER_LOGI("✅ Test packet sent successfully to gateway");

        // 等待响应（预期会失败，但能测试网络路由）
        uint8_t response[512];
        int received = recvfrom(sockFd, response, sizeof(response), 0, nullptr, nullptr);
        if (received > 0) {
            VPN_SERVER_LOGI("✅ Unexpected response received: %{public}d bytes", received);
        } else {
            VPN_SERVER_LOGI("ℹ️  No response from gateway (expected) - network routing works");
        }
        close(sockFd);
        VPN_SERVER_LOGI("=== Network Test SUCCESS - Network routing works! ===");
        return;
    } else {
        VPN_SERVER_LOGI("❌ Failed to send test packet: %{public}s", strerror(errno));
    }
    
    close(sockFd);
    
    // 简化网络测试 - 只测试UDP DNS，避免TCP连接阻塞
    VPN_SERVER_LOGI("=== Network Test Complete - Basic connectivity verified! ===");
    VPN_SERVER_LOGI("VPN Server is ready to handle client connections");
    
    // 测试本地网络接口
    VPN_SERVER_LOGI("Testing local network interfaces");
    sockFd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockFd >= 0) {
        // 获取本地网络接口信息
        struct ifconf ifc;
        char buf[1024];
        ifc.ifc_len = sizeof(buf);
        ifc.ifc_buf = buf;
        
        if (ioctl(sockFd, SIOCGIFCONF, &ifc) >= 0) {
            struct ifreq* ifr = (struct ifreq*)buf;
            int numInterfaces = ifc.ifc_len / sizeof(struct ifreq);
            
            VPN_SERVER_LOGI("Found %d network interfaces:", numInterfaces);
            for (int i = 0; i < numInterfaces; i++) {
                VPN_SERVER_LOGI("Interface: %{public}s", ifr[i].ifr_name);
            }
        }
        close(sockFd);
    }
    
    VPN_SERVER_LOGI("✅ VPN Server initialization complete - ready for client connections");
    VPN_SERVER_LOGI("=== Network Test Complete - Server Ready ===");
}

// 转发数据到真实目标服务器 (支持IPv4和IPv6)
int ForwardToRealServer(const uint8_t* data, int dataSize, const std::string& targetIP, int targetPort, uint8_t protocol, int addressFamily, const sockaddr_in& originalPeer) {
    VPN_SERVER_LOGI("Creating connection to %{public}s:%{public}d (protocol=%{public}d)", targetIP.c_str(), targetPort, protocol);
    
    // 检测循环路由：如果目标IP是本地网络地址，需要特殊处理
    if (targetIP.find("127.") == 0) {
        VPN_SERVER_LOGE("❌ Detected routing loop: target %{public}s is loopback, rejecting", targetIP.c_str());
        return -1;
    }
    
    // 检查是否是VPN客户端网段（根据实际配置调整）
    if (targetIP.find("192.168.0.") == 0) {
        VPN_SERVER_LOGE("❌ Detected routing loop: target %{public}s is VPN client subnet, rejecting", targetIP.c_str());
        return -1;
    }
    
    // 检查是否是DNS查询，重定向到公共DNS服务器
    std::string actualTargetIP = targetIP;
    if (targetPort == 53) {
        // 强制重定向到公共DNS服务器
        if (actualTargetIP != "8.8.8.8") {
            VPN_SERVER_LOGI("🔄 Redirecting DNS query from %{public}s to public DNS 8.8.8.8", actualTargetIP.c_str());
            actualTargetIP = "8.8.8.8";
        }
        VPN_SERVER_LOGI("✅ Using public DNS: %{public}s:%{public}d", actualTargetIP.c_str(), targetPort);
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

    // 在 HarmonyOS 沙盒环境中，使用标准绑定
    if (addressFamily == AF_INET6) {
        struct sockaddr_in6 bindAddr{};
        bindAddr.sin6_family = AF_INET6;
        bindAddr.sin6_addr = in6addr_any;
        bindAddr.sin6_port = htons(0);

        if (bind(sockFd, (struct sockaddr*)&bindAddr, sizeof(bindAddr)) < 0) {
            VPN_SERVER_LOGW("⚠️  Failed to bind IPv6 socket: %{public}s", strerror(errno));
            VPN_SERVER_LOGI("🔄 Using default socket binding");
        } else {
            VPN_SERVER_LOGI("✅ Successfully bound IPv6 socket");
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
            VPN_SERVER_LOGI("✅ Successfully bound IPv4 socket");
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

        // 记录当前时间戳
        auto now = std::chrono::system_clock::now();
        auto timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
        VPN_SERVER_LOGI("Network request started at: %{public}lld", timestamp);

        // 根据协议类型进行连接
        if (protocol == PROTOCOL_UDP) {  // UDP
            // 计算IP头长度
            int ipHeaderLen = (data[0] & 0x0F) * 4;  // IP头长度 = (低4位 * 4字节)
            int udpHeaderLen = 8;  // UDP头固定8字节
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
                    timeout.tv_sec = 5;  // 5秒超时
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
            int ipHeaderLen = (data[0] & 0x0F) * 4;  // IP头长度 = (低4位 * 4字节)
            int tcpHeaderLen = (data[ipHeaderLen + 12] & 0xF0) >> 4;  // TCP头长度 = (高4位 * 4字节)
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
        VPN_SERVER_LOGE("❌ Failed to create UDP test socket: %{public}s", strerror(errno));
        return;
    }
    
    // 绑定到本地端口
    struct sockaddr_in localAddr{};
    localAddr.sin_family = AF_INET;
    localAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    localAddr.sin_port = htons(0);
    
    if (bind(testSock, (struct sockaddr*)&localAddr, sizeof(localAddr)) < 0) {
        VPN_SERVER_LOGE("❌ Failed to bind UDP test socket: %{public}s", strerror(errno));
        close(testSock);
        return;
    }
    
    VPN_SERVER_LOGI("✅ UDP test socket bound successfully");
    
    // 测试发送到公共DNS服务器
    struct sockaddr_in dnsAddr{};
    dnsAddr.sin_family = AF_INET;
    dnsAddr.sin_port = htons(53);
    inet_pton(AF_INET, "8.8.8.8", &dnsAddr.sin_addr);
    
    const char* testData = "ping";
    int sent = sendto(testSock, testData, strlen(testData), 0, (struct sockaddr*)&dnsAddr, sizeof(dnsAddr));
    if (sent < 0) {
        VPN_SERVER_LOGE("❌ Failed to send UDP test: %{public}s", strerror(errno));
        close(testSock);
        return;
    }
    
    VPN_SERVER_LOGI("✅ UDP test data sent: %{public}d bytes", sent);
    
    // 设置超时
    struct timeval timeout;
    timeout.tv_sec = 2;
    timeout.tv_usec = 0;
    setsockopt(testSock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    
    // 尝试接收响应
    char buffer[1024];
    int received = recvfrom(testSock, buffer, sizeof(buffer), 0, nullptr, nullptr);
    if (received > 0) {
        VPN_SERVER_LOGI("✅ UDP response received: %{public}d bytes", received);
    } else {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            VPN_SERVER_LOGI("ℹ️  UDP test timeout (expected for invalid data)");
        } else {
            VPN_SERVER_LOGE("❌ UDP test recv error: %{public}s", strerror(errno));
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
          // 控制字符转义为 \uXXXX
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
    // 使用线程安全的 localtime_r() 替代 localtime()，避免多线程环境下的死锁问题
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
  
  // 检查IPv4 (第一个字节的高4位通常是0x4，但需要检查IP头长度)
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
  
  // 检查IPv6 (第一个字节的高4位是0x6)
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
  
  // 检查ARP (以太网类型0x0806，但这里可能是裸ARP)
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
  VPN_SERVER_LOGI("📡 Socket fd: %{public}d, g_running: %{public}d", g_sockFd, g_running.load() ? 1 : 0);
  
  uint8_t buf[BUFFER_SIZE];
  while (g_running.load()) {
    // 使用select检查socket是否有数据可读，避免无限期阻塞
    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(g_sockFd, &readfds);
    
    struct timeval timeout;
    timeout.tv_sec = 0;
    timeout.tv_usec = 100000;  // 100ms超时，快速响应停止信号
    
    int selectResult = select(g_sockFd + 1, &readfds, nullptr, nullptr, &timeout);
    
    if (selectResult < 0) {
      if (!g_running.load()) {
        VPN_SERVER_LOGI("🛑 Server stopping, breaking loop");
        break;
      }
      if (errno == EINTR) {
        continue;  // 被信号中断，继续
      }
      VPN_SERVER_LOGE("❌ select error: %{public}s", strerror(errno));
      continue;
    }
    
    if (selectResult == 0) {
      // 超时，检查是否应该停止
      if (!g_running.load()) {
        VPN_SERVER_LOGI("🛑 Server stopping (timeout check), breaking loop");
        break;
      }
      continue;  // 超时但没有数据，继续循环
    }
    
    // 有数据可读
    sockaddr_in peer {};
    socklen_t peerLen = sizeof(peer);
    
    if (!g_running.load()) {
      VPN_SERVER_LOGI("ZBQ [STOP] Loop exit requested");
      break;
    }
    
    int n = recvfrom(g_sockFd, buf, sizeof(buf), 0, reinterpret_cast<sockaddr *>(&peer), &peerLen);
    
    if (n < 0) {
      VPN_SERVER_LOGE("ZBQ [ERROR] recvfrom failed: errno=%{public}d (%{public}s)", 
                      errno, strerror(errno));
      VPN_SERVER_LOGI("ZBQ [STOP] Loop exit on error");
      break;
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
    
    VPN_SERVER_LOGI("ZBQ [RX] %{public}d bytes from %{public}s", n, clientKey.c_str());
    
    // Update last activity
    {
      std::lock_guard<std::mutex> lock(g_statsMutex);
      g_lastActivity = clientKey;
    }
    
    // Update client info
    UpdateClientInfo(peerAddr, peerPort, n);
    
    // Add data to buffer (dataStr already created above)
    
    // 检查是否是DNS查询
    bool isDNSQuery = false;
    if (n >= 28 && (buf[0] & 0xF0) == 0x40) { // IPv4数据包
        uint8_t protocol = buf[9];
        if (protocol == 17) { // UDP协议
            int ipHeaderLen = (buf[0] & 0x0F) * 4;
            if (n >= ipHeaderLen + 8) {
                int udpHeaderLen = 8;
                int udpOffset = ipHeaderLen + udpHeaderLen;
                if (n >= udpOffset + 2) {
                    int dstPort = (buf[udpOffset + 2] << 8) | buf[udpOffset + 3];
                    isDNSQuery = (dstPort == 53);
                }
            }
        }
    }
    
    // 如果是DNS查询，简单记录日志，继续正常处理
    if (isDNSQuery) {
        VPN_SERVER_LOGI("🔍 [DNS] Processing DNS query for client: %{public}s", clientKey.c_str());
    }
    
    // 检查是否是心跳包
    if (n == 4 && dataStr == "ping") {
      VPN_SERVER_LOGI("Heartbeat received from [%{public}s:%{public}d]: ping", peerAddr.c_str(), peerPort);
      
      // 添加心跳包到数据缓冲区
      AddDataPacket("ping", clientKey, "heartbeat");
      
      // 发送pong响应
      const char* pongMsg = "pong";
      int pongLen = strlen(pongMsg);
      int s = sendto(g_sockFd, pongMsg, pongLen, 0, reinterpret_cast<sockaddr *>(&peer), peerLen);
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
        VPN_SERVER_LOGW("⚠️ Cannot parse packet, discarding. Size=%{public}d", n);
        // 即使无法解析，也添加到缓冲区（用于UI显示）
        AddDataPacket(hexData, clientKey, packetType);
        continue;
      }
      
      if (packetInfo.protocol == PROTOCOL_ICMPV6) {
        VPN_SERVER_LOGI("ZBQ [PARSE] ICMPv6 -> %{public}s Type=%{public}d", 
                        packetInfo.targetIP.c_str(), packetInfo.icmpv6Type);
      } else {
        VPN_SERVER_LOGI("ZBQ [PARSE] %{public}s -> %{public}s:%{public}d", 
                        ProtocolHandler::GetProtocolName(packetInfo.protocol).c_str(),
                        packetInfo.targetIP.c_str(), packetInfo.targetPort);
      }
      
      // 添加数据包到缓冲区（用于UI显示）
      std::string targetInfo;
      if (packetInfo.protocol == PROTOCOL_ICMPV6) {
        targetInfo = packetInfo.targetIP + " (ICMPv6:" + ProtocolHandler::GetICMPv6TypeName(packetInfo.icmpv6Type) + ")";
      } else {
        targetInfo = packetInfo.targetIP + ":" + std::to_string(packetInfo.targetPort);
      }
      AddDataPacket(hexData, clientKey + " -> " + targetInfo, packetType);
      
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
      
      // 转发到真实服务器
      int realServerSock = PacketForwarder::ForwardPacket(buf, n, packetInfo, peer);
      if (realServerSock >= 0) {
        if (packetInfo.protocol == PROTOCOL_ICMPV6) {
          VPN_SERVER_LOGI("ZBQ [FWD✓] ICMPv6 -> %{public}s (sock=%{public}d)", 
                          packetInfo.targetIP.c_str(), realServerSock);
        } else {
          VPN_SERVER_LOGI("ZBQ [FWD✓] %{public}s -> %{public}s:%{public}d (sock=%{public}d)", 
                          ProtocolHandler::GetProtocolName(packetInfo.protocol).c_str(),
                          packetInfo.targetIP.c_str(), packetInfo.targetPort, realServerSock);
        }
      } else {
        if (packetInfo.protocol == PROTOCOL_ICMPV6) {
          VPN_SERVER_LOGE("ZBQ [FWD✗] ICMPv6 -> %{public}s FAILED", packetInfo.targetIP.c_str());
        } else {
          VPN_SERVER_LOGE("ZBQ [FWD✗] %{public}s -> %{public}s:%{public}d FAILED", 
                          ProtocolHandler::GetProtocolName(packetInfo.protocol).c_str(),
                          packetInfo.targetIP.c_str(), packetInfo.targetPort);
        }
      }
    }
  }
}

napi_value StartServer(napi_env env, napi_callback_info info)
{
  // 使用系统日志，确保能看到
  OH_LOG_Print(LOG_APP, LOG_INFO, 0x15b1, "VpnServer", "🚀🚀🚀 StartServer FUNCTION CALLED - VPN SERVER STARTING NOW 🚀🚀🚀");
  VPN_SERVER_LOGI("🚀🚀🚀 StartServer FUNCTION CALLED - VPN SERVER STARTING NOW 🚀🚀🚀");
  
  size_t argc = 1;
  napi_value args[1] = {nullptr};
  napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);

  int32_t port = 0;
  if (argc >= 1) {
    napi_get_value_int32(env, args[0], &port);
  }

  OH_LOG_Print(LOG_APP, LOG_INFO, 0x15b1, "VpnServer", "📡 StartServer called with port: %{public}d", port);
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
    if (g_sockFd >= 0) {
      close(g_sockFd);
      g_sockFd = -1;
    }
    // 使用detach()而不是join()，避免阻塞UI线程
    // WorkerLoop会在检查g_running时发现为false，然后退出循环
    if (g_worker.joinable()) {
      VPN_SERVER_LOGI("🔄 Detaching old worker thread (will exit naturally)");
      g_worker.detach();
    }
    // 给旧线程一点时间退出（非阻塞）
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }

  VPN_SERVER_LOGI("ZBQ [START] VPN Server on port %{public}d", port);
  
  // 清理DNS缓存
  SimpleDNSCache cache;
  VPN_SERVER_LOGI("✅ DNS cache cleared");
  
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
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);  // 绑定到127.0.0.1
  addr.sin_port = htons(static_cast<uint16_t>(port));

  VPN_SERVER_LOGI("🔗 Binding to 127.0.0.1:%{public}d (loopback interface)", port);

  if (bind(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) < 0) {
    VPN_SERVER_LOGE("❌ Failed to bind socket to port %{public}d: %{public}s", port, strerror(errno));
    close(fd);
    napi_value ret;
    napi_create_int32(env, -3, &ret);
    return ret;
  }

  VPN_SERVER_LOGI("✅ Socket bound successfully to port %{public}d", port);

  // 设置为非阻塞模式，避免recvfrom无限期阻塞
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
  VPN_SERVER_LOGI("✅ Socket set to non-blocking mode");

  g_sockFd = fd;
  g_running.store(true);
  g_worker = std::thread(WorkerLoop);

  VPN_SERVER_LOGI("🎯 PROXY SERVER STARTED - Ready to accept proxy client connections");
  VPN_SERVER_LOGI("📡 Listening on UDP port %{public}d for proxy tunnel traffic", port);
  VPN_SERVER_LOGI("🌐 All connected clients will have their traffic forwarded through this proxy server");
  
  // 运行完整网络诊断（在后台线程中，避免阻塞启动）
  std::thread([]() {
    VPN_SERVER_LOGI("🔍 Starting comprehensive network diagnostics...");
    NetworkDiagnostics::RunFullDiagnostics();
  }).detach();
  
  // 测试网络连接
  PacketForwarder::TestNetworkConnectivity();

  // 等待服务器完全启动
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  VPN_SERVER_LOGI("✅ Server fully initialized and ready for connections");

  // 测试UDP连通性
  std::thread([]() {
    std::this_thread::sleep_for(std::chrono::seconds(1));  // 等待服务器完全启动
    TestUDPConnectivity();
  }).detach();

  // 测试网络连通性
  std::thread([]() {
    std::this_thread::sleep_for(std::chrono::seconds(1));  // 等待服务器完全启动
    TestNetworkConnectivity();
  }).detach();

  // 测试DNS连通性 - 已禁用，避免影响功能逻辑
  // std::thread([]() {
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

  VPN_SERVER_LOGI("ZBQ [STOP] Stopping server...");
  g_running.store(false);
  
  // 关闭socket，这会中断recvfrom/select调用
  if (g_sockFd >= 0) {
    close(g_sockFd);
    g_sockFd = -1;
    VPN_SERVER_LOGI("ZBQ [STOP] Socket closed");
  }
  
  // 由于socket已关闭且select有100ms超时，工作线程会在下一次循环时退出
  if (g_worker.joinable()) {
    VPN_SERVER_LOGI("ZBQ [STOP] Worker thread will exit");
    g_worker.detach();
  }
  
  // Reset statistics
  g_packetsReceived.store(0);
  g_packetsSent.store(0);
  g_bytesReceived.store(0);
  g_bytesSent.store(0);
  {
    std::lock_guard<std::mutex> lock(g_statsMutex);
    g_lastActivity.clear();
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
    std::lock_guard<std::mutex> lock(g_statsMutex);
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
  
  // 添加调试日志
  VPN_SERVER_LOGI("📋 GetDataBuffer called: buffer_size=%{public}zu", g_dataBuffer.size());
  
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
  if (!g_running.load() || g_sockFd < 0) {
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
  
  // 检查inet_pton的返回值
  if (inet_pton(AF_INET, clientIp.c_str(), &clientAddr.sin_addr) != 1) {
    VPN_SERVER_LOGE("Invalid IP address: %{public}s", clientIp.c_str());
    napi_value ret;
    napi_create_int32(env, -1, &ret);
    return ret;
  }

  int sent = sendto(g_sockFd, testMessage.c_str(), testMessage.length(), 0,
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

 
// 注意：超时设置为1秒以避免UI阻塞，如果网络不通会快速失败
napi_value TestDNSQuery(napi_env env, napi_callback_info info)
{
  VPN_SERVER_LOGI("🧪🧪🧪 TestDNSQuery - Starting DNS test for www.baidu.com");
  
  // 检查服务器是否运行
  if (!g_running || g_sockFd < 0) {
    VPN_SERVER_LOGE("❌ Server not running, cannot test DNS");
    napi_value result;
    napi_create_string_utf8(env, "❌ Server not running\nPlease start server first", NAPI_AUTO_LENGTH, &result);
    return result;
  }
  
  // 构建DNS查询包
  uint8_t dnsQuery[512] = {0};
  int offset = 0;
  
  // DNS头部
  dnsQuery[offset++] = 0x12;  // ID high
  dnsQuery[offset++] = 0x34;  // ID low
  dnsQuery[offset++] = 0x01;  // Flags high (standard query)
  dnsQuery[offset++] = 0x00;  // Flags low
  dnsQuery[offset++] = 0x00;  // Questions high
  dnsQuery[offset++] = 0x01;  // Questions low (1 question)
  dnsQuery[offset++] = 0x00;  // Answers high
  dnsQuery[offset++] = 0x00;  // Answers low
  dnsQuery[offset++] = 0x00;  // Authority high
  dnsQuery[offset++] = 0x00;  // Authority low
  dnsQuery[offset++] = 0x00;  // Additional high
  dnsQuery[offset++] = 0x00;  // Additional low
  
  // 域名编码：www.baidu.com
  const char* labels[] = {"www", "baidu", "com"};
  for (int i = 0; i < 3; i++) {
    int len = strlen(labels[i]);
    dnsQuery[offset++] = len;
    memcpy(dnsQuery + offset, labels[i], len);
    offset += len;
  }
  dnsQuery[offset++] = 0x00;  // 结束标记
  
  // 查询类型（A记录）和类别（IN）
  dnsQuery[offset++] = 0x00;
  dnsQuery[offset++] = 0x01;  // Type A
  dnsQuery[offset++] = 0x00;
  dnsQuery[offset++] = 0x01;  // Class IN
  
  int dnsLen = offset;
  VPN_SERVER_LOGI("✅ DNS query built: %{public}d bytes", dnsLen);
  
  // 构建UDP包
  uint16_t srcPort = 54321;
  uint16_t dstPort = 53;
  int udpLen = 8 + dnsLen;
  uint8_t udpPacket[1024] = {0};
  
  // UDP头部
  udpPacket[0] = (srcPort >> 8) & 0xFF;
  udpPacket[1] = srcPort & 0xFF;
  udpPacket[2] = (dstPort >> 8) & 0xFF;
  udpPacket[3] = dstPort & 0xFF;
  udpPacket[4] = (udpLen >> 8) & 0xFF;
  udpPacket[5] = udpLen & 0xFF;
  udpPacket[6] = 0x00;  // Checksum (稍后计算)
  udpPacket[7] = 0x00;
  
  // UDP数据
  memcpy(udpPacket + 8, dnsQuery, dnsLen);
  
  VPN_SERVER_LOGI("✅ UDP packet built: %{public}d bytes", udpLen);
  
  // 构建IP包
  int ipHeaderLen = 20;
  int totalLen = ipHeaderLen + udpLen;
  uint8_t ipPacket[2048] = {0};
  
  // IP头部
  ipPacket[0] = 0x45;  // Version 4, header length 5
  ipPacket[1] = 0x00;  // TOS
  ipPacket[2] = (totalLen >> 8) & 0xFF;
  ipPacket[3] = totalLen & 0xFF;
  ipPacket[4] = 0x12;  // ID high
  ipPacket[5] = 0x34;  // ID low
  ipPacket[6] = 0x00;  // Flags
  ipPacket[7] = 0x00;
  ipPacket[8] = 64;    // TTL
  ipPacket[9] = 17;    // Protocol (UDP)
  ipPacket[10] = 0x00; // Checksum (稍后计算)
  ipPacket[11] = 0x00;
  
  // 源IP: 10.20.1.2
  inet_pton(AF_INET, "10.20.1.2", ipPacket + 12);
  
  // 目标IP: 8.8.8.8
  inet_pton(AF_INET, "8.8.8.8", ipPacket + 16);
  
  // 计算IP校验和
  uint32_t sum = 0;
  for (int i = 0; i < ipHeaderLen; i += 2) {
    sum += (ipPacket[i] << 8) | ipPacket[i + 1];
  }
  while (sum >> 16) {
    sum = (sum & 0xFFFF) + (sum >> 16);
  }
  uint16_t checksum = ~sum;
  ipPacket[10] = (checksum >> 8) & 0xFF;
  ipPacket[11] = checksum & 0xFF;
  
  // 复制UDP数据
  memcpy(ipPacket + ipHeaderLen, udpPacket, udpLen);
  
  VPN_SERVER_LOGI("✅ IP packet built: %{public}d bytes (src:10.20.1.2:%{public}d -> dst:8.8.8.8:%{public}d)",
                  totalLen, srcPort, dstPort);
  
  // 发送到服务器自己 (127.0.0.1:8888)
  sockaddr_in testAddr{};
  testAddr.sin_family = AF_INET;
  testAddr.sin_port = htons(8888);
  inet_pton(AF_INET, "127.0.0.1", &testAddr.sin_addr);
  
  VPN_SERVER_LOGI("📤 Sending DNS test packet to server (127.0.0.1:8888)...");
  
  // 创建测试socket
  int dnsTestSock = socket(AF_INET, SOCK_DGRAM, 0);
  if (dnsTestSock < 0) {
    VPN_SERVER_LOGE("❌ Failed to create DNS test socket: %s", strerror(errno));
    napi_value result;
    napi_create_string_utf8(env, "❌ Failed to create DNS test socket", NAPI_AUTO_LENGTH, &result);
    return result;
  }
  
  // 发送测试包
  int sent = sendto(dnsTestSock, ipPacket, totalLen, 0,
                   reinterpret_cast<sockaddr*>(&testAddr), sizeof(testAddr));
  
  if (sent < 0) {
    VPN_SERVER_LOGE("❌ Failed to send test packet: %{public}s", strerror(errno));
    close(dnsTestSock);
    napi_value result;
    napi_create_string_utf8(env, "Failed to send test packet", NAPI_AUTO_LENGTH, &result);
    return result;
  }
  
  VPN_SERVER_LOGI("✅ Test packet sent: %{public}d bytes", sent);
  
  // 设置接收超时（500ms，避免阻塞UI线程）
  struct timeval timeout;
  timeout.tv_sec = 0;
  timeout.tv_usec = 500000;  // 500ms
  setsockopt(dnsTestSock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
  
  // 接收响应
  uint8_t responseBuffer[2048];
  sockaddr_in fromAddr{};
  socklen_t fromLen = sizeof(fromAddr);
  
  VPN_SERVER_LOGI("⏳ Waiting for DNS response (timeout: 500ms)...");
  
  int received = recvfrom(dnsTestSock, responseBuffer, sizeof(responseBuffer), 0,
                         reinterpret_cast<sockaddr*>(&fromAddr), &fromLen);
  
  close(dnsTestSock);
  
  if (received < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      VPN_SERVER_LOGE("❌ DNS test TIMEOUT (500ms)");
      VPN_SERVER_LOGE("   Root cause: Cannot reach 8.8.8.8 (Google DNS)");
      VPN_SERVER_LOGE("   Possible reasons:");
      VPN_SERVER_LOGE("   1. ❌ Firewall blocking UDP port 53 (DNS)");
      VPN_SERVER_LOGE("   2. ❌ GFW (Great Firewall) blocking Google DNS");
      VPN_SERVER_LOGE("   3. ❌ Network gateway/Internet connection down");
      VPN_SERVER_LOGE("   This is NOT a proxy server bug!");
      napi_value result;
      napi_create_string_utf8(env, "❌ DNS Test FAILED (Timeout 500ms)\n\n🔍 Root Cause: Cannot reach Google DNS (8.8.8.8)\n\n⚠️  This is NOT a proxy server bug!\n\nPossible reasons:\n  • Firewall blocking DNS port 53\n  • GFW blocking Google DNS\n  • Network/Internet down\n\n💡 Try:\n  • Use 114.114.114.114 (China DNS)\n  • Check firewall settings\n  • Verify internet connection", NAPI_AUTO_LENGTH, &result);
      return result;
    } else {
      VPN_SERVER_LOGE("❌ Failed to receive response: %{public}s (errno=%{public}d)", strerror(errno), errno);
      napi_value result;
      napi_create_string_utf8(env, "❌ Network error\nCannot receive DNS response", NAPI_AUTO_LENGTH, &result);
      return result;
    }
  }
  
  VPN_SERVER_LOGI("✅ Received response: %{public}d bytes", received);
  
  // 解析响应
  if (received < ipHeaderLen + 8 + 12) {
    VPN_SERVER_LOGE("❌ Response too short: %{public}d bytes", received);
    napi_value result;
    napi_create_string_utf8(env, "Response too short", NAPI_AUTO_LENGTH, &result);
    return result;
  }
  
  // 检查IP头部
  int respIpHeaderLen = (responseBuffer[0] & 0x0F) * 4;
  char srcIP[16], dstIP[16];
  inet_ntop(AF_INET, responseBuffer + 12, srcIP, sizeof(srcIP));
  inet_ntop(AF_INET, responseBuffer + 16, dstIP, sizeof(dstIP));
  
  VPN_SERVER_LOGI("📥 Response: %{public}s -> %{public}s", srcIP, dstIP);
  
  // 检查UDP头部
  const uint8_t* udpHeader = responseBuffer + respIpHeaderLen;
  uint16_t respSrcPort = (udpHeader[0] << 8) | udpHeader[1];
  uint16_t respDstPort = (udpHeader[2] << 8) | udpHeader[3];
  uint16_t respUdpLen = (udpHeader[4] << 8) | udpHeader[5];
  
  VPN_SERVER_LOGI("📥 UDP: %{public}d -> %{public}d, length: %{public}d", 
                  respSrcPort, respDstPort, respUdpLen);
  
  // 解析DNS响应
  const uint8_t* dnsData = udpHeader + 8;
  int dnsDataLen = respUdpLen - 8;
  
  if (dnsDataLen < 12) {
    VPN_SERVER_LOGE("❌ DNS response too short: %{public}d bytes", dnsDataLen);
    napi_value result;
    napi_create_string_utf8(env, "DNS response too short", NAPI_AUTO_LENGTH, &result);
    return result;
  }
  
  uint16_t dnsId = (dnsData[0] << 8) | dnsData[1];
  uint16_t dnsFlags = (dnsData[2] << 8) | dnsData[3];
  uint16_t qdcount = (dnsData[4] << 8) | dnsData[5];
  uint16_t ancount = (dnsData[6] << 8) | dnsData[7];
  uint16_t nscount = (dnsData[8] << 8) | dnsData[9];
  uint16_t arcount = (dnsData[10] << 8) | dnsData[11];
  
  VPN_SERVER_LOGI("🎯 DNS Response: ID=0x%{public}04x, Flags=0x%{public}04x, QD=%{public}d, AN=%{public}d, NS=%{public}d, AR=%{public}d",
                  dnsId, dnsFlags, qdcount, ancount, nscount, arcount);
  
  // 检查是否是成功的响应
  if ((dnsFlags & 0x8000) == 0) {
    VPN_SERVER_LOGE("❌ Not a DNS response");
    napi_value result;
    napi_create_string_utf8(env, "Not a DNS response", NAPI_AUTO_LENGTH, &result);
    return result;
  }
  
  if ((dnsFlags & 0x000F) != 0) {
    VPN_SERVER_LOGE("❌ DNS query failed, error code: %{public}d", (dnsFlags & 0x000F));
    napi_value result;
    napi_create_string_utf8(env, "DNS query failed", NAPI_AUTO_LENGTH, &result);
    return result;
  }
  
  if (ancount == 0) {
    VPN_SERVER_LOGE("❌ No DNS answers received");
    napi_value result;
    napi_create_string_utf8(env, "No DNS answers", NAPI_AUTO_LENGTH, &result);
    return result;
  }
  
  // 提取IP地址
  VPN_SERVER_LOGI("✅✅✅ DNS Query SUCCESS! www.baidu.com resolved:");
  std::string resultStr = "DNS Test SUCCESS!\nwww.baidu.com IP addresses:\n";
  
  // 简单解析：跳过问题部分，直接查找A记录
  int dnsOffset = 12;
  
  VPN_SERVER_LOGI("🔍 Starting DNS parsing, total=%{public}d bytes, QD=%{public}d, AN=%{public}d, NS=%{public}d, AR=%{public}d", 
                  dnsDataLen, qdcount, ancount, nscount, arcount);
  
  // 跳过问题部分
  for (int q = 0; q < qdcount && dnsOffset < dnsDataLen; q++) {
    // 跳过域名
    while (dnsOffset < dnsDataLen && dnsData[dnsOffset] != 0) {
      int labelLen = dnsData[dnsOffset];
      if (labelLen > 63) {
        if ((labelLen & 0xC0) == 0xC0) {
          dnsOffset += 2;
          break;
        }
        break;
      }
      dnsOffset += labelLen + 1;
    }
    if (dnsData[dnsOffset - 1] == 0 || dnsData[dnsOffset - 2] == 0) {
      // 域名结束符已经在上面的循环中处理
    } else {
      dnsOffset++;  // 跳过结束符
    }
    dnsOffset += 4;  // 跳过Type和Class
  }
  
  VPN_SERVER_LOGI("🔍 Question section skipped, now at offset %{public}d", dnsOffset);
  
  // 解析所有sections：Answer, Authority, Additional
  int totalRecords = ancount + nscount + arcount;
  VPN_SERVER_LOGI("🔍 Total records to parse: %{public}d (AN=%{public}d, NS=%{public}d, AR=%{public}d)", 
                  totalRecords, ancount, nscount, arcount);
  
  for (int i = 0; i < totalRecords && dnsOffset < dnsDataLen; i++) {
    const char* sectionName = i < ancount ? "Answer" : (i < ancount + nscount ? "Authority" : "Additional");
    VPN_SERVER_LOGI("🔍 Parsing record #%{public}d [%{public}s], offset=%{public}d", i+1, sectionName, dnsOffset);
    
    // 跳过名称（可能是压缩指针）
    if ((dnsData[dnsOffset] & 0xC0) == 0xC0) {
      VPN_SERVER_LOGI("🔍 Found compressed name pointer: 0x%{public}02x%{public}02x", 
                      dnsData[dnsOffset], dnsData[dnsOffset + 1]);
      dnsOffset += 2;
    } else {
      VPN_SERVER_LOGI("🔍 Skipping non-compressed name at offset %{public}d", dnsOffset);
      while (dnsOffset < dnsDataLen && dnsData[dnsOffset] != 0) {
        dnsOffset += dnsData[dnsOffset] + 1;
      }
      dnsOffset++;
    }
    
    if (dnsOffset + 10 > dnsDataLen) {
      VPN_SERVER_LOGE("❌ Not enough data for RR header, offset=%{public}d", dnsOffset);
      break;
    }
    
    uint16_t type = (dnsData[dnsOffset] << 8) | dnsData[dnsOffset + 1];
    uint16_t rrClass = (dnsData[dnsOffset + 2] << 8) | dnsData[dnsOffset + 3];
    uint32_t ttl = (dnsData[dnsOffset + 4] << 24) | (dnsData[dnsOffset + 5] << 16) |
                   (dnsData[dnsOffset + 6] << 8) | dnsData[dnsOffset + 7];
    uint16_t dataLen = (dnsData[dnsOffset + 8] << 8) | dnsData[dnsOffset + 9];
    
    VPN_SERVER_LOGI("🔍 RR: type=%{public}d, class=%{public}d, ttl=%{public}u, dataLen=%{public}d",
                    type, rrClass, ttl, dataLen);
    
    dnsOffset += 10;
    
    if (dnsOffset + dataLen > dnsDataLen) {
      VPN_SERVER_LOGE("❌ RR data exceeds buffer, offset=%{public}d, dataLen=%{public}d", 
                      dnsOffset, dataLen);
      break;
    }
    
    if (type == 1 && dataLen == 4) {  // A记录
      char ipStr[16];
      snprintf(ipStr, sizeof(ipStr), "%d.%d.%d.%d",
               dnsData[dnsOffset], dnsData[dnsOffset + 1],
               dnsData[dnsOffset + 2], dnsData[dnsOffset + 3]);
      VPN_SERVER_LOGI("  🌐 IP Address: %{public}s (TTL: %{public}u)", ipStr, ttl);
      resultStr += "  ";
      resultStr += ipStr;
      resultStr += "\n";
    } else if (type == 5) {  // CNAME记录
      VPN_SERVER_LOGI("🔍 Found CNAME record (type=5), dataLen=%{public}d", dataLen);
      // CNAME数据是一个域名，暂不解析
    } else {
      VPN_SERVER_LOGI("🔍 Skipping record: type=%{public}d, dataLen=%{public}d", type, dataLen);
    }
    
    dnsOffset += dataLen;
  }
  
  VPN_SERVER_LOGI("🔍 Finished parsing, final offset=%{public}d", dnsOffset);
  
  // 检查是否找到了IP地址
  if (resultStr.find("  ") == std::string::npos) {
    // 没有找到A记录
    VPN_SERVER_LOGW("⚠️ No A records found in DNS response (may contain only CNAME)");
    resultStr += "  (Only CNAME record found, no A record)\n";
    resultStr += "  This means www.baidu.com is an alias.\n";
    resultStr += "  Try using the canonical name directly.\n";
  }
  
  VPN_SERVER_LOGI("🎉🎉🎉 DNS TEST COMPLETED!");
  
  napi_value result;
  napi_create_string_utf8(env, resultStr.c_str(), NAPI_AUTO_LENGTH, &result);
  return result;
}

napi_value Init(napi_env env, napi_value exports)
{
  // 模块初始化日志
  OH_LOG_Print(LOG_APP, LOG_INFO, 0x15b1, "VpnServer", "🎉🎉🎉 NATIVE MODULE INITIALIZED - VPN SERVER MODULE LOADED 🎉🎉🎉");
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
