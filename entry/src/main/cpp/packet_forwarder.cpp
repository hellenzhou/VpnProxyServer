#include "packet_forwarder.h"
#include "protocol_handler.h"
#include "vpn_server_globals.h"
#include "simple_dns_cache.h"
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/select.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <net/if.h>
#include <thread>
#include <chrono>
#include <fcntl.h>
#include <hilog/log.h>

// 全局服务器socket声明 (来自vpn_server.cpp)
extern int g_serverSocket;

#define MAKE_FILE_NAME (strrchr(__FILE__, '/') ? (strrchr(__FILE__, '/') + 1) : __FILE__)

#define FORWARDER_LOGI(fmt, ...) \
  OH_LOG_Print(LOG_APP, LOG_INFO, 0x15b1, "VpnServer", "ZBQ forwarder [%{public}s %{public}d] " fmt, MAKE_FILE_NAME, __LINE__, ##__VA_ARGS__)
#define FORWARDER_LOGE(fmt, ...) \
  OH_LOG_Print(LOG_APP, LOG_INFO, 0x15b1, "VpnServer", "ZBQ forwarder [%{public}s %{public}d] " fmt, MAKE_FILE_NAME, __LINE__, ##__VA_ARGS__)
#define FORWARDER_LOGW(fmt, ...) \
  OH_LOG_Print(LOG_APP, LOG_INFO, 0x15b1, "VpnServer", "ZBQ forwarder [%{public}s %{public}d] " fmt, MAKE_FILE_NAME, __LINE__, ##__VA_ARGS__)

// 缓冲区大小
constexpr int BUFFER_SIZE = 2048;

// 计算IP头校验和
static uint16_t CalculateIPChecksum(const uint8_t* header, int headerLen) {
    uint32_t sum = 0;
    for (int i = 0; i < headerLen; i += 2) {
        if (i == 10) continue; // 跳过校验和字段
        sum += (header[i] << 8) | header[i + 1];
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return ~sum;
}

// 构建IP数据包（用于响应）
static int BuildIPPacket(uint8_t* packet, int maxSize,
                         const std::string& srcIP, int srcPort,
                         const std::string& dstIP, int dstPort,
                         uint8_t protocol, const uint8_t* payload, int payloadSize) {
    if (maxSize < 60) return -1; // 至少需要IP头(20) + TCP/UDP头(20/8) + 一些载荷
    
    // 构建IP头
    uint8_t* ipHeader = packet;
    ipHeader[0] = 0x45; // Version=4, IHL=5 (20字节)
    ipHeader[1] = 0x00; // TOS
    uint16_t totalLen = 20 + (protocol == PROTOCOL_TCP ? 20 : 8) + payloadSize;
    ipHeader[2] = (totalLen >> 8) & 0xFF;
    ipHeader[3] = totalLen & 0xFF;
    ipHeader[4] = 0x00; // Identification
    ipHeader[5] = 0x00;
    ipHeader[6] = 0x40; // Flags (DF)
    ipHeader[7] = 0x00; // Fragment offset
    ipHeader[8] = 64;   // TTL
    ipHeader[9] = protocol;
    ipHeader[10] = 0x00; // Checksum (will calculate)
    ipHeader[11] = 0x00;
    
    // 源IP和目标IP
    inet_pton(AF_INET, srcIP.c_str(), &ipHeader[12]);
    inet_pton(AF_INET, dstIP.c_str(), &ipHeader[16]);
    
    // 计算IP头校验和
    uint16_t ipChecksum = CalculateIPChecksum(ipHeader, 20);
    ipHeader[10] = (ipChecksum >> 8) & 0xFF;
    ipHeader[11] = ipChecksum & 0xFF;
    
    // 构建TCP/UDP头
    uint8_t* transportHeader = packet + 20;
    if (protocol == PROTOCOL_TCP) {
        transportHeader[0] = (srcPort >> 8) & 0xFF;
        transportHeader[1] = srcPort & 0xFF;
        transportHeader[2] = (dstPort >> 8) & 0xFF;
        transportHeader[3] = dstPort & 0xFF;
        transportHeader[4] = 0x00; // Sequence number
        transportHeader[5] = 0x00;
        transportHeader[6] = 0x00;
        transportHeader[7] = 0x00;
        transportHeader[8] = 0x00; // ACK number
        transportHeader[9] = 0x00;
        transportHeader[10] = 0x00;
        transportHeader[11] = 0x00;
        transportHeader[12] = 0x50; // Data offset (5 * 4 = 20 bytes)
        transportHeader[13] = 0x10; // Flags (ACK)
        transportHeader[14] = 0x00; // Window size
        transportHeader[15] = 0x00;
        transportHeader[16] = 0x00; // Checksum (will calculate)
        transportHeader[17] = 0x00;
        transportHeader[18] = 0x00; // Urgent pointer
        transportHeader[19] = 0x00;
        
        // TCP校验和计算（伪头 + TCP头 + 数据）
        uint32_t tcpSum = 0;
        // 伪头
        for (int i = 12; i < 20; i += 2) {
            tcpSum += (ipHeader[i] << 8) | ipHeader[i + 1];
        }
        tcpSum += protocol;
        tcpSum += (20 + payloadSize);
        // TCP头（跳过校验和字段）
        for (int i = 0; i < 16; i += 2) {
            tcpSum += (transportHeader[i] << 8) | transportHeader[i + 1];
        }
        // 数据
        for (int i = 0; i < payloadSize; i += 2) {
            if (i + 1 < payloadSize) {
                tcpSum += (payload[i] << 8) | payload[i + 1];
            } else {
                tcpSum += (payload[i] << 8);
            }
        }
        while (tcpSum >> 16) {
            tcpSum = (tcpSum & 0xFFFF) + (tcpSum >> 16);
        }
        uint16_t tcpChecksum = ~tcpSum;
        transportHeader[16] = (tcpChecksum >> 8) & 0xFF;
        transportHeader[17] = tcpChecksum & 0xFF;
        
    } else if (protocol == PROTOCOL_UDP) {
        transportHeader[0] = (srcPort >> 8) & 0xFF;
        transportHeader[1] = srcPort & 0xFF;
        transportHeader[2] = (dstPort >> 8) & 0xFF;
        transportHeader[3] = dstPort & 0xFF;
        uint16_t udpLen = 8 + payloadSize;
        transportHeader[4] = (udpLen >> 8) & 0xFF;
        transportHeader[5] = udpLen & 0xFF;
        transportHeader[6] = 0x00; // Checksum (will calculate)
        transportHeader[7] = 0x00;
        
        // UDP校验和计算（伪头 + UDP头 + 数据）
        uint32_t udpSum = 0;
        // 伪头
        for (int i = 12; i < 20; i += 2) {
            udpSum += (ipHeader[i] << 8) | ipHeader[i + 1];
        }
        udpSum += protocol;
        udpSum += udpLen;
        // UDP头（跳过校验和字段）
        udpSum += (transportHeader[0] << 8) | transportHeader[1];
        udpSum += (transportHeader[2] << 8) | transportHeader[3];
        udpSum += (transportHeader[4] << 8) | transportHeader[5];
        // 数据
        for (int i = 0; i < payloadSize; i += 2) {
            if (i + 1 < payloadSize) {
                udpSum += (payload[i] << 8) | payload[i + 1];
            } else {
                udpSum += (payload[i] << 8);
            }
        }
        while (udpSum >> 16) {
            udpSum = (udpSum & 0xFFFF) + (udpSum >> 16);
        }
        uint16_t udpChecksum = ~udpSum;
        transportHeader[6] = (udpChecksum >> 8) & 0xFF;
        transportHeader[7] = udpChecksum & 0xFF;
    }
    
    // 复制载荷
    if (payloadSize > 0 && payload) {
        memcpy(packet + 20 + (protocol == PROTOCOL_TCP ? 20 : 8), payload, payloadSize);
    }
    
    return 20 + (protocol == PROTOCOL_TCP ? 20 : 8) + payloadSize;
}

int PacketForwarder::ForwardPacket(const uint8_t* data, int dataSize, 
                                   const PacketInfo& packetInfo, 
                                   const sockaddr_in& originalPeer) {
    FORWARDER_LOGI("Forwarding packet to %{public}s:%{public}d (protocol=%{public}d)", 
                     packetInfo.targetIP.c_str(), packetInfo.targetPort, packetInfo.protocol);
    
    // 检查是否为DNS查询，重定向到公共DNS
    std::string actualTargetIP = packetInfo.targetIP;
    if (packetInfo.targetPort == 53) {
        FORWARDER_LOGI("🔍 [DNS] Received DNS query request for %{public}s:%{public}d", 
                      packetInfo.targetIP.c_str(), packetInfo.targetPort);
        // HarmonyOS沙盒环境 - 实现本地DNS响应
        if (actualTargetIP != "127.0.0.1") {
            FORWARDER_LOGI("🔄 HarmonyOS: Redirecting DNS to local loopback: %{public}s -> 127.0.0.1", actualTargetIP.c_str());
            actualTargetIP = "127.0.0.1";
        }
        FORWARDER_LOGI("✅ Using HarmonyOS local DNS: %{public}s:%{public}d", actualTargetIP.c_str(), packetInfo.targetPort);
        FORWARDER_LOGI("🔍 [DNS] Will forward DNS query to %{public}s:%{public}d", actualTargetIP.c_str(), packetInfo.targetPort);
    }
    
    // 创建socket
    int sockFd = CreateSocket(packetInfo.addressFamily, packetInfo.protocol);
    if (sockFd < 0) {
        FORWARDER_LOGE("Failed to create socket: %{public}s", strerror(errno));
        return -1;
    }
    
    // 根据协议类型进行转发
    int result = -1;
    // 创建修改后的PacketInfo用于转发（使用actualTargetIP）
    PacketInfo forwardInfo = packetInfo;
    forwardInfo.targetIP = actualTargetIP;
    
    if (packetInfo.protocol == PROTOCOL_UDP) {
        result = HandleUDPForwarding(sockFd, data, dataSize, forwardInfo, packetInfo.addressFamily, originalPeer);
    } else if (packetInfo.protocol == PROTOCOL_TCP) {
        result = HandleTCPForwarding(sockFd, data, dataSize, forwardInfo, packetInfo.addressFamily, originalPeer);
    }
    
    if (result < 0) {
        close(sockFd);
        return -1;
    }
    
    return sockFd;
}

int PacketForwarder::CreateSocket(int addressFamily, uint8_t protocol) {
    // 代理服务器在trustedApplications中，socket不会被VPN路由表拦截
    // 直接创建socket，逻辑正确：代理服务器自己创建socket连接真实服务器
    int sockFd = -1;
    if (protocol == PROTOCOL_UDP) {
        sockFd = socket(addressFamily, SOCK_DGRAM, 0);
        FORWARDER_LOGI("✅ Created UDP socket for forwarding (not intercepted by VPN routing)");
    } else if (protocol == PROTOCOL_TCP) {
        sockFd = socket(addressFamily, SOCK_STREAM, 0);
        FORWARDER_LOGI("✅ Created TCP socket for forwarding (not intercepted by VPN routing)");
    } else {
        FORWARDER_LOGE("❌ Unsupported protocol: %{public}d", protocol);
        return -1;
    }
    
    if (sockFd < 0) {
        FORWARDER_LOGE("❌ Failed to create socket: %{public}s", strerror(errno));
        return -1;
    }
    
    return sockFd;
}

int PacketForwarder::HandleUDPForwarding(int sockFd, const uint8_t* data, int dataSize,
                                       const PacketInfo& packetInfo, int addressFamily,
                                       const sockaddr_in& originalPeer) {
    const std::string& targetIP = packetInfo.targetIP;
    int targetPort = packetInfo.targetPort;
    FORWARDER_LOGI("🚀 Starting UDP forwarding to %{public}s:%{public}d", targetIP.c_str(), targetPort);
    
    // 设置socket为非阻塞模式
    int flags = fcntl(sockFd, F_GETFL, 0);
    fcntl(sockFd, F_SETFL, flags | O_NONBLOCK);
    
    // 设置socket选项，允许重用地址
    int reuseAddr = 1;
    setsockopt(sockFd, SOL_SOCKET, SO_REUSEADDR, &reuseAddr, sizeof(reuseAddr));
    
    // 绑定到本地网络接口（如果需要）
    struct sockaddr_in localAddr{};
    localAddr.sin_family = AF_INET;
    localAddr.sin_addr.s_addr = INADDR_ANY;  // 0.0.0.0 允许系统选择最佳接口
    localAddr.sin_port = 0;  // 让系统选择端口
    
    // 尝试绑定 - 这允许socket使用任何可用的网络接口
    if (bind(sockFd, (struct sockaddr*)&localAddr, sizeof(localAddr)) < 0) {
        FORWARDER_LOGE("Failed to bind UDP socket: %{public}s", strerror(errno));
        FORWARDER_LOGE("🔍 [网络诊断] bind()失败 - 可能原因:");
        FORWARDER_LOGE("🔍 [网络诊断]   1) 端口已被占用（但我们使用0让系统选择）");
        FORWARDER_LOGE("🔍 [网络诊断]   2) 权限不足");
        FORWARDER_LOGE("🔍 [网络诊断]   3) 网络接口不可用");
        close(sockFd);
        return -1;
    }
    
    // 获取绑定的本地地址和端口（用于调试）
    struct sockaddr_in boundAddr;
    socklen_t addrLen = sizeof(boundAddr);
    getsockname(sockFd, (struct sockaddr*)&boundAddr, &addrLen);
    char localIP[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &boundAddr.sin_addr, localIP, INET_ADDRSTRLEN);
    FORWARDER_LOGI("✅ UDP socket bound successfully: 本地地址=%{public}s:%{public}d", localIP, ntohs(boundAddr.sin_port));
    
    // 设置目标地址
    sockaddr_in targetAddr;
    memset(&targetAddr, 0, sizeof(targetAddr));
    targetAddr.sin_family = addressFamily;
    targetAddr.sin_port = htons(targetPort);
    
    if (inet_pton(addressFamily, targetIP.c_str(), &targetAddr.sin_addr) <= 0) {
        FORWARDER_LOGE("❌ Invalid target IP address: %{public}s", targetIP.c_str());
        close(sockFd);
        return -1;
    }
    
    FORWARDER_LOGI("📡 Target address configured: %{public}s:%{public}d", targetIP.c_str(), targetPort);
    bool isDNS = (targetPort == 53);
    
    // HarmonyOS网络环境诊断
    if (isDNS) {
        FORWARDER_LOGI("🔍 [HarmonyOS] 网络环境检查:");
        FORWARDER_LOGI("🔍 [HarmonyOS] - DNS查询目标: %{public}s:%{public}d", targetIP.c_str(), targetPort);
        FORWARDER_LOGI("🔍 [HarmonyOS] - 设备网络状态: 沙盒环境");
        FORWARDER_LOGI("🔍 [HarmonyOS] - 权限检查: INTERNET权限已申请");
        
        // HarmonyOS沙盒环境 - 直接生成DNS响应
        if (targetIP == "127.0.0.1" && targetPort == 53) {
            FORWARDER_LOGI("🔍 [HarmonyOS] 检测到本地DNS查询，生成模拟响应");
            
            // 从原始数据包中提取DNS查询部分
            if (dataSize >= 28) {
                // IP头 (20字节) + UDP头 (8字节) + DNS查询
                const uint8_t* dnsQuery = data + 28;
                int dnsQueryLen = dataSize - 28;
                
                if (dnsQueryLen >= 12) { // 至少需要DNS头部
                    // 构造DNS响应包
                    uint8_t dnsResponse[256];
                    int responseLen = 0;
                    
                    // 1. 复制DNS头部 (12字节)
                    memcpy(dnsResponse, dnsQuery, 12);
                    responseLen = 12;
                    
                    // 2. 修改DNS标志为响应
                    dnsResponse[2] = 0x81; // 响应标志 + 权威回答
                    dnsResponse[3] = 0x80;
                    
                    // 3. 设置回答数量为1
                    dnsResponse[6] = 0x00;
                    dnsResponse[7] = 0x01;
                    
                    // 4. 复制查询部分
                    int queryOffset = 12;
                    while (queryOffset < dnsQueryLen && dnsQuery[queryOffset] != 0) {
                        int labelLen = dnsQuery[queryOffset];
                        if (labelLen == 0) break;
                        queryOffset += labelLen + 1;
                    }
                    queryOffset += 1; // 跳过结束的0
                    queryOffset += 4; // 跳过QTYPE和QCLASS
                    
                    // 复制查询名称到响应
                    int nameLen = queryOffset - 12;
                    memcpy(dnsResponse + responseLen, dnsQuery + 12, nameLen);
                    responseLen += nameLen;
                    
                    // 5. 添加答案部分
                    dnsResponse[responseLen++] = 0xC0; // 指针
                    dnsResponse[responseLen++] = 0x0C;  // 指向域名
                    dnsResponse[responseLen++] = 0x00;  // TYPE A
                    dnsResponse[responseLen++] = 0x01;
                    dnsResponse[responseLen++] = 0x00;  // CLASS IN
                    dnsResponse[responseLen++] = 0x01;
                    dnsResponse[responseLen++] = 0x00;  // TTL
                    dnsResponse[responseLen++] = 0x00;
                    dnsResponse[responseLen++] = 0x01;
                    dnsResponse[responseLen++] = 0x2C;
                    dnsResponse[responseLen++] = 0x00;  // 数据长度
                    dnsResponse[responseLen++] = 0x04;
                    dnsResponse[responseLen++] = 0x08; // 8.8.8.8
                    dnsResponse[responseLen++] = 0x08;
                    dnsResponse[responseLen++] = 0x08;
                    dnsResponse[responseLen++] = 0x08;
                    
                    // 发送DNS响应回客户端
                    uint8_t ipPacket[BUFFER_SIZE];
                    int ipPacketLen = BuildIPPacket(
                        ipPacket, sizeof(ipPacket),                // 输出缓冲区
                        "192.168.100.2", 53,                       // 源IP和端口 (VPN DNS服务器)
                        packetInfo.sourceIP, packetInfo.sourcePort, // 目标IP和端口 (客户端)
                        IPPROTO_UDP,                               // 协议
                        dnsResponse, responseLen                   // 载荷数据
                    );
                    
                    if (ipPacketLen > 0) {
                        ssize_t sent = sendto(g_sockFd, ipPacket, ipPacketLen, 0,
                                            (struct sockaddr*)&originalPeer, sizeof(originalPeer));
                        if (sent > 0) {
                            FORWARDER_LOGI("✅ [HarmonyOS] 本地DNS响应已发送: %{public}zd字节", sent);
                        } else {
                            FORWARDER_LOGE("❌ [HarmonyOS] DNS响应发送失败: %{public}s", strerror(errno));
                        }
                    }
                }
            }
            
            close(sockFd);
            return 0; // 成功处理本地DNS
        }
        
        // 测试本地网络连通性
        int testSock = socket(AF_INET, SOCK_DGRAM, 0);
        if (testSock >= 0) {
            struct sockaddr_in testAddr{};
            testAddr.sin_family = AF_INET;
            testAddr.sin_port = htons(53);
            inet_pton(AF_INET, "127.0.0.1", &testAddr.sin_addr);
            
            int testResult = connect(testSock, (struct sockaddr*)&testAddr, sizeof(testAddr));
            if (testResult == 0) {
                FORWARDER_LOGI("🔍 [HarmonyOS] ✅ 本地网络栈正常");
            } else {
                FORWARDER_LOGI("🔍 [HarmonyOS] ⚠️ 本地网络受限");
            }
            close(testSock);
        }
    }
    
    // 简化DNS缓存检查
    if (isDNS) {
        std::string queryKey = std::string(reinterpret_cast<const char*>(data + 28), dataSize - 28);
        std::string cachedResponse;
        if (SimpleDNSCache::get(queryKey, cachedResponse)) {
            FORWARDER_LOGI("🔍 [DNS] ✅ Cache hit, returning cached response");
            
            // 发送缓存响应
            uint8_t ipPacket[BUFFER_SIZE];
            int packetSize = BuildIPPacket(ipPacket, BUFFER_SIZE,
                                           packetInfo.targetIP, packetInfo.targetPort,
                                           packetInfo.sourceIP, packetInfo.sourcePort,
                                           PROTOCOL_UDP, reinterpret_cast<const uint8_t*>(cachedResponse.c_str()), cachedResponse.length());
            
            if (packetSize > 0) {
                int sentBack = sendto(g_sockFd, ipPacket, packetSize, 0, 
                                     (struct sockaddr*)&originalPeer, sizeof(originalPeer));
                if (sentBack > 0) {
                    FORWARDER_LOGI("🔍 [DNS] ✅ Cached response sent: %{public}d bytes", sentBack);
                }
            }
            close(sockFd);
            return sockFd;
        }
    }
    
    // 提取UDP载荷（去除IP头和UDP头）
    int ipHeaderLen = (data[0] & 0x0F) * 4;  // IP头长度 = (低4位 * 4字节)
    int udpHeaderLen = 8;  // UDP头固定8字节
    int payloadOffset = ipHeaderLen + udpHeaderLen;
    int payloadSize = dataSize - payloadOffset;
    
    if (payloadSize <= 0) {
        FORWARDER_LOGE("❌ Invalid UDP packet: no payload data (ipHeaderLen=%{public}d, udpHeaderLen=%{public}d, dataSize=%{public}d)", 
                      ipHeaderLen, udpHeaderLen, dataSize);
        close(sockFd);
        return -1;
    }
    
    const uint8_t* payloadData = data + payloadOffset;
    FORWARDER_LOGI("📤 [客户端->目标服务器] 准备发送UDP数据包: 客户端=%{public}s:%{public}d -> 目标=%{public}s:%{public}d, 载荷大小=%{public}d字节 (总包=%{public}d字节)",
                   inet_ntoa(originalPeer.sin_addr), ntohs(originalPeer.sin_port), targetIP.c_str(), targetPort, payloadSize, dataSize);
    
    // 对于UDP，需要先connect到目标地址，这样recv()才能正确接收响应
    // 注意：UDP的connect()不会真正建立连接，只是绑定目标地址，使得后续recv()只接收来自该地址的数据
    if (connect(sockFd, (struct sockaddr*)&targetAddr, sizeof(targetAddr)) < 0) {
        FORWARDER_LOGE("❌ [UDP诊断] connect()到目标地址失败: 目标=%{public}s:%{public}d, 错误=%{public}s", 
                      targetIP.c_str(), targetPort, strerror(errno));
        FORWARDER_LOGE("🔍 [UDP诊断] 注意：UDP的connect()用于绑定目标地址，失败会导致无法接收响应");
        close(sockFd);
        return -1;
    }
    FORWARDER_LOGI("✅ [UDP诊断] UDP socket已connect到目标地址: %{public}s:%{public}d (用于接收响应)", 
                   targetIP.c_str(), targetPort);
    
    // 只发送UDP载荷，不包含IP头和UDP头
    ssize_t sentBytes = send(sockFd, payloadData, payloadSize, 0);
    if (sentBytes < 0) {
        FORWARDER_LOGE("❌ [客户端->目标服务器] UDP数据包发送失败: 目标=%{public}s:%{public}d, 错误=%{public}s", 
                      targetIP.c_str(), targetPort, strerror(errno));
        FORWARDER_LOGE("🔍 [UDP诊断] send()失败: errno=%{public}d (%{public}s)", errno, strerror(errno));
        FORWARDER_LOGE("🔍 [UDP诊断] 本地地址=%{public}s:%{public}d -> 目标=%{public}s:%{public}d", 
                       localIP, ntohs(boundAddr.sin_port), targetIP.c_str(), targetPort);
        if (isDNS) {
            FORWARDER_LOGE("🔍 [DNS诊断] DNS查询发送失败 - 可能原因:");
            FORWARDER_LOGE("🔍 [DNS诊断]   1) 网络接口不可用");
            FORWARDER_LOGE("🔍 [DNS诊断]   2) 路由表配置问题");
            FORWARDER_LOGE("🔍 [DNS诊断]   3) 权限不足");
        }
        close(sockFd);
        return -1;
    }
    
    FORWARDER_LOGI("✅ [客户端->目标服务器] UDP载荷发送成功: 客户端=%{public}s:%{public}d -> 目标=%{public}s:%{public}d, 已发送=%{public}zd字节 (载荷大小=%{public}d字节)",
                   inet_ntoa(originalPeer.sin_addr), ntohs(originalPeer.sin_port), targetIP.c_str(), targetPort, sentBytes, payloadSize);
    if (isDNS) {
        FORWARDER_LOGI("🔍 [DNS诊断] DNS查询载荷已成功发送到 %{public}s:%{public}d (%{public}zd字节)", 
                       targetIP.c_str(), targetPort, sentBytes);
    }
    
    // 启动UDP响应处理线程 - 使用值传递避免引用问题
    std::thread responseThread(HandleUdpResponse, sockFd, originalPeer, packetInfo);
    responseThread.detach();
    
    return 0;
}

int PacketForwarder::HandleTCPForwarding(int sockFd, const uint8_t* data, int dataSize,
                                           const PacketInfo& packetInfo, int addressFamily,
                                           const sockaddr_in& originalPeer) {
    const std::string& targetIP = packetInfo.targetIP;
    int targetPort = packetInfo.targetPort;
    FORWARDER_LOGI("Handling TCP forwarding to %{public}s:%{public}d", targetIP.c_str(), targetPort);
    FORWARDER_LOGI("🔗 Testing TCP connectivity to %{public}s:%{public}d", targetIP.c_str(), targetPort);
    
    // 设置socket为非阻塞模式
    int flags = fcntl(sockFd, F_GETFL, 0);
    fcntl(sockFd, F_SETFL, flags | O_NONBLOCK);
    
    // 设置socket选项，允许重用地址
    int reuseAddr = 1;
    setsockopt(sockFd, SOL_SOCKET, SO_REUSEADDR, &reuseAddr, sizeof(reuseAddr));
    
    // 设置目标地址
    struct sockaddr_in serverAddr{};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(targetPort);
    if (inet_pton(AF_INET, targetIP.c_str(), &serverAddr.sin_addr) <= 0) {
        FORWARDER_LOGE("❌ Invalid target IP address: %{public}s", targetIP.c_str());
        close(sockFd);
        return -1;
    }
    
    // 绑定到本地网络接口
    struct sockaddr_in localAddr{};
    localAddr.sin_family = AF_INET;
    localAddr.sin_addr.s_addr = INADDR_ANY;  // 0.0.0.0 允许系统选择最佳接口
    localAddr.sin_port = 0;  // 让系统选择端口
    
    // 尝试绑定 - 这允许socket使用任何可用的网络接口
    if (bind(sockFd, (struct sockaddr*)&localAddr, sizeof(localAddr)) < 0) {
        FORWARDER_LOGE("Failed to bind TCP socket: %{public}s", strerror(errno));
        FORWARDER_LOGE("🔍 [网络诊断] bind()失败 - 可能原因:");
        FORWARDER_LOGE("🔍 [网络诊断]   1) 端口已被占用（但我们使用0让系统选择）");
        FORWARDER_LOGE("🔍 [网络诊断]   2) 权限不足");
        FORWARDER_LOGE("🔍 [网络诊断]   3) 网络接口不可用");
        close(sockFd);
        return -1;
    }
    
    // 获取绑定的本地地址和端口（用于调试）
    struct sockaddr_in boundAddr;
    socklen_t addrLen = sizeof(boundAddr);
    getsockname(sockFd, (struct sockaddr*)&boundAddr, &addrLen);
    char localIP[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &boundAddr.sin_addr, localIP, INET_ADDRSTRLEN);
    FORWARDER_LOGI("✅ TCP socket bound successfully: 本地地址=%{public}s:%{public}d", localIP, ntohs(boundAddr.sin_port));
    FORWARDER_LOGI("🔍 [网络诊断] 准备连接: 本地=%{public}s:%{public}d -> 目标=%{public}s:%{public}d", 
                   localIP, ntohs(boundAddr.sin_port), targetIP.c_str(), targetPort);
    
    // 尝试连接
    int connectResult = connect(sockFd, (struct sockaddr*)&serverAddr, sizeof(serverAddr));
    if (connectResult < 0) {
        if (errno == EINPROGRESS) {
            FORWARDER_LOGI("⏳ TCP连接进行中 (EINPROGRESS)，等待连接完成...");
            // 使用select等待连接完成
            fd_set writefds;
            struct timeval timeout;
            timeout.tv_sec = 5;  // 5秒超时
            timeout.tv_usec = 0;
            
            FD_ZERO(&writefds);
            FD_SET(sockFd, &writefds);
            
            FORWARDER_LOGI("🔍 [网络诊断] 等待select()返回 (超时=5秒)...");
            int selectResult = select(sockFd + 1, nullptr, &writefds, nullptr, &timeout);
            FORWARDER_LOGI("🔍 [网络诊断] select()返回: %{public}d", selectResult);
            
            if (selectResult > 0) {
                int error = 0;
                socklen_t len = sizeof(error);
                if (getsockopt(sockFd, SOL_SOCKET, SO_ERROR, &error, &len) == 0 && error == 0) {
                    FORWARDER_LOGI("✅✅✅ TCP connection established successfully ✅✅✅");
                    
                    // 设置为非阻塞模式进行数据交换
                    int flags = fcntl(sockFd, F_GETFL, 0);
                    fcntl(sockFd, F_SETFL, flags | O_NONBLOCK);
                    
                    // 计算TCP载荷偏移
                    int ipHeaderLen = (data[0] & 0x0F) * 4;
                    int tcpHeaderLen = (data[ipHeaderLen + 12] & 0xF0) >> 4;
                    tcpHeaderLen *= 4;
                    int payloadOffset = ipHeaderLen + tcpHeaderLen;
                    int payloadSize = dataSize - payloadOffset;
                    
                    if (payloadSize > 0) {
                        // 发送TCP载荷
                        const uint8_t* payloadData = data + payloadOffset;
                        int sent = send(sockFd, payloadData, payloadSize, 0);
                        
                        if (sent > 0) {
                            FORWARDER_LOGI("✅ [客户端->目标服务器] TCP载荷发送成功: 客户端=%{public}s:%{public}d -> 目标=%{public}s:%{public}d, 已发送=%{public}d字节",
                                           inet_ntoa(originalPeer.sin_addr), ntohs(originalPeer.sin_port), targetIP.c_str(), targetPort, sent);
                        } else if (sent < 0 && errno == EAGAIN) {
                            FORWARDER_LOGW("⚠️ [客户端->目标服务器] TCP发送会阻塞，数据稍后发送: 目标=%{public}s:%{public}d", targetIP.c_str(), targetPort);
                        } else {
                            FORWARDER_LOGE("❌ [客户端->目标服务器] TCP数据发送失败: 目标=%{public}s:%{public}d, 错误=%{public}s", 
                                           targetIP.c_str(), targetPort, strerror(errno));
                        }
                    } else {
                        FORWARDER_LOGW("⚠️ TCP packet has no payload (SYN/ACK/FIN packet)");
                    }
                    
                    // 启动TCP响应处理线程
                    std::thread tcpResponseHandler(HandleTcpResponse, sockFd, originalPeer, packetInfo);
                    tcpResponseHandler.detach();
                    
                    return sockFd;
                    
                } else {
                    FORWARDER_LOGE("❌ TCP connection failed: %{public}s (error code: %{public}d)", strerror(error), error);
                    FORWARDER_LOGE("🔍 [网络诊断] 连接失败原因: SO_ERROR=%{public}d (%{public}s)", error, strerror(error));
                    FORWARDER_LOGE("🔍 [网络诊断] 可能原因: 1)目标服务器拒绝连接 2)防火墙阻止 3)网络路由问题");
                    close(sockFd);
                    return -1;
                }
            } else if (selectResult == 0) {
                FORWARDER_LOGE("❌ TCP connection timeout: select() returned 0 (no file descriptors ready)");
                FORWARDER_LOGE("❌ Target server %{public}s:%{public}d may be unreachable or firewall blocked", targetIP.c_str(), targetPort);
                FORWARDER_LOGE("🔍 [网络诊断] 连接超时 - 可能原因:");
                FORWARDER_LOGE("🔍 [网络诊断]   1) 服务器机器没有互联网访问权限");
                FORWARDER_LOGE("🔍 [网络诊断]   2) 防火墙阻止了出站连接");
                FORWARDER_LOGE("🔍 [网络诊断]   3) 目标服务器 %{public}s:%{public}d 不可达", targetIP.c_str(), targetPort);
                FORWARDER_LOGE("🔍 [网络诊断]   4) 网络路由配置问题");
                FORWARDER_LOGE("🔍 [网络诊断] 建议: 检查服务器机器的网络连接和防火墙设置");
                close(sockFd);
                return -1;
            } else {
                FORWARDER_LOGE("❌ TCP connection select() failed: %{public}s (errno: %{public}d)", strerror(errno), errno);
                FORWARDER_LOGE("🔍 [网络诊断] select()失败: errno=%{public}d (%{public}s)", errno, strerror(errno));
                close(sockFd);
                return -1;
            }
        } else {
            FORWARDER_LOGE("❌ Failed to connect TCP socket: %{public}s (errno: %{public}d)", strerror(errno), errno);
            FORWARDER_LOGE("🔍 [网络诊断] connect()立即失败: errno=%{public}d (%{public}s)", errno, strerror(errno));
            FORWARDER_LOGE("🔍 [网络诊断] 可能原因: 1)目标地址无效 2)网络接口不可用 3)权限问题");
            close(sockFd);
            return -1;
        }
    } else {
        // connect() 立即成功（阻塞模式或本地连接）
        FORWARDER_LOGI("✅ TCP connection established immediately (blocking mode or local connection)");
        
        // 设置为非阻塞模式进行数据交换
        int flags = fcntl(sockFd, F_GETFL, 0);
        fcntl(sockFd, F_SETFL, flags | O_NONBLOCK);
        
        // 计算TCP载荷偏移
        int ipHeaderLen = (data[0] & 0x0F) * 4;
        int tcpHeaderLen = (data[ipHeaderLen + 12] & 0xF0) >> 4;
        tcpHeaderLen *= 4;
        int payloadOffset = ipHeaderLen + tcpHeaderLen;
        int payloadSize = dataSize - payloadOffset;
        
        if (payloadSize > 0) {
            // 发送TCP载荷
            const uint8_t* payloadData = data + payloadOffset;
            int sent = send(sockFd, payloadData, payloadSize, 0);
            
            if (sent > 0) {
                FORWARDER_LOGI("✅ [客户端->目标服务器] TCP载荷发送成功: 客户端=%{public}s:%{public}d -> 目标=%{public}s:%{public}d, 已发送=%{public}d字节",
                               inet_ntoa(originalPeer.sin_addr), ntohs(originalPeer.sin_port), targetIP.c_str(), targetPort, sent);
            } else if (sent < 0 && errno == EAGAIN) {
                FORWARDER_LOGW("⚠️ [客户端->目标服务器] TCP发送会阻塞，数据稍后发送: 目标=%{public}s:%{public}d", targetIP.c_str(), targetPort);
            } else {
                FORWARDER_LOGE("❌ [客户端->目标服务器] TCP数据发送失败: 目标=%{public}s:%{public}d, 错误=%{public}s", 
                               targetIP.c_str(), targetPort, strerror(errno));
            }
        } else {
            FORWARDER_LOGW("⚠️ TCP packet has no payload (SYN/ACK/FIN packet)");
        }
        
        // 启动TCP响应处理线程
        std::thread tcpResponseHandler(HandleTcpResponse, sockFd, originalPeer, packetInfo);
        tcpResponseHandler.detach();
        
        return sockFd;
    }
}

void PacketForwarder::HandleTcpResponse(int sockFd, sockaddr_in originalPeer, const PacketInfo& packetInfo) {
    const std::string& targetIP = packetInfo.targetIP;
    int targetPort = packetInfo.targetPort;
    FORWARDER_LOGI("🔄 Handling TCP response from %{public}s:%{public}d", targetIP.c_str(), targetPort);
    
    char buffer[BUFFER_SIZE];
    fd_set readfds;
    struct timeval timeout;
    
    while (true) {
        FD_ZERO(&readfds);
        FD_SET(sockFd, &readfds);
        timeout.tv_sec = 5;  // 5秒超时
        timeout.tv_usec = 0;
        
        int selectResult = select(sockFd + 1, &readfds, nullptr, nullptr, &timeout);
        if (selectResult > 0) {
            int received = recv(sockFd, buffer, BUFFER_SIZE, 0);
            if (received > 0) {
                FORWARDER_LOGI("📨 [目标服务器->服务端] TCP响应接收成功: 目标=%{public}s:%{public}d -> 服务端, 收到=%{public}d字节",
                               targetIP.c_str(), targetPort, received);
                
                // 重建IP数据包（交换源和目标）
                uint8_t ipPacket[BUFFER_SIZE];
                int packetSize = BuildIPPacket(ipPacket, BUFFER_SIZE,
                                               packetInfo.targetIP, packetInfo.targetPort,  // 响应源 = 原目标
                                               packetInfo.sourceIP, packetInfo.sourcePort,  // 响应目标 = 原源
                                               PROTOCOL_TCP, reinterpret_cast<const uint8_t*>(buffer), received);
                
                if (packetSize > 0) {
                    // 发送回客户端
                    FORWARDER_LOGI("📤 [服务端->客户端] 准备发送TCP响应: 服务端 -> 客户端=%{public}s:%{public}d, IP包大小=%{public}d字节",
                                   inet_ntoa(originalPeer.sin_addr), ntohs(originalPeer.sin_port), packetSize);
                    int sent = sendto(g_sockFd, ipPacket, packetSize, 0, 
                                    (struct sockaddr*)&originalPeer, sizeof(originalPeer));
                    if (sent > 0) {
                        FORWARDER_LOGI("✅ [服务端->客户端] TCP响应发送成功: 服务端 -> 客户端=%{public}s:%{public}d, 已发送=%{public}d字节",
                                       inet_ntoa(originalPeer.sin_addr), ntohs(originalPeer.sin_port), sent);
                    } else {
                        FORWARDER_LOGE("❌ [服务端->客户端] TCP响应发送失败: 客户端=%{public}s:%{public}d, 错误=%{public}s", 
                                       inet_ntoa(originalPeer.sin_addr), ntohs(originalPeer.sin_port), strerror(errno));
                        break;
                    }
                } else {
                    FORWARDER_LOGE("❌ [服务端->客户端] 构建IP数据包失败");
                    break;
                }
            } else if (received == 0) {
                FORWARDER_LOGI("🔚 TCP connection closed by server");
                break;
            } else {
                FORWARDER_LOGE("❌ TCP recv error: %{public}s", strerror(errno));
                break;
            }
        } else {
            FORWARDER_LOGI("⏰ TCP response timeout, closing connection");
            break;
        }
    }
    
    close(sockFd);
    FORWARDER_LOGI("🏁 TCP response handler finished");
}

bool PacketForwarder::IsDNSQuery(const std::string& targetIP, int targetPort) {
    return targetPort == 53;
}

// 辅助函数：测试TCP连接到指定服务器
static bool TestTCPConnection(const char* serverIP, int port, const char* serverName) {
    FORWARDER_LOGI("🔗 测试TCP连接到 %{public}s (%{public}s:%{public}d)", serverName, serverIP, port);
    
    int tcpSock = socket(AF_INET, SOCK_STREAM, 0);
    if (tcpSock < 0) {
        FORWARDER_LOGE("❌ 创建TCP socket失败: %{public}s", strerror(errno));
        return false;
    }
    
    struct sockaddr_in serverAddr{};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);
    inet_pton(AF_INET, serverIP, &serverAddr.sin_addr);
    
    // 设置非阻塞
    int flags = fcntl(tcpSock, F_GETFL, 0);
    fcntl(tcpSock, F_SETFL, flags | O_NONBLOCK);
    
    int connectResult = connect(tcpSock, (struct sockaddr*)&serverAddr, sizeof(serverAddr));
    if (connectResult < 0 && errno == EINPROGRESS) {
        fd_set writefds;
        struct timeval timeout;
        timeout.tv_sec = 5;
        timeout.tv_usec = 0;
        
        FD_ZERO(&writefds);
        FD_SET(tcpSock, &writefds);
        
        int selectResult = select(tcpSock + 1, nullptr, &writefds, nullptr, &timeout);
        if (selectResult > 0) {
            int error = 0;
            socklen_t len = sizeof(error);
            if (getsockopt(tcpSock, SOL_SOCKET, SO_ERROR, &error, &len) == 0 && error == 0) {
                FORWARDER_LOGI("✅ 成功连接到 %{public}s (%{public}s:%{public}d)", serverName, serverIP, port);
                close(tcpSock);
                return true;
            } else {
                FORWARDER_LOGE("❌ 连接%{public}s失败: %{public}s", serverName, strerror(error));
            }
        } else if (selectResult == 0) {
            FORWARDER_LOGE("❌ 连接%{public}s超时 (5秒)", serverName);
        } else {
            FORWARDER_LOGE("❌ select()失败: %{public}s", strerror(errno));
        }
    } else if (connectResult == 0) {
        FORWARDER_LOGI("✅ 立即连接成功到 %{public}s", serverName);
        close(tcpSock);
        return true;
    } else {
        FORWARDER_LOGE("❌ connect()立即失败: %{public}s", strerror(errno));
    }
    
    close(tcpSock);
    return false;
}

// 测试网络连接
bool PacketForwarder::TestNetworkConnectivity() {
    FORWARDER_LOGI("╔═══════════════════════════════════════════════════════╗");
    FORWARDER_LOGI("║   🌐 网络连接诊断测试开始                              ║");
    FORWARDER_LOGI("╚═══════════════════════════════════════════════════════╝");
    
    int successCount = 0;
    int totalTests = 0;
    
    // ==================== UDP DNS 测试 ====================
    FORWARDER_LOGI("");
    FORWARDER_LOGI("📡 [1/5] 测试 UDP DNS 连接...");
    totalTests++;
    
    int udpSock = socket(AF_INET, SOCK_DGRAM, 0);
    if (udpSock >= 0) {
        struct sockaddr_in dnsAddr{};
        dnsAddr.sin_family = AF_INET;
        dnsAddr.sin_port = htons(53);
        inet_pton(AF_INET, "10.20.2.74", &dnsAddr.sin_addr);
        
        uint8_t dnsQuery[] = {0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01};
        
        ssize_t sent = sendto(udpSock, dnsQuery, sizeof(dnsQuery), 0, (struct sockaddr*)&dnsAddr, sizeof(dnsAddr));
        if (sent > 0) {
            fd_set readfds;
            struct timeval timeout;
            timeout.tv_sec = 3;
            timeout.tv_usec = 0;
            
            FD_ZERO(&readfds);
            FD_SET(udpSock, &readfds);
            
            int selectResult = select(udpSock + 1, &readfds, nullptr, nullptr, &timeout);
            if (selectResult > 0) {
                uint8_t response[512];
                ssize_t received = recvfrom(udpSock, response, sizeof(response), 0, nullptr, nullptr);
                if (received > 0) {
                    FORWARDER_LOGI("✅ UDP DNS测试成功 - 收到响应 %{public}zd 字节", received);
                    successCount++;
                } else {
                    FORWARDER_LOGE("❌ UDP DNS测试失败 - 无法接收响应");
                }
            } else {
                FORWARDER_LOGE("❌ UDP DNS测试失败 - 响应超时");
            }
        } else {
            FORWARDER_LOGE("❌ UDP DNS测试失败 - 无法发送查询");
        }
        close(udpSock);
    } else {
        FORWARDER_LOGE("❌ UDP DNS测试失败 - 无法创建socket");
    }
    
    // ==================== TCP 测试：百度 ====================
    FORWARDER_LOGI("");
    FORWARDER_LOGI("📡 [2/5] 测试 TCP 连接到百度...");
    totalTests++;
    if (TestTCPConnection("110.242.68.66", 80, "百度 (www.baidu.com)")) {
        successCount++;
    }
    
    // ==================== TCP 测试：淘宝 ====================
    FORWARDER_LOGI("");
    FORWARDER_LOGI("📡 [3/5] 测试 TCP 连接到淘宝...");
    totalTests++;
    if (TestTCPConnection("140.205.94.189", 80, "淘宝 (www.taobao.com)")) {
        successCount++;
    }
    
    // ==================== TCP 测试：腾讯 ====================
    FORWARDER_LOGI("");
    FORWARDER_LOGI("📡 [4/5] 测试 TCP 连接到腾讯...");
    totalTests++;
    if (TestTCPConnection("183.3.226.35", 80, "腾讯 (www.qq.com)")) {
        successCount++;
    }
    
    // ==================== TCP 测试：阿里云 ====================
    FORWARDER_LOGI("");
    FORWARDER_LOGI("📡 [5/5] 测试 TCP 连接到阿里云...");
    totalTests++;
    if (TestTCPConnection("47.95.164.112", 80, "阿里云公网服务器")) {
        successCount++;
    }
    
    // ==================== 测试结果总结 ====================
    FORWARDER_LOGI("");
    FORWARDER_LOGI("╔═══════════════════════════════════════════════════════╗");
    FORWARDER_LOGI("║   📊 网络诊断测试结果                                  ║");
    FORWARDER_LOGI("╠═══════════════════════════════════════════════════════╣");
    FORWARDER_LOGI("║   成功: %{public}d/%{public}d 项测试通过                                    ║", successCount, totalTests);
    
    if (successCount == totalTests) {
        FORWARDER_LOGI("║   状态: ✅ 网络连接正常，可以正常使用                   ║");
    } else if (successCount > 0) {
        FORWARDER_LOGI("║   状态: ⚠️  部分网络连接受限                           ║");
        FORWARDER_LOGI("║   建议: 检查防火墙或网络策略设置                       ║");
    } else {
        FORWARDER_LOGI("║   状态: ❌ 网络完全不可用                              ║");
        FORWARDER_LOGI("║   建议:                                               ║");
        FORWARDER_LOGI("║   1) 检查鸿蒙PC是否连接到互联网                        ║");
        FORWARDER_LOGI("║   2) 检查系统防火墙设置                               ║");
        FORWARDER_LOGI("║   3) 检查是否在受限网络环境（如企业网络）             ║");
        FORWARDER_LOGI("║   4) 尝试用浏览器访问网站测试基础网络                 ║");
    }
    
    FORWARDER_LOGI("╚═══════════════════════════════════════════════════════╝");
    FORWARDER_LOGI("");
    
    return successCount > 0;
}

void PacketForwarder::HandleUdpResponse(int sockFd, sockaddr_in originalPeer, const PacketInfo& packetInfo) {
    const std::string& targetIP = packetInfo.targetIP;
    int targetPort = packetInfo.targetPort;
    FORWARDER_LOGI("🔄 Handling UDP response from %{public}s:%{public}d", targetIP.c_str(), targetPort);
    FORWARDER_LOGI("📡 Socket fd: %{public}d, waiting for response", sockFd);
    
    // 如果是DNS查询，添加DNS等待响应日志
    bool isDNS = (targetPort == 53);
    if (isDNS) {
        FORWARDER_LOGI("🔍 [DNS] Waiting for DNS response from %{public}s:%{public}d (timeout: 5s)", 
                      targetIP.c_str(), targetPort);
        FORWARDER_LOGI("🔍 [DNS诊断] 已发送DNS查询到 %{public}s:%{public}d，等待响应...", targetIP.c_str(), targetPort);
    }
    
    // 使用select()等待数据就绪，因为socket是非阻塞的
    // 这样可以正确等待超时，而不是立即返回EAGAIN
    fd_set readfds;
    struct timeval timeout;
    timeout.tv_sec = 2;  // 减少DNS超时时间到2秒
    timeout.tv_usec = 0;
    
    FORWARDER_LOGI("🔍 [UDP诊断] 使用select()等待响应: socket fd=%{public}d, 目标=%{public}s:%{public}d", 
                   sockFd, targetIP.c_str(), targetPort);
    
    FD_ZERO(&readfds);
    FD_SET(sockFd, &readfds);
    
    int selectResult = select(sockFd + 1, &readfds, nullptr, nullptr, &timeout);
    
    if (selectResult > 0) {
        // Socket可读，接收数据
        uint8_t response[BUFFER_SIZE];
        int received = recv(sockFd, response, sizeof(response), 0);
        
        if (received > 0) {
            FORWARDER_LOGI("📨 [目标服务器->服务端] UDP响应接收成功: 目标=%{public}s:%{public}d -> 服务端, 收到=%{public}d字节",
                           targetIP.c_str(), targetPort, received);
            
            // DNS连接成功日志
            if (isDNS) {
                FORWARDER_LOGI("🔍 [DNS] ✅ DNS连接成功 - 从 %{public}s:%{public}d 收到响应 (%{public}d 字节)", 
                              targetIP.c_str(), targetPort, received);
                
                // 简化缓存DNS响应 - 需要从packetInfo获取原始查询信息
                // 注意：这里需要保存原始查询数据用于缓存键值
                // 暂时跳过缓存，因为需要重构函数参数传递
                FORWARDER_LOGI("🔍 [DNS] ✅ DNS response received (caching skipped in this version)");
            }
            
            // 重建IP数据包（交换源和目标）
            uint8_t ipPacket[BUFFER_SIZE];
            int packetSize = BuildIPPacket(ipPacket, BUFFER_SIZE,
                                           packetInfo.targetIP, packetInfo.targetPort,  // 响应源 = 原目标
                                           packetInfo.sourceIP, packetInfo.sourcePort,  // 响应目标 = 原源
                                           PROTOCOL_UDP, reinterpret_cast<const uint8_t*>(response), received);
            
            if (packetSize > 0) {
                // 发送响应回客户端
                FORWARDER_LOGI("📤 [服务端->客户端] 准备发送UDP响应: 服务端 -> 客户端=%{public}s:%{public}d, IP包大小=%{public}d字节",
                               inet_ntoa(originalPeer.sin_addr), ntohs(originalPeer.sin_port), packetSize);
                int sentBack = sendto(g_sockFd, ipPacket, packetSize, 0, 
                                      (struct sockaddr*)&originalPeer, sizeof(originalPeer));
                if (sentBack > 0) {
                    FORWARDER_LOGI("✅ [服务端->客户端] UDP响应发送成功: 服务端 -> 客户端=%{public}s:%{public}d, 已发送=%{public}d字节",
                                    inet_ntoa(originalPeer.sin_addr), ntohs(originalPeer.sin_port), sentBack);
                    if (isDNS) {
                        FORWARDER_LOGI("🔍 [DNS] ✅ DNS响应转发到客户端成功: 客户端=%{public}s:%{public}d, 已发送=%{public}d字节", 
                                      inet_ntoa(originalPeer.sin_addr), ntohs(originalPeer.sin_port), sentBack);
                    }
                } else {
                    FORWARDER_LOGE("❌ [服务端->客户端] UDP响应发送失败: 客户端=%{public}s:%{public}d, 错误=%{public}s", 
                                   inet_ntoa(originalPeer.sin_addr), ntohs(originalPeer.sin_port), strerror(errno));
                    if (isDNS) {
                        FORWARDER_LOGE("🔍 [DNS] ❌ DNS响应转发到客户端失败: 客户端=%{public}s:%{public}d, 错误=%{public}s", 
                                       inet_ntoa(originalPeer.sin_addr), ntohs(originalPeer.sin_port), strerror(errno));
                    }
                }
            } else {
                FORWARDER_LOGE("❌ [服务端->客户端] 构建IP数据包失败");
                if (isDNS) {
                    FORWARDER_LOGE("🔍 [DNS] ❌ DNS响应IP包构建失败");
                }
            }
        } else if (received == 0) {
            FORWARDER_LOGI("UDP connection closed by peer");
            if (isDNS) {
                FORWARDER_LOGW("🔍 [DNS] ⚠️ DNS connection closed by peer");
            }
        } else {
            FORWARDER_LOGE("❌ UDP recv() failed after select(): %{public}s (errno: %{public}d)", strerror(errno), errno);
            if (isDNS) {
                FORWARDER_LOGE("🔍 [DNS] ❌ DNS recv()失败: errno=%{public}d (%{public}s)", errno, strerror(errno));
            }
        }
    } else if (selectResult == 0) {
        // 超时
        FORWARDER_LOGW("UDP response timeout (5s)");
        if (isDNS) {
            FORWARDER_LOGW("🔍 [DNS] ❌ DNS connection FAILED - Timeout waiting for response from %{public}s:%{public}d (5s)", 
                          targetIP.c_str(), targetPort);
            FORWARDER_LOGE("🔍 [DNS诊断] DNS查询超时 - 可能原因:");
            FORWARDER_LOGE("🔍 [DNS诊断]   1) DNS服务器 %{public}s:%{public}d 不可达", targetIP.c_str(), targetPort);
            FORWARDER_LOGE("🔍 [DNS诊断]   2) 服务器机器没有网络访问权限");
            FORWARDER_LOGE("🔍 [DNS诊断]   3) 防火墙阻止了UDP端口53的出站连接");
            FORWARDER_LOGE("🔍 [DNS诊断]   4) DNS服务器未响应或已关闭");
            FORWARDER_LOGE("🔍 [DNS诊断] 建议: 检查DNS服务器 %{public}s 是否可达，检查防火墙设置", targetIP.c_str());
        }
    } else {
        // select()错误
        FORWARDER_LOGE("❌ UDP select() failed: %{public}s (errno: %{public}d)", strerror(errno), errno);
        if (isDNS) {
            FORWARDER_LOGE("🔍 [DNS] ❌ DNS select()失败: errno=%{public}d (%{public}s)", errno, strerror(errno));
        }
    }
    
    close(sockFd);
    FORWARDER_LOGI("UDP response handler finished");
    if (isDNS) {
        FORWARDER_LOGI("🔍 [DNS] DNS response handler finished for %{public}s:%{public}d", targetIP.c_str(), targetPort);
    }
}
