// 🚀 最终简化版 - 专注解决NAT映射问题
#include "packet_forwarder.h"
#include "nat_table.h"
#include "protocol_handler.h"
#include "packet_builder.h"
#include "udp_retransmit.h"
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

#define LOG_INFO(fmt, ...) \
    OH_LOG_Print(LOG_APP, LOG_INFO, 0x15b1, "VpnServer", "ZHOUB [Forwarder] " fmt, ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...) \
    OH_LOG_Print(LOG_APP, LOG_ERROR, 0x15b1, "VpnServer", "ZHOUB [Forwarder] ❌ " fmt, ##__VA_ARGS__)

// 🎯 获取socket (支持TCP和UDP)
static int GetSocket(const PacketInfo& packetInfo) {
    int sockFd;
    
    if (packetInfo.protocol == PROTOCOL_UDP) {
        // UDP socket
        sockFd = socket(packetInfo.addressFamily, SOCK_DGRAM, 0);
    } else if (packetInfo.protocol == PROTOCOL_TCP) {
        // TCP socket
        sockFd = socket(packetInfo.addressFamily, SOCK_STREAM, 0);
    } else {
        LOG_ERROR("不支持的协议: %d", packetInfo.protocol);
        return -1;
    }
    
    if (sockFd < 0) {
        LOG_ERROR("创建socket失败: %s", strerror(errno));
        return -1;
    }
    
    // 设置超时 - DNS查询使用更长超时时间
    struct timeval timeout;
    if (packetInfo.protocol == PROTOCOL_UDP && packetInfo.targetPort == 53) {
        // DNS查询：10秒超时
        timeout = {10, 0};
        LOG_INFO("⏱️ DNS查询socket超时: 10秒");
    } else {
        // 其他UDP/TCP：5秒超时
        timeout = {5, 0};
    }
    setsockopt(sockFd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    
    LOG_INFO("✅ 创建新socket: fd=%d, 协议=%s", 
             sockFd, packetInfo.protocol == PROTOCOL_TCP ? "TCP" : "UDP");
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

            // 检查NAT映射
            NATConnection conn;
            if (NATTable::FindMappingBySocket(sockFd, conn)) {
                // 🔧 调试：打印发送目标
                char peerIP[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &originalPeer.sin_addr, peerIP, sizeof(peerIP));
                uint16_t peerPort = ntohs(originalPeer.sin_port);
                LOG_INFO("🔍 发送响应到: %s:%d (原始客户端)", peerIP, peerPort);

                ssize_t sent = sendto(sockFd, buffer, received, 0, (struct sockaddr*)&originalPeer, sizeof(originalPeer));
                if (sent > 0) {
                    LOG_INFO("📤 转发响应成功: %zd字节 -> %s:%d", sent, peerIP, peerPort);

                    // ✅ 确认UDP接收，停止重传 - 使用基于内容的精确匹配
                    UdpRetransmitManager::getInstance().confirmReceivedByContent(sockFd, buffer, received);
                } else {
                    LOG_ERROR("❌ 转发响应失败: %s", strerror(errno));
                }
            } else {
                LOG_ERROR("❌ NAT映射不存在: fd=%d", sockFd);
                break;
            }
        }
        
        // 🧹 清理NAT映射和socket
        LOG_INFO("🧹 清理UDP线程资源: fd=%d", sockFd);
        NATTable::RemoveMappingBySocket(sockFd);
        close(sockFd);
        
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
            
            // 检查NAT映射
            NATConnection conn;
            if (NATTable::FindMappingBySocket(sockFd, conn)) {
                // 🔧 调试：打印发送目标
                char peerIP[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &originalPeer.sin_addr, peerIP, sizeof(peerIP));
                uint16_t peerPort = ntohs(originalPeer.sin_port);
                LOG_INFO("🔍 发送响应到: %s:%d (原始客户端)", peerIP, peerPort);
                
                ssize_t sent = sendto(sockFd, buffer, received, 0, 
                                    (struct sockaddr*)&originalPeer, sizeof(originalPeer));
                if (sent > 0) {
                    LOG_INFO("📤 转发TCP响应成功: %zd字节 -> %s:%d", sent, peerIP, peerPort);
                } else {
                    LOG_ERROR("❌ 转发TCP响应失败: %s", strerror(errno));
                }
            } else {
                LOG_ERROR("❌ NAT映射不存在: fd=%d", sockFd);
                break;
            }
        }
        
        // 🧹 清理NAT映射和socket
        LOG_INFO("🧹 清理TCP线程资源: fd=%d", sockFd);
        NATTable::RemoveMappingBySocket(sockFd);
        close(sockFd);
        
    }).detach();
}


// ========== 主转发函数 ==========

int PacketForwarder::ForwardPacket(const uint8_t* data, int dataSize, 
                                  const PacketInfo& packetInfo, 
                                  const sockaddr_in& originalPeer) {
    LOG_INFO("📦 转发: %s:%d -> %s:%d (%s, %d字节)",
            packetInfo.sourceIP.c_str(), packetInfo.sourcePort,
            packetInfo.targetIP.c_str(), packetInfo.targetPort,
            packetInfo.protocol == PROTOCOL_TCP ? "TCP" : "UDP", dataSize);
    
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
        sockFd = GetSocket(packetInfo);
        if (sockFd < 0) {
            LOG_ERROR("获取socket失败");
            return -1;
        }
        
        NATTable::CreateMapping(natKey, originalPeer, packetInfo, sockFd);
        LOG_INFO("✅ 创建新NAT映射: %s -> fd=%d", natKey.c_str(), sockFd);
    }
    
    // 5. 发送数据
    if (packetInfo.protocol == PROTOCOL_UDP) {
        struct sockaddr_in targetAddr{};
        targetAddr.sin_family = AF_INET;
        // ✅ 修复：targetPort已经是主机字节序，不需要再htons
        targetAddr.sin_port = packetInfo.targetPort;
        inet_pton(AF_INET, actualTargetIP.c_str(), &targetAddr.sin_addr);

        ssize_t sent = sendto(sockFd, payload, payloadSize, 0,
                             (struct sockaddr*)&targetAddr, sizeof(targetAddr));

        if (sent < 0) {
            LOG_ERROR("UDP发送失败: fd=%d, errno=%d", sockFd, errno);
            NATTable::RemoveMapping(natKey);
            return -1;
        }

        LOG_INFO("✅ UDP发送: fd=%d, %zd字节", sockFd, sent);

        // 6. 启动响应线程 - 只在创建新映射时启动
        if (!NATTable::FindMapping(natKey, existingConn)) {
            StartUDPThread(sockFd, originalPeer);
            LOG_INFO("🚀 启动UDP响应线程: fd=%d", sockFd);
        } else {
            LOG_INFO("🔄 复用现有UDP响应线程: fd=%d", sockFd);
        }
        
    } else if (packetInfo.protocol == PROTOCOL_TCP) {
        // TCP转发实现
        struct sockaddr_in targetAddr{};
        targetAddr.sin_family = AF_INET;
        targetAddr.sin_port = htons(packetInfo.targetPort);
        inet_pton(AF_INET, actualTargetIP.c_str(), &targetAddr.sin_addr);
        
        // 连接到目标服务器
        if (connect(sockFd, (struct sockaddr*)&targetAddr, sizeof(targetAddr)) < 0) {
            LOG_ERROR("TCP连接失败: fd=%d, 目标=%s:%d, errno=%d", 
                     sockFd, actualTargetIP.c_str(), packetInfo.targetPort, errno);
            NATTable::RemoveMapping(natKey);
            return -1;
        }
        
        // 发送TCP数据
        ssize_t sent = send(sockFd, payload, payloadSize, 0);
        if (sent < 0) {
            LOG_ERROR("TCP发送失败: fd=%d, errno=%d", sockFd, errno);
            NATTable::RemoveMapping(natKey);
            return -1;
        }
        
        LOG_INFO("✅ TCP发送: fd=%d, %zd字节", sockFd, sent);
        
        // 启动TCP响应处理
        StartTCPThread(sockFd, originalPeer);
        LOG_INFO("🚀 启动TCP响应线程: fd=%d", sockFd);
        
    } else {
        LOG_ERROR("不支持的协议: %d", packetInfo.protocol);
        NATTable::RemoveMapping(natKey);
        return -1;
    }
    
    return sockFd;
}

