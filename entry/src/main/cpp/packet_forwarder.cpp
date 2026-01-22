// 🚀 最终简化版 - 专注解决NAT映射问题
#include "packet_forwarder.h"
#include "nat_table.h"
#include "protocol_handler.h"
#include "packet_builder.h"
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

// 🎯 获取socket (简化版)
static int GetSocket(const PacketInfo& packetInfo) {
    // 创建新socket
    int sockFd = socket(packetInfo.addressFamily, SOCK_DGRAM, 0);
    if (sockFd < 0) {
        LOG_ERROR("创建socket失败: %s", strerror(errno));
        return -1;
    }
    
    // 设置超时
    struct timeval timeout = {5, 0};
    setsockopt(sockFd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    
    LOG_INFO("✅ 创建新socket: fd=%d", sockFd);
    return sockFd;
}

// 🎯 UDP响应线程
static void StartUDPThread(int sockFd, const sockaddr_in& originalPeer) {
    std::thread([sockFd, originalPeer]() {
        LOG_INFO("🚀 UDP线程启动: fd=%d", sockFd);
        
        uint8_t buffer[4096];
        while (true) {
            ssize_t received = recvfrom(sockFd, buffer, sizeof(buffer), 0, nullptr, nullptr);
            if (received < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
                LOG_ERROR("UDP接收失败: fd=%d, errno=%d", sockFd, errno);
                break;
            }
            
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
                } else {
                    LOG_ERROR("❌ 转发响应失败: %s", strerror(errno));
                }
            } else {
                LOG_ERROR("❌ NAT映射不存在: fd=%d", sockFd);
                break;
            }
        }
        
        LOG_INFO("🔚 UDP线程退出: fd=%d", sockFd);
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
    
    // 3. 获取socket (关键：先确定socket)
    int sockFd = GetSocket(packetInfo);
    if (sockFd < 0) {
        LOG_ERROR("获取socket失败");
        return -1;
    }
    
    // 4. 创建NAT映射 (关键：检查是否已存在)
    std::string natKey = NATTable::GenerateKey(packetInfo);
    
    // 🔧 关键修复：检查NAT映射是否已存在
    NATConnection existingConn;
    if (NATTable::FindMappingBySocket(sockFd, existingConn)) {
        LOG_INFO("🔄 NAT映射已存在: fd=%d, key=%s", sockFd, natKey.c_str());
        // 映射已存在，直接使用
    } else {
        // 创建新映射
        NATTable::CreateMapping(natKey, originalPeer, packetInfo, sockFd);
        LOG_INFO("✅ 创建新NAT映射: %s -> fd=%d", natKey.c_str(), sockFd);
    }
    
    // 5. 发送UDP数据
    if (packetInfo.protocol == PROTOCOL_UDP) {
        struct sockaddr_in targetAddr{};
        targetAddr.sin_family = AF_INET;
        targetAddr.sin_port = htons(packetInfo.targetPort);
        inet_pton(AF_INET, actualTargetIP.c_str(), &targetAddr.sin_addr);
        
        ssize_t sent = sendto(sockFd, payload, payloadSize, 0, 
                             (struct sockaddr*)&targetAddr, sizeof(targetAddr));
        
        if (sent < 0) {
            LOG_ERROR("UDP发送失败: fd=%d, errno=%d", sockFd, errno);
            NATTable::RemoveMapping(natKey);
            return -1;
        }
        
        LOG_INFO("✅ UDP发送: fd=%d, %zd字节", sockFd, sent);
        
        // 6. 启动响应线程
        StartUDPThread(sockFd, originalPeer);
        LOG_INFO("🚀 启动UDP响应线程: fd=%d", sockFd);
        
    } else {
        LOG_ERROR("TCP转发未实现");
        NATTable::RemoveMapping(natKey);
        return -1;
    }
    
    return sockFd;
}

