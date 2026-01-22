// 🚀 极简版 - 专注核心转发功能
#include "packet_forwarder.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <hilog/log.h>
#include <thread>
#include <sys/time.h>

#define LOG_INFO(fmt, ...) \
    OH_LOG_Print(LOG_APP, LOG_INFO, 0x15b1, "VpnServer", "ZHOUB [Forwarder] " fmt, ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...) \
    OH_LOG_Print(LOG_APP, LOG_ERROR, 0x15b1, "VpnServer", "ZHOUB [Forwarder] ❌ " fmt, ##__VA_ARGS__)

// 🎯 极简转发函数
int ForwardPacket(const uint8_t* data, size_t size, const sockaddr_in& originalPeer) {
    // 1. 解析IP包
    if (size < 20) return -1; // 最小IP头长度
    
    const struct iphdr* ipHeader = (const struct iphdr*)data;
    if (ipHeader->protocol != IPPROTO_UDP) return -1; // 只处理UDP
    
    // 2. 解析UDP包
    if (size < sizeof(struct iphdr) + sizeof(struct udphdr)) return -1;
    
    const struct udphdr* udpHeader = (const struct udphdr*)(data + sizeof(struct iphdr));
    const uint8_t* udpData = data + sizeof(struct iphdr) + sizeof(struct udphdr);
    size_t udpDataSize = size - sizeof(struct iphdr) - sizeof(struct udphdr);
    
    // 3. 获取目标地址
    struct sockaddr_in targetAddr;
    targetAddr.sin_family = AF_INET;
    targetAddr.sin_port = udpHeader->dest;
    targetAddr.sin_addr.s_addr = ipHeader->daddr;
    
    // 4. DNS重定向 (如果需要)
    if (ntohs(udpHeader->dest) == 53) {
        uint32_t dnsIP = inet_addr("8.8.8.8");
        targetAddr.sin_addr.s_addr = dnsIP;
        LOG_INFO("🔄 DNS重定向到8.8.8.8");
    }
    
    // 5. 创建socket发送
    int sockFd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockFd < 0) {
        LOG_ERROR("创建socket失败");
        return -1;
    }
    
    // 6. 发送到外网
    ssize_t sent = sendto(sockFd, udpData, udpDataSize, 0, 
                          (struct sockaddr*)&targetAddr, sizeof(targetAddr));
    if (sent < 0) {
        LOG_ERROR("发送失败: %s", strerror(errno));
        close(sockFd);
        return -1;
    }
    
    LOG_INFO("✅ 转发成功: %zd字节", sent);
    
    // 7. 启动响应线程
    std::thread([sockFd, originalPeer]() {
        LOG_INFO("🚀 响应线程启动");
        
        uint8_t buffer[4096];
        while (true) {
            ssize_t received = recvfrom(sockFd, buffer, sizeof(buffer), 0, nullptr, nullptr);
            if (received < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
                LOG_ERROR("接收失败: %s", strerror(errno));
                break;
            }
            
            // 发送回VPN客户端
            ssize_t sentBack = sendto(sockFd, buffer, received, 0,
                                     (struct sockaddr*)&originalPeer, sizeof(originalPeer));
            if (sentBack > 0) {
                LOG_INFO("📤 回发成功: %zd字节", sentBack);
            } else {
                LOG_ERROR("❌ 回发失败: %s", strerror(errno));
            }
        }
        
        close(sockFd);
        LOG_INFO("🔚 响应线程结束");
    }).detach();
    
    return sockFd;
}
