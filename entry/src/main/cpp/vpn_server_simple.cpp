// 🚀 极简版VPN服务器
#include <hilog/log.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <thread>
#include <atomic>
#include <sys/select.h>

#define VPN_SERVER_LOGI(fmt, ...) \
    OH_LOG_Print(LOG_APP, LOG_INFO, 0x15b1, "VpnServer", "ZHOUB [Server] " fmt, ##__VA_ARGS__)
#define VPN_SERVER_LOGE(fmt, ...) \
    OH_LOG_Print(LOG_APP, LOG_ERROR, 0x15b1, "VpnServer", "ZHOUB [Server] ❌ " fmt, ##__VA_ARGS__)

// 全局变量
static std::atomic<bool> g_running(false);
static int g_serverSocket = -1;

// 🎯 极简转发函数
int SimpleForward(const uint8_t* data, size_t size, const sockaddr_in& clientAddr) {
    // 1. 检查是否是IP包
    if (size < 20 || data[0] != 0x45) return -1; // 简单检查IPv4
    
    // 2. 解析UDP目标
    const struct iphdr* ipHeader = (const struct iphdr*)data;
    if (ipHeader->protocol != IPPROTO_UDP) return -1;
    
    const struct udphdr* udpHeader = (const struct udphdr*)(data + sizeof(struct iphdr));
    const uint8_t* udpData = data + sizeof(struct iphdr) + sizeof(struct udphdr);
    size_t udpDataSize = size - sizeof(struct iphdr) - sizeof(struct udphdr);
    
    // 3. 创建socket转发到外网
    int sockFd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockFd < 0) return -1;
    
    // 4. 设置目标地址
    struct sockaddr_in targetAddr;
    targetAddr.sin_family = AF_INET;
    targetAddr.sin_port = udpHeader->dest;
    targetAddr.sin_addr.s_addr = ipHeader->daddr;
    
    // 5. DNS重定向
    if (ntohs(udpHeader->dest) == 53) {
        targetAddr.sin_addr.s_addr = inet_addr("8.8.8.8");
        VPN_SERVER_LOGI("🔄 DNS重定向到8.8.8.8");
    }
    
    // 6. 发送到外网
    ssize_t sent = sendto(sockFd, udpData, udpDataSize, 0,
                          (struct sockaddr*)&targetAddr, sizeof(targetAddr));
    if (sent < 0) {
        close(sockFd);
        return -1;
    }
    
    VPN_SERVER_LOGI("✅ 转发成功: %zd字节", sent);
    
    // 7. 启动响应线程
    std::thread([sockFd, clientAddr]() {
        uint8_t buffer[4096];
        while (true) {
            ssize_t received = recvfrom(sockFd, buffer, sizeof(buffer), 0, nullptr, nullptr);
            if (received <= 0) break;
            
            // 发送回VPN客户端
            sendto(sockFd, buffer, received, 0,
                   (struct sockaddr*)&clientAddr, sizeof(clientAddr));
        }
        close(sockFd);
    }).detach();
    
    return sockFd;
}

// 🎯 极简主循环
void SimpleServerLoop(int serverSocket) {
    uint8_t buffer[4096];
    
    while (g_running.load()) {
        // 等待客户端数据
        sockaddr_in clientAddr;
        socklen_t clientLen = sizeof(clientAddr);
        
        ssize_t received = recvfrom(serverSocket, buffer, sizeof(buffer), 0,
                                   (struct sockaddr*)&clientAddr, &clientLen);
        
        if (received <= 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
            VPN_SERVER_LOGE("接收失败: %s", strerror(errno));
            break;
        }
        
        VPN_SERVER_LOGI("📥 收到数据: %zd字节", received);
        
        // 直接转发
        SimpleForward(buffer, received, clientAddr);
    }
}

// 🎯 启动服务器
int StartSimpleServer(int port) {
    int sockFd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockFd < 0) return -1;
    
    // 绑定地址
    sockaddr_in serverAddr{};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(port);
    
    if (bind(sockFd, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        close(sockFd);
        return -1;
    }
    
    g_running = true;
    g_serverSocket = sockFd;
    
    VPN_SERVER_LOGI("🚀 极简服务器启动: port=%d", port);
    
    // 启动主循环
    SimpleServerLoop(sockFd);
    
    return sockFd;
}

// 🎯 停止服务器
void StopSimpleServer() {
    g_running = false;
    if (g_serverSocket >= 0) {
        close(g_serverSocket);
        g_serverSocket = -1;
    }
    VPN_SERVER_LOGI("🔚 极简服务器停止");
}
