// 🚀 极简VPN代理服务器 - 单文件版本
#include <hilog/log.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <thread>
#include <atomic>
#include <netinet/ip.h>
#include <netinet/udp.h>

#define LOG(fmt, ...) OH_LOG_Print(LOG_APP, LOG_INFO, 0x15b1, "VpnProxy", fmt, ##__VA_ARGS__)
#define ERR(fmt, ...) OH_LOG_Print(LOG_APP, LOG_ERROR, 0x15b1, "VpnProxy", "❌ " fmt, ##__VA_ARGS__)

// 全局变量
static std::atomic<bool> g_running{false};
static int g_serverSocket{-1};

// 🎯 极简转发函数
void ForwardToInternet(const uint8_t* data, size_t size, const sockaddr_in& clientAddr) {
    // 1. 检查IP包
    if (size < 20 || data[0] != 0x45) return;
    
    // 2. 解析UDP
    const iphdr* ip = (const iphdr*)data;
    if (ip->protocol != IPPROTO_UDP) return;
    
    const udphdr* udp = (const udphdr*)(data + sizeof(iphdr));
    const uint8_t* payload = data + sizeof(iphdr) + sizeof(udphdr);
    size_t payloadSize = size - sizeof(iphdr) - sizeof(udphdr);
    
    // 3. 创建socket
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return;
    
    // 4. 设置目标
    sockaddr_in target{};
    target.sin_family = AF_INET;
    target.sin_port = udp->dest;
    target.sin_addr.s_addr = ip->daddr;
    
    // 5. DNS重定向
    if (ntohs(udp->dest) == 53) {
        target.sin_addr.s_addr = inet_addr("8.8.8.8");
        LOG("🔄 DNS重定向到8.8.8.8");
    }
    
    // 6. 发送到外网
    ssize_t sent = sendto(sock, payload, payloadSize, 0, (sockaddr*)&target, sizeof(target));
    if (sent < 0) {
        close(sock);
        return;
    }
    
    LOG("✅ 转发: %zd字节", sent);
    
    // 7. 响应线程
    std::thread([sock, clientAddr]() {
        uint8_t buf[4096];
        while (true) {
            ssize_t recv = recvfrom(sock, buf, sizeof(buf), 0, nullptr, nullptr);
            if (recv <= 0) break;
            
            // 回发客户端
            sendto(sock, buf, recv, 0, (sockaddr*)&clientAddr, sizeof(clientAddr));
            LOG("📤 回发: %zd字节", recv);
        }
        close(sock);
    }).detach();
}

// 🎯 主服务循环
void RunServer(int port) {
    // 创建服务器socket
    g_serverSocket = socket(AF_INET, SOCK_DGRAM, 0);
    if (g_serverSocket < 0) {
        ERR("创建socket失败");
        return;
    }
    
    // 绑定
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    
    if (bind(g_serverSocket, (sockaddr*)&addr, sizeof(addr)) < 0) {
        ERR("绑定失败: %s", strerror(errno));
        close(g_serverSocket);
        return;
    }
    
    g_running = true;
    LOG("🚀 服务器启动: port=%d", port);
    
    // 主循环
    uint8_t buffer[4096];
    while (g_running) {
        sockaddr_in client{};
        socklen_t clientLen = sizeof(client);
        
        ssize_t recv = recvfrom(g_serverSocket, buffer, sizeof(buffer), 0,
                               (sockaddr*)&client, &clientLen);
        
        if (recv > 0) {
            LOG("📥 收到: %zd字节", recv);
            ForwardToInternet(buffer, recv, client);
        }
    }
    
    close(g_serverSocket);
    LOG("🔚 服务器停止");
}

// 🎯 启动/停止函数
extern "C" {
    int StartProxy(int port) {
        if (g_running) return -1;
        std::thread([port]() { RunServer(port); }).detach();
        return 0;
    }
    
    void StopProxy() {
        g_running = false;
        if (g_serverSocket >= 0) {
            close(g_serverSocket);
            g_serverSocket = -1;
        }
    }
}
