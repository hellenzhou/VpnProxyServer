// 鸿蒙SOCKET编程测试
// 编译命令: gcc -o harmony_socket_test harmony_socket_test.cpp

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>

// 日志宏
#define LOGI(fmt, ...) printf("[INFO] " fmt "\n", ##__VA_ARGS__)
#define LOGE(fmt, ...) printf("[ERROR] " fmt "\n", ##__VA_ARGS__)

// 鸿蒙系统兼容的网络连接测试
bool TestHarmonySocketConnection() {
    LOGI("🔍 [鸿蒙SOCKET] 开始测试网络连接能力...");
    
    // 使用鸿蒙系统推荐的socket创建方式
    int testSock = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (testSock < 0) {
        LOGE("❌ [鸿蒙SOCKET] socket创建失败: errno=%d (%s)", errno, strerror(errno));
        return false;
    }
    LOGI("✅ [鸿蒙SOCKET] socket创建成功，fd=%d", testSock);
    
    // 设置socket选项 - 鸿蒙系统兼容
    int keepAlive = 1;
    setsockopt(testSock, SOL_SOCKET, SO_KEEPALIVE, &keepAlive, sizeof(keepAlive));
    
    int reuseAddr = 1;
    setsockopt(testSock, SOL_SOCKET, SO_REUSEADDR, &reuseAddr, sizeof(reuseAddr));
    
    // 连接到百度HTTP (最简单的测试)
    struct sockaddr_in testAddr{};
    memset(&testAddr, 0, sizeof(testAddr));
    testAddr.sin_family = AF_INET;
    testAddr.sin_port = htons(80);
    inet_pton(AF_INET, "110.242.68.66", &testAddr.sin_addr); // 百度IP
    
    LOGI("🔍 [鸿蒙SOCKET] 尝试连接百度 (110.242.68.66:80)...");
    
    // 使用鸿蒙系统推荐的连接方式 - 阻塞模式，避免select()问题
    int flags = fcntl(testSock, F_GETFL, 0);
    fcntl(testSock, F_SETFL, flags & ~O_NONBLOCK); // 确保阻塞模式
    
    // 设置连接超时
    struct timeval timeout;
    timeout.tv_sec = 5;  // 5秒超时
    timeout.tv_usec = 0;
    setsockopt(testSock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    
    int connectResult = connect(testSock, (struct sockaddr*)&testAddr, sizeof(testAddr));
    
    if (connectResult == 0) {
        LOGI("✅ [鸿蒙SOCKET] 连接成功 - 网络正常！");
        
        // 发送简单HTTP请求测试
        const char* httpReq = "GET / HTTP/1.1\r\nHost: www.baidu.com\r\nConnection: close\r\n\r\n";
        ssize_t sent = send(testSock, httpReq, strlen(httpReq), MSG_NOSIGNAL);
        if (sent > 0) {
            LOGI("✅ [鸿蒙SOCKET] HTTP请求发送成功，发送%zd字节", sent);
            
            // 接收响应
            char buffer[512];
            memset(buffer, 0, sizeof(buffer));
            ssize_t received = recv(testSock, buffer, sizeof(buffer) - 1, 0);
            if (received > 0) {
                buffer[received] = '\0';
                LOGI("✅ [鸿蒙SOCKET] HTTP响应接收成功，接收%zd字节", received);
                if (strstr(buffer, "200 OK") || strstr(buffer, "302")) {
                    LOGI("✅ [鸿蒙SOCKET] 收到正确的HTTP响应 - 网络完全正常！");
                    close(testSock);
                    return true;
                } else {
                    LOGI("⚠️ [鸿蒙SOCKET] HTTP响应异常: %.100s", buffer);
                }
            } else {
                LOGE("❌ [鸿蒙SOCKET] HTTP响应接收失败: %s", strerror(errno));
            }
        } else {
            LOGE("❌ [鸿蒙SOCKET] HTTP请求发送失败: %s", strerror(errno));
        }
    } else {
        LOGE("❌ [鸿蒙SOCKET] 连接失败: errno=%d (%s)", errno, strerror(errno));
        
        // 分析具体错误
        switch (errno) {
            case ETIMEDOUT:
                LOGE("🔍 [鸿蒙SOCKET] 连接超时 - 网络可能不通");
                break;
            case ECONNREFUSED:
                LOGE("🔍 [鸿蒙SOCKET] 连接被拒绝 - 目标服务器拒绝连接");
                break;
            case ENETUNREACH:
                LOGE("🔍 [鸿蒙SOCKET] 网络不可达 - 检查网络配置");
                break;
            case EPERM:
                LOGE("🔍 [鸿蒙SOCKET] 权限不足 - 检查应用网络权限");
                break;
            default:
                LOGE("🔍 [鸿蒙SOCKET] 其他网络错误");
                break;
        }
    }
    
    close(testSock);
    return false;
}

int main() {
    printf("╔═══════════════════════════════════════════════════════╗\n");
    printf("║   🌐 鸿蒙SOCKET编程测试工具                          ║\n");
    printf("╚═══════════════════════════════════════════════════════╝\n");
    
    printf("\n🔍 开始测试鸿蒙系统SOCKET编程...\n");
    
    bool success = TestHarmonySocketConnection();
    
    printf("\n╔═══════════════════════════════════════════════════════╗\n");
    printf("║   📊 测试结果                                        ║\n");
    printf("╠═══════════════════════════════════════════════════════╣\n");
    
    if (success) {
        printf("║   状态: ✅ 鸿蒙SOCKET编程正常 - 可以用于VPN代理        ║\n");
        printf("║   建议: 可以在VPN服务器中使用这种SOCKET编程方式      ║\n");
    } else {
        printf("║   状态: ❌ 鸿蒙SOCKET编程异常 - 需要检查网络配置      ║\n");
        printf("║   建议: 检查网络连接和防火墙设置                    ║\n");
    }
    
    printf("╚═══════════════════════════════════════════════════════╝\n");
    
    return success ? 0 : 1;
}
