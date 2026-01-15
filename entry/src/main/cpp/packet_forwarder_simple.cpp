// 简化的VPN服务器转发器 - 避免UI线程阻塞

#include <napi/native_api.h>
#include <hilog/log.h>
#include <string>
#include <thread>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#define LOG_TAG "VPN_SERVER"
#define LOGI(...) OH_LOG_Print(LOG_APP, LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_TAG, __VA_ARGS__)

class PacketForwarder {
public:
    // 简化的TCP转发处理
    int HandleTCPForwarding(int sockFd, const uint8_t* data, int dataSize,
                           const std::string& targetIP, int targetPort) {
        LOGI("TCP转发: %s:%d", targetIP.c_str(), targetPort);
        
        // 创建转发socket
        int forwardSock = socket(AF_INET, SOCK_STREAM, 0);
        if (forwardSock < 0) {
            LOGE("创建socket失败: %s", strerror(errno));
            return -1;
        }
        
        // 连接目标服务器
        struct sockaddr_in serverAddr{};
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_port = htons(targetPort);
        inet_pton(AF_INET, targetIP.c_str(), &serverAddr.sin_addr);
        
        if (connect(forwardSock, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
            LOGE("连接失败: %s", strerror(errno));
            close(forwardSock);
            return -1;
        }
        
        // 发送数据
        ssize_t sent = send(forwardSock, data, dataSize, 0);
        if (sent < 0) {
            LOGE("发送失败: %s", strerror(errno));
            close(forwardSock);
            return -1;
        }
        
        LOGI("转发成功: %zd字节", sent);
        
        // 启动数据转发线程
        std::thread([sockFd, forwardSock]() {
            char buffer[4096];
            ssize_t received;
            
            while ((received = recv(forwardSock, buffer, sizeof(buffer), 0)) > 0) {
                send(sockFd, buffer, received, 0);
            }
            
            close(sockFd);
            close(forwardSock);
        }).detach();
        
        return forwardSock;
    }
    
    // 简单网络测试 - 异步执行，不阻塞UI
    bool TestNetworkConnectivity() {
        LOGI("=== 网络连接测试开始 ===");
        
        // 异步执行网络测试，避免阻塞UI线程
        std::thread([]() {
            int sock = socket(AF_INET, SOCK_STREAM, 0);
            if (sock < 0) {
                LOGE("socket创建失败: %s", strerror(errno));
                return;
            }
            
            struct sockaddr_in addr{};
            addr.sin_family = AF_INET;
            addr.sin_port = htons(80);
            inet_pton(AF_INET, "110.242.68.66", &addr.sin_addr);
            
            // 设置非阻塞模式，避免长时间阻塞
            int flags = fcntl(sock, F_GETFL, 0);
            fcntl(sock, F_SETFL, flags | O_NONBLOCK);
            
            int result = connect(sock, (struct sockaddr*)&addr, sizeof(addr));
            
            if (result == 0) {
                LOGI("✅ 网络正常 - 立即连接成功");
            } else if (errno == EINPROGRESS) {
                // 等待连接完成，但设置短超时
                fd_set writefds;
                struct timeval timeout;
                timeout.tv_sec = 1;  // 1秒超时
                timeout.tv_usec = 0;
                
                FD_ZERO(&writefds);
                FD_SET(sock, &writefds);
                
                int selectResult = select(sock + 1, nullptr, &writefds, nullptr, &timeout);
                
                if (selectResult > 0) {
                    int error = 0;
                    socklen_t len = sizeof(error);
                    if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &error, &len) == 0 && error == 0) {
                        LOGI("✅ 网络正常 - 连接成功");
                    }
                } else {
                    LOGE("❌ 网络连接超时");
                }
            } else {
                LOGE("❌ 网络连接失败: %s", strerror(errno));
            }
            
            close(sock);
            LOGI("=== 测试完成 ===");
        }).detach();
        
        // 立即返回，不等待测试完成
        return true;
    }
};

// 导出函数
static napi_value StartServer(napi_env env, napi_callback_info info) {
    PacketForwarder forwarder;
    forwarder.TestNetworkConnectivity();
    return nullptr;
}

static napi_value Init(napi_env env, napi_value exports) {
    napi_property_descriptor desc[] = {
        {"startServer", nullptr, nullptr, StartServer, nullptr, nullptr, nullptr, napi_default, nullptr}
    };
    napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc);
    return exports;
}

// 模块定义
static napi_module demo_module = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = Init,
    .nm_modname = "vpn_server",
    .nm_priv = nullptr,
    .reserved = {0},
};

// 注册模块
extern "C" __attribute__((constructor)) void RegisterDemoModule(void) {
    napi_module_register(&demo_module);
}
