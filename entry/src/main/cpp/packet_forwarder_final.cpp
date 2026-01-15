/*
 * VPN服务器数据包转发器 - 完全兼容版本
 */

#include <napi/native_api.h>
#include <hilog/log.h>
#include <string>
#include <thread>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>

// 使用鸿蒙官方日志定义
#undef LOG_TAG
#define LOG_TAG 0x0001

class PacketForwarder {
public:
    // 超简单的TCP转发
    int HandleTCPForwarding(int sockFd, const uint8_t* data, int dataSize,
                           const std::string& targetIP, int targetPort) {
        OH_LOG_Print(LOG_APP, LOG_INFO, LOG_TAG, "TCP转发: %s:%d", targetIP.c_str(), targetPort);
        
        // 创建socket
        int forwardSock = socket(AF_INET, SOCK_STREAM, 0);
        if (forwardSock < 0) {
            OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_TAG, "socket失败");
            return -1;
        }
        
        // 连接目标
        struct sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(targetPort);
        inet_pton(AF_INET, targetIP.c_str(), &addr.sin_addr);
        
        if (connect(forwardSock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_TAG, "连接失败");
            close(forwardSock);
            return -1;
        }
        
        // 发送数据
        send(forwardSock, data, dataSize, 0);
        OH_LOG_Print(LOG_APP, LOG_INFO, LOG_TAG, "转发完成");
        
        // 启动转发线程
        std::thread([sockFd, forwardSock]() {
            char buffer[1024];
            int received;
            while ((received = recv(forwardSock, buffer, sizeof(buffer), 0)) > 0) {
                send(sockFd, buffer, received, 0);
            }
            close(sockFd);
            close(forwardSock);
        }).detach();
        
        return forwardSock;
    }
    
    bool IsDNSQuery(const std::string& targetIP, int targetPort) {
        return targetPort == 53;
    }
    
    // 超简单的网络测试
    bool TestNetworkConnectivity() {
        OH_LOG_Print(LOG_APP, LOG_INFO, LOG_TAG, "开始网络测试");
        
        // 异步测试，不阻塞UI
        std::thread([]() {
            int sock = socket(AF_INET, SOCK_STREAM, 0);
            if (sock < 0) {
                OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_TAG, "socket失败");
                return;
            }
            
            struct sockaddr_in addr{};
            addr.sin_family = AF_INET;
            addr.sin_port = htons(80);
            inet_pton(AF_INET, "110.242.68.66", &addr.sin_addr);
            
            if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
                OH_LOG_Print(LOG_APP, LOG_INFO, LOG_TAG, "网络正常");
            } else {
                OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_TAG, "网络异常");
            }
            
            close(sock);
        }).detach();
        
        return true;
    }
};

// 全局实例
static PacketForwarder g_forwarder;

// 导出函数
static napi_value StartServer(napi_env env, napi_callback_info info) {
    g_forwarder.TestNetworkConnectivity();
    return nullptr;
}

static napi_value HandleTCP(napi_env env, napi_callback_info info) {
    // 简化参数处理
    size_t argc = 4;
    napi_value args[4];
    napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
    
    int sockFd;
    napi_get_value_int32(env, args[0], &sockFd);
    
    size_t dataSize;
    void* data;
    napi_get_arraybuffer_info(env, args[1], &data, &dataSize);
    
    char targetIP[64];
    size_t ipLen;
    napi_get_value_string_utf8(env, args[2], targetIP, sizeof(targetIP), &ipLen);
    
    int targetPort;
    napi_get_value_int32(env, args[3], &targetPort);
    
    // 处理转发
    int result = g_forwarder.HandleTCPForwarding(sockFd, (const uint8_t*)data, dataSize, 
                                               std::string(targetIP), targetPort);
    
    napi_value result_val;
    napi_create_int32(env, result, &result_val);
    return result_val;
}

static napi_value Init(napi_env env, napi_value exports) {
    napi_property_descriptor desc[] = {
        {"startServer", nullptr, nullptr, StartServer, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"handleTCP", nullptr, nullptr, HandleTCP, nullptr, nullptr, nullptr, napi_default, nullptr}
    };
    
    napi_define_properties(env, exports, 2, desc);
    return exports;
}

// 模块注册
static napi_module demo_module = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = Init,
    .nm_modname = "vpn_server",
    .nm_priv = nullptr,
    .reserved = {0},
};

extern "C" __attribute__((constructor)) void RegisterDemoModule(void) {
    napi_module_register(&demo_module);
}
