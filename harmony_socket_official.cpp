/*
 * 鸿蒙官方SOCKET编程模式实现
 * 基于@ohos.net.socket模块的C++接口
 * 符合鸿蒙官方编程规范
 */

#include <napi/native_api.h>
#include <hilog/log.h>
#include <string>
#include <functional>
#include <memory>
#include <thread>
#include <mutex>
#include <condition_variable>

// 鸿蒙日志标签
#define LOG_TAG "HarmonySocket"
#define LOGI(...) OH_LOG_Print(LOG_APP, LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGW(...) OH_LOG_Print(LOG_APP, LOG_WARN, LOG_TAG, __VA_ARGS__)

// 鸿蒙官方SOCKET编程模式 - TCP Socket类
class HarmonyTCPSocket {
private:
    int socketFd_;
    bool isConnected_;
    std::mutex mutex_;
    std::condition_variable cv_;
    
    // 事件回调函数类型
    std::function<void()> onConnect_;
    std::function<void(const std::string&)> onMessage_;
    std::function<void()> onClose_;
    std::function<void(const std::string&)> onError_;
    
public:
    HarmonyTCPSocket() : socketFd_(-1), isConnected_(false) {}
    
    ~HarmonyTCPSocket() {
        close();
    }
    
    // 鸿蒙官方模式：创建TCPSocket实例
    static std::unique_ptr<HarmonyTCPSocket> constructTCPSocketInstance() {
        auto socket = std::make_unique<HarmonyTCPSocket>();
        if (socket->create()) {
            return socket;
        }
        return nullptr;
    }
    
    // 创建Socket（符合鸿蒙标准）
    bool create() {
        std::lock_guard<std::mutex> lock(mutex_);
        
        // 使用鸿蒙推荐的socket创建参数
        socketFd_ = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
        if (socketFd_ < 0) {
            LOGE("❌ [鸿蒙SOCKET] 创建TCPSocket失败: errno=%d", errno);
            return false;
        }
        
        LOGI("✅ [鸿蒙SOCKET] TCPSocket创建成功，fd=%d", socketFd_);
        return true;
    }
    
    // 鸿蒙官方模式：绑定地址和端口
    void bind(const std::string& address, int port, std::function<void(bool)> callback) {
        std::thread([this, address, port, callback]() {
            std::lock_guard<std::mutex> lock(mutex_);
            
            struct sockaddr_in bindAddr{};
            bindAddr.sin_family = AF_INET;
            bindAddr.sin_port = htons(port);
            
            if (address.empty() || address == "0.0.0.0") {
                bindAddr.sin_addr.s_addr = INADDR_ANY;
            } else {
                if (inet_pton(AF_INET, address.c_str(), &bindAddr.sin_addr) <= 0) {
                    LOGE("❌ [鸿蒙SOCKET] 无效的绑定地址: %s", address.c_str());
                    callback(false);
                    return;
                }
            }
            
            int result = ::bind(socketFd_, (struct sockaddr*)&bindAddr, sizeof(bindAddr));
            if (result < 0) {
                LOGE("❌ [鸿蒙SOCKET] 绑定失败: errno=%d (%s)", errno, strerror(errno));
                callback(false);
                return;
            }
            
            LOGI("✅ [鸿蒙SOCKET] 绑定成功: %s:%d", address.c_str(), port);
            callback(true);
        }).detach();
    }
    
    // 鸿蒙官方模式：连接到指定地址
    void connect(const std::string& address, int port, int timeout, std::function<void(bool)> callback) {
        std::thread([this, address, port, timeout, callback]() {
            std::lock_guard<std::mutex> lock(mutex_);
            
            struct sockaddr_in connectAddr{};
            connectAddr.sin_family = AF_INET;
            connectAddr.sin_port = htons(port);
            
            if (inet_pton(AF_INET, address.c_str(), &connectAddr.sin_addr) <= 0) {
                LOGE("❌ [鸿蒙SOCKET] 无效的连接地址: %s", address.c_str());
                if (onError_) onError_("Invalid address");
                callback(false);
                return;
            }
            
            // 设置非阻塞模式（鸿蒙推荐方式）
            int flags = fcntl(socketFd_, F_GETFL, 0);
            fcntl(socketFd_, F_SETFL, flags | O_NONBLOCK);
            
            LOGI("🔍 [鸿蒙SOCKET] 开始连接到 %s:%d，超时%dms (非阻塞模式)", address.c_str(), port, timeout);
            
            int result = ::connect(socketFd_, (struct sockaddr*)&connectAddr, sizeof(connectAddr));
            
            if (result == 0) {
                isConnected_ = true;
                LOGI("✅ [鸿蒙SOCKET] 连接立即成功: %s:%d", address.c_str(), port);
                if (onConnect_) onConnect_();
                callback(true);
                
                // 启动消息接收线程
                startReceiving();
            } else if (errno == EINPROGRESS) {
                // 连接正在进行中，使用select等待
                LOGI("⏳ [鸿蒙SOCKET] 连接进行中，等待完成...");
                
                fd_set writefds;
                struct timeval tv;
                tv.tv_sec = timeout / 1000;
                tv.tv_usec = (timeout % 1000) * 1000;
                
                FD_ZERO(&writefds);
                FD_SET(socketFd_, &writefds);
                
                int selectResult = select(socketFd_ + 1, nullptr, &writefds, nullptr, &tv);
                if (selectResult > 0) {
                    // 检查连接是否成功
                    int error = 0;
                    socklen_t len = sizeof(error);
                    if (getsockopt(socketFd_, SOL_SOCKET, SO_ERROR, &error, &len) == 0 && error == 0) {
                        isConnected_ = true;
                        LOGI("✅ [鸿蒙SOCKET] 连接成功: %s:%d", address.c_str(), port);
                        if (onConnect_) onConnect_();
                        callback(true);
                        
                        // 启动消息接收线程
                        startReceiving();
                    } else {
                        LOGE("❌ [鸿蒙SOCKET] 连接失败: errno=%d (%s)", error, strerror(error));
                        if (onError_) onError_(strerror(error));
                        callback(false);
                    }
                } else if (selectResult == 0) {
                    LOGE("❌ [鸿蒙SOCKET] 连接超时: %dms", timeout);
                    if (onError_) onError_("Connection timeout");
                    callback(false);
                } else {
                    LOGE("❌ [鸿蒙SOCKET] select失败: errno=%d (%s)", errno, strerror(errno));
                    if (onError_) onError_(strerror(errno));
                    callback(false);
                }
            } else {
                LOGE("❌ [鸿蒙SOCKET] 连接失败: errno=%d (%s)", errno, strerror(errno));
                if (onError_) onError_(strerror(errno));
                callback(false);
            }
        }).detach();
    }
    
    // 鸿蒙官方模式：发送数据
    void send(const std::string& data, std::function<void(bool)> callback) {
        std::thread([this, data, callback]() {
            std::lock_guard<std::mutex> lock(mutex_);
            
            if (!isConnected_) {
                LOGE("❌ [鸿蒙SOCKET] 未连接，无法发送数据");
                callback(false);
                return;
            }
            
            ssize_t sent = ::send(socketFd_, data.c_str(), data.length(), MSG_NOSIGNAL);
            if (sent < 0) {
                LOGE("❌ [鸿蒙SOCKET] 发送失败: errno=%d (%s)", errno, strerror(errno));
                if (onError_) onError_(strerror(errno));
                callback(false);
                return;
            }
            
            LOGI("✅ [鸿蒙SOCKET] 发送成功: %zd字节", sent);
            callback(true);
        }).detach();
    }
    
    // 鸿蒙官方模式：订阅事件
    void on(const std::string& event, std::function<void()> callback) {
        if (event == "connect") {
            onConnect_ = callback;
        } else if (event == "close") {
            onClose_ = callback;
        }
    }
    
    void on(const std::string& event, std::function<void(const std::string&)> callback) {
        if (event == "message") {
            onMessage_ = callback;
        } else if (event == "error") {
            onError_ = callback;
        }
    }
    
    // 取消事件订阅
    void off(const std::string& event) {
        if (event == "connect") {
            onConnect_ = nullptr;
        } else if (event == "message") {
            onMessage_ = nullptr;
        } else if (event == "close") {
            onClose_ = nullptr;
        } else if (event == "error") {
            onError_ = nullptr;
        }
    }
    
    // 关闭连接
    void close() {
        std::lock_guard<std::mutex> lock(mutex_);
        
        if (socketFd_ >= 0) {
            ::close(socketFd_);
            socketFd_ = -1;
        }
        
        isConnected_ = false;
        if (onClose_) onClose_();
    }
    
private:
    // 启动消息接收线程
    void startReceiving() {
        std::thread([this]() {
            char buffer[4096];
            
            while (isConnected_) {
                ssize_t received = ::recv(socketFd_, buffer, sizeof(buffer) - 1, 0);
                
                if (received > 0) {
                    buffer[received] = '\0';
                    std::string message(buffer, received);
                    LOGI("📥 [鸿蒙SOCKET] 接收消息: %zd字节", received);
                    if (onMessage_) onMessage_(message);
                } else if (received == 0) {
                    LOGI("🔚 [鸿蒙SOCKET] 连接关闭");
                    isConnected_ = false;
                    if (onClose_) onClose_();
                    break;
                } else {
                    if (errno != EAGAIN && errno != EWOULDBLOCK) {
                        LOGE("❌ [鸿蒙SOCKET] 接收错误: errno=%d (%s)", errno, strerror(errno));
                        if (onError_) onError_(strerror(errno));
                        break;
                    }
                }
            }
        }).detach();
    }
};

// 鸿蒙官方SOCKET编程模式示例
void HarmonySocketProgrammingExample() {
    LOGI("╔═══════════════════════════════════════════════════════╗");
    LOGI("║   🌐 鸿蒙官方SOCKET编程模式示例                        ║");
    LOGI("╚═══════════════════════════════════════════════════════╝");
    
    // 1. 创建TCPSocket实例（鸿蒙官方方式）
    auto tcp = HarmonyTCPSocket::constructTCPSocketInstance();
    if (!tcp) {
        LOGE("❌ 创建TCPSocket失败");
        return;
    }
    
    // 2. 订阅TCPSocket相关事件（鸿蒙官方方式）
    tcp->on("connect", []() {
        LOGI("✅ [鸿蒙事件] on connect - 连接建立");
    });
    
    tcp->on("message", [](const std::string& message) {
        LOGI("✅ [鸿蒙事件] on message - 收到消息: %.100s", message.c_str());
    });
    
    tcp->on("close", []() {
        LOGI("✅ [鸿蒙事件] on close - 连接关闭");
    });
    
    tcp->on("error", [](const std::string& error) {
        LOGE("❌ [鸿蒙事件] on error - 错误: %s", error.c_str());
    });
    
    // 3. 绑定IP地址和端口（鸿蒙官方方式）
    tcp->bind("0.0.0.0", 0, [](bool success) {
        if (success) {
            LOGI("✅ [鸿蒙绑定] 绑定成功");
        } else {
            LOGE("❌ [鸿蒙绑定] 绑定失败");
        }
    });
    
    // 4. 连接到指定的IP地址和端口（鸿蒙官方方式）
    tcp->connect("110.242.68.66", 80, 6000, [](bool success) {
        if (success) {
            LOGI("✅ [鸿蒙连接] 连接成功");
            
            // 5. 发送数据（鸿蒙官方方式）
            std::string httpRequest = 
                "GET / HTTP/1.1\r\n"
                "Host: www.baidu.com\r\n"
                "Connection: close\r\n"
                "User-Agent: HarmonyOS-Socket/1.0\r\n"
                "\r\n";
            
            // 注意：这里需要获取tcp实例，实际使用中需要通过智能指针传递
            LOGI("📤 [鸿蒙发送] 准备发送HTTP请求");
        } else {
            LOGE("❌ [鸿蒙连接] 连接失败");
        }
    });
    
    // 6. 连接使用完毕后，主动关闭（鸿蒙官方方式）
    std::thread([tcpPtr = tcp.get()]() {
        std::this_thread::sleep_for(std::chrono::seconds(10));
        tcpPtr->close();
        tcpPtr->off("message");
        tcpPtr->off("connect");
        tcpPtr->off("close");
        tcpPtr->off("error");
        LOGI("✅ [鸿蒙清理] Socket已关闭，事件已取消");
    }).detach();
}

// 导出给NAPI使用的接口
static napi_value InitHarmonySocket(napi_env env, napi_value exports) {
    HarmonySocketProgrammingExample();
    return nullptr;
}

// NAPI模块定义
static napi_module g_module = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = InitHarmonySocket,
    .nm_modname = "harmony_socket",
    .nm_priv = nullptr,
    .reserved = {0},
};

// 注册模块
extern "C" __attribute__((constructor)) void RegisterHarmonySocketModule(void) {
    napi_module_register(&g_module);
}
