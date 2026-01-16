#pragma once

#include <functional>
#include <memory>
#include <atomic>
#include <chrono>

namespace vpn {
namespace core {

/**
 * @brief 事件类型
 */
enum class EventType : uint32_t {
    READ = 1 << 0,   // 可读
    WRITE = 1 << 1,  // 可写
    ERROR = 1 << 2,  // 错误
    HANGUP = 1 << 3  // 挂断
};

inline EventType operator|(EventType a, EventType b) {
    return static_cast<EventType>(
        static_cast<uint32_t>(a) | static_cast<uint32_t>(b)
    );
}

inline bool operator&(EventType a, EventType b) {
    return (static_cast<uint32_t>(a) & static_cast<uint32_t>(b)) != 0;
}

/**
 * @brief 事件处理器接口
 */
class EventHandler {
public:
    virtual ~EventHandler() = default;
    
    /**
     * @brief 处理事件
     * @param events 发生的事件类型
     */
    virtual void OnEvent(EventType events) = 0;
    
    /**
     * @brief 获取文件描述符
     */
    virtual int GetFd() const = 0;
};

/**
 * @brief 定时器回调
 */
using TimerCallback = std::function<void()>;

/**
 * @brief 事件循环
 * 
 * 使用 epoll (Linux) / kqueue (BSD/macOS) / IOCP (Windows)
 * 实现高性能的 I/O 多路复用
 */
class EventLoop {
public:
    /**
     * @brief 构造函数
     */
    EventLoop();
    
    /**
     * @brief 析构函数
     */
    ~EventLoop();
    
    // 禁止拷贝和移动
    EventLoop(const EventLoop&) = delete;
    EventLoop& operator=(const EventLoop&) = delete;
    
    /**
     * @brief 运行事件循环
     * 阻塞直到 Stop() 被调用
     */
    void Run();
    
    /**
     * @brief 停止事件循环
     */
    void Stop();
    
    /**
     * @brief 检查是否正在运行
     */
    bool IsRunning() const;
    
    /**
     * @brief 添加事件处理器
     * @param handler 事件处理器
     * @param events 感兴趣的事件类型
     * @return true 成功，false 失败
     */
    bool AddHandler(EventHandler* handler, EventType events);
    
    /**
     * @brief 修改事件处理器的事件类型
     * @param handler 事件处理器
     * @param events 新的事件类型
     * @return true 成功，false 失败
     */
    bool ModifyHandler(EventHandler* handler, EventType events);
    
    /**
     * @brief 移除事件处理器
     * @param handler 事件处理器
     * @return true 成功，false 失败
     */
    bool RemoveHandler(EventHandler* handler);
    
    /**
     * @brief 添加一次性定时器
     * @param delay 延迟时间
     * @param callback 回调函数
     * @return 定时器 ID（可用于取消）
     */
    uint64_t AddTimer(std::chrono::milliseconds delay, TimerCallback callback);
    
    /**
     * @brief 添加周期性定时器
     * @param interval 周期间隔
     * @param callback 回调函数
     * @return 定时器 ID（可用于取消）
     */
    uint64_t AddPeriodicTimer(std::chrono::milliseconds interval, TimerCallback callback);
    
    /**
     * @brief 取消定时器
     * @param timerId 定时器 ID
     * @return true 成功，false 失败（定时器不存在）
     */
    bool CancelTimer(uint64_t timerId);
    
    /**
     * @brief 在事件循环线程中执行任务
     * @param task 要执行的任务
     * 
     * 如果当前线程就是事件循环线程，立即执行
     * 否则，加入队列，在下一次循环迭代时执行
     */
    void RunInLoop(std::function<void()> task);
    
    /**
     * @brief 检查当前线程是否是事件循环线程
     */
    bool IsInLoopThread() const;
    
    /**
     * @brief 获取事件循环统计信息
     */
    struct Stats {
        uint64_t iterations = 0;     // 循环迭代次数
        uint64_t eventsProcessed = 0;  // 处理的事件数
        uint64_t timersExecuted = 0;   // 执行的定时器数
        std::chrono::microseconds avgLoopTime{0};  // 平均循环时间
    };
    
    Stats GetStats() const;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace core
} // namespace vpn
