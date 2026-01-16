#pragma once

#include <vector>
#include <queue>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <functional>
#include <future>
#include <atomic>
#include <memory>

namespace vpn {
namespace resource {

/**
 * @brief 高性能线程池
 * 
 * 特性：
 * - 固定大小线程池
 * - 支持任务优先级
 * - 支持任务取消
 * - 工作窃取（可选）
 */
class ThreadPool {
public:
    /**
     * @brief 任务优先级
     */
    enum class Priority {
        LOW = 0,
        NORMAL = 1,
        HIGH = 2
    };
    
    /**
     * @brief 构造函数
     * @param numThreads 线程数量（0 = 自动检测）
     */
    explicit ThreadPool(size_t numThreads = 0);
    
    /**
     * @brief 析构函数 - 等待所有任务完成
     */
    ~ThreadPool();
    
    // 禁止拷贝和移动
    ThreadPool(const ThreadPool&) = delete;
    ThreadPool& operator=(const ThreadPool&) = delete;
    
    /**
     * @brief 提交任务
     * @param func 任务函数
     * @param args 任务参数
     * @return std::future，可用于获取返回值和等待完成
     */
    template<typename Func, typename... Args>
    auto Submit(Func&& func, Args&&... args)
        -> std::future<typename std::invoke_result<Func, Args...>::type>;
    
    /**
     * @brief 提交带优先级的任务
     * @param priority 任务优先级
     * @param func 任务函数
     * @param args 任务参数
     * @return std::future
     */
    template<typename Func, typename... Args>
    auto SubmitWithPriority(Priority priority, Func&& func, Args&&... args)
        -> std::future<typename std::invoke_result<Func, Args...>::type>;
    
    /**
     * @brief 等待所有任务完成
     */
    void WaitAll();
    
    /**
     * @brief 获取线程数量
     */
    size_t GetThreadCount() const;
    
    /**
     * @brief 获取待处理任务数量
     */
    size_t GetPendingTaskCount() const;
    
    /**
     * @brief 获取正在执行的任务数量
     */
    size_t GetRunningTaskCount() const;
    
    /**
     * @brief 获取统计信息
     */
    struct Stats {
        uint64_t tasksCompleted = 0;
        uint64_t tasksFailed = 0;
        std::chrono::microseconds totalExecutionTime{0};
        std::chrono::microseconds avgTaskTime{0};
    };
    
    Stats GetStats() const;
    
    /**
     * @brief 优雅关闭
     * 不再接受新任务，等待现有任务完成
     */
    void Shutdown();
    
    /**
     * @brief 强制关闭
     * 不再接受新任务，清空队列，等待正在执行的任务完成
     */
    void ShutdownNow();

private:
    struct Task {
        std::function<void()> func;
        Priority priority;
        
        bool operator<(const Task& other) const {
            return priority < other.priority;  // 高优先级在前
        }
    };
    
    std::vector<std::thread> workers_;
    std::priority_queue<Task> tasks_;
    
    std::mutex mutex_;
    std::condition_variable condition_;
    
    std::atomic<bool> stop_{false};
    std::atomic<size_t> runningTasks_{0};
    
    Stats stats_;
    
    void WorkerThread();
};

// ===== 模板实现 =====

template<typename Func, typename... Args>
auto ThreadPool::Submit(Func&& func, Args&&... args)
    -> std::future<typename std::invoke_result<Func, Args...>::type>
{
    return SubmitWithPriority(Priority::NORMAL, 
                              std::forward<Func>(func), 
                              std::forward<Args>(args)...);
}

template<typename Func, typename... Args>
auto ThreadPool::SubmitWithPriority(Priority priority, Func&& func, Args&&... args)
    -> std::future<typename std::invoke_result<Func, Args...>::type>
{
    using ReturnType = typename std::invoke_result<Func, Args...>::type;
    
    // 创建打包任务
    auto task = std::make_shared<std::packaged_task<ReturnType()>>(
        std::bind(std::forward<Func>(func), std::forward<Args>(args)...)
    );
    
    std::future<ReturnType> result = task->get_future();
    
    {
        std::unique_lock<std::mutex> lock(mutex_);
        
        if (stop_) {
            throw std::runtime_error("Cannot submit task to stopped thread pool");
        }
        
        tasks_.push({
            [task]() { (*task)(); },
            priority
        });
    }
    
    condition_.notify_one();
    return result;
}

} // namespace resource
} // namespace vpn
