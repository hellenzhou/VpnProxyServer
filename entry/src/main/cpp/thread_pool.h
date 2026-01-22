#pragma once

#include <vector>
#include <queue>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <future>
#include <functional>
#include <atomic>
#include <memory>
#include <hilog/log.h>

#define POOL_LOGI(fmt, ...) \
    OH_LOG_Print(LOG_APP, LOG_INFO, 0x15b1, "VpnServer", "ZHOUB [ThreadPool] " fmt, ##__VA_ARGS__)
#define POOL_LOGE(fmt, ...) \
    OH_LOG_Print(LOG_APP, LOG_ERROR, 0x15b1, "VpnServer", "ZHOUB [ThreadPool] ❌ " fmt, ##__VA_ARGS__)

// VPN专用线程池
class VPNThreadPool {
public:
    enum ThreadType {
        FORWARD_WORKER,    // 转发工作线程
        RESPONSE_WORKER,   // 响应工作线程
        NETWORK_WORKER     // 网络工作线程
    };

private:
    struct ThreadInfo {
        std::thread thread;
        ThreadType type;
        int id;
        std::atomic<bool> running{true};
        std::queue<std::function<void()>> tasks;
        std::mutex taskMutex;
        std::condition_variable taskCondition;
    };

    std::vector<std::unique_ptr<ThreadInfo>> threads_;
    std::atomic<bool> shutdown_{false};
    std::mutex globalMutex_;
    
    // 统计信息
    std::atomic<uint64_t> totalTasks_{0};
    std::atomic<uint64_t> completedTasks_{0};

public:
    VPNThreadPool() = default;
    
    ~VPNThreadPool() {
        shutdown();
    }

    // 启动线程池
    bool start(int forwardWorkers, int responseWorkers, int networkWorkers) {
        std::lock_guard<std::mutex> lock(globalMutex_);
        
        if (!threads_.empty()) {
            POOL_LOGE("ThreadPool already started");
            return false;
        }

        POOL_LOGI("Starting ThreadPool: forward=%d, response=%d, network=%d", 
                 forwardWorkers, responseWorkers, networkWorkers);

        // 创建转发工作线程
        for (int i = 0; i < forwardWorkers; ++i) {
            createThread(ThreadType::FORWARD_WORKER, i);
        }
        
        // 创建响应工作线程
        for (int i = 0; i < responseWorkers; ++i) {
            createThread(ThreadType::RESPONSE_WORKER, i);
        }
        
        // 创建网络工作线程
        for (int i = 0; i < networkWorkers; ++i) {
            createThread(ThreadType::NETWORK_WORKER, i);
        }

        POOL_LOGI("ThreadPool started with %zu threads", threads_.size());
        return true;
    }

    // 提交任务到指定类型线程
    template<class F, class... Args>
    auto submit(ThreadType type, F&& f, Args&&... args) -> std::future<decltype(f(args...))> {
        using ReturnType = decltype(f(args...));
        
        auto task = std::make_shared<std::packaged_task<ReturnType()>>(
            std::bind(std::forward<F>(f), std::forward<Args>(args)...)
        );
        
        std::future<ReturnType> result = task->get_future();
        
        {
            std::lock_guard<std::mutex> lock(globalMutex_);
            if (shutdown_) {
                throw std::runtime_error("ThreadPool is shutdown");
            }
            
            // 找到对应类型的线程
            ThreadInfo* targetThread = nullptr;
            for (auto& threadInfo : threads_) {
                if (threadInfo->type == type && threadInfo->running.load()) {
                    targetThread = threadInfo.get();
                    break;
                }
            }
            
            if (!targetThread) {
                throw std::runtime_error("No available thread for specified type");
            }
            
            {
                std::lock_guard<std::mutex> taskLock(targetThread->taskMutex);
                targetThread->tasks.emplace([task](){ (*task)(); });
            }
            targetThread->taskCondition.notify_one();
        }
        
        totalTasks_++;
        return result;
    }

    // 提交任务到任意可用线程
    template<class F, class... Args>
    auto submitAny(F&& f, Args&&... args) -> std::future<decltype(f(args...))> {
        // 简化版本：提交到转发工作线程
        return submit(ThreadType::FORWARD_WORKER, std::forward<F>(f), std::forward<Args>(args)...);
    }

    // 关闭线程池
    void shutdown() {
        {
            std::lock_guard<std::mutex> lock(globalMutex_);
            if (shutdown_) return;
            shutdown_ = true;
        }

        POOL_LOGI("Shutting down ThreadPool...");

        // 通知所有线程退出
        for (auto& threadInfo : threads_) {
            {
                std::lock_guard<std::mutex> taskLock(threadInfo->taskMutex);
                threadInfo->running = false;
            }
            threadInfo->taskCondition.notify_all();
        }

        // 等待所有线程退出
        for (auto& threadInfo : threads_) {
            if (threadInfo->thread.joinable()) {
                threadInfo->thread.join();
            }
        }

        threads_.clear();
        POOL_LOGI("ThreadPool shutdown completed");
    }

    // 容量管理
    struct CapacityInfo {
        size_t maxThreads;
        size_t currentThreads;
        size_t activeThreads;
        size_t queuedTasks;
        double cpuUsage;
        size_t memoryUsageMB;
    };
    
    // 获取容量信息
    CapacityInfo getCapacityInfo() const {
        CapacityInfo info;
        info.maxThreads = threads_.size();
        info.currentThreads = threads_.size();
        info.activeThreads = 0;
        info.queuedTasks = 0;
        
        for (const auto& threadInfo : threads_) {
            if (threadInfo->running.load()) {
                info.activeThreads++;
            }
            {
                std::lock_guard<std::mutex> lock(threadInfo->taskMutex);
                info.queuedTasks += threadInfo->tasks.size();
            }
        }
        
        // 简化的CPU和内存估算
        info.cpuUsage = (double)info.activeThreads / std::thread::hardware_concurrency() * 100.0;
        info.memoryUsageMB = info.currentThreads * 2;  // 每线程约2MB
        
        return info;
    }
    
    // 检查是否接近容量限制
    bool isNearCapacity() const {
        auto info = getCapacityInfo();
        return info.queuedTasks > info.maxThreads * 2 ||  // 队列任务超过线程数2倍
               info.cpuUsage > 80.0;                     // CPU使用率超过80%
    }
    
    // 打印容量信息
    void printCapacityInfo() const {
        auto info = getCapacityInfo();
        POOL_LOGI("Capacity: %zu/%zu active, %zu queued, CPU=%.1f%%, %zuMB",
                 info.activeThreads, info.maxThreads, info.queuedTasks,
                 info.cpuUsage, info.memoryUsageMB);
        
        if (isNearCapacity()) {
            POOL_LOGI("⚠️ Thread pool near capacity!");
        }
    }

private:
    void createThread(ThreadType type, int id) {
        auto threadInfo = std::make_unique<ThreadInfo>();
        threadInfo->type = type;
        threadInfo->id = id;
        
        const char* typeName = (type == ThreadType::FORWARD_WORKER) ? "Forward" :
                              (type == ThreadType::RESPONSE_WORKER) ? "Response" : "Network";
        
        threadInfo->thread = std::thread([this, threadPtr = threadInfo.get(), typeName, id]() {
            POOL_LOGI("%s worker #%d started", typeName, id);
            
            while (threadPtr->running.load()) {
                std::function<void()> task;
                
                {
                    std::unique_lock<std::mutex> lock(threadPtr->taskMutex);
                    threadPtr->taskCondition.wait(lock, [&threadPtr]() {
                        return !threadPtr->running.load() || !threadPtr->tasks.empty();
                    });
                    
                    if (!threadPtr->running.load()) break;
                    
                    if (!threadPtr->tasks.empty()) {
                        task = std::move(threadPtr->tasks.front());
                        threadPtr->tasks.pop();
                    }
                }
                
                if (task) {
                    try {
                        task();
                        completedTasks_++;
                    } catch (const std::exception& e) {
                        POOL_LOGE("Task execution error: %s", e.what());
                    }
                }
            }
            
            POOL_LOGI("%s worker #%d stopped", typeName, id);
        });
        
        threads_.push_back(std::move(threadInfo));
    }
};

// 全局线程池实例
extern std::unique_ptr<VPNThreadPool> g_threadPool;
