#pragma once

#include <vector>
#include <thread>
#include <atomic>
#include <functional>
#include "task_queue.h"

/**
 * 工作线程池
 * 
 * 功能：
 * 1. 管理固定数量的工作线程
 * 2. 从任务队列获取任务并执行
 * 3. 支持优雅关闭
 */
class WorkerThreadPool {
public:
    static WorkerThreadPool& getInstance() {
        static WorkerThreadPool instance;
        return instance;
    }
    
    // 启动线程池
    bool start(int numForwardWorkers = 4, int numResponseWorkers = 2);
    
    // 停止线程池
    void stop();
    
    // 检查是否正在运行
    bool isRunning() const { return running_.load(); }
    
    // 获取线程统计
    struct Stats {
        uint64_t forwardTasksProcessed;
        uint64_t responseTasksProcessed;
        uint64_t forwardTasksFailed;
        uint64_t responseTasksFailed;
    };
    
    Stats getStats() const;

private:
    WorkerThreadPool() 
        : running_(false),
          forwardTasksProcessed_(0),
          responseTasksProcessed_(0),
          forwardTasksFailed_(0),
          responseTasksFailed_(0) {}
    
    ~WorkerThreadPool() {
        stop();
    }
    
    // 禁止拷贝
    WorkerThreadPool(const WorkerThreadPool&) = delete;
    WorkerThreadPool& operator=(const WorkerThreadPool&) = delete;
    
    // 工作线程函数
    void forwardWorkerThread();
    void responseWorkerThread();
    
    std::vector<std::thread> forwardWorkers_;
    std::vector<std::thread> responseWorkers_;
    std::atomic<bool> running_;
    
    // 统计信息
    std::atomic<uint64_t> forwardTasksProcessed_;
    std::atomic<uint64_t> responseTasksProcessed_;
    std::atomic<uint64_t> forwardTasksFailed_;
    std::atomic<uint64_t> responseTasksFailed_;
};

/**
 * 响应批量发送器
 * 
 * 功能：
 * 1. 批量发送响应，减少系统调用
 * 2. 支持响应合并（同一客户端的多个响应）
 */
class ResponseBatcher {
public:
    static ResponseBatcher& getInstance() {
        static ResponseBatcher instance;
        return instance;
    }
    
    // 添加待发送响应
    void addResponse(const uint8_t* data, int dataSize,
                    const sockaddr_in& clientAddr,
                    int forwardSocket,
                    uint8_t protocol);
    
    // 刷新所有待发送响应
    int flush();
    
    // 获取统计
    uint64_t getTotalSent() const { return totalSent_.load(); }
    uint64_t getTotalBatches() const { return totalBatches_.load(); }

private:
    ResponseBatcher() : totalSent_(0), totalBatches_(0) {}
    ~ResponseBatcher() = default;
    
    // 禁止拷贝
    ResponseBatcher(const ResponseBatcher&) = delete;
    ResponseBatcher& operator=(const ResponseBatcher&) = delete;
    
    struct BatchedResponse {
        std::vector<ResponseTask> responses;
        sockaddr_in clientAddr;
    };
    
    std::vector<ResponseTask> pendingResponses_;
    std::mutex mutex_;
    
    std::atomic<uint64_t> totalSent_;
    std::atomic<uint64_t> totalBatches_;
};
