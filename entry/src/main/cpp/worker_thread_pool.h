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
    // numTcpWorkers: 专门处理TCP任务的线程数（建议2-4个）
    // numUdpWorkers: 专门处理UDP任务的线程数（建议2-4个）
    // numResponseWorkers: 处理响应任务的线程数（建议2个）
    bool start(int numTcpWorkers = 2, int numUdpWorkers = 2, int numResponseWorkers = 2);
    
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
        uint64_t tcpTasksProcessed;
        uint64_t udpTasksProcessed;
    };
    
    Stats getStats() const;

private:
    WorkerThreadPool() 
        : running_(false),
          forwardTasksProcessed_(0),
          responseTasksProcessed_(0),
          forwardTasksFailed_(0),
          responseTasksFailed_(0),
          tcpTasksProcessed_(0),
          udpTasksProcessed_(0) {}
    
    ~WorkerThreadPool() {
        stop();
    }
    
    // 禁止拷贝
    WorkerThreadPool(const WorkerThreadPool&) = delete;
    WorkerThreadPool& operator=(const WorkerThreadPool&) = delete;
    
    // 工作线程函数
    void forwardWorkerThread();  // 通用worker（兼容旧代码）
    void tcpWorkerThread(int workerIndex);      // 专门处理TCP任务（传入worker索引）
    void udpWorkerThread();       // 专门处理UDP任务
    void responseWorkerThread();
    
    std::vector<std::thread> forwardWorkers_;  // 保留用于兼容
    std::vector<std::thread> tcpWorkers_;      // TCP专用线程
    std::vector<std::thread> udpWorkers_;      // UDP专用线程
    std::vector<std::thread> responseWorkers_;
    std::atomic<bool> running_;
    
    // 统计信息
    std::atomic<uint64_t> forwardTasksProcessed_;
    std::atomic<uint64_t> responseTasksProcessed_;
    std::atomic<uint64_t> forwardTasksFailed_;
    std::atomic<uint64_t> responseTasksFailed_;
    std::atomic<uint64_t> tcpTasksProcessed_;
    std::atomic<uint64_t> udpTasksProcessed_;
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
