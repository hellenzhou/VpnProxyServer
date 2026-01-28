#pragma once

#include <cstdint>
#include <string>
#include <memory>
#include <vector>
#include <netinet/in.h>
#include "protocol_handler.h"
#include "thread_safe_queue.h"

// 任务类型
enum class TaskType {
    FORWARD_REQUEST,   // 转发请求
    SEND_RESPONSE      // 发送响应
};

// 转发请求任务
struct ForwardTask {
    uint8_t data[2048];       // 数据包内容
    int dataSize;             // 数据包大小
    PacketInfo packetInfo;    // 解析后的包信息
    sockaddr_in clientAddr;   // 客户端地址
    int tunnelFd;             // VPN隧道FD

    ForwardTask() : dataSize(0), tunnelFd(-1) {}
};

// 响应发送任务
struct ResponseTask {
    uint8_t data[4096];       // 响应数据
    int dataSize;             // 数据大小
    sockaddr_in clientAddr;   // 目标客户端地址
    int forwardSocket;        // 来源socket（用于NAT查找）
    uint8_t protocol;         // 协议类型
    std::chrono::steady_clock::time_point timestamp;  // 时间戳
    
    ResponseTask() : dataSize(0), forwardSocket(-1), protocol(0) {}
};

// 通用任务结构
// 🐛 修复：避免使用union，使用单独成员变量避免数据污染
struct Task {
    TaskType type;
    ForwardTask forwardTask;
    ResponseTask responseTask;

    Task() : type(TaskType::FORWARD_REQUEST) {}

    explicit Task(TaskType t) : type(t) {}

    ~Task() = default;

    // 拷贝构造
    Task(const Task& other) : type(other.type) {
        if (type == TaskType::FORWARD_REQUEST) {
            forwardTask = other.forwardTask;
        } else {
            responseTask = other.responseTask;
        }
    }

    // 赋值操作
    Task& operator=(const Task& other) {
        if (this != &other) {
            type = other.type;
            if (type == TaskType::FORWARD_REQUEST) {
                forwardTask = other.forwardTask;
            } else {
                responseTask = other.responseTask;
            }
        }
        return *this;
    }
};

// 任务队列管理器
class TaskQueueManager {
public:
    static TaskQueueManager& getInstance() {
        static TaskQueueManager instance;
        return instance;
    }
    
    // 提交转发任务
    bool submitForwardTask(const uint8_t* data, int dataSize,
                          const PacketInfo& packetInfo,
                          const sockaddr_in& clientAddr,
                          int tunnelFd);
    
    // 提交响应任务
    bool submitResponseTask(const uint8_t* data, int dataSize,
                           const sockaddr_in& clientAddr,
                           int forwardSocket,
                           uint8_t protocol);
    
    // 获取转发任务（通用，兼容旧代码）
    Optional<Task> popForwardTask(std::chrono::milliseconds timeout);
    
    // 🚀 优雅方案：按协议分离的队列
    // 注意：TCP任务使用连接哈希路由，确保同一连接的任务由同一线程处理
    Optional<Task> popTcpTask(int workerIndex, std::chrono::milliseconds timeout);
    Optional<Task> popUdpTask(std::chrono::milliseconds timeout);
    
    // 🚀 优雅方案：根据连接哈希计算应该使用哪个TCP worker
    // 返回worker索引，确保同一连接的任务由同一线程处理
    int getTcpWorkerIndex(const PacketInfo& packetInfo, const sockaddr_in& clientAddr) const;
    
    // 获取响应任务
    Optional<Task> popResponseTask(std::chrono::milliseconds timeout);
    
    // 获取队列统计
    size_t getForwardQueueSize() const { return forwardQueue_.size(); }
    size_t getTcpQueueSize() const { 
        size_t total = 0;
        for (const auto& q : tcpQueues_) {
            if (q) {
                total += q->size();
            }
        }
        return total;
    }
    size_t getUdpQueueSize() const { return udpQueue_.size(); }
    size_t getResponseQueueSize() const { return responseQueue_.size(); }
    
    // 检查队列是否为空
    bool isForwardQueueEmpty() const { return forwardQueue_.empty(); }
    bool isTcpQueueEmpty() const { 
        for (const auto& q : tcpQueues_) {
            if (q && !q->empty()) return false;
        }
        return true;
    }
    bool isUdpQueueEmpty() const { return udpQueue_.empty(); }
    bool isResponseQueueEmpty() const { return responseQueue_.empty(); }
    
    // 关闭所有队列
    void shutdown();
    
    // 清空所有队列
    void clear();
    
    // 初始化TCP队列数组（由WorkerThreadPool调用，必须在worker启动前调用）
    // 🚀 修复：改为public，允许WorkerThreadPool调用
    void initializeTcpQueues(int numWorkers);

private:
    TaskQueueManager() 
        : forwardQueue_(2000),    // 转发队列（兼容旧代码，ICMP等）
          tcpQueues_(),           // TCP队列数组（动态初始化）
          udpQueue_(500),        // UDP队列：500个任务（UDP可容忍丢包）
          responseQueue_(2000),   // 响应队列：2000个任务（响应通常较快）
          numTcpWorkers_(2)        // 默认2个TCP worker
    {
        // 初始化TCP队列数组（默认2个，会在start时重新初始化）
        // 🚀 修复：使用emplace_back创建unique_ptr，因为ThreadSafeQueue包含mutex，不可拷贝
        for (int i = 0; i < 2; ++i) {
            tcpQueues_.emplace_back(std::make_unique<ThreadSafeQueue<Task>>(1000));
        }
    }
    
    ~TaskQueueManager() {
        // 🐛 修复：析构时不调用shutdown()，因为可能已经被显式调用
        // shutdown()应该由用户在StopServer中显式调用
    }
    
    // 禁止拷贝
    TaskQueueManager(const TaskQueueManager&) = delete;
    TaskQueueManager& operator=(const TaskQueueManager&) = delete;
    
    ThreadSafeQueue<Task> forwardQueue_;    // 转发请求队列（兼容旧代码）
    // 🚀 修复：使用unique_ptr，因为ThreadSafeQueue包含mutex，不可拷贝
    std::vector<std::unique_ptr<ThreadSafeQueue<Task>>> tcpQueues_;  // TCP专用队列数组（每个worker一个）
    ThreadSafeQueue<Task> udpQueue_;        // UDP专用队列（优雅方案）
    ThreadSafeQueue<Task> responseQueue_;   // 响应发送队列
    
    int numTcpWorkers_;  // TCP worker数量（用于哈希路由）
};
