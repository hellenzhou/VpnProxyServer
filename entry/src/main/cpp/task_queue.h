#pragma once

#include <cstdint>
#include <string>
#include <memory>
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
    
    ForwardTask() : dataSize(0) {}
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
struct Task {
    TaskType type;
    union {
        ForwardTask forwardTask;
        ResponseTask responseTask;
    };
    
    Task() : type(TaskType::FORWARD_REQUEST) {
        new (&forwardTask) ForwardTask();
    }
    
    explicit Task(TaskType t) : type(t) {
        if (t == TaskType::FORWARD_REQUEST) {
            new (&forwardTask) ForwardTask();
        } else {
            new (&responseTask) ResponseTask();
        }
    }
    
    ~Task() {
        // Union不需要显式析构
    }
    
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
            // 🐛 修复：根据源类型正确赋值，避免类型不匹配
            if (other.type == TaskType::FORWARD_REQUEST) {
                type = TaskType::FORWARD_REQUEST;
                forwardTask = other.forwardTask;
            } else {
                type = TaskType::SEND_RESPONSE;
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
                          const sockaddr_in& clientAddr);
    
    // 提交响应任务
    bool submitResponseTask(const uint8_t* data, int dataSize,
                           const sockaddr_in& clientAddr,
                           int forwardSocket,
                           uint8_t protocol);
    
    // 获取转发任务
    std::optional<Task> popForwardTask(std::chrono::milliseconds timeout);
    
    // 获取响应任务
    std::optional<Task> popResponseTask(std::chrono::milliseconds timeout);
    
    // 获取队列统计
    size_t getForwardQueueSize() const { return forwardQueue_.size(); }
    size_t getResponseQueueSize() const { return responseQueue_.size(); }
    
    // 关闭所有队列
    void shutdown();
    
    // 清空所有队列
    void clear();

private:
    TaskQueueManager() 
        : forwardQueue_(5000),   // 转发队列最大5000个任务
          responseQueue_(10000)  // 响应队列最大10000个任务
    {}
    
    ~TaskQueueManager() {
        // 🐛 修复：析构时不调用shutdown()，因为可能已经被显式调用
        // shutdown()应该由用户在StopServer中显式调用
    }
    
    // 禁止拷贝
    TaskQueueManager(const TaskQueueManager&) = delete;
    TaskQueueManager& operator=(const TaskQueueManager&) = delete;
    
    ThreadSafeQueue<Task> forwardQueue_;    // 转发请求队列
    ThreadSafeQueue<Task> responseQueue_;   // 响应发送队列
};
