#include "task_queue.h"
#include <hilog/log.h>
#include <cstring>
#include <sstream>
#include "traffic_stats.h"

// 🔧 调试开关：设置为 true 启用详细日志（每个任务都记录）
// 生产环境请设置为 false 避免日志爆炸
#define ENABLE_VERBOSE_TASK_LOG false

#define MAKE_FILE_NAME (strrchr(__FILE__, '/') ? (strrchr(__FILE__, '/') + 1) : __FILE__)
#define TASK_LOGI(fmt, ...) \
  OH_LOG_Print(LOG_APP, LOG_INFO, 0x15b1, "VpnServer", "ZHOUB [Queue] [%{public}s:%{public}d] " fmt, MAKE_FILE_NAME, __LINE__, ##__VA_ARGS__)
#define TASK_LOGE(fmt, ...) \
  OH_LOG_Print(LOG_APP, LOG_ERROR, 0x15b1, "VpnServer", "ZHOUB [Queue] [%{public}s:%{public}d] " fmt, MAKE_FILE_NAME, __LINE__, ##__VA_ARGS__)
#define TASK_LOGV(fmt, ...) \
  if (ENABLE_VERBOSE_TASK_LOG) { \
    OH_LOG_Print(LOG_APP, LOG_INFO, 0x15b1, "VpnServer", "ZHOUB [Queue] [%{public}s:%{public}d] " fmt, MAKE_FILE_NAME, __LINE__, ##__VA_ARGS__); \
  }

bool TaskQueueManager::submitForwardTask(const uint8_t* data, int dataSize,
                                        const PacketInfo& packetInfo,
                                        const sockaddr_in& clientAddr,
                                        int tunnelFd) {
    // 🐛 修复：更严格的边界检查
    if (!data || dataSize <= 0 || dataSize > sizeof(ForwardTask::data)) {
        TASK_LOGE("❌ Invalid forward task: data=%p, dataSize=%{public}d (max=%{public}zu)",
                 data, dataSize, sizeof(ForwardTask::data));
        return false;
    }

    Task task(TaskType::FORWARD_REQUEST);
    std::memcpy(task.forwardTask.data, data, dataSize);
    task.forwardTask.dataSize = dataSize;
    task.forwardTask.packetInfo = packetInfo;
    task.forwardTask.clientAddr = clientAddr;
    task.forwardTask.tunnelFd = tunnelFd;

    // Stats: enqueue forward task (best-effort)
    TrafficStats::fwdEnqueueTotal.fetch_add(1, std::memory_order_relaxed);
    switch (packetInfo.protocol) {
        case PROTOCOL_TCP:
            TrafficStats::fwdEnqueueTcp.fetch_add(1, std::memory_order_relaxed);
            break;
        case PROTOCOL_UDP:
            TrafficStats::fwdEnqueueUdp.fetch_add(1, std::memory_order_relaxed);
            break;
        case PROTOCOL_ICMP:
        case PROTOCOL_ICMPV6:
            TrafficStats::fwdEnqueueIcmp.fetch_add(1, std::memory_order_relaxed);
            break;
        default:
            TrafficStats::fwdEnqueueOther.fetch_add(1, std::memory_order_relaxed);
            break;
    }

    // 🔍 诊断：记录入队前的队列状态
    size_t queueSizeBefore = forwardQueue_.size();
    bool queueEmptyBefore = isForwardQueueEmpty();
    
    // 🚨 关键诊断：TCP任务入队前记录详细信息
    bool isTcp = (packetInfo.protocol == PROTOCOL_TCP);
    if (isTcp) {
        TASK_LOGI("🚀 [Queue] TCP任务准备入队: 源=%s:%d -> 目标=%s:%d, 大小=%d, 入队前队列大小=%zu, 空=%d",
                 packetInfo.sourceIP.c_str(), packetInfo.sourcePort,
                 packetInfo.targetIP.c_str(), packetInfo.targetPort,
                 dataSize, queueSizeBefore, queueEmptyBefore ? 1 : 0);
    }

    // 🚀 优雅方案：根据协议类型将任务放入对应的队列
    bool pushResult = false;
    size_t queueSizeAfter = 0;
    bool queueEmptyAfter = false;
    
    if (packetInfo.protocol == PROTOCOL_TCP) {
        // 🚀 优雅方案：根据连接哈希路由TCP任务到对应的worker队列
        int workerIndex = getTcpWorkerIndex(packetInfo, clientAddr);
        if (workerIndex < 0 || workerIndex >= static_cast<int>(tcpQueues_.size()) || !tcpQueues_[workerIndex]) {
            TASK_LOGE("⚠️ Invalid TCP worker index: %d (队列数=%zu)", workerIndex, tcpQueues_.size());
            return false;
        }
        
        // 🚀 关键优化：TCP任务使用阻塞push，避免任务丢失导致连接失败
        // 如果队列满，会阻塞等待，确保TCP连接不会因为队列满而失败
        // 这比丢弃任务更优雅，因为TCP是可靠协议，不能容忍丢包
        pushResult = tcpQueues_[workerIndex]->push(task);
        queueSizeAfter = tcpQueues_[workerIndex]->size();
        queueEmptyAfter = tcpQueues_[workerIndex]->empty();
        
        if (pushResult) {
            // 队列监控：如果队列超过80%容量，记录警告
            if (queueSizeAfter > 800) {  // 1000 * 0.8
                TASK_LOGE("⚠️ [Queue] TCP队列接近满载: worker#%d, 队列大小=%zu/%d (80%%)", 
                         workerIndex, queueSizeAfter, 1000);
            }
            // 详细日志只在调试时启用，避免日志爆炸
            // TASK_LOGI("✅ [Queue] TCP任务入队成功: worker#%d, 队列大小=%zu", workerIndex, queueSizeAfter);
        } else {
            // push返回false表示队列已关闭，这是正常关闭流程
            TASK_LOGI("⚠️ TCP queue[%d] closed, task not enqueued", workerIndex);
            return false;
        }
    } else if (packetInfo.protocol == PROTOCOL_UDP) {
        // UDP任务放入UDP专用队列
        // 🚀 UDP可以使用tryPush，因为UDP本身可以容忍丢包
        pushResult = udpQueue_.tryPush(task);
        queueSizeAfter = udpQueue_.size();
        queueEmptyAfter = udpQueue_.empty();
        
        if (!pushResult) {
            // UDP队列满时丢弃是合理的，因为UDP本身是无状态协议
            TASK_LOGE("⚠️ UDP queue full, dropping packet: 队列大小=%zu (UDP可容忍丢包)", udpQueue_.size());
            return false;
        }
        
        // 队列监控：如果队列超过80%容量，记录警告
        if (queueSizeAfter > 400) {  // 500 * 0.8
            TASK_LOGE("⚠️ [Queue] UDP队列接近满载: 队列大小=%zu/%d (80%%)", queueSizeAfter, 500);
        }
    } else {
        // 其他协议（ICMP等）放入通用队列（兼容旧代码）
        pushResult = forwardQueue_.tryPush(task);
        queueSizeAfter = forwardQueue_.size();
        queueEmptyAfter = forwardQueue_.empty();
        
        if (!pushResult) {
            TASK_LOGE("⚠️ Forward queue full, dropping packet: 队列大小=%zu", queueSizeBefore);
            return false;
        }
    }

    return true;
}

bool TaskQueueManager::submitResponseTask(const uint8_t* data, int dataSize,
                                         const sockaddr_in& clientAddr,
                                         int forwardSocket,
                                         uint8_t protocol) {
    // 🐛 修复：更严格的边界检查
    if (!data || dataSize <= 0 || dataSize > sizeof(ResponseTask::data)) {
        TASK_LOGE("❌ Invalid response task: data=%p, dataSize=%{public}d (max=%{public}zu)",
                 data, dataSize, sizeof(ResponseTask::data));
        return false;
    }

    Task task(TaskType::SEND_RESPONSE);
    std::memcpy(task.responseTask.data, data, dataSize);
    task.responseTask.dataSize = dataSize;
    task.responseTask.clientAddr = clientAddr;
    task.responseTask.forwardSocket = forwardSocket;
    task.responseTask.protocol = protocol;
    task.responseTask.timestamp = std::chrono::steady_clock::now();

    // Stats: enqueue response task (best-effort)
    TrafficStats::respEnqueueTotal.fetch_add(1, std::memory_order_relaxed);
    if (protocol == PROTOCOL_TCP) {
        TrafficStats::respEnqueueTcp.fetch_add(1, std::memory_order_relaxed);
    } else if (protocol == PROTOCOL_UDP) {
        TrafficStats::respEnqueueUdp.fetch_add(1, std::memory_order_relaxed);
    } else {
        TrafficStats::respEnqueueOther.fetch_add(1, std::memory_order_relaxed);
    }

    if (!responseQueue_.tryPush(task)) {
        TASK_LOGE("⚠️ Response queue full, dropping response");
        return false;
    }

    return true;
}

Optional<Task> TaskQueueManager::popForwardTask(std::chrono::milliseconds timeout) {
    // 🚨 IMPORTANT:
    // The old implementation used many shared `static int` counters across multiple worker threads.
    // That is a data race (UB) and can lead to hangs / weird behavior exactly like "enqueue grows, pop stops".
    // Keep this path minimal and thread-safe. Use TrafficStats for global counters.

    auto result = forwardQueue_.popWithTimeout(timeout);
    if (!result.has_value()) {
        return result;
    }

    TrafficStats::fwdPopTotal.fetch_add(1, std::memory_order_relaxed);
    const Task& task = result.value();
    if (task.type == TaskType::FORWARD_REQUEST) {
        uint8_t protocol = task.forwardTask.packetInfo.protocol;
        if (protocol == PROTOCOL_TCP) {
            TrafficStats::fwdPopTcp.fetch_add(1, std::memory_order_relaxed);
        } else if (protocol == PROTOCOL_UDP) {
            TrafficStats::fwdPopUdp.fetch_add(1, std::memory_order_relaxed);
        } else if (protocol == PROTOCOL_ICMP || protocol == PROTOCOL_ICMPV6) {
            TrafficStats::fwdPopIcmp.fetch_add(1, std::memory_order_relaxed);
        } else {
            TrafficStats::fwdPopOther.fetch_add(1, std::memory_order_relaxed);
        }
    }

    return result;
}

Optional<Task> TaskQueueManager::popResponseTask(std::chrono::milliseconds timeout) {
    return responseQueue_.popWithTimeout(timeout);
}

// 🚀 优雅方案：TCP专用队列pop（根据worker索引）
Optional<Task> TaskQueueManager::popTcpTask(int workerIndex, std::chrono::milliseconds timeout) {
    if (workerIndex < 0 || workerIndex >= static_cast<int>(tcpQueues_.size()) || !tcpQueues_[workerIndex]) {
        TASK_LOGE("⚠️ Invalid TCP worker index: %d (队列数=%zu)", workerIndex, tcpQueues_.size());
        return Optional<Task>();
    }
    
    auto result = tcpQueues_[workerIndex]->popWithTimeout(timeout);
    if (!result.has_value()) {
        return result;
    }

    TrafficStats::fwdPopTotal.fetch_add(1, std::memory_order_relaxed);
    TrafficStats::fwdPopTcp.fetch_add(1, std::memory_order_relaxed);
    return result;
}

// 🚀 优雅方案：根据连接哈希计算TCP worker索引
// 确保同一连接的任务由同一线程处理，避免时序错乱
// 关键：TCP三次握手（SYN -> SYN-ACK -> ACK）必须由同一线程按顺序处理
int TaskQueueManager::getTcpWorkerIndex(const PacketInfo& packetInfo, const sockaddr_in& clientAddr) const {
    // 🚨 防御性检查：确保队列数组已初始化
    if (tcpQueues_.empty()) {
        return 0;
    }
    
    // 使用连接的五元组计算哈希值：源IP:源端口 -> 目标IP:目标端口
    // 这确保了同一连接的所有包（包括SYN、SYN-ACK、ACK）都路由到同一个worker
    // 由于队列是FIFO的，worker线程按顺序处理，保证了TCP三次握手不会被打乱
    std::hash<std::string> hasher;
    std::ostringstream oss;
    oss << packetInfo.sourceIP << ":" << packetInfo.sourcePort << "->"
        << packetInfo.targetIP << ":" << packetInfo.targetPort;
    std::string connectionKey = oss.str();
    
    size_t hash = hasher(connectionKey);
    int workerIndex = static_cast<int>(hash % tcpQueues_.size());
    
    // 🚨 防御性检查：确保索引有效
    if (workerIndex < 0 || workerIndex >= static_cast<int>(tcpQueues_.size())) {
        return 0;
    }
    
    return workerIndex;
}

// 初始化TCP队列数组（实现）
void TaskQueueManager::initializeTcpQueues(int numWorkers) {
    if (numWorkers <= 0 || numWorkers > 16) {
        TASK_LOGE("⚠️ Invalid TCP worker count: %d (must be 1-16)", numWorkers);
        return;
    }
    numTcpWorkers_ = numWorkers;
    tcpQueues_.clear();
    // 🚀 修复：使用emplace_back创建unique_ptr，因为ThreadSafeQueue包含mutex，不可拷贝
    for (int i = 0; i < numWorkers; ++i) {
        tcpQueues_.emplace_back(std::make_unique<ThreadSafeQueue<Task>>(1000));
    }
    TASK_LOGI("✅ TCP队列数组初始化完成: %d个worker，每个队列容量1000", numWorkers);
}

// 🚀 优雅方案：UDP专用队列pop
Optional<Task> TaskQueueManager::popUdpTask(std::chrono::milliseconds timeout) {
    auto result = udpQueue_.popWithTimeout(timeout);
    if (!result.has_value()) {
        return result;
    }

    TrafficStats::fwdPopTotal.fetch_add(1, std::memory_order_relaxed);
    TrafficStats::fwdPopUdp.fetch_add(1, std::memory_order_relaxed);
    return result;
}

void TaskQueueManager::shutdown() {
    TASK_LOGI("🔒 Shutting down task queues...");
    forwardQueue_.shutdown();
    for (auto& q : tcpQueues_) {
        if (q) {
            q->shutdown();
        }
    }
    udpQueue_.shutdown();
    responseQueue_.shutdown();
}

void TaskQueueManager::clear() {
    // 🐛 修复：清空队列并重置shutdown状态，允许队列重新使用
    TASK_LOGI("🧹 Clearing all task queues and resetting shutdown state...");
    forwardQueue_.reset();   // 使用reset而不是clear，重置shutdown标志
    for (auto& q : tcpQueues_) {
        if (q) {
            q->reset();
        }
    }
    udpQueue_.reset();
    responseQueue_.reset();  // 使用reset而不是clear，重置shutdown标志
    TASK_LOGI("✅ Task queues cleared and ready for reuse");
}
