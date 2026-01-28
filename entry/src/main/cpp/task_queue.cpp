#include "task_queue.h"
#include <hilog/log.h>
#include <cstring>
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

    bool pushResult = forwardQueue_.tryPush(task);
    
    // 🔍 诊断：记录入队后的队列状态
    size_t queueSizeAfter = forwardQueue_.size();
    bool queueEmptyAfter = isForwardQueueEmpty();
    
    if (!pushResult) {
        TASK_LOGE("⚠️ Forward queue full, dropping packet: 队列大小=%zu", queueSizeBefore);
        return false;
    }

    // 🚨 关键诊断：如果入队后队列状态异常，记录错误
    if (isTcp) {
        TASK_LOGI("✅ [Queue] TCP任务入队成功: 入队后队列大小=%zu, 空=%d (入队前: 大小=%zu, 空=%d)",
                 queueSizeAfter, queueEmptyAfter ? 1 : 0, queueSizeBefore, queueEmptyBefore ? 1 : 0);
        
        // 检查状态一致性
        if ((queueSizeAfter == queueSizeBefore && queueSizeBefore > 0) || 
            (queueSizeAfter != queueSizeBefore + 1)) {
            TASK_LOGE("🚨 [Queue] ⚠️⚠️⚠️ TCP任务入队后队列状态异常: 入队前大小=%zu, 入队后大小=%zu ⚠️⚠️⚠️", 
                     queueSizeBefore, queueSizeAfter);
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

void TaskQueueManager::shutdown() {
    TASK_LOGI("🔒 Shutting down task queues...");
    forwardQueue_.shutdown();
    responseQueue_.shutdown();
}

void TaskQueueManager::clear() {
    // 🐛 修复：清空队列并重置shutdown状态，允许队列重新使用
    TASK_LOGI("🧹 Clearing all task queues and resetting shutdown state...");
    forwardQueue_.reset();   // 使用reset而不是clear，重置shutdown标志
    responseQueue_.reset();  // 使用reset而不是clear，重置shutdown标志
    TASK_LOGI("✅ Task queues cleared and ready for reuse");
}
