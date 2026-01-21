#include "task_queue.h"
#include <hilog/log.h>
#include <cstring>

// 🔧 调试开关：设置为 true 启用详细日志（每个任务都记录）
// 生产环境请设置为 false 避免日志爆炸
#define ENABLE_VERBOSE_TASK_LOG false

#define MAKE_FILE_NAME (strrchr(__FILE__, '/') ? (strrchr(__FILE__, '/') + 1) : __FILE__)
#define TASK_LOGI(fmt, ...) \
  OH_LOG_Print(LOG_APP, LOG_INFO, 0x15b1, "VpnServer", "ZBQ [Queue] [%{public}s:%{public}d] " fmt, MAKE_FILE_NAME, __LINE__, ##__VA_ARGS__)
#define TASK_LOGE(fmt, ...) \
  OH_LOG_Print(LOG_APP, LOG_ERROR, 0x15b1, "VpnServer", "ZBQ [Queue] [%{public}s:%{public}d] " fmt, MAKE_FILE_NAME, __LINE__, ##__VA_ARGS__)
#define TASK_LOGV(fmt, ...) \
  if (ENABLE_VERBOSE_TASK_LOG) { \
    OH_LOG_Print(LOG_APP, LOG_INFO, 0x15b1, "VpnServer", "ZBQ [Queue] [%{public}s:%{public}d] " fmt, MAKE_FILE_NAME, __LINE__, ##__VA_ARGS__); \
  }

bool TaskQueueManager::submitForwardTask(const uint8_t* data, int dataSize,
                                        const PacketInfo& packetInfo,
                                        const sockaddr_in& clientAddr) {
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

    if (!forwardQueue_.tryPush(task)) {
        TASK_LOGE("⚠️ Forward queue full, dropping packet");
        return false;
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

    if (!responseQueue_.tryPush(task)) {
        TASK_LOGE("⚠️ Response queue full, dropping response");
        return false;
    }

    return true;
}

Optional<Task> TaskQueueManager::popForwardTask(std::chrono::milliseconds timeout) {
    static int popCount = 0;
    static int lastLogCount = 0;
    auto result = forwardQueue_.popWithTimeout(timeout);
    
    if (result.has_value()) {
        popCount++;
        
        // 🔧 详细日志模式：每个任务都记录（调试用）
        TASK_LOGV("📤 [VERBOSE] popForwardTask #%d, queue: %zu", popCount, forwardQueue_.size());
        
        // 🔧 智能日志策略：
        // 1. 前10次：每次都记录（启动诊断）
        // 2. 10-100次：每10次记录一次（早期监控）
        // 3. 100-1000次：每100次记录一次（正常运行）
        // 4. 1000次以后：每1000次记录一次（稳定状态）
        bool shouldLog = false;
        
        if (popCount <= 10) {
            shouldLog = true;  // 前10次全记录
        } else if (popCount <= 100) {
            shouldLog = (popCount % 10 == 0);  // 每10次
        } else if (popCount <= 1000) {
            shouldLog = (popCount % 100 == 0);  // 每100次
        } else {
            shouldLog = (popCount % 1000 == 0);  // 每1000次
        }
        
        if (shouldLog) {
            TASK_LOGI("📤 popForwardTask #%d (+%d since last log), queue size: %zu", 
                      popCount, popCount - lastLogCount, forwardQueue_.size());
            lastLogCount = popCount;
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
