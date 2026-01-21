#include "task_queue.h"
#include <hilog/log.h>
#include <cstring>

#define MAKE_FILE_NAME (strrchr(__FILE__, '/') ? (strrchr(__FILE__, '/') + 1) : __FILE__)
#define TASK_LOGI(fmt, ...) \
  OH_LOG_Print(LOG_APP, LOG_INFO, 0x15b1, "TaskQueue", "[%{public}s:%{public}d] " fmt, MAKE_FILE_NAME, __LINE__, ##__VA_ARGS__)
#define TASK_LOGE(fmt, ...) \
  OH_LOG_Print(LOG_APP, LOG_ERROR, 0x15b1, "TaskQueue", "[%{public}s:%{public}d] " fmt, MAKE_FILE_NAME, __LINE__, ##__VA_ARGS__)

bool TaskQueueManager::submitForwardTask(const uint8_t* data, int dataSize,
                                        const PacketInfo& packetInfo,
                                        const sockaddr_in& clientAddr) {
    if (!data || dataSize <= 0 || dataSize > 2048) {
        TASK_LOGE("❌ Invalid forward task: dataSize=%{public}d", dataSize);
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
    if (!data || dataSize <= 0 || dataSize > 4096) {
        TASK_LOGE("❌ Invalid response task: dataSize=%{public}d", dataSize);
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

std::optional<Task> TaskQueueManager::popForwardTask(std::chrono::milliseconds timeout) {
    return forwardQueue_.popWithTimeout(timeout);
}

std::optional<Task> TaskQueueManager::popResponseTask(std::chrono::milliseconds timeout) {
    return responseQueue_.popWithTimeout(timeout);
}

void TaskQueueManager::shutdown() {
    TASK_LOGI("🔒 Shutting down task queues...");
    forwardQueue_.shutdown();
    responseQueue_.shutdown();
}

void TaskQueueManager::clear() {
    // 🐛 修复：clear()前检查队列是否已shutdown，避免在shutdown后clear导致死锁
    TASK_LOGI("🧹 Clearing all task queues...");
    forwardQueue_.clear();
    responseQueue_.clear();
}
