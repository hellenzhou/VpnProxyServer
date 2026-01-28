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
    static int popCount = 0;
    static int lastLogCount = 0;
    static int tcpTaskCount = 0;
    static int udpTaskCount = 0;
    static int timeoutCount = 0;
    static int emptyCount = 0;
    static int consecutiveTimeouts = 0;  // 连续超时次数
    static int consecutiveTimeoutsWithData = 0;  // 连续超时但队列有数据
    static int callCount = 0;  // 调用次数
    
    callCount++;
    
    // 🔍 诊断：在pop之前检查队列状态
    auto queueStateBefore = forwardQueue_.getState();
    size_t queueSizeBefore = queueStateBefore.size;
    bool queueEmptyBefore = queueStateBefore.empty;
    bool queueShutdownBefore = queueStateBefore.shutdown;
    
    // 🚨 强制记录：每次调用都记录（前50次或队列有数据时，避免日志过多）
    if (callCount <= 50 || queueSizeBefore > 0) {
        TASK_LOGI("🔍 [Queue] popForwardTask调用 #%d: 队列大小=%zu, 空=%d, shutdown=%d, 超时=%lldms", 
                 callCount, queueSizeBefore, queueEmptyBefore ? 1 : 0, queueShutdownBefore ? 1 : 0, (long long)timeout.count());
    }
    
    // 🚨 关键诊断：如果队列已关闭，记录错误
    if (queueShutdownBefore) {
        TASK_LOGE("🚨 [Queue] ⚠️⚠️⚠️ 队列已关闭但仍在尝试pop! shutdown=%d ⚠️⚠️⚠️", queueShutdownBefore ? 1 : 0);
    }
    
    // 🚨 关键诊断：如果size()和empty()不一致，记录错误
    if ((queueSizeBefore > 0 && queueEmptyBefore) || (queueSizeBefore == 0 && !queueEmptyBefore)) {
        TASK_LOGE("🚨 [Queue] ⚠️⚠️⚠️ 队列状态不一致: size()=%zu, empty()=%d ⚠️⚠️⚠️", queueSizeBefore, queueEmptyBefore ? 1 : 0);
    }
    
    // 🚨 关键诊断：如果队列有数据，记录详细信息
    if (queueSizeBefore > 0) {
        static int lastQueueSize = 0;
        static int queueCheckCount = 0;
        queueCheckCount++;
        
        // 🚨 强制记录：队列有数据时总是记录
        TASK_LOGE("🚨 [Queue] ⚠️⚠️⚠️ 队列有数据但popForwardTask被调用: 队列大小=%zu, 空=%d, shutdown=%d, 调用次数=%d, 已弹出=%d ⚠️⚠️⚠️", 
                 queueSizeBefore, queueEmptyBefore ? 1 : 0, queueShutdownBefore ? 1 : 0, callCount, popCount);
        
        if (queueSizeBefore > 20) {
            TASK_LOGE("⚠️ [Queue] 队列积压严重: 当前队列大小=%zu (可能worker线程被阻塞)", queueSizeBefore);
        }
        
        if (queueSizeBefore > lastQueueSize) {
            // 队列在增长
            TASK_LOGE("🚨 [Queue] 队列持续增长: 当前=%zu, 上次=%d (可能有任务积压)", 
                     queueSizeBefore, lastQueueSize);
        }
        lastQueueSize = queueSizeBefore;
    }
    
    // 🚨 关键诊断：记录popWithTimeout调用（仅在队列有数据或前50次调用时记录，避免日志过多）
    if (queueSizeBefore > 0 || callCount <= 50) {
        TASK_LOGI("🔍 [Queue] 准备调用popWithTimeout: 队列大小=%zu, 空=%d", queueSizeBefore, queueEmptyBefore ? 1 : 0);
    }
    auto result = forwardQueue_.popWithTimeout(timeout);
    if (queueSizeBefore > 0 || callCount <= 50) {
        TASK_LOGI("🔍 [Queue] popWithTimeout返回: has_value=%d", result.has_value() ? 1 : 0);
    }
    
    // 🚨 关键诊断：记录popWithTimeout的结果
    if (!result.has_value()) {
        timeoutCount++;
        consecutiveTimeouts++;
        auto queueStateAfter = forwardQueue_.getState();
        size_t queueSizeAfter = queueStateAfter.size;
        bool queueEmptyAfter = queueStateAfter.empty;
        bool queueShutdownAfter = queueStateAfter.shutdown;
        
        // 🚨 关键诊断：如果队列已关闭，记录
        if (queueShutdownAfter) {
            TASK_LOGE("🚨 [Queue] popWithTimeout返回空值: 队列已关闭 (shutdown=%d)", queueShutdownAfter ? 1 : 0);
        }
        
        // 如果队列有数据但返回空值，说明可能超时或队列被锁定
        if (queueSizeAfter > 0 || !queueEmptyAfter) {
            consecutiveTimeoutsWithData++;
            // 🚨 关键：如果连续多次超时但队列有数据，立即记录错误
            if (consecutiveTimeoutsWithData >= 3 || queueSizeAfter > 20) {
                TASK_LOGE("🚨 [Queue] ⚠️⚠️⚠️ popWithTimeout返回空值但队列有%zu个任务 (超时次数=%d, 连续超时=%d, 连续超时(有数据)=%d, 队列空=%d, shutdown=%d) ⚠️⚠️⚠️", 
                         queueSizeAfter, timeoutCount, consecutiveTimeouts, consecutiveTimeoutsWithData, queueEmptyAfter ? 1 : 0, queueShutdownAfter ? 1 : 0);
                TASK_LOGE("🚨 [Queue] 这可能是ThreadSafeQueue的bug：队列有数据但popWithTimeout返回空值！");
                TASK_LOGE("🚨 [Queue] 队列状态: 入队前(size=%zu, empty=%d, shutdown=%d) -> 出队后(size=%zu, empty=%d, shutdown=%d)", 
                         queueSizeBefore, queueEmptyBefore ? 1 : 0, queueShutdownBefore ? 1 : 0,
                         queueSizeAfter, queueEmptyAfter ? 1 : 0, queueShutdownAfter ? 1 : 0);
            } else if (timeoutCount % 10 == 0) {
                TASK_LOGE("🚨 [Queue] popWithTimeout返回空值但队列有%zu个任务 (超时次数=%d, shutdown=%d, 可能队列被锁定或超时)", 
                         queueSizeAfter, timeoutCount, queueShutdownAfter ? 1 : 0);
            }
        } else {
            consecutiveTimeoutsWithData = 0;  // 重置连续超时(有数据)计数
            emptyCount++;
            if (emptyCount % 100 == 0) {
                TASK_LOGI("🔍 [Queue] popWithTimeout返回空值: 队列为空 (空次数=%d)", emptyCount);
            }
        }
    } else {
        // 成功弹出，重置连续超时计数
        consecutiveTimeouts = 0;
        consecutiveTimeoutsWithData = 0;
    }
    
    if (result.has_value()) {
        popCount++;
        TrafficStats::fwdPopTotal.fetch_add(1, std::memory_order_relaxed);

        // 🚨 强制记录：TCP任务从队列弹出（用于诊断TCP任务是否被正确取出）
        Task& task = result.value();
        if (task.type == TaskType::FORWARD_REQUEST) {
            const char* protocolName = "UNKNOWN";
            uint8_t protocol = task.forwardTask.packetInfo.protocol;
            if (protocol == PROTOCOL_TCP) {
                protocolName = "TCP";
                tcpTaskCount++;
                TrafficStats::fwdPopTcp.fetch_add(1, std::memory_order_relaxed);
                // 🚨 关键诊断：TCP任务被弹出，立即记录
                TASK_LOGI("🚀 [Queue] ✅ TCP任务弹出成功 #%d: 源=%s:%d -> 目标=%s:%d, 大小=%d, 队列剩余=%zu", 
                         popCount,
                         task.forwardTask.packetInfo.sourceIP.c_str(), 
                         task.forwardTask.packetInfo.sourcePort,
                         task.forwardTask.packetInfo.targetIP.c_str(), 
                         task.forwardTask.packetInfo.targetPort,
                         task.forwardTask.dataSize,
                         forwardQueue_.size());
            } else if (protocol == PROTOCOL_UDP) {
                protocolName = "UDP";
                udpTaskCount++;
                TrafficStats::fwdPopUdp.fetch_add(1, std::memory_order_relaxed);
            } else if (protocol == PROTOCOL_ICMP) {
                protocolName = "ICMP";
                TrafficStats::fwdPopIcmp.fetch_add(1, std::memory_order_relaxed);
            } else if (protocol == PROTOCOL_ICMPV6) {
                protocolName = "ICMPv6";
                TrafficStats::fwdPopIcmp.fetch_add(1, std::memory_order_relaxed);
            } else {
                TrafficStats::fwdPopOther.fetch_add(1, std::memory_order_relaxed);
            }
            
            // TCP任务强制记录，其他任务按策略记录
            bool isTcp = (protocol == PROTOCOL_TCP);
            bool shouldLog = isTcp;  // TCP任务总是记录
            
            // 🔍 诊断：每处理100个任务，统计TCP/UDP比例
            if ((tcpTaskCount + udpTaskCount) % 100 == 0 && (tcpTaskCount + udpTaskCount) > 0) {
                TASK_LOGI("📊 [Queue] 任务统计: TCP=%d, UDP=%d, 总计=%d (TCP占比=%.1f%%)", 
                         tcpTaskCount, udpTaskCount, tcpTaskCount + udpTaskCount,
                         (tcpTaskCount * 100.0) / (tcpTaskCount + udpTaskCount));
            }
            
            if (!isTcp) {
                // 更前断点：仅前20次弹出记录，避免日志爆炸
                if (popCount <= 20) {
                    shouldLog = true;
                } else {
                    // 🔧 智能日志策略：
                    // 1. 前10次：每次都记录（启动诊断）
                    // 2. 10-100次：每10次记录一次（早期监控）
                    // 3. 100-1000次：每100次记录一次（正常运行）
                    // 4. 1000次以后：每1000次记录一次（稳定状态）
                    if (popCount <= 10) {
                        shouldLog = true;  // 前10次全记录
                    } else if (popCount <= 100) {
                        shouldLog = (popCount % 10 == 0);  // 每10次
                    } else if (popCount <= 1000) {
                        shouldLog = (popCount % 100 == 0);  // 每100次
                    } else {
                        shouldLog = (popCount % 1000 == 0);  // 每1000次
                    }
                }
            }
            
            if (shouldLog && !isTcp) {
                // TCP任务已经在上面记录了，这里只记录非TCP任务
                TASK_LOGI("📤 popForwardTask #%d (+%d since last log), 协议=%s, queue size: %zu", 
                          popCount, popCount - lastLogCount, protocolName, forwardQueue_.size());
                lastLogCount = popCount;
            }
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
