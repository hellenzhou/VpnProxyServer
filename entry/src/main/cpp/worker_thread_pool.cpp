#include "worker_thread_pool.h"
#include "packet_forwarder.h"
#include "udp_retransmit.h"
#include "vpn_server_globals.h"
#include <hilog/log.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define MAKE_FILE_NAME (strrchr(__FILE__, '/') ? (strrchr(__FILE__, '/') + 1) : __FILE__)
#define WORKER_LOGI(fmt, ...) \
  OH_LOG_Print(LOG_APP, LOG_INFO, 0x15b1, "WorkerPool", "[%{public}s:%{public}d] " fmt, MAKE_FILE_NAME, __LINE__, ##__VA_ARGS__)
#define WORKER_LOGE(fmt, ...) \
  OH_LOG_Print(LOG_APP, LOG_ERROR, 0x15b1, "WorkerPool", "[%{public}s:%{public}d] " fmt, MAKE_FILE_NAME, __LINE__, ##__VA_ARGS__)

bool WorkerThreadPool::start(int numForwardWorkers, int numResponseWorkers) {
    if (running_.load()) {
        WORKER_LOGI("⚠️ Worker thread pool already running");
        return false;
    }
    
    running_.store(true);
    
    // 启动转发工作线程
    for (int i = 0; i < numForwardWorkers; ++i) {
        forwardWorkers_.emplace_back([this, i]() {
            WORKER_LOGI("🚀 Forward worker #%{public}d started", i);
            forwardWorkerThread();
            WORKER_LOGI("🔚 Forward worker #%{public}d stopped", i);
        });
    }
    
    // 启动响应工作线程
    for (int i = 0; i < numResponseWorkers; ++i) {
        responseWorkers_.emplace_back([this, i]() {
            WORKER_LOGI("🚀 Response worker #%{public}d started", i);
            responseWorkerThread();
            WORKER_LOGI("🔚 Response worker #%{public}d stopped", i);
        });
    }
    
    WORKER_LOGI("✅ Worker thread pool started: %{public}d forward workers, %{public}d response workers",
                numForwardWorkers, numResponseWorkers);
    
    return true;
}

void WorkerThreadPool::stop() {
    if (!running_.load()) {
        return;
    }
    
    WORKER_LOGI("🛑 Stopping worker thread pool...");
    running_.store(false);
    
    // 关闭任务队列，唤醒所有等待的线程
    TaskQueueManager::getInstance().shutdown();
    
    // 等待所有转发工作线程结束
    for (auto& worker : forwardWorkers_) {
        if (worker.joinable()) {
            worker.join();
        }
    }
    forwardWorkers_.clear();
    
    // 等待所有响应工作线程结束
    for (auto& worker : responseWorkers_) {
        if (worker.joinable()) {
            worker.join();
        }
    }
    responseWorkers_.clear();
    
    WORKER_LOGI("✅ Worker thread pool stopped");
}

void WorkerThreadPool::forwardWorkerThread() {
    auto& taskQueue = TaskQueueManager::getInstance();
    
    while (running_.load()) {
        // 从队列获取任务（100ms超时）
        auto taskOpt = taskQueue.popForwardTask(std::chrono::milliseconds(100));
        
        if (!taskOpt.has_value()) {
            continue;  // 超时或队列关闭
        }
        
        Task& task = taskOpt.value();
        if (task.type != TaskType::FORWARD_REQUEST) {
            WORKER_LOGE("❌ Invalid task type in forward queue");
            continue;
        }
        
        ForwardTask& fwdTask = task.forwardTask;
        
        // 转发数据包
        int sockFd = PacketForwarder::ForwardPacket(
            fwdTask.data,
            fwdTask.dataSize,
            fwdTask.packetInfo,
            fwdTask.clientAddr
        );
        
        if (sockFd >= 0) {
            forwardTasksProcessed_.fetch_add(1);
            
            // UDP包记录到重传管理器
            if (fwdTask.packetInfo.protocol == PROTOCOL_UDP && 
                fwdTask.packetInfo.targetPort == 53) {  // 只对DNS查询启用重传
                
                uint16_t packetId = UdpRetransmitManager::generatePacketId();
                
                // 提取payload
                const uint8_t* payload = nullptr;
                int payloadSize = 0;
                // 🐛 修复：添加错误处理，ExtractPayload可能失败
                if (PacketBuilder::ExtractPayload(fwdTask.data, fwdTask.dataSize, 
                                                 fwdTask.packetInfo, &payload, &payloadSize)) {
                    if (payload && payloadSize > 0) {
                        sockaddr_in targetAddr{};
                        targetAddr.sin_family = AF_INET;
                        targetAddr.sin_port = htons(fwdTask.packetInfo.targetPort);
                        
                        if (inet_pton(AF_INET, fwdTask.packetInfo.targetIP.c_str(), &targetAddr.sin_addr) > 0) {
                            UdpRetransmitManager::getInstance().recordSentPacket(
                                packetId, payload, payloadSize, targetAddr, sockFd);
                        } else {
                            WORKER_LOGE("❌ Invalid IP address for retransmit: %{public}s", 
                                       fwdTask.packetInfo.targetIP.c_str());
                        }
                    }
                } else {
                    WORKER_LOGE("❌ Failed to extract payload for retransmit");
                }
            }
        } else {
            forwardTasksFailed_.fetch_add(1);
        }
    }
}

void WorkerThreadPool::responseWorkerThread() {
    auto& taskQueue = TaskQueueManager::getInstance();
    
    while (running_.load()) {
        // 从队列获取任务（100ms超时）
        auto taskOpt = taskQueue.popResponseTask(std::chrono::milliseconds(100));
        
        if (!taskOpt.has_value()) {
            continue;  // 超时或队列关闭
        }
        
        Task& task = taskOpt.value();
        if (task.type != TaskType::SEND_RESPONSE) {
            WORKER_LOGE("❌ Invalid task type in response queue");
            continue;
        }
        
        ResponseTask& respTask = task.responseTask;
        
        // 🐛 修复：保存g_sockFd副本，避免并发修改导致的问题
        int tunnelFd = g_sockFd;
        
        // 发送响应给客户端
        if (tunnelFd >= 0 && g_running.load()) {
            ssize_t sent = sendto(tunnelFd, respTask.data, respTask.dataSize, 0,
                                 (struct sockaddr*)&respTask.clientAddr,
                                 sizeof(respTask.clientAddr));
            
            if (sent > 0) {
                responseTasksProcessed_.fetch_add(1);
                
                // 计算延迟
                auto now = std::chrono::steady_clock::now();
                auto latency = std::chrono::duration_cast<std::chrono::milliseconds>(
                    now - respTask.timestamp).count();
                
                if (latency > 100) {
                    WORKER_LOGI("⚠️ High response latency: %{public}lldms", 
                               static_cast<long long>(latency));
                }
            } else {
                responseTasksFailed_.fetch_add(1);
                WORKER_LOGE("❌ Failed to send response: errno=%{public}d (%{public}s)",
                           errno, strerror(errno));
            }
        } else {
            responseTasksFailed_.fetch_add(1);
        }
    }
}

WorkerThreadPool::Stats WorkerThreadPool::getStats() const {
    return {
        forwardTasksProcessed_.load(),
        responseTasksProcessed_.load(),
        forwardTasksFailed_.load(),
        responseTasksFailed_.load()
    };
}

// ========== ResponseBatcher 实现 ==========

void ResponseBatcher::addResponse(const uint8_t* data, int dataSize,
                                  const sockaddr_in& clientAddr,
                                  int forwardSocket,
                                  uint8_t protocol) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    ResponseTask task;
    if (dataSize > 0 && dataSize <= 4096) {
        std::memcpy(task.data, data, dataSize);
        task.dataSize = dataSize;
        task.clientAddr = clientAddr;
        task.forwardSocket = forwardSocket;
        task.protocol = protocol;
        task.timestamp = std::chrono::steady_clock::now();
        
        pendingResponses_.push_back(task);
    }
}

int ResponseBatcher::flush() {
    std::vector<ResponseTask> toSend;
    
    {
        std::lock_guard<std::mutex> lock(mutex_);
        toSend.swap(pendingResponses_);
    }
    
    if (toSend.empty()) {
        return 0;
    }
    
    int sent = 0;
    for (const auto& task : toSend) {
        if (g_sockFd >= 0) {
            ssize_t n = sendto(g_sockFd, task.data, task.dataSize, 0,
                              (struct sockaddr*)&task.clientAddr,
                              sizeof(task.clientAddr));
            if (n > 0) {
                sent++;
            }
        }
    }
    
    totalSent_.fetch_add(sent);
    totalBatches_.fetch_add(1);
    
    return sent;
}
