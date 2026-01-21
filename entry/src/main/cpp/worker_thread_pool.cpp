#include "worker_thread_pool.h"
#include "packet_forwarder.h"
#include "udp_retransmit.h"
#include "vpn_server_globals.h"
#include "packet_builder.h"
#include "protocol_handler.h"
#include <hilog/log.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <thread>
#include <chrono>

#define MAKE_FILE_NAME (strrchr(__FILE__, '/') ? (strrchr(__FILE__, '/') + 1) : __FILE__)
#define WORKER_LOGI(fmt, ...) \
  OH_LOG_Print(LOG_APP, LOG_INFO, 0x15b1, "VpnServer", "ZBQ [Worker] [%{public}s:%{public}d] " fmt, MAKE_FILE_NAME, __LINE__, ##__VA_ARGS__)
#define WORKER_LOGE(fmt, ...) \
  OH_LOG_Print(LOG_APP, LOG_ERROR, 0x15b1, "VpnServer", "ZBQ [Worker] [%{public}s:%{public}d] " fmt, MAKE_FILE_NAME, __LINE__, ##__VA_ARGS__)

bool WorkerThreadPool::start(int numForwardWorkers, int numResponseWorkers) {
    WORKER_LOGI("📍 WorkerThreadPool::start() called - numForward=%d, numResponse=%d", 
                numForwardWorkers, numResponseWorkers);
    WORKER_LOGI("📍 Current state: running_=%d, forwardWorkers.size=%zu, responseWorkers.size=%zu",
                running_.load() ? 1 : 0, forwardWorkers_.size(), responseWorkers_.size());
    
    if (running_.load()) {
        WORKER_LOGE("⚠️ Worker thread pool already running - cannot start again!");
        return false;
    }
    
    WORKER_LOGI("📍 Setting running_ to true...");
    running_.store(true);
    
    WORKER_LOGI("📍 Starting %d forward worker threads...", numForwardWorkers);
    // 启动转发工作线程
    for (int i = 0; i < numForwardWorkers; ++i) {
        WORKER_LOGI("📍 Creating forward worker #%d...", i);
        forwardWorkers_.emplace_back([this, i]() {
            WORKER_LOGI("🚀 Forward worker #%{public}d thread STARTED (running_=%d)", i, running_.load() ? 1 : 0);
            forwardWorkerThread();
            WORKER_LOGI("🔚 Forward worker #%{public}d thread STOPPED", i);
        });
    }
    WORKER_LOGI("✅ %d forward workers created", numForwardWorkers);
    
    WORKER_LOGI("📍 Starting %d response worker threads...", numResponseWorkers);
    // 启动响应工作线程
    for (int i = 0; i < numResponseWorkers; ++i) {
        WORKER_LOGI("📍 Creating response worker #%d...", i);
        responseWorkers_.emplace_back([this, i]() {
            WORKER_LOGI("🚀 Response worker #%{public}d thread STARTED (running_=%d)", i, running_.load() ? 1 : 0);
            responseWorkerThread();
            WORKER_LOGI("🔚 Response worker #%{public}d thread STOPPED", i);
        });
    }
    WORKER_LOGI("✅ %d response workers created", numResponseWorkers);
    
    WORKER_LOGI("✅✅✅ Worker thread pool FULLY started: %{public}d forward workers, %{public}d response workers",
                numForwardWorkers, numResponseWorkers);
    
    // 给线程一点时间启动
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    
    WORKER_LOGI("📍 Final state: running_=%d", running_.load() ? 1 : 0);
    
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
    int iteration = 0;
    int processedTasks = 0;

    WORKER_LOGI("🚀🚀🚀 Forward worker LOOP STARTED - running_=%d", running_.load() ? 1 : 0);

    while (running_.load()) {
        iteration++;
        
        // 每1000次迭代输出一次心跳
        if (iteration % 1000 == 0) {
            WORKER_LOGI("💓 Forward worker heartbeat: iteration=%d, processed=%d, running_=%d", 
                        iteration, processedTasks, running_.load() ? 1 : 0);
        }

        // 从队列获取任务（100ms超时）
        auto taskOpt = taskQueue.popForwardTask(std::chrono::milliseconds(100));

        if (!taskOpt.has_value()) {
            continue;  // 超时或队列关闭
        }

        // 🐛 修复：复制Task对象而不是引用，避免生命周期问题
        Task task = taskOpt.value();
        if (task.type != TaskType::FORWARD_REQUEST) {
            WORKER_LOGE("❌ Invalid task type in forward queue");
            continue;
        }

        ForwardTask& fwdTask = task.forwardTask;
        processedTasks++;

        // 记录前几个任务和每100个任务
        if (processedTasks <= 10 || processedTasks % 100 == 0) {
            WORKER_LOGI("📊 Forward worker processing task #%{public}d: %s -> %s:%d", 
                        processedTasks,
                        ProtocolHandler::GetProtocolName(fwdTask.packetInfo.protocol).c_str(),
                        fwdTask.packetInfo.targetIP.c_str(), 
                        fwdTask.packetInfo.targetPort);
        }

        // 转发数据包
        int sockFd = PacketForwarder::ForwardPacket(
            fwdTask.data,
            fwdTask.dataSize,
            fwdTask.packetInfo,
            fwdTask.clientAddr
        );

        if (sockFd >= 0) {
            forwardTasksProcessed_.fetch_add(1);

            // UDP包记录到重传管理器（只对DNS查询）
            if (fwdTask.packetInfo.protocol == PROTOCOL_UDP &&
                fwdTask.packetInfo.targetPort == 53) {

                uint16_t packetId = UdpRetransmitManager::generatePacketId();

                // 提取payload
                const uint8_t* payload = nullptr;
                int payloadSize = 0;
                if (PacketBuilder::ExtractPayload(fwdTask.data, fwdTask.dataSize,
                                                 fwdTask.packetInfo, &payload, &payloadSize)) {
                    if (payload && payloadSize > 0) {
                        sockaddr_in targetAddr{};
                        targetAddr.sin_family = AF_INET;
                        targetAddr.sin_port = htons(fwdTask.packetInfo.targetPort);

                        if (inet_pton(AF_INET, fwdTask.packetInfo.targetIP.c_str(), &targetAddr.sin_addr) > 0) {
                            UdpRetransmitManager::getInstance().recordSentPacket(
                                packetId, payload, payloadSize, targetAddr, sockFd);
                        }
                    }
                }
            }
        } else {
            forwardTasksFailed_.fetch_add(1);
            WORKER_LOGE("❌ Forward task #%{public}d FAILED", processedTasks);
        }
    }

    WORKER_LOGI("🔚🔚🔚 Forward worker LOOP STOPPED (processed %{public}d tasks, running_=%d)", 
                processedTasks, running_.load() ? 1 : 0);
}

void WorkerThreadPool::responseWorkerThread() {
    auto& taskQueue = TaskQueueManager::getInstance();
    int processedTasks = 0;

    WORKER_LOGI("🚀 Response worker started");

    while (running_.load()) {
        // 从队列获取任务（100ms超时）
        auto taskOpt = taskQueue.popResponseTask(std::chrono::milliseconds(100));

        if (!taskOpt.has_value()) {
            continue;  // 超时或队列关闭
        }

        // 🐛 修复：复制Task对象而不是引用，避免生命周期问题
        Task task = taskOpt.value();
        if (task.type != TaskType::SEND_RESPONSE) {
            WORKER_LOGE("❌ Invalid task type in response queue");
            continue;
        }

        ResponseTask& respTask = task.responseTask;
        processedTasks++;

        // 只记录重要的响应事件，避免日志过多
        if (processedTasks % 100 == 0) {
            WORKER_LOGI("📊 Response worker processed %{public}d tasks", processedTasks);
        }

        // 🐛 修复：保存g_sockFd副本，避免并发修改导致的问题
        int tunnelFd = g_sockFd;

        // 发送响应给客户端
        if (tunnelFd >= 0 && g_running.load()) {
            ssize_t sent = sendto(tunnelFd, respTask.data, respTask.dataSize, 0,
                                 (struct sockaddr*)&respTask.clientAddr,
                                 sizeof(respTask.clientAddr));

            if (sent > 0) {
                responseTasksProcessed_.fetch_add(1);
                WORKER_LOGI("✅ Response sent successfully: %{public}zd bytes", sent);

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
            WORKER_LOGE("❌ Cannot send response: tunnelFd=%{public}d, running=%{public}d",
                       tunnelFd, g_running.load());
        }
    }

    WORKER_LOGI("🔚 Response worker exiting main loop");
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
