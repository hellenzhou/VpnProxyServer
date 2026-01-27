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
  OH_LOG_Print(LOG_APP, LOG_INFO, 0x15b1, "VpnServer", "ZHOUB [Worker] [%{public}s:%{public}d] " fmt, MAKE_FILE_NAME, __LINE__, ##__VA_ARGS__)
#define WORKER_LOGE(fmt, ...) \
  OH_LOG_Print(LOG_APP, LOG_ERROR, 0x15b1, "VpnServer", "ZHOUB [Worker] [%{public}s:%{public}d] " fmt, MAKE_FILE_NAME, __LINE__, ##__VA_ARGS__)

bool WorkerThreadPool::start(int numForwardWorkers, int numResponseWorkers) {
    if (running_.load()) {
        WORKER_LOGE("Worker thread pool already running");
        return false;
    }
    
    running_.store(true);
    
    // 启动转发工作线程
    for (int i = 0; i < numForwardWorkers; ++i) {
        try {
            forwardWorkers_.emplace_back([this]() {
                forwardWorkerThread();
            });
        } catch (const std::exception& e) {
            WORKER_LOGE("Failed to create forward worker #%d: %s", i, e.what());
            return false;
        }
    }
    
    // 启动响应工作线程
    for (int i = 0; i < numResponseWorkers; ++i) {
        try {
            responseWorkers_.emplace_back([this]() {
                responseWorkerThread();
            });
        } catch (const std::exception& e) {
            WORKER_LOGE("Failed to create response worker #%d: %s", i, e.what());
            return false;
        }
    }
    
    WORKER_LOGI("Worker thread pool started: %d forward, %d response", numForwardWorkers, numResponseWorkers);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
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
    int processedTasks = 0;

    while (running_.load()) {
        auto taskOpt = taskQueue.popForwardTask(std::chrono::milliseconds(100));

        if (!taskOpt.has_value()) {
            continue;  // 超时或队列关闭
        }

        Task task = taskOpt.value();
        if (task.type != TaskType::FORWARD_REQUEST) {
            WORKER_LOGE("Invalid task type in forward queue");
            continue;
        }

        ForwardTask& fwdTask = task.forwardTask;
        processedTasks++;

        // 转发数据包
        int sockFd = PacketForwarder::ForwardPacket(
            fwdTask.data,
            fwdTask.dataSize,
            fwdTask.packetInfo,
            fwdTask.clientAddr,
            fwdTask.tunnelFd
        );

        if (sockFd >= 0) {
            forwardTasksProcessed_.fetch_add(1);

            // UDP包记录到重传管理器（只对IPv4 DNS查询）
            if (fwdTask.packetInfo.protocol == PROTOCOL_UDP &&
                fwdTask.packetInfo.targetPort == 53 &&
                fwdTask.packetInfo.addressFamily == AF_INET) {

                uint16_t packetId = UdpRetransmitManager::generatePacketId();

                // 提取payload
                const uint8_t* payload = nullptr;
                int payloadSize = 0;
                if (PacketBuilder::ExtractPayload(fwdTask.data, fwdTask.dataSize,
                                                 fwdTask.packetInfo, &payload, &payloadSize)) {
                    if (payload && payloadSize > 0) {
                        sockaddr_in targetAddr{};
                        targetAddr.sin_family = AF_INET;
                        // ✅ 修复：targetPort已经是主机字节序，不需要再htons
                        targetAddr.sin_port = fwdTask.packetInfo.targetPort;

                        if (inet_pton(AF_INET, fwdTask.packetInfo.targetIP.c_str(), &targetAddr.sin_addr) > 0) {
                            UdpRetransmitManager::getInstance().recordSentPacket(
                                packetId, payload, payloadSize, targetAddr, fwdTask.clientAddr, sockFd);
                        }
                    }
                }
            }
        } else {
            forwardTasksFailed_.fetch_add(1);
        }
    }

    WORKER_LOGI("Forward worker stopped, processed %d tasks", processedTasks);
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


        // 🐛 修复：保存g_sockFd副本，避免并发修改导致的问题
        int tunnelFd = g_sockFd.load();

        // ✅ 关键修复：直接发送完整IP包，不要提取payload！
        // packet_forwarder.cpp已经用BuildResponsePacket构建了完整IP包
        // VPN客户端期望收到完整的IP包（包含IP头和传输层头部）
        const uint8_t* sendData = respTask.data;
        int sendSize = respTask.dataSize;
        
        if (respTask.dataSize < 20 || (respTask.data[0] >> 4) != 4) {
            WORKER_LOGE("响应数据不是有效的IP包");
        }

        // 发送完整IP包给客户端
        if (tunnelFd >= 0 && g_running.load()) {
            char clientIP[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &respTask.clientAddr.sin_addr, clientIP, sizeof(clientIP));
            
            ssize_t sent = sendto(tunnelFd, sendData, sendSize, 0,
                                 (struct sockaddr*)&respTask.clientAddr,
                                 sizeof(respTask.clientAddr));

            if (sent > 0) {
                responseTasksProcessed_.fetch_add(1);
            } else {
                responseTasksFailed_.fetch_add(1);
                WORKER_LOGE("Failed to send response: errno=%d (%s)", errno, strerror(errno));
            }
        } else {
            responseTasksFailed_.fetch_add(1);
            WORKER_LOGE("Cannot send response: tunnelFd=%d, running=%d", tunnelFd, g_running.load());
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
    int sockFd = g_sockFd.load();  // 🔧 使用atomic的load()方法
    for (const auto& task : toSend) {
        if (sockFd >= 0) {
            ssize_t n = sendto(sockFd, task.data, task.dataSize, 0,
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
