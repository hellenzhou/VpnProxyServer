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
            // 每10秒输出一次等待状态
            if (iteration % 100000 == 0) {  // 1000次/秒 * 100秒 = 100000
                WORKER_LOGI("⏳ Forward worker waiting for tasks... (iteration=%d, processed=%d)",
                           iteration, processedTasks);
            }
            continue;  // 超时或队列关闭
        }

        Task& taskRef = taskOpt.value();
        WORKER_LOGI("📨 Forward worker received task: type=%d, iteration=%d",
                   static_cast<int>(taskRef.type), iteration);

        // 🐛 修复：复制Task对象而不是引用，避免生命周期问题
        Task task = taskOpt.value();
        if (task.type != TaskType::FORWARD_REQUEST) {
            WORKER_LOGE("❌ Invalid task type in forward queue");
            continue;
        }

        ForwardTask& fwdTask = task.forwardTask;
        processedTasks++;

        // 🚨 关键诊断：记录每个任务的详细处理过程
        WORKER_LOGI("🔍 [任务处理开始] 任务#%d: %s %s:%d -> %s:%d (%d字节)",
                   processedTasks,
                   fwdTask.packetInfo.protocol == PROTOCOL_TCP ? "TCP" : "UDP",
                   fwdTask.packetInfo.sourceIP.c_str(), fwdTask.packetInfo.sourcePort,
                   fwdTask.packetInfo.targetIP.c_str(), fwdTask.packetInfo.targetPort,
                   fwdTask.dataSize);

        // 更前断点：仅前20次打印，确认已进入ForwardPacket调用
        if (processedTasks <= 20) {
            WORKER_LOGE("FWD_CALL #%d proto=%s %s:%d -> %s:%d size=%d",
                        processedTasks,
                        fwdTask.packetInfo.protocol == PROTOCOL_TCP ? "TCP" : "UDP",
                        fwdTask.packetInfo.sourceIP.c_str(), fwdTask.packetInfo.sourcePort,
                        fwdTask.packetInfo.targetIP.c_str(), fwdTask.packetInfo.targetPort,
                        fwdTask.dataSize);
        }

        // 🔍 调试：记录任务处理开始
        WORKER_LOGI("🔄 开始处理转发任务: %s %s:%d -> %s:%d (%d字节)",
                   fwdTask.packetInfo.protocol == PROTOCOL_TCP ? "TCP" : "UDP",
                   fwdTask.packetInfo.sourceIP.c_str(), fwdTask.packetInfo.sourcePort,
                   fwdTask.packetInfo.targetIP.c_str(), fwdTask.packetInfo.targetPort,
                   fwdTask.dataSize);

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
            WORKER_LOGI("✅ 转发任务成功: %s %s:%d -> %s:%d (fd=%d)",
                       fwdTask.packetInfo.protocol == PROTOCOL_TCP ? "TCP" : "UDP",
                       fwdTask.packetInfo.sourceIP.c_str(), fwdTask.packetInfo.sourcePort,
                       fwdTask.packetInfo.targetIP.c_str(), fwdTask.packetInfo.targetPort,
                       sockFd);

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
        int tunnelFd = g_sockFd.load();

        // ✅ 关键修复：直接发送完整IP包，不要提取payload！
        // packet_forwarder.cpp已经用BuildResponsePacket构建了完整IP包
        // VPN客户端期望收到完整的IP包（包含IP头和传输层头部）
        const uint8_t* sendData = respTask.data;
        int sendSize = respTask.dataSize;
        
        // 🔍 验证：检查是否是完整IP包
        if (respTask.dataSize >= 20 && (respTask.data[0] >> 4) == 4) {
            WORKER_LOGI("✅ 准备发送完整IP包: %{public}d字节 (协议=%{public}s)", 
                       sendSize,
                       respTask.protocol == PROTOCOL_UDP ? "UDP" : "TCP");
        } else {
            WORKER_LOGE("⚠️ 警告：响应数据不是有效的IP包（可能导致客户端解析失败）");
        }

        // 发送完整IP包给客户端
        if (tunnelFd >= 0 && g_running.load()) {
            // 🔍 详细诊断日志
            char clientIP[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &respTask.clientAddr.sin_addr, clientIP, sizeof(clientIP));
            
            // 🔥 ZHOUB日志：解析IP包信息
            char srcIP[INET_ADDRSTRLEN] = {0}, dstIP[INET_ADDRSTRLEN] = {0};
            uint16_t srcPort = 0, dstPort = 0;
            const char* protocolName = "未知";
            
            if (sendSize >= 20 && (sendData[0] >> 4) == 4) {  // IPv4
                inet_ntop(AF_INET, &sendData[12], srcIP, sizeof(srcIP));
                inet_ntop(AF_INET, &sendData[16], dstIP, sizeof(dstIP));
                uint8_t protocol = sendData[9];
                uint8_t ipHeaderLen = (sendData[0] & 0x0F) * 4;
                
                if (protocol == 17 && sendSize >= ipHeaderLen + 8) {  // UDP
                    protocolName = "UDP";
                    srcPort = (sendData[ipHeaderLen + 0] << 8) | sendData[ipHeaderLen + 1];
                    dstPort = (sendData[ipHeaderLen + 2] << 8) | sendData[ipHeaderLen + 3];
                } else if (protocol == 6 && sendSize >= ipHeaderLen + 20) {  // TCP
                    protocolName = "TCP";
                    srcPort = (sendData[ipHeaderLen + 0] << 8) | sendData[ipHeaderLen + 1];
                    dstPort = (sendData[ipHeaderLen + 2] << 8) | sendData[ipHeaderLen + 3];
                } else if (protocol == 1) {  // ICMP
                    protocolName = "ICMP";
                }
            }
            
            // 🔥 ZHOUB日志：代理成功后给客户端
            char dataHex[129] = {0};  // 64字节 * 2 + 1
            int hexLen = sendSize < 64 ? sendSize : 64;
            for (int i = 0; i < hexLen; i++) {
                snprintf(dataHex + i * 2, 3, "%02x", sendData[i]);
            }
            
            WORKER_LOGI("ZHOUB [代理→客户端] 源IP:%{public}s 目的IP:%{public}s 源端口:%{public}d 目的端口:%{public}d 协议:%{public}s 大小:%{public}d字节 数据:%{public}s",
                       srcIP, dstIP, srcPort, dstPort, protocolName, sendSize, dataHex);
            
            WORKER_LOGI("🔍 [响应发送] 准备发送 %{public}d字节到 %{public}s:%{public}d (tunnelFd=%{public}d)", 
                       sendSize, clientIP, ntohs(respTask.clientAddr.sin_port), tunnelFd);
            
            ssize_t sent = sendto(tunnelFd, sendData, sendSize, 0,
                                 (struct sockaddr*)&respTask.clientAddr,
                                 sizeof(respTask.clientAddr));

            if (sent > 0) {
                responseTasksProcessed_.fetch_add(1);
                WORKER_LOGI("✅✅✅ Response sent successfully: %{public}zd bytes to %{public}s:%{public}d", 
                           sent, clientIP, ntohs(respTask.clientAddr.sin_port));

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
