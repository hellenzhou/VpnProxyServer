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
#include <sstream>

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
    static thread_local uint64_t localTasks = 0;
    
    // 获取当前线程ID用于日志
    std::thread::id threadId = std::this_thread::get_id();
    std::ostringstream ss;
    ss << threadId;
    std::string threadIdStr = ss.str();
    WORKER_LOGI("🚀 [Forward Worker] Worker线程启动: thread_id=%{public}s", threadIdStr.c_str());

    while (running_.load()) {
        // 🔍 [关键排查] 记录pop前的队列状态
        size_t queueSizeBefore = taskQueue.getForwardQueueSize();
        
        auto taskOpt = taskQueue.popForwardTask(std::chrono::milliseconds(100));
        
        // 🔍 [关键排查] 记录pop后的队列状态
        size_t queueSizeAfter = taskQueue.getForwardQueueSize();
        
        // 🚨 关键诊断：如果队列有大量任务但pop返回空，说明队列可能被锁定或worker线程有问题
        if (queueSizeBefore > 10 && !taskOpt.has_value()) {
            static int timeoutCount = 0;
            timeoutCount++;
            if (timeoutCount <= 5 || timeoutCount % 10 == 0) {
                WORKER_LOGE("🚨 [关键排查] popForwardTask超时但队列有%zu个任务！(超时次数=%d, 已处理=%d, 线程ID=%s)", 
                           queueSizeBefore, timeoutCount, processedTasks, threadIdStr.c_str());
            }
        }
        
        // 🔍 诊断：记录队列状态（在pop之后检查）
        if (queueSizeAfter > 20) {
            static int backlogCount = 0;
            backlogCount++;
            if (backlogCount <= 5 || backlogCount % 10 == 0) {
                WORKER_LOGE("⚠️ [Forward Worker] 队列严重积压: 当前队列大小=%zu, 已处理任务=%d (线程ID=%s)", 
                           queueSizeAfter, processedTasks, threadIdStr.c_str());
            }
        }

        if (!taskOpt.has_value()) {
            continue;  // 超时或队列关闭
        }
        
        // 🔍 [关键排查] 成功弹出任务，记录详细信息
        static int popSuccessCount = 0;
        popSuccessCount++;
        if (popSuccessCount <= 10 || popSuccessCount % 50 == 0) {
            WORKER_LOGI("✅ [关键排查] popForwardTask成功: 队列大小 %zu -> %zu (已处理=%d)", 
                       queueSizeBefore, queueSizeAfter, processedTasks);
        }

        Task task = taskOpt.value();
        if (task.type != TaskType::FORWARD_REQUEST) {
            WORKER_LOGE("Invalid task type in forward queue");
            continue;
        }

        ForwardTask& fwdTask = task.forwardTask;
        processedTasks++;
        localTasks++;

        // Logging policy:
        // - TCP is important but can be very bursty; sample logs.
        // - UDP can be extremely high-rate (DNS/QUIC/etc); sample aggressively.
        const char* protocolName = "UNKNOWN";
        if (fwdTask.packetInfo.protocol == PROTOCOL_TCP) {
            protocolName = "TCP";
        } else if (fwdTask.packetInfo.protocol == PROTOCOL_UDP) {
            protocolName = "UDP";
        } else if (fwdTask.packetInfo.protocol == PROTOCOL_ICMP) {
            protocolName = "ICMP";
        } else if (fwdTask.packetInfo.protocol == PROTOCOL_ICMPV6) {
            protocolName = "ICMPv6";
        }

        bool shouldLog = false;
        if (fwdTask.packetInfo.protocol == PROTOCOL_TCP) {
            // log first few and then every 50th per thread
            shouldLog = (localTasks <= 10) || (localTasks % 50 == 0);
        } else {
            // non-TCP: log very sparingly
            shouldLog = (localTasks <= 5) || (localTasks % 500 == 0);
        }
        if (shouldLog) {
            WORKER_LOGI("🔍 [Forward Worker] task#%{public}d(proto=%{public}s) %{public}s:%{public}d -> %{public}s:%{public}d size=%{public}d",
                       processedTasks, protocolName,
                       fwdTask.packetInfo.sourceIP.c_str(), fwdTask.packetInfo.sourcePort,
                       fwdTask.packetInfo.targetIP.c_str(), fwdTask.packetInfo.targetPort,
                       fwdTask.dataSize);
        }

        // 🔍 [关键排查] 记录ForwardPacket调用前
        if (fwdTask.packetInfo.protocol == PROTOCOL_TCP) {
            static int tcpProcessCount = 0;
            tcpProcessCount++;
            if (tcpProcessCount <= 10 || tcpProcessCount % 20 == 0) {
                WORKER_LOGI("🔍 [关键排查] 开始处理TCP任务 #%d: %s:%d -> %s:%d (队列剩余=%zu)",
                           tcpProcessCount,
                           fwdTask.packetInfo.sourceIP.c_str(), fwdTask.packetInfo.sourcePort,
                           fwdTask.packetInfo.targetIP.c_str(), fwdTask.packetInfo.targetPort,
                           taskQueue.getForwardQueueSize());
            }
        }
        
        // 转发数据包
        auto t0 = std::chrono::steady_clock::now();
        int sockFd = PacketForwarder::ForwardPacket(
            fwdTask.data,
            fwdTask.dataSize,
            fwdTask.packetInfo,
            fwdTask.clientAddr,
            fwdTask.tunnelFd
        );
        auto t1 = std::chrono::steady_clock::now();
        auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
        
        // 🔍 [关键排查] 记录ForwardPacket调用后
        if (fwdTask.packetInfo.protocol == PROTOCOL_TCP) {
            static int tcpProcessedCount = 0;
            tcpProcessedCount++;
            if (tcpProcessedCount <= 10 || tcpProcessedCount % 20 == 0) {
                WORKER_LOGI("✅ [关键排查] TCP任务处理完成 #%d: fd=%d, 耗时=%lldms",
                           tcpProcessedCount, sockFd, (long long)costMs);
            }
        }
        
        if (costMs > 200) {
            WORKER_LOGE("⏱️ [Forward Worker] ForwardPacket slow: %{public}lldms proto=%{public}s %{public}s:%{public}d -> %{public}s:%{public}d size=%{public}d",
                       (long long)costMs, protocolName,
                       fwdTask.packetInfo.sourceIP.c_str(), fwdTask.packetInfo.sourcePort,
                       fwdTask.packetInfo.targetIP.c_str(), fwdTask.packetInfo.targetPort,
                       fwdTask.dataSize);
        }

        // Always log failures; success only sampled (to avoid log I/O starvation)
        if (sockFd < 0) {
            WORKER_LOGE("❌ [Forward Worker] forward failed(proto=%{public}s) %{public}s:%{public}d -> %{public}s:%{public}d",
                       protocolName,
                       fwdTask.packetInfo.sourceIP.c_str(), fwdTask.packetInfo.sourcePort,
                       fwdTask.packetInfo.targetIP.c_str(), fwdTask.packetInfo.targetPort);
        } else if (fwdTask.packetInfo.protocol == PROTOCOL_TCP && shouldLog) {
            WORKER_LOGI("✅ [Forward Worker] TCP forward ok: fd=%{public}d", sockFd);
        }

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
        
        // ✅ 支持 IPv4/IPv6：之前仅检查 IPv4(version=4) 会把 IPv6(version=6) 误报成“非IP包”。
        if (respTask.dataSize <= 0) {
            WORKER_LOGE("响应数据为空");
        } else {
            uint8_t version = (respTask.data[0] >> 4) & 0x0F;
            if (version == 4) {
                if (respTask.dataSize < 20) {
                    WORKER_LOGE("响应数据不是有效的IPv4包(dataSize=%d)", respTask.dataSize);
                }
            } else if (version == 6) {
                if (respTask.dataSize < 40) {
                    WORKER_LOGE("响应数据不是有效的IPv6包(dataSize=%d)", respTask.dataSize);
                }
            } else {
                WORKER_LOGE("响应数据不是有效的IP包(version=%d, dataSize=%d)", version, respTask.dataSize);
            }
        }

        // 🔍 流程跟踪：记录响应发送给VPN客户端
        if (respTask.dataSize >= 20) {
            uint8_t version = (respTask.data[0] >> 4) & 0x0F;
            if (version == 4) {
                char srcIP[INET_ADDRSTRLEN], dstIP[INET_ADDRSTRLEN];
                snprintf(srcIP, sizeof(srcIP), "%d.%d.%d.%d", 
                        respTask.data[12], respTask.data[13], respTask.data[14], respTask.data[15]);
                snprintf(dstIP, sizeof(dstIP), "%d.%d.%d.%d", 
                        respTask.data[16], respTask.data[17], respTask.data[18], respTask.data[19]);
                uint8_t protocol = respTask.data[9];
                
                char clientIP[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &respTask.clientAddr.sin_addr, clientIP, sizeof(clientIP));
                
                WORKER_LOGI("🔍 [流程跟踪] 准备发送响应给VPN客户端: %s:%d -> %s:%d (协议=%d, %d字节) -> 客户端%s", 
                           srcIP, protocol == 6 ? ((respTask.data[20] << 8) | respTask.data[21]) : 0,
                           dstIP, protocol == 6 ? ((respTask.data[22] << 8) | respTask.data[23]) : 0,
                           protocol, respTask.dataSize, clientIP);
            }
        }
        
        // 🔍 [排查点6] 服务端发送响应到客户端
        if (tunnelFd >= 0 && g_running.load()) {
            char clientIP[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &respTask.clientAddr.sin_addr, clientIP, sizeof(clientIP));
            
            ssize_t sent = sendto(tunnelFd, sendData, sendSize, 0,
                                 (struct sockaddr*)&respTask.clientAddr,
                                 sizeof(respTask.clientAddr));

            if (sent > 0) {
                // 🔍 [排查点6] 服务端发送响应到客户端成功
                static int responseSendCount = 0;
                responseSendCount++;
                if (processedTasks <= 10 || responseSendCount % 50 == 0) {
                    if (sendSize >= 20 && (sendData[0] >> 4) == 4) {
                        char srcIP[INET_ADDRSTRLEN], dstIP[INET_ADDRSTRLEN];
                        snprintf(srcIP, sizeof(srcIP), "%d.%d.%d.%d", sendData[12], sendData[13], sendData[14], sendData[15]);
                        snprintf(dstIP, sizeof(dstIP), "%d.%d.%d.%d", sendData[16], sendData[17], sendData[18], sendData[19]);
                        uint8_t protocol = sendData[9];
                        uint16_t srcPort = 0, dstPort = 0;
                        if ((protocol == 6 || protocol == 17) && sendSize >= 28) {
                            srcPort = ntohs(*(uint16_t*)&sendData[20]);
                            dstPort = ntohs(*(uint16_t*)&sendData[22]);
                        }
                        WORKER_LOGI("✅ [排查点6] 服务端->客户端: %{public}s:%{public}d -> %{public}s:%{public}d (协议=%{public}d, %{public}zd字节) -> 客户端%{public}s",
                                   srcIP, srcPort, dstIP, dstPort, protocol, sent, clientIP);
                    } else {
                        WORKER_LOGI("✅ [排查点6] 服务端->客户端: 响应包%{public}zd字节 -> 客户端%{public}s", sent, clientIP);
                    }
                }
                responseTasksProcessed_.fetch_add(1);
                WORKER_LOGI("🔍 [流程跟踪] 响应已发送给VPN客户端: %zd字节 -> %s", sent, clientIP);
                if (respTask.protocol == PROTOCOL_TCP && respTask.dataSize >= 20 && (respTask.data[0] >> 4) == 4) {
                    uint16_t srcPort = (respTask.data[20] << 8) | respTask.data[21];
                    uint16_t dstPort = (respTask.data[22] << 8) | respTask.data[23];
                    char srcIP[INET_ADDRSTRLEN], dstIP[INET_ADDRSTRLEN];
                    snprintf(srcIP, sizeof(srcIP), "%d.%d.%d.%d",
                             respTask.data[12], respTask.data[13], respTask.data[14], respTask.data[15]);
                    snprintf(dstIP, sizeof(dstIP), "%d.%d.%d.%d",
                             respTask.data[16], respTask.data[17], respTask.data[18], respTask.data[19]);
                    WORKER_LOGI("🧭 [TCP-TRACE] RESP_SEND ok %s:%d -> %s:%d size=%d client=%s",
                               srcIP, srcPort, dstIP, dstPort, respTask.dataSize, clientIP);
                }
            } else {
                responseTasksFailed_.fetch_add(1);
                // 🔍 [排查点6] 服务端发送响应到客户端失败
                WORKER_LOGE("❌ [排查点6] 服务端->客户端失败: 响应包%{public}d字节 -> 客户端%{public}s, errno=%{public}d (%{public}s), tunnelFd=%{public}d",
                           sendSize, clientIP, errno, strerror(errno), tunnelFd);
                if (respTask.protocol == PROTOCOL_TCP && respTask.dataSize >= 20 && (respTask.data[0] >> 4) == 4) {
                    uint16_t srcPort = (respTask.data[20] << 8) | respTask.data[21];
                    uint16_t dstPort = (respTask.data[22] << 8) | respTask.data[23];
                    char srcIP[INET_ADDRSTRLEN], dstIP[INET_ADDRSTRLEN];
                    snprintf(srcIP, sizeof(srcIP), "%d.%d.%d.%d",
                             respTask.data[12], respTask.data[13], respTask.data[14], respTask.data[15]);
                    snprintf(dstIP, sizeof(dstIP), "%d.%d.%d.%d",
                             respTask.data[16], respTask.data[17], respTask.data[18], respTask.data[19]);
                    WORKER_LOGE("🧭 [TCP-TRACE] RESP_SEND fail %s:%d -> %s:%d size=%d client=%s errno=%d (%s)",
                               srcIP, srcPort, dstIP, dstPort, respTask.dataSize, clientIP, errno, strerror(errno));
                }
            }
        } else {
            responseTasksFailed_.fetch_add(1);
            WORKER_LOGE("🔍 [流程跟踪] 无法发送响应: tunnelFd=%d, running=%d", tunnelFd, g_running.load());
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
