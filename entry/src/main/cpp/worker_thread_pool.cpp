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
    
    // 获取当前线程ID用于日志
    std::thread::id threadId = std::this_thread::get_id();
    std::ostringstream ss;
    ss << threadId;
    std::string threadIdStr = ss.str();
    WORKER_LOGI("🚀 [Forward Worker] Worker线程启动: thread_id=%{public}s", threadIdStr.c_str());

    while (running_.load()) {
        auto taskOpt = taskQueue.popForwardTask(std::chrono::milliseconds(100));
        
        // 🔍 诊断：记录队列状态（在pop之后检查）
        size_t queueSize = taskQueue.getForwardQueueSize();
        if (queueSize > 20) {
            WORKER_LOGE("⚠️ [Forward Worker] 队列严重积压: 当前队列大小=%zu, 已处理任务=%d (线程ID=%s)", 
                       queueSize, processedTasks, threadIdStr.c_str());
        }

        if (!taskOpt.has_value()) {
            // 🔍 诊断：如果队列有数据但超时，记录警告
            if (queueSize > 0 && processedTasks % 100 == 0) {
                WORKER_LOGE("⚠️ [Forward Worker] popForwardTask超时，但队列有%zu个任务（可能队列被锁定）", queueSize);
            }
            continue;  // 超时或队列关闭
        }

        Task task = taskOpt.value();
        if (task.type != TaskType::FORWARD_REQUEST) {
            WORKER_LOGE("Invalid task type in forward queue");
            continue;
        }

        ForwardTask& fwdTask = task.forwardTask;
        processedTasks++;

        // 🚨 强制记录：每个任务都记录协议类型（用于诊断TCP任务是否被worker线程接收）
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
        
        WORKER_LOGI("🔍 [Forward Worker] 任务#%{public}d: 协议=%{public}s, 源=%{public}s:%{public}d, 目标=%{public}s:%{public}d, 大小=%{public}d字节", 
                   processedTasks, protocolName,
                   fwdTask.packetInfo.sourceIP.c_str(), fwdTask.packetInfo.sourcePort,
                   fwdTask.packetInfo.targetIP.c_str(), fwdTask.packetInfo.targetPort,
                   fwdTask.dataSize);

        // 🚨 强制记录：TCP任务被worker线程处理（用于诊断TCP任务是否被worker线程接收）
        if (fwdTask.packetInfo.protocol == PROTOCOL_TCP) {
            WORKER_LOGI("🚀 [Forward Worker] ========== 开始处理TCP任务 ==========");
            WORKER_LOGI("🚀 [Forward Worker] 源: %{public}s:%{public}d -> 目标: %{public}s:%{public}d", 
                       fwdTask.packetInfo.sourceIP.c_str(), fwdTask.packetInfo.sourcePort,
                       fwdTask.packetInfo.targetIP.c_str(), fwdTask.packetInfo.targetPort);
            WORKER_LOGI("🚀 [Forward Worker] 数据大小: %{public}d字节, 任务#%{public}d", 
                       fwdTask.dataSize, processedTasks);
        }

        // 转发数据包
        int sockFd = PacketForwarder::ForwardPacket(
            fwdTask.data,
            fwdTask.dataSize,
            fwdTask.packetInfo,
            fwdTask.clientAddr,
            fwdTask.tunnelFd
        );
        
        // 🚨 强制记录：TCP任务处理结果
        if (fwdTask.packetInfo.protocol == PROTOCOL_TCP) {
            if (sockFd >= 0) {
                WORKER_LOGI("✅ [Forward Worker] TCP任务处理成功: sockFd=%{public}d", sockFd);
            } else {
                WORKER_LOGE("❌ [Forward Worker] TCP任务处理失败: sockFd=%{public}d", sockFd);
            }
            WORKER_LOGI("🚀 [Forward Worker] ========================================");
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
        
        if (respTask.dataSize < 20 || (respTask.data[0] >> 4) != 4) {
            WORKER_LOGE("响应数据不是有效的IP包");
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
        
        // 发送完整IP包给客户端
        if (tunnelFd >= 0 && g_running.load()) {
            char clientIP[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &respTask.clientAddr.sin_addr, clientIP, sizeof(clientIP));
            
            ssize_t sent = sendto(tunnelFd, sendData, sendSize, 0,
                                 (struct sockaddr*)&respTask.clientAddr,
                                 sizeof(respTask.clientAddr));

            if (sent > 0) {
                responseTasksProcessed_.fetch_add(1);
                WORKER_LOGI("🔍 [流程跟踪] 响应已发送给VPN客户端: %d字节 -> %s", sent, clientIP);
            } else {
                responseTasksFailed_.fetch_add(1);
                WORKER_LOGE("🔍 [流程跟踪] 发送响应失败: errno=%d (%s)", errno, strerror(errno));
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
