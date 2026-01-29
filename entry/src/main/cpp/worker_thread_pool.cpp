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

bool WorkerThreadPool::start(int numTcpWorkers, int numUdpWorkers, int numResponseWorkers) {
    if (running_.load()) {
        WORKER_LOGE("Worker thread pool already running");
        return false;
    }
    
    // 🚀 关键修复：在启动worker线程前初始化TCP队列数组
    // 避免竞态条件：如果worker线程启动后才初始化队列，可能导致任务路由到不存在的队列
    TaskQueueManager::getInstance().initializeTcpQueues(numTcpWorkers);
    
    running_.store(true);
    
    // 🚀 启动TCP专用工作线程
    // 🐛 修复：直接传递worker索引，避免通过thread ID查找（不可靠）
    for (int i = 0; i < numTcpWorkers; ++i) {
        try {
            tcpWorkers_.emplace_back([this, i]() {
                WORKER_LOGI("🚀 [TCP Worker] TCP专用线程 #%d 启动", i);
                tcpWorkerThread(i);  // 🐛 修复：直接传递索引
            });
        } catch (const std::exception& e) {
            WORKER_LOGE("Failed to create TCP worker #%d: %s", i, e.what());
            return false;
        }
    }
    
    // 🚀 启动UDP专用工作线程
    // 🐛 修复：直接传递worker索引，避免通过thread ID查找（不可靠）
    for (int i = 0; i < numUdpWorkers; ++i) {
        try {
            udpWorkers_.emplace_back([this, i]() {
                WORKER_LOGI("🚀 [UDP Worker] UDP专用线程 #%d 启动", i);
                udpWorkerThread(i);  // 🐛 修复：直接传递索引
            });
        } catch (const std::exception& e) {
            WORKER_LOGE("Failed to create UDP worker #%d: %s", i, e.what());
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
    
    WORKER_LOGI("✅ Worker thread pool started: %d TCP workers, %d UDP workers, %d response workers", 
                numTcpWorkers, numUdpWorkers, numResponseWorkers);
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
    
    // 等待所有转发工作线程结束（兼容旧代码）
    for (auto& worker : forwardWorkers_) {
        if (worker.joinable()) {
            worker.join();
        }
    }
    forwardWorkers_.clear();
    
    // 等待所有TCP工作线程结束
    for (auto& worker : tcpWorkers_) {
        if (worker.joinable()) {
            worker.join();
        }
    }
    tcpWorkers_.clear();
    
    // 等待所有UDP工作线程结束
    for (auto& worker : udpWorkers_) {
        if (worker.joinable()) {
            worker.join();
        }
    }
    udpWorkers_.clear();
    
    // 等待所有响应工作线程结束
    for (auto& worker : responseWorkers_) {
        if (worker.joinable()) {
            worker.join();
        }
    }
    responseWorkers_.clear();
    
    WORKER_LOGI("✅ Worker thread pool stopped");
}

// TCP专用worker线程 - 只处理TCP任务，确保TCP任务不被UDP任务阻塞
// 🐛 修复：直接接收worker索引参数，避免通过thread ID查找（不可靠且低效）
void WorkerThreadPool::tcpWorkerThread(int workerIndex) {
    auto& taskQueue = TaskQueueManager::getInstance();
    int processedTasks = 0;
    
    // 获取当前线程ID用于日志
    std::thread::id threadId = std::this_thread::get_id();
    std::ostringstream ss;
    ss << threadId;
    std::string threadIdStr = ss.str();
    
    // 🐛 修复：直接使用传入的workerIndex，不再通过thread ID查找
    size_t threadIndex = static_cast<size_t>(workerIndex);
    
    WORKER_LOGI("🚀 [TCP Worker] TCP专用线程 #%zu 启动: thread_id=%s", threadIndex, threadIdStr.c_str());

    while (running_.load()) {
        try {
            // 🔍 记录pop前的队列状态
            size_t queueSizeBefore = taskQueue.getTcpQueueSize();
            
            // 🚀 优雅方案：从对应的TCP队列pop（连接哈希路由）
            auto timeout = queueSizeBefore > 0 ? std::chrono::milliseconds(10) : std::chrono::milliseconds(100);
            auto taskOpt = taskQueue.popTcpTask(static_cast<int>(threadIndex), timeout);
            
            size_t queueSizeAfter = taskQueue.getTcpQueueSize();

            if (!taskOpt.has_value()) {
                continue;  // 超时或队列关闭
            }
            
            Task task = taskOpt.value();
            if (task.type != TaskType::FORWARD_REQUEST) {
                WORKER_LOGE("Invalid task type in TCP worker");
                continue;
            }

            ForwardTask& fwdTask = task.forwardTask;
            
            // 🚨 防御性检查：确保是TCP任务（理论上不应该发生）
            if (fwdTask.packetInfo.protocol != PROTOCOL_TCP) {
                WORKER_LOGE("🚨 [TCP Worker] 收到非TCP任务！协议=%d，这不应该发生", fwdTask.packetInfo.protocol);
                continue;
            }
            
            // 🔍 记录TCP任务处理
            processedTasks++;
            WORKER_LOGI("✅ [TCP Worker] popForwardTask成功: 协议=TCP, 队列大小 %zu -> %zu (已处理=%d, 源=%s:%d -> 目标=%s:%d, 线程#%zu)", 
                       queueSizeBefore, queueSizeAfter, processedTasks,
                       fwdTask.packetInfo.sourceIP.c_str(), fwdTask.packetInfo.sourcePort,
                       fwdTask.packetInfo.targetIP.c_str(), fwdTask.packetInfo.targetPort,
                       threadIndex);
            
            // 🔍 记录ForwardPacket调用前
            WORKER_LOGI("🔍 [TCP Worker] 开始处理TCP任务: %s:%d -> %s:%d (队列剩余=%zu, 数据大小=%d, 线程#%zu)",
                       fwdTask.packetInfo.sourceIP.c_str(), fwdTask.packetInfo.sourcePort,
                       fwdTask.packetInfo.targetIP.c_str(), fwdTask.packetInfo.targetPort,
                       taskQueue.getTcpQueueSize(), fwdTask.dataSize, threadIndex);
            
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
            
            // 🔍 记录ForwardPacket调用后
            WORKER_LOGI("✅ [TCP Worker] TCP任务处理完成: fd=%d, 耗时=%lldms (线程#%zu, 队列剩余=%zu)",
                       sockFd, (long long)costMs, threadIndex, taskQueue.getTcpQueueSize());
            
            if (costMs > 200) {
                WORKER_LOGE("⏱️ [TCP Worker] ForwardPacket slow: %lldms %s:%d -> %s:%d size=%d",
                           (long long)costMs,
                           fwdTask.packetInfo.sourceIP.c_str(), fwdTask.packetInfo.sourcePort,
                           fwdTask.packetInfo.targetIP.c_str(), fwdTask.packetInfo.targetPort,
                           fwdTask.dataSize);
            }

            if (sockFd < 0) {
                WORKER_LOGE("❌ [TCP Worker] forward failed %s:%d -> %s:%d",
                           fwdTask.packetInfo.sourceIP.c_str(), fwdTask.packetInfo.sourcePort,
                           fwdTask.packetInfo.targetIP.c_str(), fwdTask.packetInfo.targetPort);
                forwardTasksFailed_.fetch_add(1);
            } else {
                forwardTasksProcessed_.fetch_add(1);
                tcpTasksProcessed_.fetch_add(1);
            }
        } catch (const std::exception& e) {
            WORKER_LOGE("🚨 [TCP Worker] 处理任务时发生异常: %s (已处理=%d)", e.what(), processedTasks);
            forwardTasksFailed_.fetch_add(1);
        } catch (...) {
            WORKER_LOGE("🚨 [TCP Worker] 处理任务时发生未知异常 (已处理=%d)", processedTasks);
            forwardTasksFailed_.fetch_add(1);
        }
    }

    WORKER_LOGI("TCP worker #%zu stopped, processed %d tasks", threadIndex, processedTasks);
}

// UDP专用worker线程 - 只处理UDP任务
// 🐛 修复：直接接收worker索引参数，避免通过thread ID查找（不可靠且低效）
void WorkerThreadPool::udpWorkerThread(int workerIndex) {
    auto& taskQueue = TaskQueueManager::getInstance();
    int processedTasks = 0;
    
    // 获取当前线程ID用于日志
    std::thread::id threadId = std::this_thread::get_id();
    std::ostringstream ss;
    ss << threadId;
    std::string threadIdStr = ss.str();
    
    // 🐛 修复：直接使用传入的workerIndex，不再通过thread ID查找
    size_t threadIndex = static_cast<size_t>(workerIndex);
    
    WORKER_LOGI("🚀 [UDP Worker] UDP专用线程 #%zu 启动: thread_id=%s", threadIndex, threadIdStr.c_str());
    
    // 🐛 诊断：添加心跳日志
    static std::atomic<int> heartbeatCounter{0};

    while (running_.load()) {
        try {
            size_t queueSizeBefore = taskQueue.getUdpQueueSize();
            auto timeout = queueSizeBefore > 0 ? std::chrono::milliseconds(10) : std::chrono::milliseconds(100);
            
            // 🐛 诊断：每100次循环输出一次心跳
            int hb = ++heartbeatCounter;
            if (hb % 100 == 0) {
                WORKER_LOGI("🔍 [UDP Worker #%zu] 心跳 #%d: 队列大小=%zu, running=%d", 
                           threadIndex, hb, queueSizeBefore, running_.load() ? 1 : 0);
            }
            
            auto taskOpt = taskQueue.popUdpTask(timeout);
            size_t queueSizeAfter = taskQueue.getUdpQueueSize();
            
            if (!taskOpt.has_value()) {
                // 🐛 诊断：记录pop失败的原因
                if (queueSizeBefore > 0) {
                    WORKER_LOGE("⚠️ [UDP Worker #%zu] popUdpTask返回空，但队列有%zu个任务！队列后=%zu", 
                               threadIndex, queueSizeBefore, queueSizeAfter);
                }
                continue;
            }
            
            // 🐛 诊断：成功pop到任务
            Task task = taskOpt.value();
            if (task.type != TaskType::FORWARD_REQUEST) {
                WORKER_LOGE("Invalid task type in UDP worker");
                continue;
            }

            ForwardTask& fwdTask = task.forwardTask;
            WORKER_LOGI("✅ [UDP Worker #%zu] 成功pop到UDP任务，队列: %zu -> %zu, 源=%{public}s:%{public}d -> 目标=%{public}s:%{public}d", 
                       threadIndex, queueSizeBefore, queueSizeAfter,
                       fwdTask.packetInfo.sourceIP.c_str(), fwdTask.packetInfo.sourcePort,
                       fwdTask.packetInfo.targetIP.c_str(), fwdTask.packetInfo.targetPort);
            
            // 🚨 防御性检查：确保是UDP任务（理论上不应该发生）
            if (fwdTask.packetInfo.protocol != PROTOCOL_UDP) {
                WORKER_LOGE("🚨 [UDP Worker] 收到非UDP任务！协议=%d，这不应该发生", fwdTask.packetInfo.protocol);
                continue;
            }
            
            processedTasks++;
            
            // 转发数据包
            WORKER_LOGI("🔍 [UDP Worker #%zu] 开始处理UDP任务: %s:%d -> %s:%d, 大小=%d", 
                       threadIndex,
                       fwdTask.packetInfo.sourceIP.c_str(), fwdTask.packetInfo.sourcePort,
                       fwdTask.packetInfo.targetIP.c_str(), fwdTask.packetInfo.targetPort,
                       fwdTask.dataSize);
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
            WORKER_LOGI("✅ [UDP Worker #%zu] ForwardPacket完成: sockFd=%d, 耗时=%lldms", 
                       threadIndex, sockFd, (long long)costMs);
            
            if (costMs > 200) {
                WORKER_LOGE("⏱️ [UDP Worker] ForwardPacket slow: %lldms %s:%d -> %s:%d size=%d",
                           (long long)costMs,
                           fwdTask.packetInfo.sourceIP.c_str(), fwdTask.packetInfo.sourcePort,
                           fwdTask.packetInfo.targetIP.c_str(), fwdTask.packetInfo.targetPort,
                           fwdTask.dataSize);
            }

            if (sockFd < 0) {
                forwardTasksFailed_.fetch_add(1);
            } else {
                forwardTasksProcessed_.fetch_add(1);
                udpTasksProcessed_.fetch_add(1);
                
                // UDP包记录到重传管理器（只对IPv4 DNS查询）
                if (fwdTask.packetInfo.targetPort == 53 &&
                    fwdTask.packetInfo.addressFamily == AF_INET) {
                    uint16_t packetId = UdpRetransmitManager::generatePacketId();
                    const uint8_t* payload = nullptr;
                    int payloadSize = 0;
                    if (PacketBuilder::ExtractPayload(fwdTask.data, fwdTask.dataSize,
                                                     fwdTask.packetInfo, &payload, &payloadSize)) {
                        if (payload && payloadSize > 0) {
                            sockaddr_in targetAddr{};
                            targetAddr.sin_family = AF_INET;
                            targetAddr.sin_port = fwdTask.packetInfo.targetPort;
                            if (inet_pton(AF_INET, fwdTask.packetInfo.targetIP.c_str(), &targetAddr.sin_addr) > 0) {
                                UdpRetransmitManager::getInstance().recordSentPacket(
                                    packetId, payload, payloadSize, targetAddr, fwdTask.clientAddr, sockFd);
                            }
                        }
                    }
                }
            }
        } catch (const std::exception& e) {
            WORKER_LOGE("🚨 [UDP Worker] 处理任务时发生异常: %s (已处理=%d)", e.what(), processedTasks);
            forwardTasksFailed_.fetch_add(1);
        } catch (...) {
            WORKER_LOGE("🚨 [UDP Worker] 处理任务时发生未知异常 (已处理=%d)", processedTasks);
            forwardTasksFailed_.fetch_add(1);
        }
    }

    WORKER_LOGI("UDP worker #%zu stopped, processed %d tasks", threadIndex, processedTasks);
}

// 通用forward worker线程（保留用于兼容，但不再使用）
void WorkerThreadPool::forwardWorkerThread() {
    // 这个函数保留用于兼容，但实际上不再使用
    // 现在使用tcpWorkerThread和udpWorkerThread代替
    WORKER_LOGI("⚠️ [Forward Worker] 通用worker线程已废弃，请使用TCP/UDP专用线程");
}

// 响应worker线程
void WorkerThreadPool::responseWorkerThread() {
    auto& taskQueue = TaskQueueManager::getInstance();
    int processedTasks = 0;

    WORKER_LOGI("🚀 Response worker started");

    while (running_.load()) {
        try {
            auto taskOpt = taskQueue.popResponseTask(std::chrono::milliseconds(100));
            
            if (!taskOpt.has_value()) {
                continue;
            }
            
            Task task = taskOpt.value();
            if (task.type != TaskType::SEND_RESPONSE) {
                WORKER_LOGE("Invalid task type in response queue");
                continue;
            }

            ResponseTask& respTask = task.responseTask;
            processedTasks++;
            responseTasksProcessed_.fetch_add(1);

            // 发送响应给VPN客户端
            ssize_t sent = sendto(g_sockFd.load(), respTask.data, respTask.dataSize, 0,
                                 reinterpret_cast<const sockaddr*>(&respTask.clientAddr),
                                 sizeof(respTask.clientAddr));
            
            if (sent < 0) {
                int savedErr = errno;
                WORKER_LOGE("❌ [Response Worker] sendto失败: errno=%d (%s), size=%d", 
                           savedErr, strerror(savedErr), respTask.dataSize);
                responseTasksFailed_.fetch_add(1);
            }
        } catch (const std::exception& e) {
            WORKER_LOGE("🚨 [Response Worker] 处理任务时发生异常: %s (已处理=%d)", e.what(), processedTasks);
            responseTasksFailed_.fetch_add(1);
        } catch (...) {
            WORKER_LOGE("🚨 [Response Worker] 处理任务时发生未知异常 (已处理=%d)", processedTasks);
            responseTasksFailed_.fetch_add(1);
        }
    }

    WORKER_LOGI("Response worker stopped, processed %d tasks", processedTasks);
}

WorkerThreadPool::Stats WorkerThreadPool::getStats() const {
    return {
        forwardTasksProcessed_.load(),
        responseTasksProcessed_.load(),
        forwardTasksFailed_.load(),
        responseTasksFailed_.load(),
        tcpTasksProcessed_.load(),
        udpTasksProcessed_.load()
    };
}
