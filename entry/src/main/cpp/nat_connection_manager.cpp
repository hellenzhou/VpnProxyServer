/*
 * NAT连接管理器实现
 */

#include "nat_connection_manager.h"
#include "nat_table.h"  // 为了使用NATConnection结构体
#include <hilog/log.h>
#include <sstream>
#include <arpa/inet.h>
#include <algorithm>

// 使用 packet_forwarder.h 中的 SocketConnectionPool 声明
#include "packet_forwarder.h"

// 日志宏
#define NAT_MGR_LOGI(fmt, ...) \
    OH_LOG_Print(LOG_APP, LOG_INFO, 0x15b1, "VpnServer", "ZHOUB [NAT-MGR] " fmt, ##__VA_ARGS__)
#define NAT_MGR_LOGW(fmt, ...) \
    OH_LOG_Print(LOG_APP, LOG_WARN, 0x15b1, "VpnServer", "ZHOUB [NAT-MGR] ⚠️ " fmt, ##__VA_ARGS__)
#define NAT_MGR_LOGE(fmt, ...) \
    OH_LOG_Print(LOG_APP, LOG_ERROR, 0x15b1, "VpnServer", "ZHOUB [NAT-MGR] ❌ " fmt, ##__VA_ARGS__)

// ===== 辅助函数 =====

const char* CleanupReasonToString(CleanupReason reason) {
    switch (reason) {
        case CleanupReason::UDP_ADDRESS_FAIL: return "UDP_ADDRESS_FAIL";
        case CleanupReason::UDP_SEND_FAIL: return "UDP_SEND_FAIL";
        case CleanupReason::UDP_TIMEOUT: return "UDP_TIMEOUT";
        case CleanupReason::TCP_ADDRESS_FAIL: return "TCP_ADDRESS_FAIL";
        case CleanupReason::TCP_CONNECT_FAIL: return "TCP_CONNECT_FAIL";
        case CleanupReason::TCP_SEND_FAIL: return "TCP_SEND_FAIL";
        case CleanupReason::TCP_RST_RECEIVED: return "TCP_RST_RECEIVED";
        case CleanupReason::TCP_CLIENT_FIN: return "TCP_CLIENT_FIN";
        case CleanupReason::TCP_SERVER_FIN: return "TCP_SERVER_FIN";
        case CleanupReason::TCP_TIMEOUT: return "TCP_TIMEOUT";
        case CleanupReason::NORMAL_CLOSE: return "NORMAL_CLOSE";
        case CleanupReason::FORCED_CLEANUP: return "FORCED_CLEANUP";
        default: return "UNKNOWN";
    }
}

// ===== TCP状态机实现 =====

const char* TcpStateMachine::StateToString(State state) {
    switch (state) {
        case State::NONE: return "NONE";
        case State::CONNECTING: return "CONNECTING";
        case State::SYN_RECEIVED: return "SYN_RECEIVED";
        case State::ESTABLISHED: return "ESTABLISHED";
        case State::FIN_SENT: return "FIN_SENT";
        case State::CLOSED: return "CLOSED";
        default: return "UNKNOWN";
    }
}

bool TcpStateMachine::isValidTransition(State from, State to) const {
    // 定义合法的状态转换
    // NONE -> CONNECTING (创建新连接)
    // CONNECTING -> SYN_RECEIVED (发送SYN-ACK)
    // SYN_RECEIVED -> ESTABLISHED (收到ACK)
    // ESTABLISHED -> FIN_SENT (收到FIN)
    // FIN_SENT -> CLOSED (FIN确认)
    // 任何状态 -> CLOSED (RST或错误)
    
    if (from == to) return true;  // 同状态转换允许（重复事件）
    
    switch (from) {
        case State::NONE:
            return to == State::CONNECTING;
        case State::CONNECTING:
            return to == State::SYN_RECEIVED || to == State::CLOSED;
        case State::SYN_RECEIVED:
            return to == State::ESTABLISHED || to == State::CLOSED;
        case State::ESTABLISHED:
            return to == State::FIN_SENT || to == State::CLOSED;
        case State::FIN_SENT:
            return to == State::CLOSED;
        case State::CLOSED:
            return false;  // CLOSED是终态
        default:
            return false;
    }
}

bool TcpStateMachine::onSynReceived(NATConnection& conn, uint32_t clientIsn) {
    State currentState = static_cast<State>(conn.tcpState);
    State newState = State::CONNECTING;
    
    if (!isValidTransition(currentState, newState)) {
        NAT_MGR_LOGW("Invalid SYN transition: %{public}s -> %{public}s",
                     StateToString(currentState), StateToString(newState));
        return false;
    }
    
    conn.tcpState = static_cast<NATConnection::TcpState>(newState);
    conn.clientIsn = clientIsn;
    conn.nextClientSeq = clientIsn + 1;  // SYN消耗一个seq
    return true;
}

bool TcpStateMachine::onSynAckSent(NATConnection& conn, uint32_t serverIsn) {
    State currentState = static_cast<State>(conn.tcpState);
    State newState = State::SYN_RECEIVED;
    
    if (!isValidTransition(currentState, newState)) {
        NAT_MGR_LOGW("Invalid SYN-ACK transition: %{public}s -> %{public}s",
                     StateToString(currentState), StateToString(newState));
        return false;
    }
    
    conn.tcpState = static_cast<NATConnection::TcpState>(newState);
    conn.serverIsn = serverIsn;
    conn.nextServerSeq = serverIsn + 1;  // SYN消耗一个seq
    return true;
}

bool TcpStateMachine::onEstablished(NATConnection& conn) {
    State currentState = static_cast<State>(conn.tcpState);
    State newState = State::ESTABLISHED;
    
    if (!isValidTransition(currentState, newState)) {
        NAT_MGR_LOGW("Invalid ESTABLISHED transition: %{public}s -> %{public}s",
                     StateToString(currentState), StateToString(newState));
        return false;
    }
    
    conn.tcpState = static_cast<NATConnection::TcpState>(newState);
    return true;
}

bool TcpStateMachine::onFinReceived(NATConnection& conn, bool fromClient) {
    State currentState = static_cast<State>(conn.tcpState);
    State newState = State::FIN_SENT;
    
    if (!isValidTransition(currentState, newState)) {
        NAT_MGR_LOGW("Invalid FIN transition: %{public}s -> %{public}s (fromClient=%{public}d)",
                     StateToString(currentState), StateToString(newState), fromClient);
        return false;
    }
    
    conn.tcpState = static_cast<NATConnection::TcpState>(newState);
    return true;
}

bool TcpStateMachine::onRstReceived(NATConnection& conn) {
    // RST可以在任何状态下转到CLOSED
    conn.tcpState = static_cast<NATConnection::TcpState>(State::CLOSED);
    return true;
}

// ===== NATConnectionManager实现 =====

NATConnectionManager::NATConnectionManager() {
    NAT_MGR_LOGI("NATConnectionManager constructed");
}

NATConnectionManager::~NATConnectionManager() {
    stop();
    NAT_MGR_LOGI("NATConnectionManager destroyed");
}

NATConnectionManager& NATConnectionManager::getInstance() {
    static NATConnectionManager instance;
    return instance;
}

bool NATConnectionManager::start() {
    if (running_.load()) {
        NAT_MGR_LOGW("Already running");
        return false;
    }
    
    running_.store(true);
    
    try {
        cleanupThread_ = std::thread([this]() {
            cleanupThreadFunc();
        });
        NAT_MGR_LOGI("✅ Cleanup thread started");
        return true;
    } catch (const std::exception& e) {
        NAT_MGR_LOGE("Failed to start cleanup thread: %{public}s", e.what());
        running_.store(false);
        return false;
    }
}

void NATConnectionManager::stop() {
    if (!running_.load()) {
        return;
    }
    
    size_t pendingTasks = 0;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        pendingTasks = cleanupQueue_.size();
    }
    
    NAT_MGR_LOGI("Stopping cleanup thread... (pending_tasks=%{public}zu)", pendingTasks);
    running_.store(false);
    cv_.notify_all();
    
    if (cleanupThread_.joinable()) {
        cleanupThread_.join();
    }
    
    // 检查是否还有未处理的任务
    size_t remainingTasks = 0;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        remainingTasks = cleanupQueue_.size();
    }
    
    if (remainingTasks > 0) {
        NAT_MGR_LOGW("⚠️ Cleanup thread stopped with %{public}zu pending tasks (possible socket leak)",
                    remainingTasks);
    } else {
        NAT_MGR_LOGI("✅ Cleanup thread stopped (all tasks processed)");
    }
}

NATConnectionManager::ConnectionHandle NATConnectionManager::createConnection(
    const PacketInfo& packetInfo,
    const sockaddr_in& clientAddr,
    int forwardSocket
) {
    // 🔧 边界条件检查
    if (forwardSocket < 0) {
        NAT_MGR_LOGE("Invalid socket: fd=%{public}d", forwardSocket);
        return ConnectionHandle();
    }
    
    if (packetInfo.sourceIP.empty() || packetInfo.targetIP.empty()) {
        NAT_MGR_LOGE("Invalid IP addresses: src=%{public}s dst=%{public}s",
                    packetInfo.sourceIP.c_str(), packetInfo.targetIP.c_str());
        return ConnectionHandle();
    }
    
    if (packetInfo.sourcePort == 0 || packetInfo.targetPort == 0) {
        NAT_MGR_LOGE("Invalid ports: src=%{public}d dst=%{public}d",
                    packetInfo.sourcePort, packetInfo.targetPort);
        return ConnectionHandle();
    }
    
    std::lock_guard<std::mutex> lock(mutex_);
    
    // 生成key
    std::string key = generateKey(packetInfo, clientAddr);
    
    // 检查是否已存在
    auto it = connections_.find(key);
    if (it != connections_.end()) {
        int oldSocket = it->second.conn.forwardSocket;
        if (oldSocket == forwardSocket) {
            // 同一socket，更新活动时间和原始请求
            it->second.lastActivity = std::chrono::steady_clock::now();
            it->second.conn.originalRequest = packetInfo;
            NAT_MGR_LOGI("Updated existing connection: key=%{public}s fd=%{public}d",
                        key.c_str(), forwardSocket);
            return ConnectionHandle(key, forwardSocket);
        } else {
            // 不同socket，拒绝覆盖（防止映射混乱）
            NAT_MGR_LOGE("Refuse to overwrite connection: key=%{public}s old_fd=%{public}d new_fd=%{public}d",
                        key.c_str(), oldSocket, forwardSocket);
            return ConnectionHandle();  // 返回无效句柄
        }
    }
    
    // 创建新连接
    ConnectionEntry entry;
    entry.conn.clientPhysicalAddr = clientAddr;
    entry.conn.clientVirtualIP = packetInfo.sourceIP;
    entry.conn.clientVirtualPort = packetInfo.sourcePort;
    entry.conn.serverIP = packetInfo.targetIP;
    entry.conn.serverPort = packetInfo.targetPort;
    entry.conn.forwardSocket = forwardSocket;
    entry.conn.protocol = packetInfo.protocol;
    entry.conn.originalRequest = packetInfo;
    entry.conn.tcpState = NATConnection::TcpState::NONE;
    
    // 🔧 使用insert方法（兼容HarmonyOS libc++）
    auto result = connections_.insert(std::make_pair(key, entry));
    if (!result.second) {
        // 如果插入失败（理论上不应该发生，因为前面已经检查过）
        NAT_MGR_LOGE("Failed to insert connection: key=%{public}s", key.c_str());
        return ConnectionHandle();
    }
    socketToKey_[forwardSocket] = key;
    
    // 🔧 使用relaxed内存顺序优化性能（统计不需要严格同步）
    totalCreated_.fetch_add(1, std::memory_order_relaxed);
    
    // 仅对TCP和DNS记录日志
    if (packetInfo.protocol == PROTOCOL_TCP || packetInfo.targetPort == 53) {
        NAT_MGR_LOGI("✅ Created connection: %{public}s -> %{public}s:%{public}d/%{public}s (fd=%{public}d, total=%{public}zu)",
                    packetInfo.sourceIP.c_str(), packetInfo.targetIP.c_str(), packetInfo.targetPort,
                    packetInfo.protocol == PROTOCOL_TCP ? "TCP" : "UDP",
                    forwardSocket, connections_.size());
    }
    
    return ConnectionHandle(key, forwardSocket);
}

Optional<NATConnection> NATConnectionManager::findConnection(const std::string& key) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = connections_.find(key);
    if (it != connections_.end()) {
        it->second.lastActivity = std::chrono::steady_clock::now();
        return Optional<NATConnection>(it->second.conn);
    }
    
    return Optional<NATConnection>();  // 返回空Optional
}

Optional<NATConnection> NATConnectionManager::findConnectionBySocket(int socket) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto socketIt = socketToKey_.find(socket);
    if (socketIt == socketToKey_.end()) {
        return Optional<NATConnection>();  // 返回空Optional
    }
    
    auto connIt = connections_.find(socketIt->second);
    if (connIt != connections_.end()) {
        connIt->second.lastActivity = std::chrono::steady_clock::now();
        return Optional<NATConnection>(connIt->second.conn);
    }
    
    return Optional<NATConnection>();  // 返回空Optional
}

void NATConnectionManager::updateActivity(const std::string& key) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = connections_.find(key);
    if (it != connections_.end()) {
        it->second.lastActivity = std::chrono::steady_clock::now();
    }
}

bool NATConnectionManager::withConnection(const std::string& key, 
                                         const std::function<void(NATConnection&)>& fn) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = connections_.find(key);
    if (it == connections_.end()) {
        return false;
    }
    
    fn(it->second.conn);
    it->second.lastActivity = std::chrono::steady_clock::now();
    return true;
}

bool NATConnectionManager::withConnectionBySocket(int socket, 
                                                  const std::function<void(NATConnection&)>& fn) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto socketIt = socketToKey_.find(socket);
    if (socketIt == socketToKey_.end()) {
        return false;
    }
    
    auto connIt = connections_.find(socketIt->second);
    if (connIt == connections_.end()) {
        return false;
    }
    
    fn(connIt->second.conn);
    connIt->second.lastActivity = std::chrono::steady_clock::now();
    return true;
}

void NATConnectionManager::scheduleRemove(const std::string& key, CleanupReason reason) {
    // 🔧 边界条件检查
    if (key.empty()) {
        NAT_MGR_LOGE("Invalid empty key in scheduleRemove");
        return;
    }
    
    std::lock_guard<std::mutex> lock(mutex_);
    
    // 检查连接是否存在
    auto it = connections_.find(key);
    if (it == connections_.end()) {
        return;  // 连接已被删除，忽略
    }
    
    const NATConnection& conn = it->second.conn;
    
    // 计算延迟时间
    auto delay = getDelayForReason(reason);
    auto scheduledTime = std::chrono::steady_clock::now() + delay;
    
    // 🔧 保存socket归还信息到task中，确保延迟删除时同步归还socket
    // 从clientPhysicalAddr提取IP和端口
    char clientPhysicalIP[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &conn.clientPhysicalAddr.sin_addr, clientPhysicalIP, sizeof(clientPhysicalIP));
    uint16_t clientPhysicalPort = ntohs(conn.clientPhysicalAddr.sin_port);
    
    // 🔧 检查清理队列大小，防止内存无限增长
    size_t queueSize = cleanupQueue_.size();
    if (queueSize >= MAX_CLEANUP_QUEUE_SIZE) {
        NAT_MGR_LOGE("⚠️ Cleanup queue full (size=%{public}zu), forcing immediate cleanup for key=%{public}s",
                    queueSize, key.c_str());
        // 队列已满，立即删除映射（防止内存耗尽）
        removeConnectionLocked(key);
        // 仍然需要归还socket（在锁外）
        mutex_.unlock();
        try {
            SocketConnectionPool::getInstance().returnSocket(
                conn.forwardSocket, clientPhysicalIP, clientPhysicalPort,
                conn.serverIP, conn.serverPort, conn.protocol, conn.originalRequest.addressFamily
            );
        } catch (...) {
            NAT_MGR_LOGE("Socket return failed during emergency cleanup: fd=%{public}d", conn.forwardSocket);
        }
        mutex_.lock();
        return;
    }
    
    // 告警阈值检查
    if (queueSize >= CLEANUP_QUEUE_WARN_THRESHOLD && queueSize % 1000 == 0) {
        NAT_MGR_LOGW("⚠️ Cleanup queue size high: %{public}zu (threshold=%{public}zu)",
                    queueSize, CLEANUP_QUEUE_WARN_THRESHOLD);
    }
    
    // 添加到清理队列
    CleanupTask task;
    task.key = key;
    task.socket = conn.forwardSocket;
    task.reason = reason;
    task.scheduledTime = scheduledTime;
    task.clientIP = clientPhysicalIP;
    task.clientPort = clientPhysicalPort;
    task.serverIP = conn.serverIP;
    task.serverPort = conn.serverPort;
    task.protocol = conn.protocol;
    task.addressFamily = conn.originalRequest.addressFamily;
    
    cleanupQueue_.push(task);
    
    // 🔧 更新统计（map中的值不是atomic，直接递增即可，已在mutex保护下）
    cleanupsByReason_[reason]++;
    
    NAT_MGR_LOGI("Scheduled cleanup: key=%{public}s reason=%{public}s delay=%{public}lldms (queue_size=%{public}zu)",
                key.c_str(), CleanupReasonToString(reason),
                std::chrono::duration_cast<std::chrono::milliseconds>(delay).count(),
                cleanupQueue_.size());
    
    // 通知清理线程
    cv_.notify_one();
}

void NATConnectionManager::scheduleRemoveBySocket(int socket, CleanupReason reason) {
    // 🔧 修复：使用局部作用域复制key，避免手动unlock导致的未定义行为
    std::string key;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        
        auto socketIt = socketToKey_.find(socket);
        if (socketIt == socketToKey_.end()) {
            return;  // socket不存在，忽略
        }
        
        key = socketIt->second;  // 复制key
    }  // lock_guard自动释放锁
    
    // 锁已释放，安全调用scheduleRemove
    scheduleRemove(key, reason);
}

void NATConnectionManager::removeImmediate(const std::string& key) {
    std::lock_guard<std::mutex> lock(mutex_);
    removeConnectionLocked(key);
}

void NATConnectionManager::removeImmediateBySocket(int socket) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto socketIt = socketToKey_.find(socket);
    if (socketIt == socketToKey_.end()) {
        return;
    }
    
    std::string key = socketIt->second;
    removeConnectionLocked(key);
}

void NATConnectionManager::removeConnectionLocked(const std::string& key) {
    // 调用者必须持有mutex_
    
    auto it = connections_.find(key);
    if (it == connections_.end()) {
        return;
    }
    
    int socket = it->second.conn.forwardSocket;
    
    // 删除双向映射
    socketToKey_.erase(socket);
    connections_.erase(it);
    
    // 🔧 使用relaxed内存顺序优化性能
    totalCleaned_.fetch_add(1, std::memory_order_relaxed);
    
    NAT_MGR_LOGI("🗑️ Removed connection: key=%{public}s fd=%{public}d (remaining=%{public}zu)",
                key.c_str(), socket, connections_.size());
}

std::chrono::milliseconds NATConnectionManager::getDelayForReason(CleanupReason reason) {
    using namespace std::chrono;
    
    switch (reason) {
        case CleanupReason::UDP_ADDRESS_FAIL:
            return milliseconds(1000);  // 1秒
        case CleanupReason::UDP_SEND_FAIL:
            return milliseconds(2000);  // 2秒（允许重传）
        case CleanupReason::UDP_TIMEOUT:
            return milliseconds(0);     // 立即
            
        case CleanupReason::TCP_ADDRESS_FAIL:
            return milliseconds(2000);  // 2秒
        case CleanupReason::TCP_CONNECT_FAIL:
            return milliseconds(2000);  // 2秒
        case CleanupReason::TCP_SEND_FAIL:
            return milliseconds(2000);  // 2秒
        case CleanupReason::TCP_RST_RECEIVED:
            return milliseconds(1000);  // 1秒
        case CleanupReason::TCP_CLIENT_FIN:
            return milliseconds(2000);  // 2秒
        case CleanupReason::TCP_SERVER_FIN:
            return milliseconds(5000);  // 5秒（等待客户端ACK）
        case CleanupReason::TCP_TIMEOUT:
            return milliseconds(0);     // 立即
            
        case CleanupReason::NORMAL_CLOSE:
        case CleanupReason::FORCED_CLEANUP:
            return milliseconds(0);     // 立即
            
        default:
            return milliseconds(1000);  // 默认1秒
    }
}

void NATConnectionManager::cleanupThreadFunc() {
    NAT_MGR_LOGI("Cleanup thread started");
    
    while (running_.load()) {
        std::unique_lock<std::mutex> lock(mutex_);
        
        // 等待任务或超时（100ms）
        cv_.wait_for(lock, std::chrono::milliseconds(100), [this]() {
            return !running_.load() || !cleanupQueue_.empty();
        });
        
        if (!running_.load()) {
            // 🔧 关键修复：停止前先处理所有pending任务
            size_t pendingCount = cleanupQueue_.size();
            if (pendingCount > 0) {
                NAT_MGR_LOGI("Processing %{public}zu pending cleanup tasks before stopping...",
                            pendingCount);
            }
            break;  // 跳出主循环，进入cleanup阶段
        }
        
        auto now = std::chrono::steady_clock::now();
        
        // 处理所有到期的任务
        while (!cleanupQueue_.empty()) {
            const auto& task = cleanupQueue_.top();
            
            if (task.scheduledTime > now) {
                // 队列顶部任务还未到期，等待
                break;
            }
            
            // 复制任务（因为pop会销毁）
            CleanupTask taskCopy = task;
            cleanupQueue_.pop();
            
            // 释放锁执行清理（避免长时间持锁）
            lock.unlock();
            executeCleanupTask(taskCopy);
            lock.lock();
        }
    }
    
    // 🚀 关键：停止前清理所有pending任务（立即执行，不等延迟）
    {
        std::unique_lock<std::mutex> lock(mutex_);
        size_t processedCount = 0;
        
        while (!cleanupQueue_.empty()) {
            CleanupTask taskCopy = cleanupQueue_.top();
            cleanupQueue_.pop();
            
            // 释放锁执行清理
            lock.unlock();
            executeCleanupTask(taskCopy);
            processedCount++;
            lock.lock();
        }
        
        if (processedCount > 0) {
            NAT_MGR_LOGI("Processed %{public}zu pending tasks during shutdown", processedCount);
        }
    }
    
    NAT_MGR_LOGI("✅ Cleanup thread stopped");
}

void NATConnectionManager::executeCleanupTask(const CleanupTask& task) {
    bool mappingRemoved = false;
    
    try {
        // 🔧 先在锁内删除NAT映射
        {
            std::lock_guard<std::mutex> lock(mutex_);
            
            // 检查连接是否仍然存在
            auto it = connections_.find(task.key);
            if (it == connections_.end()) {
                // 连接已被删除，可能被其他线程清理了
                return;
            }
            
            // 验证socket是否匹配（防止连接被复用）
            if (it->second.conn.forwardSocket != task.socket) {
                NAT_MGR_LOGW("Socket mismatch during cleanup: key=%{public}s expected_fd=%{public}d actual_fd=%{public}d",
                            task.key.c_str(), task.socket, it->second.conn.forwardSocket);
                return;
            }
            
            // 执行删除NAT映射
            removeConnectionLocked(task.key);
            mappingRemoved = true;
            
            NAT_MGR_LOGI("✅ Cleanup executed: key=%{public}s reason=%{public}s fd=%{public}d",
                        task.key.c_str(), CleanupReasonToString(task.reason), task.socket);
        }
        
        // 🚀 关键修复：在锁外归还socket到连接池
        // 即使returnSocket失败，也要记录错误（socket可能泄漏）
        try {
            SocketConnectionPool::getInstance().returnSocket(
                task.socket, 
                task.clientIP, task.clientPort,
                task.serverIP, task.serverPort,
                task.protocol, task.addressFamily
            );
            
            NAT_MGR_LOGI("🔙 Socket returned to pool: fd=%{public}d protocol=%{public}s",
                        task.socket, task.protocol == PROTOCOL_TCP ? "TCP" : "UDP");
        } catch (const std::exception& e) {
            // ⚠️ Socket可能泄漏，但NAT映射已删除
            NAT_MGR_LOGE("Socket return failed: fd=%{public}d error=%{public}s (POTENTIAL SOCKET LEAK)",
                        task.socket, e.what());
            totalCleanupErrors_.fetch_add(1, std::memory_order_relaxed);
        }
        
    } catch (const std::exception& e) {
        NAT_MGR_LOGE("Cleanup failed: key=%{public}s error=%{public}s mapping_removed=%{public}d",
                    task.key.c_str(), e.what(), mappingRemoved ? 1 : 0);
        totalCleanupErrors_.fetch_add(1, std::memory_order_relaxed);
    }
}

NATConnectionManager::Stats NATConnectionManager::getStats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    Stats stats;
    stats.activeConnections = connections_.size();
    stats.pendingCleanups = cleanupQueue_.size();
    stats.totalCreated = totalCreated_.load();
    stats.totalCleaned = totalCleaned_.load();
    stats.totalCleanupErrors = totalCleanupErrors_.load();
    stats.cleanupsByReason = cleanupsByReason_;
    
    return stats;
}

std::vector<int> NATConnectionManager::getAllActiveSockets() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<int> sockets;
    sockets.reserve(socketToKey_.size());
    
    for (const auto& pair : socketToKey_) {
        if (pair.first >= 0) {
            sockets.push_back(pair.first);
        }
    }
    
    NAT_MGR_LOGI("Retrieved %{public}zu active sockets", sockets.size());
    return sockets;
}

void NATConnectionManager::cleanupExpired(int timeoutSeconds) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto now = std::chrono::steady_clock::now();
    auto timeout = std::chrono::seconds(timeoutSeconds);
    
    std::vector<std::string> expiredKeys;
    
    for (const auto& pair : connections_) {
        auto age = now - pair.second.lastActivity;
        if (age > timeout) {
            expiredKeys.push_back(pair.first);
        }
    }
    
    for (const auto& key : expiredKeys) {
        removeConnectionLocked(key);
    }
    
    if (!expiredKeys.empty()) {
        NAT_MGR_LOGI("Cleaned up %{public}zu expired connections (timeout=%{public}ds)",
                    expiredKeys.size(), timeoutSeconds);
    }
}

void NATConnectionManager::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    size_t count = connections_.size();
    connections_.clear();
    socketToKey_.clear();
    
    // 清空清理队列
    while (!cleanupQueue_.empty()) {
        cleanupQueue_.pop();
    }
    
    if (count > 0) {
        NAT_MGR_LOGI("🧹 Cleared all connections: %{public}zu", count);
    }
}

std::string NATConnectionManager::generateKey(const PacketInfo& info, 
                                              const sockaddr_in& clientPhysicalAddr) {
    char clientIP[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &clientPhysicalAddr.sin_addr, clientIP, sizeof(clientIP));
    int clientPort = ntohs(clientPhysicalAddr.sin_port);
    
    return generateKeyInternal(info.sourceIP, info.sourcePort,
                              info.targetIP, info.targetPort,
                              info.protocol, clientIP, clientPort);
}

std::string NATConnectionManager::generateKey(
    const std::string& clientVirtualIP, int clientVirtualPort,
    const std::string& serverIP, int serverPort,
    uint8_t protocol,
    const std::string& clientPhysicalIP, int clientPhysicalPort
) {
    return generateKeyInternal(clientVirtualIP, clientVirtualPort,
                              serverIP, serverPort,
                              protocol, clientPhysicalIP, clientPhysicalPort);
}

std::string NATConnectionManager::generateKeyInternal(
    const std::string& clientVirtualIP, int clientVirtualPort,
    const std::string& serverIP, int serverPort,
    uint8_t protocol,
    const std::string& clientPhysicalIP, int clientPhysicalPort
) {
    std::ostringstream oss;
    // 格式: physicalIP:physicalPort/virtualIP:virtualPort->serverIP:serverPort/proto
    oss << clientPhysicalIP << ":" << clientPhysicalPort << "/"
        << clientVirtualIP << ":" << clientVirtualPort << "->"
        << serverIP << ":" << serverPort << "/"
        << (protocol == PROTOCOL_TCP ? "TCP" : "UDP");
    return oss.str();
}
