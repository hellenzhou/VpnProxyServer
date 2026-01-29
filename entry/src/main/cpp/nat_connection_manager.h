/*
 * NAT连接管理器 - 统一的连接生命周期管理
 * 
 * 设计目标：
 * 1. 统一所有NAT映射的创建、更新、删除逻辑
 * 2. 使用单一后台清理线程代替多个detached线程
 * 3. 提供显式的TCP状态机
 * 4. 减少代码重复和维护成本
 */

#pragma once

#include <string>
#include <unordered_map>
#include <queue>
#include <vector>
#include <mutex>
#include <condition_variable>
#include <thread>
#include <atomic>
#include <chrono>
#include <functional>
#include <netinet/in.h>
#include "protocol_handler.h"
#include "nat_table.h"  // 需要完整定义NATConnection
#include "thread_safe_queue.h"  // 使用自定义的Optional类

// ===== 清理原因枚举 =====
// 每种原因对应不同的延迟时间和清理策略
enum class CleanupReason {
    // UDP相关
    UDP_ADDRESS_FAIL,       // UDP地址解析失败 - 1秒延迟
    UDP_SEND_FAIL,          // UDP发送失败 - 2秒延迟（允许重传）
    UDP_TIMEOUT,            // UDP超时 - 立即删除
    
    // TCP相关
    TCP_ADDRESS_FAIL,       // TCP地址解析失败 - 2秒延迟
    TCP_CONNECT_FAIL,       // TCP连接失败 - 2秒延迟
    TCP_SEND_FAIL,          // TCP发送失败 - 2秒延迟（发送RST后）
    TCP_RST_RECEIVED,       // 收到RST - 1秒延迟
    TCP_CLIENT_FIN,         // 客户端FIN - 2秒延迟（等待最后ACK）
    TCP_SERVER_FIN,         // 服务器FIN - 5秒延迟（等待客户端ACK）
    TCP_TIMEOUT,            // TCP超时 - 立即删除
    
    // 通用
    NORMAL_CLOSE,           // 正常关闭 - 立即删除
    FORCED_CLEANUP          // 强制清理（服务器停止） - 立即删除
};

// 获取清理原因的可读名称
const char* CleanupReasonToString(CleanupReason reason);

// ===== TCP状态机 =====
class TcpStateMachine {
public:
    // TCP状态定义（与NATConnection::TcpState保持一致）
    enum class State : uint8_t {
        NONE = 0,           // 初始状态
        CONNECTING = 1,     // 后端连接中，未发送SYN-ACK
        SYN_RECEIVED = 2,   // 已发送SYN-ACK给客户端
        ESTABLISHED = 3,    // 连接已建立
        FIN_SENT = 4,       // FIN已发送
        CLOSED = 5          // 连接已关闭
    };
    
    // 状态转换事件
    bool onSynReceived(NATConnection& conn, uint32_t clientIsn);
    bool onSynAckSent(NATConnection& conn, uint32_t serverIsn);
    bool onEstablished(NATConnection& conn);
    bool onFinReceived(NATConnection& conn, bool fromClient);
    bool onRstReceived(NATConnection& conn);
    
    // 验证状态转换是否合法
    bool isValidTransition(State from, State to) const;
    
    // 状态到字符串
    static const char* StateToString(State state);
};

// ===== NAT连接管理器 =====
class NATConnectionManager {
public:
    // 单例模式
    static NATConnectionManager& getInstance();
    
    // 禁止拷贝和赋值
    NATConnectionManager(const NATConnectionManager&) = delete;
    NATConnectionManager& operator=(const NATConnectionManager&) = delete;
    
    // ===== 连接生命周期管理 =====
    
    // 连接句柄（安全的连接标识符）
    struct ConnectionHandle {
        std::string key;
        int socket;
        
        ConnectionHandle() : socket(-1) {}
        ConnectionHandle(const std::string& k, int s) : key(k), socket(s) {}
        
        bool isValid() const { return !key.empty() && socket >= 0; }
    };
    
    // 创建新连接（返回句柄）
    ConnectionHandle createConnection(
        const PacketInfo& packetInfo,
        const sockaddr_in& clientAddr,
        int forwardSocket
    );
    
    // 查询连接（使用自定义Optional类，兼容HarmonyOS）
    Optional<NATConnection> findConnection(const std::string& key);
    Optional<NATConnection> findConnectionBySocket(int socket);
    
    // 更新连接活动时间（自动调用，通常不需要手动调用）
    void updateActivity(const std::string& key);
    
    // 在持有锁的情况下修改连接（用于原子更新TCP状态等）
    // 注意：回调函数必须快速执行，不能做网络I/O
    bool withConnection(const std::string& key, const std::function<void(NATConnection&)>& fn);
    bool withConnectionBySocket(int socket, const std::function<void(NATConnection&)>& fn);
    
    // ===== 统一的清理策略 =====
    
    // 调度删除（根据原因自动决定延迟时间）
    void scheduleRemove(const std::string& key, CleanupReason reason);
    void scheduleRemoveBySocket(int socket, CleanupReason reason);
    
    // 立即删除（仅用于测试或特殊情况）
    void removeImmediate(const std::string& key);
    void removeImmediateBySocket(int socket);
    
    // ===== 生命周期管理 =====
    
    // 启动后台清理线程
    bool start();
    
    // 停止并等待所有pending任务完成
    void stop();
    
    // 检查是否正在运行
    bool isRunning() const { return running_.load(); }
    
    // ===== 统计和监控 =====
    
    struct Stats {
        size_t activeConnections;        // 当前活跃连接数
        size_t pendingCleanups;          // 待清理任务数
        uint64_t totalCreated;           // 总创建连接数
        uint64_t totalCleaned;           // 总清理连接数
        uint64_t totalCleanupErrors;     // 清理错误数
        
        // 按原因分类的清理统计
        std::unordered_map<CleanupReason, uint64_t> cleanupsByReason;
    };
    
    Stats getStats() const;
    
    // 获取所有活跃socket（用于服务器停止时强制关闭）
    std::vector<int> getAllActiveSockets();
    
    // 清理过期连接（通常由后台线程自动调用）
    void cleanupExpired(int timeoutSeconds = 300);
    
    // 清空所有连接（用于测试或重启）
    void clear();
    
    // ===== 兼容性接口（向后兼容旧的NATTable API） =====
    
    // 生成NAT映射key（与NATTable兼容）
    static std::string generateKey(const PacketInfo& info, const sockaddr_in& clientPhysicalAddr);
    static std::string generateKey(
        const std::string& clientVirtualIP, int clientVirtualPort,
        const std::string& serverIP, int serverPort,
        uint8_t protocol,
        const std::string& clientPhysicalIP, int clientPhysicalPort
    );
    
private:
    NATConnectionManager();
    ~NATConnectionManager();
    
    // ===== 常量定义 =====
    static constexpr size_t MAX_CLEANUP_QUEUE_SIZE = 10000;  // 清理队列最大容量
    static constexpr size_t CLEANUP_QUEUE_WARN_THRESHOLD = 5000;  // 告警阈值
    
    // ===== 内部数据结构 =====
    
    // 连接条目（包含连接信息和元数据）
    struct ConnectionEntry {
        NATConnection conn;
        std::chrono::steady_clock::time_point createdAt;
        std::chrono::steady_clock::time_point lastActivity;
        
        ConnectionEntry() : createdAt(std::chrono::steady_clock::now()),
                           lastActivity(std::chrono::steady_clock::now()) {}
    };
    
    // 清理任务
    struct CleanupTask {
        std::string key;
        int socket;
        CleanupReason reason;
        std::chrono::steady_clock::time_point scheduledTime;
        
        // Socket归还信息（用于在清理时同步归还socket）
        std::string clientIP;
        uint16_t clientPort;
        std::string serverIP;
        uint16_t serverPort;
        uint8_t protocol;
        int addressFamily;
        
        // 用于优先队列排序（最早的任务优先）
        bool operator>(const CleanupTask& other) const {
            return scheduledTime > other.scheduledTime;
        }
    };
    
    // ===== 数据成员 =====
    
    // 连接映射
    std::unordered_map<std::string, ConnectionEntry> connections_;
    std::unordered_map<int, std::string> socketToKey_;
    
    // 清理任务队列（按时间排序，最早的任务在顶部）
    std::priority_queue<CleanupTask, std::vector<CleanupTask>, std::greater<CleanupTask>> cleanupQueue_;
    
    // TCP状态机
    TcpStateMachine tcpStateMachine_;
    
    // 同步原语
    mutable std::mutex mutex_;
    std::condition_variable cv_;
    
    // 后台清理线程
    std::thread cleanupThread_;
    std::atomic<bool> running_{false};
    
    // 统计数据
    std::atomic<uint64_t> totalCreated_{0};
    std::atomic<uint64_t> totalCleaned_{0};
    std::atomic<uint64_t> totalCleanupErrors_{0};
    
    // 按原因分类的清理统计（需要mutex保护）
    std::unordered_map<CleanupReason, uint64_t> cleanupsByReason_;
    
    // ===== 内部方法 =====
    
    // 后台清理线程函数
    void cleanupThreadFunc();
    
    // 执行单个清理任务
    void executeCleanupTask(const CleanupTask& task);
    
    // 根据原因获取延迟时间
    static std::chrono::milliseconds getDelayForReason(CleanupReason reason);
    
    // 内部删除连接（不加锁，调用者需持有mutex_）
    void removeConnectionLocked(const std::string& key);
    
    // 生成NAT key的内部实现
    static std::string generateKeyInternal(
        const std::string& clientVirtualIP, int clientVirtualPort,
        const std::string& serverIP, int serverPort,
        uint8_t protocol,
        const std::string& clientPhysicalIP, int clientPhysicalPort
    );
};
