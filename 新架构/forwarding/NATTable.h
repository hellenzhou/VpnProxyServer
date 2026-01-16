#pragma once

#include <unordered_map>
#include <shared_mutex>
#include <array>
#include <optional>
#include <chrono>
#include <memory>
#include <functional>
#include "../network/SocketAddress.h"

namespace vpn {
namespace forwarding {

/**
 * @brief 协议类型
 */
enum class Protocol : uint8_t {
    TCP = 6,
    UDP = 17
};

/**
 * @brief 会话密钥
 * 用于唯一标识一个 NAT 会话
 */
struct SessionKey {
    std::string clientVirtualIP;   // 客户端虚拟 IP
    uint16_t clientVirtualPort;     // 客户端虚拟端口
    std::string serverIP;           // 服务器 IP
    uint16_t serverPort;            // 服务器端口
    Protocol protocol;              // 协议类型
    
    /**
     * @brief 计算哈希值
     */
    size_t Hash() const {
        size_t h1 = std::hash<std::string>{}(clientVirtualIP);
        size_t h2 = std::hash<uint16_t>{}(clientVirtualPort);
        size_t h3 = std::hash<std::string>{}(serverIP);
        size_t h4 = std::hash<uint16_t>{}(serverPort);
        size_t h5 = std::hash<uint8_t>{}(static_cast<uint8_t>(protocol));
        
        // 组合哈希
        return h1 ^ (h2 << 1) ^ (h3 << 2) ^ (h4 << 3) ^ (h5 << 4);
    }
    
    /**
     * @brief 比较相等
     */
    bool operator==(const SessionKey& other) const {
        return clientVirtualIP == other.clientVirtualIP &&
               clientVirtualPort == other.clientVirtualPort &&
               serverIP == other.serverIP &&
               serverPort == other.serverPort &&
               protocol == other.protocol;
    }
    
    /**
     * @brief 转换为字符串（用于日志）
     */
    std::string ToString() const;
};

/**
 * @brief NAT 会话条目
 */
struct NATEntry {
    network::SocketAddress clientPhysicalAddr;  // 客户端物理地址
    int forwardSocketFd;                         // 转发 socket 文件描述符
    std::chrono::steady_clock::time_point lastActivity;  // 最后活动时间
    
    // 统计信息
    uint64_t packetsForwarded = 0;
    uint64_t bytesForwarded = 0;
    
    /**
     * @brief 检查会话是否过期
     */
    bool IsExpired(std::chrono::seconds timeout) const {
        auto now = std::chrono::steady_clock::now();
        return (now - lastActivity) > timeout;
    }
    
    /**
     * @brief 更新活动时间
     */
    void UpdateActivity() {
        lastActivity = std::chrono::steady_clock::now();
    }
};

/**
 * @brief 高性能 NAT 映射表
 * 
 * 特性：
 * - 分段锁设计，提高并发性能
 * - 读写锁，读操作不互斥
 * - 自动清理过期会话
 * - 线程安全
 */
class NATTable {
public:
    /**
     * @brief 构造函数
     * @param numShards 分片数量（必须是 2 的幂，建议 16-256）
     */
    explicit NATTable(size_t numShards = 16);
    
    /**
     * @brief 析构函数
     */
    ~NATTable();
    
    // 禁止拷贝和移动
    NATTable(const NATTable&) = delete;
    NATTable& operator=(const NATTable&) = delete;
    
    /**
     * @brief 创建 NAT 映射
     * @param key 会话密钥
     * @param entry NAT 条目
     * @return true 成功，false 失败（已存在）
     */
    bool CreateMapping(const SessionKey& key, NATEntry entry);
    
    /**
     * @brief 查找 NAT 映射
     * @param key 会话密钥
     * @return NAT 条目，不存在返回 nullopt
     */
    std::optional<NATEntry> FindMapping(const SessionKey& key);
    
    /**
     * @brief 更新 NAT 映射
     * @param key 会话密钥
     * @param updater 更新函数（接收 NATEntry& 参数）
     * @return true 成功，false 失败（不存在）
     */
    bool UpdateMapping(const SessionKey& key, 
                      std::function<void(NATEntry&)> updater);
    
    /**
     * @brief 移除 NAT 映射
     * @param key 会话密钥
     * @return true 成功，false 失败（不存在）
     */
    bool RemoveMapping(const SessionKey& key);
    
    /**
     * @brief 清理过期会话
     * @param timeout 超时时间
     * @return 清理的会话数量
     */
    size_t CleanupExpired(std::chrono::seconds timeout);
    
    /**
     * @brief 清空所有映射
     */
    void Clear();
    
    /**
     * @brief 获取映射数量
     */
    size_t GetSize() const;
    
    /**
     * @brief 获取统计信息
     */
    struct Stats {
        size_t totalMappings = 0;
        size_t activeMappings = 0;
        uint64_t lookupsTotal = 0;
        uint64_t lookupsSuccess = 0;
        uint64_t insertsTotal = 0;
        uint64_t insertsSuccess = 0;
        uint64_t removalsTotal = 0;
    };
    
    Stats GetStats() const;
    
    /**
     * @brief 遍历所有映射（仅用于调试/监控）
     * @param visitor 访问器函数
     */
    void ForEach(std::function<void(const SessionKey&, const NATEntry&)> visitor) const;

private:
    struct Shard {
        std::unordered_map<SessionKey, NATEntry, 
                          std::function<size_t(const SessionKey&)>> entries;
        mutable std::shared_mutex mutex;  // 读写锁
        
        Shard() : entries(16, [](const SessionKey& key) { return key.Hash(); }) {}
    };
    
    std::vector<Shard> shards_;
    mutable Stats stats_;
    
    /**
     * @brief 获取密钥对应的分片
     */
    Shard& GetShard(const SessionKey& key);
    const Shard& GetShard(const SessionKey& key) const;
};

} // namespace forwarding
} // namespace vpn

/**
 * @brief SessionKey 的哈希特化（用于 std::unordered_map）
 */
namespace std {
    template<>
    struct hash<vpn::forwarding::SessionKey> {
        size_t operator()(const vpn::forwarding::SessionKey& key) const {
            return key.Hash();
        }
    };
}
