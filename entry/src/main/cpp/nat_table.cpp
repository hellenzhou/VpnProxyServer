/*
 * NAT映射表实现 - 管理VPN连接状态
 */

#include "nat_table.h"
#include <vector>
#include <hilog/log.h>
#include <sstream>
#include <arpa/inet.h>

#define MAKE_FILE_NAME (strrchr(__FILE__, '/') ? (strrchr(__FILE__, '/') + 1) : __FILE__)

// 🔧 添加LOG_INFO和LOG_ERROR宏定义
#define LOG_INFO(fmt, ...) \
  OH_LOG_Print(LOG_APP, LOG_INFO, 0x15b1, "VpnServer", "ZHOUB [%{public}s:%{public}d] " fmt, MAKE_FILE_NAME, __LINE__, ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...) \
  OH_LOG_Print(LOG_APP, LOG_ERROR, 0x15b1, "VpnServer", "ZHOUB [%{public}s:%{public}d] " fmt, MAKE_FILE_NAME, __LINE__, ##__VA_ARGS__)

// 🔧 NAT日志级别控制
// 0 = 关闭所有日志
// 1 = 仅错误和关键操作（创建/删除映射仅记录总数）
// 2 = 详细日志（每个映射的详细信息）
#define NAT_LOG_LEVEL 1

#if NAT_LOG_LEVEL >= 2
  #define NAT_LOG_DEBUG(fmt, ...) \
    OH_LOG_Print(LOG_APP, LOG_INFO, 0x15b1, "VpnServer", "ZHOUB [NAT] [%{public}s:%{public}d] " fmt, MAKE_FILE_NAME, __LINE__, ##__VA_ARGS__)
  #define NAT_LOGI(fmt, ...) \
    OH_LOG_Print(LOG_APP, LOG_INFO, 0x15b1, "VpnServer", "ZHOUB [NAT] [%{public}s:%{public}d] " fmt, MAKE_FILE_NAME, __LINE__, ##__VA_ARGS__)
  #define NAT_LOGE(fmt, ...) \
    OH_LOG_Print(LOG_APP, LOG_ERROR, 0x15b1, "VpnServer", "ZHOUB [NAT] [%{public}s:%{public}d] " fmt, MAKE_FILE_NAME, __LINE__, ##__VA_ARGS__)
#elif NAT_LOG_LEVEL >= 1
  #define NAT_LOG_DEBUG(fmt, ...) /* 详细日志已禁用 */
  #define NAT_LOGI(fmt, ...) \
    OH_LOG_Print(LOG_APP, LOG_INFO, 0x15b1, "VpnServer", "ZHOUB [NAT] [%{public}s:%{public}d] " fmt, MAKE_FILE_NAME, __LINE__, ##__VA_ARGS__)
  #define NAT_LOGE(fmt, ...) \
    OH_LOG_Print(LOG_APP, LOG_ERROR, 0x15b1, "VpnServer", "ZHOUB [NAT] [%{public}s:%{public}d] " fmt, MAKE_FILE_NAME, __LINE__, ##__VA_ARGS__)
#else
  #define NAT_LOG_DEBUG(fmt, ...) /* 日志已禁用 */
  #define NAT_LOGI(fmt, ...) /* 日志已禁用 */
  #define NAT_LOGE(fmt, ...) /* 日志已禁用 */
#endif

// 静态成员初始化
std::unordered_map<std::string, NATConnection> NATTable::mappings_;
std::unordered_map<int, std::string> NATTable::socketToKey_;
std::mutex NATTable::mutex_;

// 创建NAT映射
bool NATTable::CreateMapping(const std::string& key,
                            const sockaddr_in& clientPhysicalAddr,
                            const PacketInfo& packetInfo,
                            int forwardSocket) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // 🚨 并发安全：禁止“同key覆盖不同socket”
    // 覆盖会导致：
    // - socketToKey_ 失配（旧socket收到了响应却找不到key）
    // - TCP/UDP 回包线程通过 socket 查映射失败，表现为“客户端几乎收不到响应”
    // 真实场景：多个 Forward worker 同时处理同一 flow（DNS重传/SYN重传）时会发生。
    auto existingIt = mappings_.find(key);
    if (existingIt != mappings_.end()) {
        int oldSocket = existingIt->second.forwardSocket;
        if (oldSocket == forwardSocket) {
            // 同一socket重复创建：只更新活动时间与原始请求（用于构包）
            existingIt->second.lastActivity = std::chrono::steady_clock::now();
            existingIt->second.originalRequest = packetInfo;
            return true;
        }
        NAT_LOGE("🚨 Refuse to overwrite NAT mapping: key=%{public}s old_fd=%{public}d new_fd=%{public}d proto=%{public}s",
                 key.c_str(), oldSocket, forwardSocket,
                 packetInfo.protocol == PROTOCOL_TCP ? "TCP" : "UDP");
        return false;
    }

    NATConnection conn;
    conn.clientPhysicalAddr = clientPhysicalAddr;
    conn.clientVirtualIP = packetInfo.sourceIP;
    conn.clientVirtualPort = packetInfo.sourcePort;
    conn.serverIP = packetInfo.targetIP;
    conn.serverPort = packetInfo.targetPort;
    conn.forwardSocket = forwardSocket;
    conn.protocol = packetInfo.protocol;
    conn.lastActivity = std::chrono::steady_clock::now();
    conn.originalRequest = packetInfo;

    mappings_[key] = conn;
    socketToKey_[forwardSocket] = key;
    
    // 仅在详细日志模式下打印详细信息
    NAT_LOG_DEBUG("✅ Created NAT mapping: %{public}s", key.c_str());
    
    if (NAT_LOG_LEVEL >= 2) {
        char clientPhysicalIP[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &clientPhysicalAddr.sin_addr, clientPhysicalIP, sizeof(clientPhysicalIP));
        int clientPhysicalPort = ntohs(clientPhysicalAddr.sin_port);
        
        NAT_LOG_DEBUG("   Client Physical: %{public}s:%{public}d", clientPhysicalIP, clientPhysicalPort);
        NAT_LOG_DEBUG("   Client Virtual: %{public}s:%{public}d", conn.clientVirtualIP.c_str(), conn.clientVirtualPort);
        NAT_LOG_DEBUG("   Server: %{public}s:%{public}d", conn.serverIP.c_str(), conn.serverPort);
        NAT_LOG_DEBUG("   Forward Socket: %{public}d, Protocol: %{public}s", 
                 forwardSocket, packetInfo.protocol == PROTOCOL_TCP ? "TCP" : "UDP");
        NAT_LOG_DEBUG("   Total mappings: %{public}zu", mappings_.size());
    }
    
    // 仅在创建新映射且是重要协议时记录简要信息
    if (packetInfo.protocol == PROTOCOL_TCP || packetInfo.targetPort == 53) {
        NAT_LOGI("✅ NAT: %{public}s -> %{public}s:%{public}d/%{public}s (total: %{public}zu)", 
                 conn.clientVirtualIP.c_str(), conn.serverIP.c_str(), conn.serverPort,
                 packetInfo.protocol == PROTOCOL_TCP ? "TCP" : "UDP", mappings_.size());
    }
    
    return true;
}

bool NATTable::WithConnection(const std::string& key, const std::function<void(NATConnection&)>& fn)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = mappings_.find(key);
    if (it == mappings_.end()) {
        return false;
    }
    fn(it->second);
    it->second.lastActivity = std::chrono::steady_clock::now();
    return true;
}

bool NATTable::WithConnectionBySocket(int forwardSocket, const std::function<void(NATConnection&)>& fn)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto socketIt = socketToKey_.find(forwardSocket);
    if (socketIt == socketToKey_.end()) {
        return false;
    }
    auto connIt = mappings_.find(socketIt->second);
    if (connIt == mappings_.end()) {
        return false;
    }
    fn(connIt->second);
    connIt->second.lastActivity = std::chrono::steady_clock::now();
    return true;
}

// 查找NAT映射
bool NATTable::FindMapping(const std::string& key, NATConnection& conn) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = mappings_.find(key);
    if (it != mappings_.end()) {
        conn = it->second;
        return true;
    }
    
    return false;
}

// 通过socket查找映射
bool NATTable::FindMappingBySocket(int forwardSocket, NATConnection& conn) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = socketToKey_.find(forwardSocket);
    if (it != socketToKey_.end()) {
        const std::string& key = it->second;
        auto connIt = mappings_.find(key);
        if (connIt != mappings_.end()) {
            conn = connIt->second;
            return true;
        } else {
            LOG_ERROR("socket存在但映射不存在: socket=%d, key=%s", forwardSocket, key.c_str());
        }
    }
    
    return false;
}

// 更新活动时间
void NATTable::UpdateActivity(const std::string& key) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = mappings_.find(key);
    if (it != mappings_.end()) {
        it->second.lastActivity = std::chrono::steady_clock::now();
    }
}

// 移除映射
void NATTable::RemoveMapping(const std::string& key) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = mappings_.find(key);
    if (it != mappings_.end()) {
        int socket = it->second.forwardSocket;
        socketToKey_.erase(socket);
        mappings_.erase(it);
        NAT_LOG_DEBUG("🗑️ Removed NAT mapping: %{public}s, remaining: %{public}zu", 
                 key.c_str(), mappings_.size());
    }
}

// 通过socket移除映射
void NATTable::RemoveMappingBySocket(int forwardSocket) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto socketIt = socketToKey_.find(forwardSocket);
    if (socketIt != socketToKey_.end()) {
        std::string key = socketIt->second;
        
        // 🚨 修复：先清理socketToKey_，再清理mappings_，避免不一致
        socketToKey_.erase(socketIt);
        
        auto it = mappings_.find(key);
        if (it != mappings_.end()) {
            mappings_.erase(it);
        }
    }
}

// 清理过期映射
void NATTable::CleanupExpired(int timeoutSeconds) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto now = std::chrono::steady_clock::now();
    auto timeout = std::chrono::seconds(timeoutSeconds);
    
    std::vector<std::string> expiredKeys;
    
    for (const auto& pair : mappings_) {
        auto age = now - pair.second.lastActivity;
        if (age > timeout) {
            expiredKeys.push_back(pair.first);
        }
    }
    
    for (const auto& key : expiredKeys) {
        auto it = mappings_.find(key);
        if (it != mappings_.end()) {
            int socket = it->second.forwardSocket;
            socketToKey_.erase(socket);
            mappings_.erase(it);
        }
    }
    
    if (!expiredKeys.empty()) {
        NAT_LOG_DEBUG("🧹 Cleaned up %{public}zu expired mappings, remaining: %{public}zu",
                 expiredKeys.size(), mappings_.size());
    }
}

// 生成映射key
std::string NATTable::GenerateKey(const PacketInfo& info, const sockaddr_in& clientPhysicalAddr) {
    char clientIP[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &clientPhysicalAddr.sin_addr, clientIP, sizeof(clientIP));
    int clientPort = ntohs(clientPhysicalAddr.sin_port);

    return GenerateKey(info.sourceIP, info.sourcePort,
                      info.targetIP, info.targetPort,
                      info.protocol, clientIP, clientPort);
}

std::string NATTable::GenerateKey(const std::string& clientVirtualIP,
                                  int clientVirtualPort,
                                  const std::string& serverIP,
                                  int serverPort,
                                  uint8_t protocol,
                                  const std::string& clientPhysicalIP,
                                  int clientPhysicalPort) {
    std::ostringstream oss;
    // NAT key MUST be stable per flow, otherwise mappings will churn and TCP state is impossible.
    // Format: physicalIP:physicalPort/virtualIP:virtualPort->serverIP:serverPort/proto
    oss << clientPhysicalIP << ":" << clientPhysicalPort << "/"
        << clientVirtualIP << ":" << clientVirtualPort << "->"
        << serverIP << ":" << serverPort << "/"
        << (protocol == PROTOCOL_TCP ? "TCP" : "UDP");
    return oss.str();
}

// 获取映射数量
int NATTable::GetMappingCount() {
    std::lock_guard<std::mutex> lock(mutex_);
    return mappings_.size();
}

// 清空所有映射
void NATTable::Clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    size_t count = mappings_.size();
    mappings_.clear();
    socketToKey_.clear();
    
    if (count > 0) {
        NAT_LOGI("🧹 Cleared all NAT mappings: %{public}zu", count);
    }
}

// 🚨 获取所有活跃的转发socket（用于强制关闭）
std::vector<int> NATTable::GetAllActiveSockets() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<int> sockets;
    sockets.reserve(socketToKey_.size());
    
    for (const auto& pair : socketToKey_) {
        if (pair.first >= 0) {  // 有效的socket fd
            sockets.push_back(pair.first);
        }
    }
    
    LOG_INFO("ZHOUB [清理] 获取到 %zu 个活跃的转发socket", sockets.size());
    return sockets;
}
