/*
 * NAT映射表实现 - 管理VPN连接状态
 */

#include "nat_table.h"
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
    
    // 检查是否是新映射还是更新
    bool isNewMapping = (mappings_.find(key) == mappings_.end());
    
    // 🔧 监控：检查是否覆盖现有映射
    if (!isNewMapping) {
        LOG_ERROR("ZHOUB 🚨🚨🚨 覆盖现有NAT映射! key=%s", key.c_str());
        LOG_ERROR("ZHOUB 🚨🚨🚨 原有socket=%d, 新socket=%d", mappings_[key].forwardSocket, forwardSocket);
    }
    
    mappings_[key] = conn;
    mappings_[key].lastActivity = std::chrono::steady_clock::now();  // 🔧 修复：设置活动时间
    socketToKey_[forwardSocket] = key;
    
    // 🔧 监控：检查socketToKey_映射是否建立成功
    LOG_ERROR("ZHOUB 🚨🚨🚨 socketToKey_映射建立: socket=%d -> key=%s", forwardSocket, key.c_str());
    LOG_ERROR("ZHOUB 🚨🚨🚨 socketToKey_大小=%zu, mappings_大小=%zu", socketToKey_.size(), mappings_.size());
    
    // 🔧 验证映射是否正确
    auto verifyIt = socketToKey_.find(forwardSocket);
    if (verifyIt != socketToKey_.end()) {
        LOG_ERROR("ZHOUB 🚨🚨🚨 socketToKey_映射验证成功: %s", verifyIt->second.c_str());
    } else {
        LOG_ERROR("ZHOUB 🚨🚨🚨 socketToKey_映射验证失败! socket=%d", forwardSocket);
    }
    
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
    if (isNewMapping && (packetInfo.protocol == PROTOCOL_TCP || packetInfo.targetPort == 53)) {
        NAT_LOGI("✅ NAT: %{public}s -> %{public}s:%{public}d/%{public}s (total: %{public}zu)", 
                 conn.clientVirtualIP.c_str(), conn.serverIP.c_str(), conn.serverPort,
                 packetInfo.protocol == PROTOCOL_TCP ? "TCP" : "UDP", mappings_.size());
    }
    
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
            LOG_INFO("✅ NAT映射查找成功: socket=%d -> key=%s", forwardSocket, key.c_str());
            return true;
        } else {
            LOG_ERROR("❌ socket存在但映射不存在: socket=%d, key=%s", forwardSocket, key.c_str());
        }
    } else {
        LOG_ERROR("❌ socket不存在: socket=%d", forwardSocket);
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
    
    // 🔧 强制输出删除日志
    LOG_ERROR("ZHOUB 🚨🚨🚨 NAT映射删除! key=%s", key.c_str());
    LOG_ERROR("ZHOUB 🚨🚨🚨 调用栈: 正在删除NAT映射");
    LOG_ERROR("ZHOUB 🚨🚨🚨 删除前: socketToKey_大小=%zu, mappings_大小=%zu", socketToKey_.size(), mappings_.size());
    
    auto it = mappings_.find(key);
    if (it != mappings_.end()) {
        int socket = it->second.forwardSocket;
        
        // 🔧 检查socketToKey_中是否存在这个socket
        auto socketIt = socketToKey_.find(socket);
        if (socketIt != socketToKey_.end()) {
            LOG_ERROR("ZHOUB 🚨🚨🚨 socketToKey_中找到socket: %d -> %s", socket, socketIt->second.c_str());
        } else {
            LOG_ERROR("ZHOUB 🚨🚨🚨 socketToKey_中未找到socket: %d", socket);
        }
        
        socketToKey_.erase(socket);
        mappings_.erase(it);
        
        LOG_ERROR("ZHOUB 🚨🚨🚨 映射已删除: socket=%d, 剩余映射数=%zu", socket, mappings_.size());
        LOG_ERROR("ZHOUB 🚨🚨🚨 删除后: socketToKey_大小=%zu, mappings_大小=%zu", socketToKey_.size(), mappings_.size());
        NAT_LOG_DEBUG("🗑️ Removed NAT mapping: %{public}s, remaining: %{public}zu", 
                 key.c_str(), mappings_.size());
    } else {
        LOG_ERROR("ZHOUB 🚨🚨🚨 映射不存在: key=%s", key.c_str());
    }
}

// 通过socket移除映射
void NATTable::RemoveMappingBySocket(int forwardSocket) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto socketIt = socketToKey_.find(forwardSocket);
    if (socketIt != socketToKey_.end()) {
        std::string key = socketIt->second;
        
        auto it = mappings_.find(key);
        if (it != mappings_.end()) {
            LOG_INFO("🧹 通过socket清理NAT映射: fd=%d, key=%s", forwardSocket, key.c_str());
            
            socketToKey_.erase(socketIt);
            mappings_.erase(it);
            
            LOG_INFO("✅ NAT映射清理完成: fd=%d, 剩余映射数=%zu", forwardSocket, mappings_.size());
        } else {
            LOG_ERROR("❌ socket存在但映射不存在: fd=%d, key=%s", forwardSocket, key.c_str());
        }
    } else {
        LOG_ERROR("❌ socket不存在于映射中: fd=%d", forwardSocket);
    }
}

// 清理过期映射
void NATTable::CleanupExpired(int timeoutSeconds) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // 🔧 强制输出清理日志
    LOG_ERROR("ZHOUB 🚨🚨🚨 CleanupExpired被调用! timeout=%d秒", timeoutSeconds);
    LOG_ERROR("ZHOUB 🚨🚨🚨 调用栈: 正在清理过期NAT映射");
    LOG_ERROR("ZHOUB 🚨🚨🚨 清理前: socketToKey_大小=%zu, mappings_大小=%zu", socketToKey_.size(), mappings_.size());
    
    auto now = std::chrono::steady_clock::now();
    auto timeout = std::chrono::seconds(timeoutSeconds);
    
    std::vector<std::string> expiredKeys;
    
    for (const auto& pair : mappings_) {
        auto age = now - pair.second.lastActivity;
        LOG_INFO("ZHOUB 检查映射 %s: 年龄=%lld秒, 超时=%d秒", 
               pair.first.c_str(), std::chrono::duration_cast<std::chrono::seconds>(age).count(), timeoutSeconds);
        
        if (age > timeout) {
            expiredKeys.push_back(pair.first);
            LOG_ERROR("ZHOUB 🚨🚨🚨 发现过期映射: %s (年龄=%lld秒)", 
                   pair.first.c_str(), std::chrono::duration_cast<std::chrono::seconds>(age).count());
        }
    }
    
    LOG_ERROR("ZHOUB 🚨🚨🚨 发现过期映射: %zu个", expiredKeys.size());
    
    for (const auto& key : expiredKeys) {
        auto it = mappings_.find(key);
        if (it != mappings_.end()) {
            int socket = it->second.forwardSocket;
            
            // 🔧 检查socketToKey_中是否存在这个socket
            auto socketIt = socketToKey_.find(socket);
            if (socketIt != socketToKey_.end()) {
                LOG_ERROR("ZHOUB 🚨🚨🚨 CleanupExpired找到socket: %d -> %s", socket, socketIt->second.c_str());
            } else {
                LOG_ERROR("ZHOUB 🚨🚨🚨 CleanupExpired未找到socket: %d", socket);
            }
            
            socketToKey_.erase(socket);
            mappings_.erase(it);
            LOG_ERROR("ZHOUB 🚨🚨🚨 CleanupExpired删除过期映射: key=%s, socket=%d", key.c_str(), socket);
        }
    }
    
    LOG_ERROR("ZHOUB 🚨🚨🚨 清理后: socketToKey_大小=%zu, mappings_大小=%zu", socketToKey_.size(), mappings_.size());
    
    if (!expiredKeys.empty()) {
        NAT_LOG_DEBUG("🧹 Cleaned up %{public}zu expired mappings, remaining: %{public}zu",
                 expiredKeys.size(), mappings_.size());
    }
}

// 生成映射key
std::string NATTable::GenerateKey(const PacketInfo& info) {
    return GenerateKey(info.sourceIP, info.sourcePort, 
                      info.targetIP, info.targetPort, 
                      info.protocol);
}

std::string NATTable::GenerateKey(const std::string& clientVirtualIP, 
                                  int clientVirtualPort,
                                  const std::string& serverIP,
                                  int serverPort,
                                  uint8_t protocol) {
    std::ostringstream oss;
    oss << clientVirtualIP << ":" << clientVirtualPort << "->"
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
    
    // 🔧 强制输出清空日志
    LOG_ERROR("ZHOUB 🚨🚨🚨 NAT表被清空! 当前映射数=%zu", mappings_.size());
    LOG_ERROR("ZHOUB 🚨🚨🚨 调用栈: 正在清空所有NAT映射");
    
    size_t count = mappings_.size();
    mappings_.clear();
    socketToKey_.clear();
    
    LOG_ERROR("ZHOUB 🚨🚨🚨 已清空所有映射: %zu条", count);
    NAT_LOGI("🧹 Cleared all NAT mappings");
}
