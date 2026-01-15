/*
 * NAT映射表实现 - 管理VPN连接状态
 */

#include "nat_table.h"
#include <hilog/log.h>
#include <sstream>
#include <arpa/inet.h>

#define MAKE_FILE_NAME (strrchr(__FILE__, '/') ? (strrchr(__FILE__, '/') + 1) : __FILE__)
#define NAT_LOGI(fmt, ...) \
  OH_LOG_Print(LOG_APP, LOG_INFO, 0x15b1, "NATTable", "[%{public}s:%{public}d] " fmt, MAKE_FILE_NAME, __LINE__, ##__VA_ARGS__)
#define NAT_LOGE(fmt, ...) \
  OH_LOG_Print(LOG_APP, LOG_ERROR, 0x15b1, "NATTable", "[%{public}s:%{public}d] " fmt, MAKE_FILE_NAME, __LINE__, ##__VA_ARGS__)

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
    
    mappings_[key] = conn;
    socketToKey_[forwardSocket] = key;
    
    char clientPhysicalIP[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &clientPhysicalAddr.sin_addr, clientPhysicalIP, sizeof(clientPhysicalIP));
    int clientPhysicalPort = ntohs(clientPhysicalAddr.sin_port);
    
    NAT_LOGI("✅ Created NAT mapping: %{public}s", key.c_str());
    NAT_LOGI("   Client Physical: %{public}s:%{public}d", clientPhysicalIP, clientPhysicalPort);
    NAT_LOGI("   Client Virtual: %{public}s:%{public}d", conn.clientVirtualIP.c_str(), conn.clientVirtualPort);
    NAT_LOGI("   Server: %{public}s:%{public}d", conn.serverIP.c_str(), conn.serverPort);
    NAT_LOGI("   Forward Socket: %{public}d, Protocol: %{public}s", 
             forwardSocket, packetInfo.protocol == PROTOCOL_TCP ? "TCP" : "UDP");
    NAT_LOGI("   Total mappings: %{public}zu", mappings_.size());
    
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
        
        NAT_LOGI("🗑️ Removed NAT mapping: %{public}s, remaining: %{public}zu", 
                 key.c_str(), mappings_.size());
    }
}

// 清理过期映射
void NATTable::CleanupExpired(int timeoutSeconds) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto now = std::chrono::steady_clock::now();
    auto timeout = std::chrono::seconds(timeoutSeconds);
    
    std::vector<std::string> expiredKeys;
    
    for (const auto& pair : mappings_) {
        if (now - pair.second.lastActivity > timeout) {
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
        NAT_LOGI("🧹 Cleaned up %{public}zu expired mappings, remaining: %{public}zu",
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
    mappings_.clear();
    socketToKey_.clear();
    NAT_LOGI("🧹 Cleared all NAT mappings");
}
