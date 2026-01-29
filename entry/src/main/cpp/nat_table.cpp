/*
 * NAT映射表实现 -  delegate 到 NATConnectionManager 以解决同步问题
 */

#include "nat_table.h"
#include "nat_connection_manager.h"
#include <vector>
#include <hilog/log.h>

#define MAKE_FILE_NAME (strrchr(__FILE__, '/') ? (strrchr(__FILE__, '/') + 1) : __FILE__)

#define LOG_INFO(fmt, ...) \
  OH_LOG_Print(LOG_APP, LOG_INFO, 0x15b1, "VpnServer", "ZHOUB [NAT-Table] " fmt, ##__VA_ARGS__)

// 移除静态成员定义，现在全部 delegate 给 NATConnectionManager
// std::unordered_map<std::string, NATConnection> NATTable::mappings_;
// std::unordered_map<int, std::string> NATTable::socketToKey_;
// std::mutex NATTable::mutex_;

// 创建NAT映射
bool NATTable::CreateMapping(const std::string& key,
                            const sockaddr_in& clientPhysicalAddr,
                            const PacketInfo& packetInfo,
                            int forwardSocket) {
    // 使用 NATConnectionManager 创建连接
    auto handle = NATConnectionManager::getInstance().createConnection(
        packetInfo, clientPhysicalAddr, forwardSocket
    );
    return handle.isValid();
}

bool NATTable::WithConnection(const std::string& key, const std::function<void(NATConnection&)>& fn)
{
    return NATConnectionManager::getInstance().withConnection(key, fn);
}

bool NATTable::WithConnectionBySocket(int forwardSocket, const std::function<void(NATConnection&)>& fn)
{
    return NATConnectionManager::getInstance().withConnectionBySocket(forwardSocket, fn);
}

// 查找NAT映射
bool NATTable::FindMapping(const std::string& key, NATConnection& conn) {
    auto optConn = NATConnectionManager::getInstance().findConnection(key);
    if (optConn.has_value()) {
        conn = optConn.value();
        return true;
    }
    return false;
}

// 通过socket查找映射
bool NATTable::FindMappingBySocket(int forwardSocket, NATConnection& conn) {
    auto optConn = NATConnectionManager::getInstance().findConnectionBySocket(forwardSocket);
    if (optConn.has_value()) {
        conn = optConn.value();
        return true;
    }
    return false;
}

bool NATTable::GetKeyBySocket(int forwardSocket, std::string& key) {
    // 技巧：利用 withConnectionBySocket 获取 key
    bool found = false;
    NATConnectionManager::getInstance().withConnectionBySocket(forwardSocket, [&](NATConnection& c) {
        // 这里无法直接拿到 key，但 NATConnectionManager 内部已经有了映射
        // 我们在 NATConnectionManager 中添加一个直接获取 key 的方法更优雅
        found = true;
    });
    
    // 既然 WithConnectionBySocket 没直接暴露 key，我们从 socketToKey_ 获取
    // 注意：NATConnectionManager 的 socketToKey_ 是私有的，我们需要一个公共方法
    // 暂且用 findConnectionBySocket 重新查找
    auto optConn = NATConnectionManager::getInstance().findConnectionBySocket(forwardSocket);
    if (optConn.has_value()) {
        const auto& c = optConn.value();
        // 重新生成 key (注意：这里假设 generateKey 逻辑一致)
        key = NATConnectionManager::getInstance().generateKey(c.originalRequest, c.clientPhysicalAddr);
        return true;
    }
    return false;
}

// 更新活动时间
void NATTable::UpdateActivity(const std::string& key) {
    NATConnectionManager::getInstance().updateActivity(key);
}

// 移除映射
void NATTable::RemoveMapping(const std::string& key) {
    NATConnectionManager::getInstance().removeImmediate(key);
}

// 通过socket移除映射
void NATTable::RemoveMappingBySocket(int forwardSocket) {
    NATConnectionManager::getInstance().removeImmediateBySocket(forwardSocket);
}

// 清理过期映射
void NATTable::CleanupExpired(int timeoutSeconds) {
    NATConnectionManager::getInstance().cleanupExpired(timeoutSeconds);
}

// 生成映射key
std::string NATTable::GenerateKey(const PacketInfo& info, const sockaddr_in& clientPhysicalAddr) {
    return NATConnectionManager::getInstance().generateKey(info, clientPhysicalAddr);
}

std::string NATTable::GenerateKey(const std::string& clientVirtualIP,
                                  int clientVirtualPort,
                                  const std::string& serverIP,
                                  int serverPort,
                                  uint8_t protocol,
                                  const std::string& clientPhysicalIP,
                                  int clientPhysicalPort) {
    return NATConnectionManager::getInstance().generateKey(
        clientVirtualIP, clientVirtualPort, serverIP, serverPort, protocol, clientPhysicalIP, clientPhysicalPort
    );
}

// 获取映射数量
int NATTable::GetMappingCount() {
    return static_cast<int>(NATConnectionManager::getInstance().getStats().activeConnections);
}

// 清空所有映射
void NATTable::Clear() {
    NATConnectionManager::getInstance().clear();
}

// 获取所有活跃的转发socket（用于强制关闭）
std::vector<int> NATTable::GetAllActiveSockets() {
    return NATConnectionManager::getInstance().getAllActiveSockets();
}
