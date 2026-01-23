#pragma once

#include <string>
#include <unordered_map>
#include <mutex>
#include <chrono>
#include <netinet/in.h>
#include "protocol_handler.h"

// NAT连接信息
struct NATConnection {
    // 客户端信息（物理地址）
    sockaddr_in clientPhysicalAddr;  // 客户端的实际网络地址
    
    // VPN虚拟IP信息
    std::string clientVirtualIP;     // 客户端的VPN虚拟IP
    int clientVirtualPort;            // 客户端的虚拟端口
    
    // 真实服务器信息
    std::string serverIP;
    int serverPort;
    
    // 转发socket
    int forwardSocket;               // 用于转发的socket
    
    // 协议类型
    uint8_t protocol;                // TCP or UDP
    
    // 时间戳
    std::chrono::steady_clock::time_point lastActivity;
    
    // 原始请求信息（用于构建响应）
    PacketInfo originalRequest;
    
    NATConnection() : forwardSocket(-1), clientVirtualPort(0), 
                     serverPort(0), protocol(0), 
                     lastActivity(std::chrono::steady_clock::now()) {}
};

// NAT映射表 - 管理客户端到服务器的连接映射
class NATTable {
public:
    // 创建新的NAT映射
    static bool CreateMapping(const std::string& key,
                            const sockaddr_in& clientPhysicalAddr,
                            const PacketInfo& packetInfo,
                            int forwardSocket);
    
    // 查找NAT映射
    static bool FindMapping(const std::string& key, NATConnection& conn);
    
    // 通过转发socket查找映射（用于响应处理）
    static bool FindMappingBySocket(int forwardSocket, NATConnection& conn);
    
    // 更新最后活动时间
    static void UpdateActivity(const std::string& key);
    
    // 移除映射
    static void RemoveMapping(const std::string& key);
    
    // 通过socket移除映射
    static void RemoveMappingBySocket(int forwardSocket);
    
    // 移除过期的映射
    static void CleanupExpired(int timeoutSeconds = 300);
    
    // 生成映射key
    static std::string GenerateKey(const PacketInfo& info, const sockaddr_in& clientPhysicalAddr);
    static std::string GenerateKey(const std::string& clientVirtualIP,
                                   int clientVirtualPort,
                                   const std::string& serverIP,
                                   int serverPort,
                                   uint8_t protocol,
                                   const std::string& clientPhysicalIP,
                                   int clientPhysicalPort);
    
    // 获取映射数量
    static int GetMappingCount();
    
    // 清空所有映射
    static void Clear();
    
private:
    static std::unordered_map<std::string, NATConnection> mappings_;
    static std::unordered_map<int, std::string> socketToKey_;  // socket -> key映射
    static std::mutex mutex_;
};
