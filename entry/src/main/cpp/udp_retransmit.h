#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <mutex>
#include <chrono>
#include <vector>
#include <netinet/in.h>

// UDP包信息
struct UdpPacketInfo {
    uint8_t data[2048];                              // 数据包内容
    int dataSize;                                    // 数据大小
    sockaddr_in targetAddr;                          // 目标地址
    int forwardSocket;                               // 转发socket
    std::chrono::steady_clock::time_point sendTime;  // 发送时间
    int retryCount;                                  // 重传次数
    uint16_t packetId;                               // 数据包ID
    
    UdpPacketInfo() : dataSize(0), forwardSocket(-1), retryCount(0), packetId(0) {}
};

/**
 * UDP重传管理器
 * 
 * 功能：
 * 1. 记录已发送的UDP包
 * 2. 检测超时并自动重传
 * 3. 收到响应后确认并移除
 * 4. 达到最大重传次数后放弃
 */
class UdpRetransmitManager {
public:
    static UdpRetransmitManager& getInstance() {
        static UdpRetransmitManager instance;
        return instance;
    }
    
    // 记录已发送的UDP包（用于重传）
    void recordSentPacket(uint16_t packetId,
                         const uint8_t* data, int dataSize,
                         const sockaddr_in& targetAddr,
                         int forwardSocket);
    
    // 确认收到响应（移除待重传记录）
    void confirmReceived(uint16_t packetId);
    
    // 检查超时并重传
    int checkAndRetransmit(int timeoutMs = 1000, int maxRetries = 3);
    
    // 清理所有记录
    void clear();
    
    // 获取统计信息
    size_t getPendingCount() const;
    uint64_t getTotalRetransmits() const { return totalRetransmits_; }
    uint64_t getTotalDropped() const { return totalDropped_; }
    
    // 生成唯一的包ID
    static uint16_t generatePacketId();

private:
    UdpRetransmitManager() 
        : totalRetransmits_(0), totalDropped_(0), nextPacketId_(1) {}
    
    ~UdpRetransmitManager() = default;
    
    // 禁止拷贝
    UdpRetransmitManager(const UdpRetransmitManager&) = delete;
    UdpRetransmitManager& operator=(const UdpRetransmitManager&) = delete;
    
    std::unordered_map<uint16_t, UdpPacketInfo> pendingPackets_;
    mutable std::mutex mutex_;
    
    // 统计信息
    uint64_t totalRetransmits_;  // 总重传次数
    uint64_t totalDropped_;      // 总丢弃次数（超过最大重传）
    
    // 包ID生成器
    static std::atomic<uint16_t> nextPacketId_;
};
