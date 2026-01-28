#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <map>
#include <mutex>
#include <chrono>
#include <vector>
#include <netinet/in.h>

// UDP协议类型枚举
enum class UdpProtocolType {
    UNKNOWN = 0,
    DNS = 1,
    NTP = 2,
    SNMP = 3,
    DHCP = 4,
    TFTP = 5,
    QUIC = 6,    // Google QUIC
    WIREGUARD = 7, // WireGuard
    OPENVPN = 8   // OpenVPN
};

// UDP包信息
struct UdpPacketInfo {
    uint8_t data[2048];                              // 数据包内容
    int dataSize;                                    // 数据大小
    sockaddr_in targetAddr;                          // 目标地址
    sockaddr_in clientAddr;                          // VPN客户端地址
    int forwardSocket;                               // 转发socket
    std::chrono::steady_clock::time_point sendTime;  // 发送时间
    int retryCount;                                  // 重传次数
    uint16_t packetId;                               // 数据包ID

    UdpPacketInfo() : dataSize(0), forwardSocket(-1), retryCount(0), packetId(0) {
        memset(&clientAddr, 0, sizeof(clientAddr));
    }
};

/**
 * UDP重传管理器
 *
 * 功能：
 * 1. 记录已发送的UDP包
 * 2. 检测超时并自动重传
 * 3. 收到响应后确认并移除
 * 4. 达到最大重传次数后放弃
 * 5. 动态调整重试次数和超时时间（自适应重传）
 */

// 网络质量评估结构体
struct NetworkQualityMetrics {
    double packetLossRate;     // 丢包率 (0.0 - 1.0)
    double averageRTT;         // 平均往返时间 (ms)
    double jitter;             // 抖动 (ms)
    int networkType;           // 网络类型: 0=未知, 1=WIFI, 2=移动网络, 3=有线
    bool isHighLatency;        // 是否为高延迟网络

    NetworkQualityMetrics() : packetLossRate(0.0), averageRTT(0.0), jitter(0.0),
                             networkType(0), isHighLatency(false) {}

    // 获取网络类型描述
    const char* getNetworkTypeString() const {
        switch (networkType) {
            case 1: return "WIFI";
            case 2: return "移动网络";
            case 3: return "有线网络";
            default: return "未知";
        }
    }
};
class UdpRetransmitManager {
public:
    static UdpRetransmitManager& getInstance() {
        static UdpRetransmitManager instance;
        return instance;
    }

    // ---------------------------------------------------------------------
    // Public protocol helpers (used by forwarder for lightweight classification)
    // NOTE: These are thin wrappers over internal helpers. They are stateless.
    // ---------------------------------------------------------------------
    static UdpProtocolType DetectProtocol(const uint8_t* data, int size) {
        return getInstance().detectUdpProtocol(data, size);
    }

    static uint32_t ExtractProtocolIdentifier(UdpProtocolType protocol, const uint8_t* data, int size) {
        return getInstance().extractProtocolIdentifier(protocol, data, size);
    }

    static const char* ProtocolName(UdpProtocolType protocol) {
        return getInstance().getProtocolTypeName(protocol);
    }

    // 记录已发送的UDP包（用于重传）
    void recordSentPacket(uint16_t packetId,
                         const uint8_t* data, int dataSize,
                         const sockaddr_in& targetAddr,
                         const sockaddr_in& clientAddr,
                         int forwardSocket);

    // 确认收到响应（移除待重传记录）
    void confirmReceived(uint16_t packetId, double rtt = 0.0);
    void confirmReceivedBySocket(int forwardSocket);  // 确认指定socket的所有pending包
    void confirmReceivedByContent(int forwardSocket, const uint8_t* responseData, int responseSize);  // 基于内容匹配确认

    // 获取统计信息
    size_t getPendingCount() const;
    uint64_t getTotalRetransmits() const { return totalRetransmits_; }
    uint64_t getTotalDropped() const { return totalDropped_; }

    // 网络质量评估和自适应重传
    void updateNetworkMetrics(uint16_t packetId, double rtt, bool success);
    int calculateRetriesBasedOnNetworkQuality();
    int calculateAdaptiveTimeout();

    // 获取网络质量统计
    NetworkQualityMetrics getNetworkQualityMetrics() const;

    // 生成唯一的包ID (需要公开给worker_thread_pool使用)
    static uint16_t generatePacketId();

    // 检查超时并重传 (需要公开给vpn_server使用)
    int checkAndRetransmit(int timeoutMs = 1000, int maxRetries = 3);

    // 清理所有记录 (需要公开给vpn_server使用)
    void clear();

    // 清理超时的pending packets
    void cleanupExpiredPackets();

private:
    // 自适应重传
    int checkAndRetransmitAdaptive();

    // 协议识别和匹配辅助方法
    UdpProtocolType detectUdpProtocol(const uint8_t* data, int size);
    uint32_t extractProtocolIdentifier(UdpProtocolType protocol, const uint8_t* data, int size);
    const char* getProtocolTypeName(UdpProtocolType protocol);
    uint32_t hashString(const char* str, int len);

private:
    UdpRetransmitManager()
        : totalRetransmits_(0), totalDropped_(0), recentRTTs_(50), recentSuccesses_(50) {}

    ~UdpRetransmitManager() = default;

    // 禁止拷贝
    UdpRetransmitManager(const UdpRetransmitManager&) = delete;
    UdpRetransmitManager& operator=(const UdpRetransmitManager&) = delete;

    std::unordered_map<uint16_t, UdpPacketInfo> pendingPackets_;
    mutable std::mutex mutex_;

    // 统计信息
    uint64_t totalRetransmits_;  // 总重传次数
    uint64_t totalDropped_;      // 总丢弃次数（超过最大重传）

    // 网络质量评估和自适应重传
    NetworkQualityMetrics networkMetrics_;
    std::vector<double> recentRTTs_;           // 最近RTT测量值
    std::vector<bool> recentSuccesses_;        // 最近传输成功记录
    mutable std::mutex networkMetricsMutex_;  // 网络指标互斥锁

    // 包ID生成器
    static std::atomic<uint16_t> nextPacketId_;
};