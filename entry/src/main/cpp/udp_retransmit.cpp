#include "udp_retransmit.h"
#include <hilog/log.h>
#include <sys/socket.h>
#include <cstring>
#include <arpa/inet.h>
#include <algorithm>
#include <numeric>
#include <cmath>

#define MAKE_FILE_NAME (strrchr(__FILE__, '/') ? (strrchr(__FILE__, '/') + 1) : __FILE__)
#define RETRANS_LOGI(fmt, ...) \
  OH_LOG_Print(LOG_APP, LOG_INFO, 0x15b1, "VpnServer", "ZHOUB [UdpRetrans] [%{public}s:%{public}d] " fmt, MAKE_FILE_NAME, __LINE__, ##__VA_ARGS__)
#define RETRANS_LOGE(fmt, ...) \
  OH_LOG_Print(LOG_APP, LOG_ERROR, 0x15b1, "VpnServer", "ZHOUB [UdpRetrans] [%{public}s:%{public}d] " fmt, MAKE_FILE_NAME, __LINE__, ##__VA_ARGS__)

// 静态成员初始化
std::atomic<uint16_t> UdpRetransmitManager::nextPacketId_(1);

uint16_t UdpRetransmitManager::generatePacketId() {
    uint16_t id = nextPacketId_.fetch_add(1);
    if (id == 0) {  // 避免使用0作为ID
        id = nextPacketId_.fetch_add(1);
    }
    return id;
}

void UdpRetransmitManager::recordSentPacket(uint16_t packetId,
                                           const uint8_t* data, int dataSize,
                                           const sockaddr_in& targetAddr,
                                           int forwardSocket) {
    if (!data || dataSize <= 0 || dataSize > 2048) {
        RETRANS_LOGE("❌ Invalid packet: dataSize=%{public}d", dataSize);
        return;
    }
    
    std::lock_guard<std::mutex> lock(mutex_);
    
    UdpPacketInfo info;
    std::memcpy(info.data, data, dataSize);
    info.dataSize = dataSize;
    info.targetAddr = targetAddr;
    info.forwardSocket = forwardSocket;
    info.sendTime = std::chrono::steady_clock::now();
    info.retryCount = 0;
    info.packetId = packetId;
    
    pendingPackets_[packetId] = info;
    
    RETRANS_LOGI("📝 Recorded UDP packet: id=%{public}u, size=%{public}d, pending=%{public}zu",
                 packetId, dataSize, pendingPackets_.size());
}

void UdpRetransmitManager::confirmReceived(uint16_t packetId, double rtt) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = pendingPackets_.find(packetId);
    if (it != pendingPackets_.end()) {
        RETRANS_LOGI("✅ Confirmed UDP packet: id=%{public}u (retries=%{public}d, RTT=%.1fms)",
                     packetId, it->second.retryCount, rtt);

        // 更新网络质量指标
        updateNetworkMetrics(packetId, rtt, true);

        pendingPackets_.erase(it);
    }
}

int UdpRetransmitManager::checkAndRetransmit(int timeoutMs, int maxRetries) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto now = std::chrono::steady_clock::now();
    int retransmitCount = 0;
    const int maxRetransmitsPerCall = 5;  // 🐛 修复：每次调用最多重传5个包，避免重传风暴
    std::vector<uint16_t> toRemove;

    for (auto& pair : pendingPackets_) {
        // 🐛 修复：限制每次调用的重传数量
        if (retransmitCount >= maxRetransmitsPerCall) {
            break;  // 本次检查结束，避免重传风暴
        }

        UdpPacketInfo& info = pair.second;

        // 检查是否超时
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            now - info.sendTime).count();

        if (elapsed >= timeoutMs) {
            if (info.retryCount >= maxRetries) {
                // 达到最大重传次数，放弃
                char targetIP[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &info.targetAddr.sin_addr, targetIP, sizeof(targetIP));

                // 减少日志噪音 - 只在必要时记录
                if (info.retryCount >= 3) {
                    RETRANS_LOGE("❌ UDP packet dropped: id=%u, target=%s:%d, retries=%d",
                                info.packetId, targetIP, ntohs(info.targetAddr.sin_port), info.retryCount);
                }

                toRemove.push_back(pair.first);
                totalDropped_++;
            } else {
                // 重传
                ssize_t sent = sendto(info.forwardSocket, info.data, info.dataSize, 0,
                                     (struct sockaddr*)&info.targetAddr, sizeof(info.targetAddr));

                if (sent > 0) {
                    info.retryCount++;
                    info.sendTime = now;  // 更新发送时间
                    retransmitCount++;
                    totalRetransmits_++;

                    char targetIP[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &info.targetAddr.sin_addr, targetIP, sizeof(targetIP));

                    // 减少重传日志频率，每10次记录一次
                    if ((retransmitCount + 1) % 10 == 0) {
                        RETRANS_LOGI("🔄 UDP重传: id=%{public}u -> %{public}s:%{public}d (%{public}d/%{public}d)",
                                    info.packetId, targetIP, ntohs(info.targetAddr.sin_port),
                                    info.retryCount, maxRetries);
                    }
                } else {
                    RETRANS_LOGE("❌ Failed to retransmit: id=%{public}u, errno=%{public}d (%{public}s)",
                                info.packetId, errno, strerror(errno));
                    toRemove.push_back(pair.first);
                }
            }
        }
    }
    
    // 移除已放弃的包
    for (uint16_t id : toRemove) {
        pendingPackets_.erase(id);
    }
    
    // 统计日志：每分钟记录一次或有重要事件时记录
    static auto lastStatsLog = std::chrono::steady_clock::now();
    auto currentTime = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::minutes>(currentTime - lastStatsLog).count();

    if (elapsed >= 1 || retransmitCount >= 10 || !toRemove.empty()) {
        if (totalRetransmits_ > 0 || totalDropped_ > 0) {
            RETRANS_LOGI("📊 UDP重传统计: 待处理%{public}zu, 累计重传%{public}llu, 丢弃%{public}llu",
                        pendingPackets_.size(),
                        static_cast<unsigned long long>(totalRetransmits_),
                        static_cast<unsigned long long>(totalDropped_));
        }
        lastStatsLog = now;
    }
    
    return retransmitCount;
}

void UdpRetransmitManager::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    pendingPackets_.clear();
    RETRANS_LOGI("🧹 Cleared all pending UDP packets");
}

size_t UdpRetransmitManager::getPendingCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return pendingPackets_.size();
}

// ============================================================================
// 网络质量评估和自适应重传功能
// ============================================================================

void UdpRetransmitManager::updateNetworkMetrics(uint16_t packetId, double rtt, bool success) {
    std::lock_guard<std::mutex> lock(networkMetricsMutex_);

    // 记录RTT和成功状态
    recentRTTs_.push_back(rtt);
    recentSuccesses_.push_back(success);

    // 保持最近50个测量值的窗口
    if (recentRTTs_.size() > 50) {
        recentRTTs_.erase(recentRTTs_.begin());
        recentSuccesses_.erase(recentSuccesses_.begin());
    }

    // 计算丢包率
    if (!recentSuccesses_.empty()) {
        int successCount = std::count(recentSuccesses_.begin(), recentSuccesses_.end(), true);
        networkMetrics_.packetLossRate = 1.0 - (double)successCount / recentSuccesses_.size();
    }

    // 计算平均RTT
    if (!recentRTTs_.empty()) {
        networkMetrics_.averageRTT = std::accumulate(recentRTTs_.begin(), recentRTTs_.end(), 0.0) / recentRTTs_.size();
    }

    // 计算抖动（RTT标准差）
    if (recentRTTs_.size() > 1) {
        double mean = networkMetrics_.averageRTT;
        double variance = 0.0;
        for (double rtt : recentRTTs_) {
            variance += (rtt - mean) * (rtt - mean);
        }
        networkMetrics_.jitter = std::sqrt(variance / (recentRTTs_.size() - 1));
    }

    // 检测高延迟网络
    networkMetrics_.isHighLatency = (networkMetrics_.averageRTT > 200.0);  // 200ms作为高延迟阈值

    // 检测网络类型（简化版）
    if (networkMetrics_.averageRTT < 50.0) {
        networkMetrics_.networkType = 3;  // 有线网络
    } else if (networkMetrics_.averageRTT < 150.0) {
        networkMetrics_.networkType = 1;  // WIFI
    } else {
        networkMetrics_.networkType = 2;  // 移动网络
    }

    RETRANS_LOGI("📊 Network metrics updated: RTT=%.1fms, Loss=%.1f%%, Jitter=%.1fms, Type=%d, HighLatency=%d",
                 networkMetrics_.averageRTT, networkMetrics_.packetLossRate * 100.0,
                 networkMetrics_.jitter, networkMetrics_.networkType, networkMetrics_.isHighLatency ? 1 : 0);
}

int UdpRetransmitManager::calculateRetriesBasedOnNetworkQuality() {
    std::lock_guard<std::mutex> lock(networkMetricsMutex_);

    // 基础重试次数
    int baseRetries = 3;

    // 根据网络质量调整重试次数
    if (networkMetrics_.packetLossRate > 0.1) {  // 丢包率 > 10%
        baseRetries += 2;  // 多重试2次
    } else if (networkMetrics_.packetLossRate > 0.05) {  // 丢包率 > 5%
        baseRetries += 1;  // 多重试1次
    }

    // 高延迟网络增加重试次数
    if (networkMetrics_.isHighLatency) {
        baseRetries += 1;
    }

    // 移动网络通常更不稳定，增加重试次数
    if (networkMetrics_.networkType == 2) {  // 移动网络
        baseRetries += 1;
    }

    // 限制最大重试次数，避免过度重传
    int maxAllowedRetries = 8;
    int adaptiveRetries = std::min(baseRetries, maxAllowedRetries);

    RETRANS_LOGI("🎯 Adaptive retries calculated: %d (base=%d, loss=%.1f%%, highLatency=%d, networkType=%d)",
                 adaptiveRetries, baseRetries, networkMetrics_.packetLossRate * 100.0,
                 networkMetrics_.isHighLatency ? 1 : 0, networkMetrics_.networkType);

    return adaptiveRetries;
}

int UdpRetransmitManager::calculateAdaptiveTimeout() {
    std::lock_guard<std::mutex> lock(networkMetricsMutex_);

    // 基础超时时间
    int baseTimeout = 1000;  // 1秒

    // 根据RTT调整超时时间
    if (networkMetrics_.averageRTT > 0) {
        // 超时时间 = RTT + 抖动 + 缓冲时间
        int rttBasedTimeout = static_cast<int>(networkMetrics_.averageRTT + networkMetrics_.jitter + 100.0);

        // 限制超时时间范围
        rttBasedTimeout = std::max(500, std::min(5000, rttBasedTimeout));  // 500ms ~ 5000ms

        RETRANS_LOGI("⏱️ Adaptive timeout calculated: %dms (RTT=%.1fms, Jitter=%.1fms)",
                     rttBasedTimeout, networkMetrics_.averageRTT, networkMetrics_.jitter);

        return rttBasedTimeout;
    }

    return baseTimeout;
}

int UdpRetransmitManager::checkAndRetransmitAdaptive() {
    int adaptiveRetries = calculateRetriesBasedOnNetworkQuality();
    int adaptiveTimeout = calculateAdaptiveTimeout();

    RETRANS_LOGI("🔄 Starting adaptive retransmit: timeout=%dms, maxRetries=%d",
                 adaptiveTimeout, adaptiveRetries);

    return checkAndRetransmit(adaptiveTimeout, adaptiveRetries);
}

NetworkQualityMetrics UdpRetransmitManager::getNetworkQualityMetrics() const {
    std::lock_guard<std::mutex> lock(networkMetricsMutex_);
    return networkMetrics_;
}

