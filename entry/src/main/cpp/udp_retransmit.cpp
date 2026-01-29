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
#define RETRANS_LOGW(fmt, ...) \
  OH_LOG_Print(LOG_APP, LOG_WARN, 0x15b1, "VpnServer", "ZHOUB [UdpRetrans] [%{public}s:%{public}d] " fmt, MAKE_FILE_NAME, __LINE__, ##__VA_ARGS__)

// 静态成员初始化
std::atomic<uint16_t> UdpRetransmitManager::nextPacketId_(1);

// 协议检测
UdpProtocolType UdpRetransmitManager::detectUdpProtocol(const uint8_t* data, int size) {
    if (!data || size < 8) {
        return UdpProtocolType::UNKNOWN;
    }

    // DNS: 检查标准DNS头部特征 (端口53)
    if (size >= 12) {
        // DNS查询/响应有特定的格式
        uint16_t txnId = (data[0] << 8) | data[1];
        uint16_t flags = (data[2] << 8) | data[3];
        uint16_t qdCount = (data[4] << 8) | data[5];
        uint16_t anCount = (data[6] << 8) | data[7];

        // DNS头部合理性检查：事务ID不为0，标志位合理，问题/回答计数合理
        if (txnId != 0 && (flags & 0x8000) != 0 && qdCount <= 10 && anCount <= 50) {
            return UdpProtocolType::DNS;
        }
    }

    // NTP: 检查NTP头部特征 (端口123)
    if (size >= 48) {
        uint8_t version = (data[0] >> 3) & 0x07;
        uint8_t mode = data[0] & 0x07;

        // NTP版本通常是3或4，模式合理
        if (version >= 3 && version <= 4 && mode >= 1 && mode <= 5) {
            return UdpProtocolType::NTP;
        }
    }

    // SNMP: 检查SNMP头部特征 (端口161/162)
    if (size >= 20) {
        // SNMP以ASN.1序列开始
        if (data[0] == 0x30 && data[1] > 10) {
            // 检查是否包含SNMP版本
            if (data[4] == 0x02 && data[6] >= 0 && data[6] <= 2) { // SNMP v1/v2c/v3
                return UdpProtocolType::SNMP;
            }
        }
    }

    // DHCP: 检查DHCP头部特征 (端口67/68)
    if (size >= 240) {
        // DHCP包有特定的魔术数字
        if (data[236] == 0x63 && data[237] == 0x82 &&
            data[238] == 0x53 && data[239] == 0x63) {
            return UdpProtocolType::DHCP;
        }
    }

    // TFTP: 检查TFTP头部特征 (端口69)
    if (size >= 4) {
        uint16_t opcode = (data[0] << 8) | data[1];
        // TFTP操作码：1=RRQ, 2=WRQ, 3=DATA, 4=ACK, 5=ERROR
        if (opcode >= 1 && opcode <= 5) {
            return UdpProtocolType::TFTP;
        }
    }

    // QUIC: 检查QUIC头部特征 (端口443或其他)
    if (size >= 4) {
        // QUIC包以特定格式开始
        uint8_t firstByte = data[0];
        if ((firstByte & 0x80) != 0) { // Long header
            uint8_t versionByte = data[1];
            if (versionByte >= 0x01) { // QUIC version
                return UdpProtocolType::QUIC;
            }
        }
    }

    return UdpProtocolType::UNKNOWN;
}

// 提取协议标识符
uint32_t UdpRetransmitManager::extractProtocolIdentifier(UdpProtocolType protocol, const uint8_t* data, int size) {
    if (!data || size < 2) {
        return 0;
    }

    switch (protocol) {
        case UdpProtocolType::DNS:
            // DNS事务ID (前2字节)
            return (data[0] << 8) | data[1];

        case UdpProtocolType::NTP:
            // NTP使用时间戳作为标识符 (字节8-11)
            if (size >= 12) {
                return (data[8] << 24) | (data[9] << 16) | (data[10] << 8) | data[11];
            }
            return 0;

        case UdpProtocolType::SNMP:
            // SNMP请求ID (通常在PDU中)
            if (size >= 20) {
                // 查找请求ID字段 (简化实现)
                for (int i = 10; i < size - 4; i++) {
                    if (data[i] == 0x02 && data[i+1] >= 1 && data[i+1] <= 4) {
                        // ASN.1 INTEGER类型，后面跟请求ID
                        int len = data[i+1];
                        if (len == 4) {
                            return (data[i+2] << 24) | (data[i+3] << 16) | (data[i+4] << 8) | data[i+5];
                        }
                    }
                }
            }
            return 0;

        case UdpProtocolType::DHCP:
            // DHCP使用事务ID (字节4-7)
            if (size >= 8) {
                return (data[4] << 24) | (data[5] << 16) | (data[6] << 8) | data[7];
            }
            return 0;

        case UdpProtocolType::TFTP:
            // TFTP使用块号或文件名哈希作为标识符
            if (size >= 4) {
                uint16_t opcode = (data[0] << 8) | data[1];
                if (opcode == 3 || opcode == 4) { // DATA or ACK
                    return (data[2] << 8) | data[3]; // 块号
                } else {
                    // 对于RRQ/WRQ，使用文件名哈希
                    return hashString((const char*)&data[2], size - 2);
                }
            }
            return 0;

        case UdpProtocolType::QUIC:
            // QUIC使用连接ID作为标识符
            if (size >= 10) {
                if ((data[0] & 0x80) != 0) { // Long header
                    // 提取Destination Connection ID
                    uint8_t dcidLen = data[5];
                    if (dcidLen > 0 && dcidLen <= 20 && 6 + dcidLen <= size) {
                        // 使用前4字节作为标识符
                        uint32_t id = 0;
                        for (int i = 0; i < std::min(4, (int)dcidLen); i++) {
                            id = (id << 8) | data[6 + i];
                        }
                        return id;
                    }
                }
            }
            return 0;

        default:
            // 默认使用前4字节作为标识符
            if (size >= 4) {
                return (data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3];
            }
            return (data[0] << 8) | data[1];
    }
}

// 简单的字符串哈希函数
uint32_t UdpRetransmitManager::hashString(const char* str, int len) {
    uint32_t hash = 5381;
    for (int i = 0; i < len && str[i] != '\0'; i++) {
        hash = ((hash << 5) + hash) + str[i]; // djb2算法
    }
    return hash;
}

// 获取协议类型名称
const char* UdpRetransmitManager::getProtocolTypeName(UdpProtocolType protocol) {
    switch (protocol) {
        case UdpProtocolType::DNS: return "DNS";
        case UdpProtocolType::NTP: return "NTP";
        case UdpProtocolType::SNMP: return "SNMP";
        case UdpProtocolType::DHCP: return "DHCP";
        case UdpProtocolType::TFTP: return "TFTP";
        case UdpProtocolType::QUIC: return "QUIC";
        case UdpProtocolType::WIREGUARD: return "WireGuard";
        case UdpProtocolType::OPENVPN: return "OpenVPN";
        default: return "UNKNOWN";
    }
}

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
                                           const sockaddr_in& clientAddr,
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
    info.clientAddr = clientAddr;
    info.forwardSocket = forwardSocket;
    info.sendTime = std::chrono::steady_clock::now();
    info.retryCount = 0;
    info.packetId = packetId;
    
    pendingPackets_[packetId] = info;
    
    RETRANS_LOGI("📝 Recorded UDP packet: id=%{public}u, size=%{public}d, pending=%{public}zu, client=%s:%d",
                 packetId, dataSize, pendingPackets_.size(),
                 inet_ntoa(info.clientAddr.sin_addr), ntohs(info.clientAddr.sin_port));

    // 定期清理超时的pending packets，避免内存泄漏
    // 🚨 修复：不要在持有锁的情况下调用获取锁的函数（避免死锁）
    // cleanupExpiredPackets(); 
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

void UdpRetransmitManager::confirmReceivedBySocket(int forwardSocket) {
    std::lock_guard<std::mutex> lock(mutex_);

    // 找到并确认所有使用此socket的pending包
    std::vector<uint16_t> packetsToConfirm;
    for (const auto& pair : pendingPackets_) {
        if (pair.second.forwardSocket == forwardSocket) {
            packetsToConfirm.push_back(pair.first);
        }
    }

    // 确认找到的包
    for (uint16_t packetId : packetsToConfirm) {
        auto it = pendingPackets_.find(packetId);
        if (it != pendingPackets_.end()) {
            RETRANS_LOGI("✅ Confirmed UDP packet by socket: id=%{public}u, socket=%{public}d",
                         packetId, forwardSocket);

            // 更新网络质量指标
            updateNetworkMetrics(packetId, 0.0, true);  // RTT未知，设为0

            pendingPackets_.erase(it);
        }
    }

    if (!packetsToConfirm.empty()) {
        RETRANS_LOGI("📊 Confirmed %{public}zu UDP packets for socket %{public}d",
                     packetsToConfirm.size(), forwardSocket);
    }
}

void UdpRetransmitManager::confirmReceivedByContent(int forwardSocket, const uint8_t* responseData, int responseSize) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (!responseData || responseSize < 2) {
        RETRANS_LOGW("⚠️ Invalid response data for content matching");
        return;
    }

    // 1. 检测协议类型并提取标识符
    UdpProtocolType protocolType = detectUdpProtocol(responseData, responseSize);
    uint32_t protocolIdentifier = extractProtocolIdentifier(protocolType, responseData, responseSize);

    RETRANS_LOGI("🔍 检测到UDP协议: %{public}s, 标识符: 0x%{public}08x",
                 getProtocolTypeName(protocolType), protocolIdentifier);

    // 2. 在pending包中查找匹配的请求
    uint16_t bestMatchPacketId = 0;
    int bestMatchScore = 0;

    auto currentTime = std::chrono::steady_clock::now();

    for (const auto& pair : pendingPackets_) {
        const UdpPacketInfo& info = pair.second;
        if (info.forwardSocket != forwardSocket || info.dataSize < 2) {
            continue;
        }

        int matchScore = 0;

        // 协议类型匹配
        UdpProtocolType requestProtocolType = detectUdpProtocol(info.data, info.dataSize);
        if (requestProtocolType == protocolType) {
            matchScore += 50; // 协议匹配加分
        } else {
            continue; // 协议不匹配，跳过
        }

        // 协议标识符匹配
        uint32_t requestIdentifier = extractProtocolIdentifier(requestProtocolType, info.data, info.dataSize);
        if (requestIdentifier == protocolIdentifier) {
            matchScore += 100; // 标识符完全匹配
        }

        // 时间相近度 (最近发送的优先)
        auto timeDiff = std::chrono::duration_cast<std::chrono::milliseconds>(
            currentTime - info.sendTime).count();
        if (timeDiff < 1000) matchScore += 30;      // 1秒内
        else if (timeDiff < 5000) matchScore += 20; // 5秒内
        else if (timeDiff < 10000) matchScore += 10; // 10秒内

        // 内容相似度检查 (暂时简化，主要依赖事务ID匹配)
        // TODO: 可以后续添加更复杂的内容相似度检查

        RETRANS_LOGI("🔍 候选包 ID=%{public}u, 协议=%{public}s, 标识符=0x%{public}08x, 分数=%{public}d",
                     pair.first, getProtocolTypeName(requestProtocolType), requestIdentifier, matchScore);

        if (matchScore > bestMatchScore) {
            bestMatchScore = matchScore;
            bestMatchPacketId = pair.first;
        }
    }

    // 3. 执行最佳匹配
    if (bestMatchPacketId != 0 && bestMatchScore >= 100) {
        auto it = pendingPackets_.find(bestMatchPacketId);
        if (it != pendingPackets_.end()) {
            RETRANS_LOGI("✅ 响应匹配成功: 协议=%{public}s, 标识符=0x%{public}08x, 包ID=%{public}u, 分数=%{public}d",
                         getProtocolTypeName(protocolType), protocolIdentifier, bestMatchPacketId, bestMatchScore);

            // 更新网络质量指标
            updateNetworkMetrics(bestMatchPacketId, 0.0, true);
            pendingPackets_.erase(it);
            return;
        }
    }

    // 4. 备选方案：确认最有可能的包
    if (bestMatchPacketId != 0 && bestMatchScore >= 50) {
        auto it = pendingPackets_.find(bestMatchPacketId);
        if (it != pendingPackets_.end()) {
            RETRANS_LOGI("🔄 备选方案1：确认高分候选包 ID=%{public}u (分数=%{public}d)",
                         bestMatchPacketId, bestMatchScore);
            updateNetworkMetrics(bestMatchPacketId, 0.0, true);
            pendingPackets_.erase(it);
            return;
        }
    }

    // 5. 最后备选：确认最旧的包
    auto oldestIt = pendingPackets_.end();
    for (auto it = pendingPackets_.begin(); it != pendingPackets_.end(); ++it) {
        if (it->second.forwardSocket == forwardSocket) {
            if (oldestIt == pendingPackets_.end() ||
                it->second.sendTime < oldestIt->second.sendTime) {
                oldestIt = it;
            }
        }
    }

    if (oldestIt != pendingPackets_.end()) {
        RETRANS_LOGI("🔄 备选方案2：确认最旧的pending包 ID=%{public}u", oldestIt->first);
        updateNetworkMetrics(oldestIt->first, 0.0, true);
        pendingPackets_.erase(oldestIt);
    } else {
        RETRANS_LOGW("❌ 所有匹配方案都失败，等待超时重传");
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
    totalRetransmits_ = 0;
    totalDropped_ = 0;
    RETRANS_LOGI("🧹 Cleared all pending UDP packets");
}

void UdpRetransmitManager::cleanupExpiredPackets() {
    std::lock_guard<std::mutex> lock(mutex_);

    auto now = std::chrono::steady_clock::now();
    std::vector<uint16_t> expiredPackets;

    // 找出超时的packets (30秒超时)
    for (const auto& pair : pendingPackets_) {
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            now - pair.second.sendTime).count();
        if (elapsed > 30) {
            expiredPackets.push_back(pair.first);
        }
    }

    // 清理超时的packets
    for (uint16_t packetId : expiredPackets) {
        auto it = pendingPackets_.find(packetId);
        if (it != pendingPackets_.end()) {
            totalDropped_++;
            RETRANS_LOGW("⏰ Expired UDP packet: id=%{public}u, dropped", packetId);
            pendingPackets_.erase(it);
        }
    }

    if (!expiredPackets.empty()) {
        RETRANS_LOGI("🧹 Cleaned up %{public}zu expired UDP packets, remaining: %{public}zu",
                     expiredPackets.size(), pendingPackets_.size());
    }
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

