#include "udp_retransmit.h"
#include <hilog/log.h>
#include <sys/socket.h>
#include <cstring>
#include <arpa/inet.h>

#define MAKE_FILE_NAME (strrchr(__FILE__, '/') ? (strrchr(__FILE__, '/') + 1) : __FILE__)
#define RETRANS_LOGI(fmt, ...) \
  OH_LOG_Print(LOG_APP, LOG_INFO, 0x15b1, "UdpRetrans", "[%{public}s:%{public}d] " fmt, MAKE_FILE_NAME, __LINE__, ##__VA_ARGS__)
#define RETRANS_LOGE(fmt, ...) \
  OH_LOG_Print(LOG_APP, LOG_ERROR, 0x15b1, "UdpRetrans", "[%{public}s:%{public}d] " fmt, MAKE_FILE_NAME, __LINE__, ##__VA_ARGS__)

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

void UdpRetransmitManager::confirmReceived(uint16_t packetId) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = pendingPackets_.find(packetId);
    if (it != pendingPackets_.end()) {
        RETRANS_LOGI("✅ Confirmed UDP packet: id=%{public}u (retries=%{public}d)",
                     packetId, it->second.retryCount);
        pendingPackets_.erase(it);
    }
}

int UdpRetransmitManager::checkAndRetransmit(int timeoutMs, int maxRetries) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto now = std::chrono::steady_clock::now();
    int retransmitCount = 0;
    std::vector<uint16_t> toRemove;
    
    for (auto& pair : pendingPackets_) {
        UdpPacketInfo& info = pair.second;
        
        // 检查是否超时
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            now - info.sendTime).count();
        
        if (elapsed >= timeoutMs) {
            if (info.retryCount >= maxRetries) {
                // 达到最大重传次数，放弃
                char targetIP[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &info.targetAddr.sin_addr, targetIP, sizeof(targetIP));
                
                RETRANS_LOGE("❌ UDP packet dropped: id=%{public}u, target=%{public}s:%{public}d, retries=%{public}d",
                            info.packetId, targetIP, ntohs(info.targetAddr.sin_port), info.retryCount);
                
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
                    
                    RETRANS_LOGI("🔄 Retransmitted UDP packet: id=%{public}u, target=%{public}s:%{public}d, retry=%{public}d/%{public}d",
                                info.packetId, targetIP, ntohs(info.targetAddr.sin_port), 
                                info.retryCount, maxRetries);
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
    
    if (retransmitCount > 0 || !toRemove.empty()) {
        RETRANS_LOGI("📊 Retransmit stats: sent=%{public}d, dropped=%{public}zu, pending=%{public}zu, total_retrans=%{public}llu, total_dropped=%{public}llu",
                    retransmitCount, toRemove.size(), pendingPackets_.size(),
                    static_cast<unsigned long long>(totalRetransmits_),
                    static_cast<unsigned long long>(totalDropped_));
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
