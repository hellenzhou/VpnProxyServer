#include "simple_dns_cache.h"
#include <algorithm>
#include <sstream>

// 静态成员初始化
std::unordered_map<std::string, DNSCacheEntry> DNSCacheManager::cache_;
std::mutex DNSCacheManager::cache_mutex_;
const std::chrono::seconds DNSCacheManager::CACHE_TTL{300};  // 5分钟

// 解析DNS查询域名
std::string DNSCacheManager::parseQueryDomain(const uint8_t* dnsData, int dataSize) {
    if (dataSize < sizeof(DNSHeader) + 5) {  // DNS头部 + 最少域名长度
        return "";
    }

    // 跳过DNS头部(12字节)
    const uint8_t* ptr = dnsData + sizeof(DNSHeader);
    const uint8_t* end = dnsData + dataSize;

    std::string domain;
    while (ptr < end && *ptr != 0) {
        uint8_t labelLen = *ptr++;
        if (ptr + labelLen > end) {
            return "";  // 数据不完整
        }

        if (!domain.empty()) {
            domain += ".";
        }

        domain.append(reinterpret_cast<const char*>(ptr), labelLen);
        ptr += labelLen;
    }

    return domain;
}

// 生成缓存键
std::string DNSCacheManager::makeCacheKey(const std::string& domain, uint16_t qtype) {
    std::stringstream ss;
    ss << domain << ":" << qtype;
    return ss.str();
}

// 检查缓存
bool DNSCacheManager::getCachedResponse(const std::string& cacheKey,
                                       const uint8_t* queryData, int querySize,
                                       uint8_t* responseBuffer, int& responseSize) {
    std::lock_guard<std::mutex> lock(cache_mutex_);

    auto it = cache_.find(cacheKey);
    if (it == cache_.end()) {
        return false;  // 缓存未命中
    }

    // 检查是否过期
    if (std::chrono::steady_clock::now() - it->second.timestamp > CACHE_TTL) {
        cache_.erase(it);
        return false;  // 缓存过期
    }

    // 复制响应数据
    const auto& cachedResponse = it->second.responseData;
    if (cachedResponse.size() > responseSize) {
        return false;  // 缓冲区不够
    }

    // 复制响应数据，但更新查询ID为原始查询ID
    memcpy(responseBuffer, cachedResponse.data(), cachedResponse.size());

    // 从查询数据中提取ID
    if (querySize >= 2) {
        uint16_t queryId = (queryData[0] << 8) | queryData[1];
        responseBuffer[0] = (queryId >> 8) & 0xFF;
        responseBuffer[1] = queryId & 0xFF;
    }

    responseSize = cachedResponse.size();
    return true;
}

// 设置缓存
void DNSCacheManager::setCachedResponse(const std::string& cacheKey,
                                       const uint8_t* queryData, int querySize,
                                       const uint8_t* responseData, int responseSize) {
    std::lock_guard<std::mutex> lock(cache_mutex_);

    DNSCacheEntry entry;
    entry.responseData.assign(responseData, responseData + responseSize);
    entry.timestamp = std::chrono::steady_clock::now();

    // 存储原始查询ID
    if (querySize >= 2) {
        entry.originalId = (queryData[0] << 8) | queryData[1];
    } else {
        entry.originalId = 0;
    }

    cache_[cacheKey] = std::move(entry);

    // 限制缓存大小，防止内存溢出
    if (cache_.size() > 10000) {  // 最多缓存10000个条目
        cleanupExpired();
        if (cache_.size() > 8000) {  // 如果清理后仍然太多，删除最老的
            auto oldest = std::min_element(cache_.begin(), cache_.end(),
                [](const auto& a, const auto& b) {
                    return a.second.timestamp < b.second.timestamp;
                });
            if (oldest != cache_.end()) {
                cache_.erase(oldest);
            }
        }
    }
}

// 清理过期缓存
void DNSCacheManager::cleanupExpired() {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    auto now = std::chrono::steady_clock::now();

    for (auto it = cache_.begin(); it != cache_.end();) {
        if (now - it->second.timestamp > CACHE_TTL) {
            it = cache_.erase(it);
        } else {
            ++it;
        }
    }
}

// 清空所有缓存
void DNSCacheManager::clear() {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    cache_.clear();
}

// 获取缓存统计
size_t DNSCacheManager::getCacheSize() {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    return cache_.size();
}
