#pragma once
#include <string>
#include <unordered_map>
#include <vector>
#include <chrono>
#include <mutex>
#include <cstring>
#include <arpa/inet.h>

// DNS头部结构 (简化版)
struct DNSHeader {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};

// DNS查询问题结构
struct DNSQuestion {
    std::string qname;
    uint16_t qtype;
    uint16_t qclass;
};

// DNS缓存条目
struct DNSCacheEntry {
    std::vector<uint8_t> responseData;
    std::chrono::steady_clock::time_point timestamp;
    uint16_t originalId;  // 原始查询ID
};

// DNS缓存管理器
class DNSCacheManager {
private:
    static std::unordered_map<std::string, DNSCacheEntry> cache_;
    static std::mutex cache_mutex_;
    static const std::chrono::seconds CACHE_TTL;  // 5分钟缓存

public:
    // 解析DNS查询域名 (从DNS查询数据包中提取域名)
    static std::string parseQueryDomain(const uint8_t* dnsData, int dataSize);

    // 生成缓存键 (域名 + 查询类型)
    static std::string makeCacheKey(const std::string& domain, uint16_t qtype);

    // 检查缓存
    static bool getCachedResponse(const std::string& cacheKey,
                                 const uint8_t* queryData, int querySize,
                                 uint8_t* responseBuffer, int& responseSize);

    // 设置缓存
    static void setCachedResponse(const std::string& cacheKey,
                                 const uint8_t* queryData, int querySize,
                                 const uint8_t* responseData, int responseSize);

    // 清理过期缓存
    static void cleanupExpired();

    // 清空所有缓存
    static void clear();

    // 获取缓存统计
    static size_t getCacheSize();
};
