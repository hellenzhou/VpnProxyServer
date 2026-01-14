#include "simple_dns_cache.h"

// 静态成员初始化
std::unordered_map<std::string, std::string> SimpleDNSCache::cache_;
std::unordered_map<std::string, std::chrono::steady_clock::time_point> SimpleDNSCache::cache_time_;
std::mutex SimpleDNSCache::cache_mutex_;
const std::chrono::seconds SimpleDNSCache::CACHE_TTL{300};
