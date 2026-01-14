#include "dns_cache.h"

// 静态成员初始化
std::unordered_map<std::string, std::string> DNSCache::cache_;
std::unordered_map<std::string, std::chrono::steady_clock::time_point> DNSCache::cache_time_;
std::mutex DNSCache::cache_mutex_;

std::unordered_map<std::string, std::chrono::steady_clock::time_point> DNSThrottler::pending_queries_;
std::mutex DNSThrottler::throttle_mutex_;
