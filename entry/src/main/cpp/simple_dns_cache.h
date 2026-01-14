#pragma once
#include <string>
#include <unordered_map>
#include <chrono>
#include <mutex>

// 简化版DNS缓存 - 只缓存，不去重
class SimpleDNSCache {
private:
    static std::unordered_map<std::string, std::string> cache_;
    static std::unordered_map<std::string, std::chrono::steady_clock::time_point> cache_time_;
    static std::mutex cache_mutex_;
    static const std::chrono::seconds CACHE_TTL;
    
public:
    static bool get(const std::string& query, std::string& response) {
        std::lock_guard<std::mutex> lock(cache_mutex_);
        auto it = cache_.find(query);
        if (it != cache_.end()) {
            auto time_it = cache_time_.find(query);
            if (std::chrono::steady_clock::now() - time_it->second < CACHE_TTL) {
                return true;
            }
            cache_.erase(it);
            cache_time_.erase(time_it);
        }
        return false;
    }
    
    static void set(const std::string& query, const std::string& response) {
        std::lock_guard<std::mutex> lock(cache_mutex_);
        cache_[query] = response;
        cache_time_[query] = std::chrono::steady_clock::now();
    }
};
