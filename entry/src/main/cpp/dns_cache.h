#pragma once
#include <string>
#include <unordered_map>
#include <chrono>
#include <mutex>

class DNSCache {
private:
    static std::unordered_map<std::string, std::string> cache_;
    static std::unordered_map<std::string, std::chrono::steady_clock::time_point> cache_time_;
    static std::mutex cache_mutex_;
    static const std::chrono::seconds CACHE_TTL{300}; // 5分钟缓存
    
public:
    static bool getCachedResponse(const std::string& query, std::string& response) {
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
    
    static void setCachedResponse(const std::string& query, const std::string& response) {
        std::lock_guard<std::mutex> lock(cache_mutex_);
        cache_[query] = response;
        cache_time_[query] = std::chrono::steady_clock::now();
    }
    
    static void clearCache() {
        std::lock_guard<std::mutex> lock(cache_mutex_);
        cache_.clear();
        cache_time_.clear();
    }
};

class DNSThrottler {
private:
    static std::unordered_map<std::string, std::chrono::steady_clock::time_point> pending_queries_;
    static std::mutex throttle_mutex_;
    static const std::chrono::seconds THROTTLE_WINDOW{60}; // 1分钟内相同查询只处理一次
    
public:
    static bool shouldProcessQuery(const std::string& query) {
        std::lock_guard<std::mutex> lock(throttle_mutex_);
        auto it = pending_queries_.find(query);
        if (it != pending_queries_.end()) {
            if (std::chrono::steady_clock::now() - it->second < THROTTLE_WINDOW) {
                return false; // 限制处理
            }
        }
        pending_queries_[query] = std::chrono::steady_clock::now();
        return true;
    }
    
    static void cleanupOldQueries() {
        std::lock_guard<std::mutex> lock(throttle_mutex_);
        auto now = std::chrono::steady_clock::now();
        for (auto it = pending_queries_.begin(); it != pending_queries_.end();) {
            if (now - it->second > THROTTLE_WINDOW) {
                it = pending_queries_.erase(it);
            } else {
                ++it;
            }
        }
    }
};
