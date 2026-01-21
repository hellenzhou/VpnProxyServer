#pragma once

#include <queue>
#include <mutex>
#include <condition_variable>
#include <optional>
#include <chrono>

/**
 * 线程安全队列 - 支持多生产者多消费者
 */
template<typename T>
class ThreadSafeQueue {
public:
    ThreadSafeQueue(size_t maxSize = 10000) : maxSize_(maxSize), shutdown_(false) {}
    
    ~ThreadSafeQueue() {
        shutdown();
    }
    
    // 入队（阻塞直到有空间）
    bool push(const T& item) {
        std::unique_lock<std::mutex> lock(mutex_);
        
        // 等待队列有空间
        notFull_.wait(lock, [this] {
            return queue_.size() < maxSize_ || shutdown_;
        });
        
        if (shutdown_) {
            return false;
        }
        
        queue_.push(item);
        notEmpty_.notify_one();
        return true;
    }
    
    // 入队（非阻塞，队列满时返回false）
    bool tryPush(const T& item) {
        std::unique_lock<std::mutex> lock(mutex_);
        
        if (queue_.size() >= maxSize_ || shutdown_) {
            return false;
        }
        
        queue_.push(item);
        notEmpty_.notify_one();
        return true;
    }
    
    // 出队（阻塞直到有数据）
    std::optional<T> pop() {
        std::unique_lock<std::mutex> lock(mutex_);
        
        // 等待队列非空
        notEmpty_.wait(lock, [this] {
            return !queue_.empty() || shutdown_;
        });
        
        if (shutdown_ && queue_.empty()) {
            return std::nullopt;
        }
        
        T item = queue_.front();
        queue_.pop();
        notFull_.notify_one();
        return item;
    }
    
    // 出队（带超时）
    std::optional<T> popWithTimeout(std::chrono::milliseconds timeout) {
        std::unique_lock<std::mutex> lock(mutex_);
        
        if (!notEmpty_.wait_for(lock, timeout, [this] {
            return !queue_.empty() || shutdown_;
        })) {
            return std::nullopt;  // 超时
        }
        
        if (shutdown_ && queue_.empty()) {
            return std::nullopt;
        }
        
        T item = queue_.front();
        queue_.pop();
        notFull_.notify_one();
        return item;
    }
    
    // 获取队列大小
    size_t size() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return queue_.size();
    }
    
    // 检查队列是否为空
    bool empty() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return queue_.empty();
    }
    
    // 关闭队列
    void shutdown() {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            shutdown_ = true;
        }
        notEmpty_.notify_all();
        notFull_.notify_all();
    }
    
    // 清空队列
    void clear() {
        std::lock_guard<std::mutex> lock(mutex_);
        // 🐛 修复：clear时不修改shutdown_状态，只清空数据
        std::queue<T> empty;
        std::swap(queue_, empty);
        notFull_.notify_all();
    }
    
    // 重置队列（清空并允许重新使用）
    void reset() {
        std::lock_guard<std::mutex> lock(mutex_);
        std::queue<T> empty;
        std::swap(queue_, empty);
        shutdown_.store(false);  // 重置shutdown状态
        notFull_.notify_all();
        notEmpty_.notify_all();
    }

private:
    std::queue<T> queue_;
    mutable std::mutex mutex_;
    std::condition_variable notEmpty_;
    std::condition_variable notFull_;
    size_t maxSize_;
    std::atomic<bool> shutdown_;  // 🐛 修复：必须是atomic，多线程并发访问
};
