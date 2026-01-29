#pragma once

#include <queue>
#include <mutex>
#include <condition_variable>
#include <chrono>
#include <memory>

// 🔧 简单的Optional实现（HarmonyOS可能不支持std::optional）
template<typename T>
class Optional {
public:
    Optional() : hasValue_(false) {}
    Optional(const T& value) : hasValue_(true), value_(value) {}

    bool has_value() const { return hasValue_; }

    T& value() {
        if (!hasValue_) {
            // 🐛 修复：避免返回未初始化的值
            throw std::runtime_error("Optional has no value");
        }
        return value_;
    }

    const T& value() const {
        if (!hasValue_) {
            throw std::runtime_error("Optional has no value");
        }
        return value_;
    }

    explicit operator bool() const { return hasValue_; }

private:
    bool hasValue_;
    T value_;
};

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
            return queue_.size() < maxSize_ || shutdown_.load();
        });
        
        if (shutdown_.load()) {
            return false;
        }
        
        queue_.push(item);
        notEmpty_.notify_one();
        return true;
    }
    
    // 入队（非阻塞，队列满时返回false）
    bool tryPush(const T& item) {
        std::unique_lock<std::mutex> lock(mutex_);
        
        if (queue_.size() >= maxSize_ || shutdown_.load()) {
            return false;
        }
        
        queue_.push(item);
        notEmpty_.notify_one();
        return true;
    }
    
    // 出队（阻塞直到有数据）
    Optional<T> pop() {
        std::unique_lock<std::mutex> lock(mutex_);
        
        // 等待队列非空
        notEmpty_.wait(lock, [this] {
            return !queue_.empty() || shutdown_.load();
        });
        
        if (shutdown_.load() && queue_.empty()) {
            return Optional<T>();  // 空值
        }
        
        T item = queue_.front();
        queue_.pop();
        notFull_.notify_one();
        return Optional<T>(item);
    }
    
    // 出队（带超时）
    Optional<T> popWithTimeout(std::chrono::milliseconds timeout) {
        std::unique_lock<std::mutex> lock(mutex_);
        
        // 🚨 关键修复：在等待前检查队列是否已经有数据
        // 这解决了条件变量通知丢失或竞态条件导致的问题
        if (!queue_.empty()) {
            // 队列已经有数据，直接返回，不需要等待
            T item = queue_.front();
            queue_.pop();
            notFull_.notify_one();
            return Optional<T>(item);
        }
        
        // 如果已关闭且队列为空，直接返回
        if (shutdown_.load()) {
            return Optional<T>();
        }
        
        // 队列为空，等待数据到达
        bool waitResult = notEmpty_.wait_for(lock, timeout, [this] {
            return !queue_.empty() || shutdown_.load();
        });
        
        // 检查等待结果
        if (!waitResult) {
            // 超时，但再次检查队列（防止竞态条件：数据在超时瞬间到达）
            if (!queue_.empty()) {
                T item = queue_.front();
                queue_.pop();
                notFull_.notify_one();
                return Optional<T>(item);
            }
            return Optional<T>();  // 超时且队列仍为空
        }
        
        // waitResult 为 true，说明队列非空或已关闭
        if (shutdown_.load() && queue_.empty()) {
            return Optional<T>();  // 已关闭且队列为空
        }
        
        // 此时队列应该非空（因为 waitResult 为 true 且 shutdown_ 为 false 或队列非空）
        if (queue_.empty()) {
            // 🚨 防御性检查：理论上不应该发生，但为了健壮性保留
            return Optional<T>();
        }
        
        T item = queue_.front();
        queue_.pop();
        notFull_.notify_one();
        return Optional<T>(item);
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
    
    // 诊断方法：获取队列状态（用于调试）
    struct QueueState {
        size_t size;
        bool empty;
        bool shutdown;
    };
    
    QueueState getState() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return {queue_.size(), queue_.empty(), shutdown_.load()};
    }
    
    // 关闭队列
    void shutdown() {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            shutdown_.store(true);
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
        {
            std::lock_guard<std::mutex> lock(mutex_);
            std::queue<T> empty;
            std::swap(queue_, empty);
            shutdown_.store(false);  // 重置shutdown状态
        }
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
