#include "thread_pool.h"

// 全局线程池实例
std::unique_ptr<VPNThreadPool> g_threadPool = nullptr;

// 初始化全局线程池
bool InitializeThreadPool(int forwardWorkers = 2, int responseWorkers = 2, int networkWorkers = 1) {
    if (g_threadPool) {
        return true; // 已经初始化
    }
    
    g_threadPool = std::make_unique<VPNThreadPool>();
    return g_threadPool->start(forwardWorkers, responseWorkers, networkWorkers);
}

// 获取全局线程池
VPNThreadPool* GetThreadPool() {
    return g_threadPool.get();
}

// 清理全局线程池
void CleanupThreadPool() {
    if (g_threadPool) {
        g_threadPool->shutdown();
        g_threadPool.reset();
    }
}
