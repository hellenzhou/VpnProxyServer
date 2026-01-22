// 使用示例：在packet_forwarder.cpp中
#include "thread_pool.h"

// 替换原来的线程创建
void StartUDPThread(int sockFd, const sockaddr_in& originalPeer) {
    // 使用线程池而不是直接创建线程
    auto* pool = GetThreadPool();
    if (pool) {
        pool->submit(VPNThreadPool::RESPONSE_WORKER, [sockFd, originalPeer]() {
            // 原来的UDP处理逻辑
            handleUDPResponse(sockFd, originalPeer);
        });
    }
}

// 替换原来的TCP线程
void StartTCPThread(int sockFd, const sockaddr_in& originalPeer) {
    auto* pool = GetThreadPool();
    if (pool) {
        pool->submit(VPNThreadPool::RESPONSE_WORKER, [sockFd, originalPeer]() {
            // 原来的TCP处理逻辑
            handleTCPResponse(sockFd, originalPeer);
        });
    }
}

// 在vpn_server.cpp中初始化
bool StartServer(int port) {
    // 初始化线程池
    if (!InitializeThreadPool(2, 2, 1)) {
        LOG_ERROR("Failed to initialize thread pool");
        return false;
    }
    
    // 其他启动逻辑...
    
    return true;
}

// 在服务器关闭时清理
void StopServer() {
    CleanupThreadPool();
    // 其他清理逻辑...
}
