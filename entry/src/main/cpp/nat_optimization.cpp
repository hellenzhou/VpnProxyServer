// 优化方案：使用线程池替换独立响应线程

// 当前实现：每个连接创建一个线程
void StartUDPThread(int sockFd, const sockaddr_in& originalPeer) {
    std::thread([sockFd, originalPeer]() {
        while (true) {
            ssize_t received = recvfrom(sockFd, buffer, sizeof(buffer), 0, nullptr, nullptr);
            // 处理响应...
        }
    }).detach();
}

// 优化实现：使用线程池管理响应任务
void SubmitUDPResponseTask(int sockFd, const sockaddr_in& originalPeer) {
    auto* threadPool = GetThreadPool();
    if (threadPool) {
        threadPool->submit(VPNThreadPool::RESPONSE_WORKER, [sockFd, originalPeer]() {
            uint8_t buffer[4096];
            int noResponseCount = 0;
            
            while (noResponseCount < 3) {
                ssize_t received = recvfrom(sockFd, buffer, sizeof(buffer), 0, nullptr, nullptr);
                if (received < 0) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        noResponseCount++;
                        continue;
                    }
                    break;
                }
                
                // 重置计数，处理响应
                noResponseCount = 0;
                handleUDPResponse(sockFd, originalPeer, buffer, received);
            }
            
            // 清理NAT映射
            NATTable::RemoveMappingBySocket(sockFd);
            close(sockFd);
        });
    }
}

// 进一步优化：事件驱动模型
class EventDrivenNAT {
private:
    std::unordered_map<int, std::function<void(uint8_t*, size_t)>> socketHandlers;
    int epollFd;
    
public:
    void addSocketHandler(int sockFd, std::function<void(uint8_t*, size_t)> handler) {
        // 注册socket到epoll
        struct epoll_event ev;
        ev.events = EPOLLIN;
        ev.data.fd = sockFd;
        epoll_ctl(epollFd, EPOLL_CTL_ADD, sockFd, &ev);
        
        // 保存处理器
        socketHandlers[sockFd] = handler;
    }
    
    void eventLoop() {
        struct epoll_event events[100];
        while (running) {
            int nfds = epoll_wait(epollFd, events, 100, 1000);
            for (int i = 0; i < nfds; i++) {
                int fd = events[i].data.fd;
                if (socketHandlers.find(fd) != socketHandlers.end()) {
                    // 处理事件
                    uint8_t buffer[4096];
                    ssize_t received = recv(fd, buffer, sizeof(buffer), 0);
                    if (received > 0) {
                        socketHandlers[fd](buffer, received);
                    }
                }
            }
        }
    }
};
