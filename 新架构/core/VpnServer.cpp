#include "VpnServer.h"
#include "EventLoop.h"
#include "../network/UdpSocket.h"
#include "../network/AsyncReceiver.h"
#include "../resource/ThreadPool.h"
#include "../forwarding/NATTable.h"
#include "../forwarding/Forwarder.h"
#include "../packet/PacketProcessor.h"
#include "../util/Logger.h"
#include <thread>
#include <atomic>

namespace vpn {
namespace core {

using namespace network;
using namespace resource;
using namespace forwarding;
using namespace packet;
using namespace util;

/**
 * @brief VpnServer 的内部实现（PIMPL）
 */
class VpnServer::Impl {
public:
    explicit Impl(const Config& config)
        : config_(config)
        , running_(false)
        , threadPool_(config.numWorkerThreads > 0 
                     ? config.numWorkerThreads 
                     : std::thread::hardware_concurrency())
        , natTable_(config.natTableShards)
    {
        LOG_INFO("Initializing VPN Server with {} worker threads", 
                 threadPool_.GetThreadCount());
    }
    
    ~Impl() {
        Stop();
    }
    
    bool Start() {
        if (running_.load()) {
            LOG_WARN("Server already running");
            return false;
        }
        
        try {
            // 创建监听 socket
            socket_ = std::make_unique<UdpSocket>();
            if (!socket_->Bind(config_.listenAddress, config_.listenPort)) {
                LOG_ERROR("Failed to bind to {}:{}", 
                         config_.listenAddress, config_.listenPort);
                return false;
            }
            
            LOG_INFO("Server bound to {}:{}", 
                     config_.listenAddress, config_.listenPort);
            
            // 设置 socket 缓冲区
            socket_->SetReceiveBufferSize(config_.socketRecvBufferSize);
            socket_->SetSendBufferSize(config_.socketSendBufferSize);
            
            // 创建事件循环
            eventLoop_ = std::make_unique<EventLoop>();
            
            // 创建转发器
            forwarder_ = std::make_unique<Forwarder>(
                natTable_, threadPool_, *eventLoop_, config_
            );
            
            // 创建数据包处理器
            packetProcessor_ = std::make_unique<PacketProcessor>(
                *forwarder_, config_
            );
            
            // 创建异步接收器
            receiver_ = std::make_unique<AsyncReceiver>(
                *socket_, *eventLoop_
            );
            
            // 设置接收回调
            SetupReceiveHandler();
            
            // 设置定期清理任务
            SetupMaintenanceTasks();
            
            // 启动事件循环线程
            running_.store(true);
            eventLoopThread_ = std::thread([this]() {
                LOG_INFO("Event loop starting");
                eventLoop_->Run();
                LOG_INFO("Event loop stopped");
            });
            
            LOG_INFO("VPN Server started successfully");
            return true;
            
        } catch (const std::exception& e) {
            LOG_ERROR("Failed to start server: {}", e.what());
            Cleanup();
            return false;
        }
    }
    
    void Stop() {
        if (!running_.load()) {
            return;
        }
        
        LOG_INFO("Stopping VPN Server...");
        running_.store(false);
        
        // 停止事件循环
        if (eventLoop_) {
            eventLoop_->Stop();
        }
        
        // 等待事件循环线程
        if (eventLoopThread_.joinable()) {
            eventLoopThread_.join();
        }
        
        // 等待所有任务完成
        threadPool_.WaitAll();
        
        // 清理资源
        Cleanup();
        
        LOG_INFO("VPN Server stopped");
    }
    
    void WaitForShutdown() {
        if (eventLoopThread_.joinable()) {
            eventLoopThread_.join();
        }
    }
    
    bool IsRunning() const {
        return running_.load();
    }
    
    VpnServer::Stats GetStats() const {
        VpnServer::Stats stats;
        
        stats.packetsReceived = stats_.packetsReceived.load();
        stats.packetsSent = stats_.packetsSent.load();
        stats.bytesReceived = stats_.bytesReceived.load();
        stats.bytesSent = stats_.bytesSent.load();
        stats.activeConnections = natTable_.GetSize();
        stats.totalConnections = stats_.totalConnections.load();
        stats.errors = stats_.errors.load();
        
        // 计算平均延迟
        uint64_t totalLatency = stats_.totalLatencyUs.load();
        uint64_t packets = stats.packetsReceived;
        stats.avgLatencyMs = packets > 0 
            ? static_cast<double>(totalLatency) / packets / 1000.0 
            : 0.0;
        
        return stats;
    }

private:
    Config config_;
    std::atomic<bool> running_;
    
    // 核心组件
    std::unique_ptr<UdpSocket> socket_;
    std::unique_ptr<EventLoop> eventLoop_;
    std::unique_ptr<AsyncReceiver> receiver_;
    std::unique_ptr<PacketProcessor> packetProcessor_;
    std::unique_ptr<Forwarder> forwarder_;
    
    ThreadPool threadPool_;
    NATTable natTable_;
    
    std::thread eventLoopThread_;
    
    // 统计信息
    struct {
        std::atomic<uint64_t> packetsReceived{0};
        std::atomic<uint64_t> packetsSent{0};
        std::atomic<uint64_t> bytesReceived{0};
        std::atomic<uint64_t> bytesSent{0};
        std::atomic<uint64_t> totalConnections{0};
        std::atomic<uint64_t> errors{0};
        std::atomic<uint64_t> totalLatencyUs{0};
    } stats_;
    
    void SetupReceiveHandler() {
        // 链式接收：接收完成后立即开始下一次接收
        std::function<void()> receiveLoop = [this, receiveLoop]() {
            receiver_->AsyncReceive([this, receiveLoop](
                network::Result<network::Buffer> result,
                network::SocketAddress from
            ) {
                if (!running_.load()) {
                    return;
                }
                
                if (result.IsSuccess()) {
                    OnPacketReceived(result.Value(), from);
                } else {
                    LOG_ERROR("Receive error: {}", result.GetError().Message());
                    stats_.errors.fetch_add(1);
                }
                
                // 继续接收
                receiveLoop();
            });
        };
        
        // 启动初始接收
        receiveLoop();
    }
    
    void OnPacketReceived(const network::Buffer& data, 
                         const network::SocketAddress& from) {
        auto startTime = std::chrono::steady_clock::now();
        
        // 更新统计
        stats_.packetsReceived.fetch_add(1);
        stats_.bytesReceived.fetch_add(data.size());
        
        LOG_DEBUG("Received {} bytes from {}", data.size(), from.ToString());
        
        // 提交到线程池处理（避免阻塞事件循环）
        threadPool_.Submit([this, data, from, startTime]() {
            try {
                packetProcessor_->ProcessPacket(data, from);
                
                // 记录延迟
                auto endTime = std::chrono::steady_clock::now();
                auto latency = std::chrono::duration_cast<std::chrono::microseconds>(
                    endTime - startTime
                );
                stats_.totalLatencyUs.fetch_add(latency.count());
                
            } catch (const std::exception& e) {
                LOG_ERROR("Error processing packet: {}", e.what());
                stats_.errors.fetch_add(1);
            }
        });
    }
    
    void SetupMaintenanceTasks() {
        // 定期清理过期会话
        eventLoop_->AddPeriodicTimer(config_.cleanupInterval, [this]() {
            LOG_DEBUG("Running maintenance tasks");
            
            size_t removed = natTable_.CleanupExpired(config_.sessionTimeout);
            if (removed > 0) {
                LOG_INFO("Cleaned up {} expired sessions", removed);
            }
        });
        
        // 定期输出统计信息
        eventLoop_->AddPeriodicTimer(config_.statsUpdateInterval, [this]() {
            auto stats = GetStats();
            LOG_INFO("Stats: packets_rx={} packets_tx={} connections={} errors={}",
                    stats.packetsReceived, stats.packetsSent, 
                    stats.activeConnections, stats.errors);
        });
    }
    
    void Cleanup() {
        receiver_.reset();
        packetProcessor_.reset();
        forwarder_.reset();
        socket_.reset();
        eventLoop_.reset();
        
        natTable_.Clear();
    }
};

// ===== VpnServer 公共接口实现 =====

VpnServer::VpnServer(const Config& config)
    : impl_(std::make_unique<Impl>(config))
{
}

VpnServer::~VpnServer() = default;

VpnServer::VpnServer(VpnServer&&) noexcept = default;
VpnServer& VpnServer::operator=(VpnServer&&) noexcept = default;

bool VpnServer::Start() {
    return impl_->Start();
}

void VpnServer::Stop() {
    impl_->Stop();
}

void VpnServer::WaitForShutdown() {
    impl_->WaitForShutdown();
}

bool VpnServer::IsRunning() const {
    return impl_->IsRunning();
}

VpnServer::Stats VpnServer::GetStats() const {
    return impl_->GetStats();
}

bool VpnServer::ReloadConfig(const Config& config) {
    // TODO: 实现热重载部分配置
    return false;
}

} // namespace core
} // namespace vpn
