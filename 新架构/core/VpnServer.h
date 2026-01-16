#pragma once

#include <memory>
#include <atomic>
#include <string>
#include "Config.h"

namespace vpn {
namespace core {

/**
 * @brief VPN 代理服务器主类
 * 
 * 职责：
 * - 管理服务器生命周期
 * - 协调各个子模块
 * - 提供统计信息接口
 */
class VpnServer {
public:
    /**
     * @brief 服务器统计信息
     */
    struct Stats {
        uint64_t packetsReceived = 0;
        uint64_t packetsSent = 0;
        uint64_t bytesReceived = 0;
        uint64_t bytesSent = 0;
        uint64_t activeConnections = 0;
        uint64_t totalConnections = 0;
        uint64_t errors = 0;
        double avgLatencyMs = 0.0;
    };
    
    /**
     * @brief 构造函数
     * @param config 服务器配置
     */
    explicit VpnServer(const Config& config);
    
    /**
     * @brief 析构函数 - 自动停止服务器
     */
    ~VpnServer();
    
    // 禁止拷贝
    VpnServer(const VpnServer&) = delete;
    VpnServer& operator=(const VpnServer&) = delete;
    
    // 允许移动
    VpnServer(VpnServer&&) noexcept;
    VpnServer& operator=(VpnServer&&) noexcept;
    
    /**
     * @brief 启动服务器
     * @return true 成功，false 失败
     */
    bool Start();
    
    /**
     * @brief 停止服务器（优雅关闭）
     */
    void Stop();
    
    /**
     * @brief 等待服务器停止
     * 阻塞当前线程直到服务器完全停止
     */
    void WaitForShutdown();
    
    /**
     * @brief 检查服务器是否正在运行
     */
    bool IsRunning() const;
    
    /**
     * @brief 获取服务器统计信息
     */
    Stats GetStats() const;
    
    /**
     * @brief 重新加载配置（部分配置）
     * @param config 新配置
     * @return true 成功，false 失败
     */
    bool ReloadConfig(const Config& config);

private:
    class Impl;  // PIMPL 模式，隐藏实现细节
    std::unique_ptr<Impl> impl_;
};

} // namespace core
} // namespace vpn
