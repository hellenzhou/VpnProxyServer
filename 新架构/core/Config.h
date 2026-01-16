#pragma once

#include <string>
#include <chrono>
#include <optional>
#include <thread>

namespace vpn {
namespace core {

/**
 * @brief 日志级别
 */
enum class LogLevel {
    TRACE,
    DEBUG,
    INFO,
    WARN,
    ERROR,
    FATAL
};

/**
 * @brief 服务器配置
 */
struct Config {
    // ===== 网络配置 =====
    
    /// 监听地址
    std::string listenAddress = "127.0.0.1";
    
    /// 监听端口
    uint16_t listenPort = 8888;
    
    /// 最大连接数
    size_t maxConnections = 10000;
    
    /// Socket 接收缓冲区大小（字节）
    size_t socketRecvBufferSize = 2 * 1024 * 1024;  // 2MB
    
    /// Socket 发送缓冲区大小（字节）
    size_t socketSendBufferSize = 2 * 1024 * 1024;  // 2MB
    
    // ===== 线程配置 =====
    
    /// 工作线程数（0 = 自动检测）
    size_t numWorkerThreads = 0;
    
    /// I/O 线程数
    size_t numIOThreads = 1;
    
    // ===== 性能配置 =====
    
    /// 会话超时时间
    std::chrono::seconds sessionTimeout{300};  // 5 分钟
    
    /// DNS 查询超时
    std::chrono::seconds dnsTimeout{5};
    
    /// NAT 表分片数（必须是 2 的幂）
    size_t natTableShards = 16;
    
    /// 数据包缓冲区大小
    size_t packetBufferSize = 2048;
    
    /// 对象池初始大小
    size_t objectPoolSize = 1000;
    
    // ===== 功能开关 =====
    
    /// 启用 DNS 缓存
    bool enableDNSCache = true;
    
    /// DNS 缓存 TTL
    std::chrono::seconds dnsCacheTTL{300};
    
    /// 启用性能指标收集
    bool enableMetrics = true;
    
    /// 指标导出端口（0 = 禁用 HTTP 导出）
    uint16_t metricsPort = 9090;
    
    /// 启用 TCP 转发（实验性）
    bool enableTCPForwarding = false;
    
    // ===== 日志配置 =====
    
    /// 日志级别
    LogLevel logLevel = LogLevel::INFO;
    
    /// 日志文件路径（空 = 仅控制台）
    std::string logFilePath;
    
    /// 日志最大大小（字节，0 = 无限）
    size_t logMaxSize = 100 * 1024 * 1024;  // 100MB
    
    /// 日志文件数量
    size_t logMaxFiles = 5;
    
    // ===== 高级配置 =====
    
    /// 定期清理间隔
    std::chrono::seconds cleanupInterval{30};
    
    /// 统计信息更新间隔
    std::chrono::seconds statsUpdateInterval{1};
    
    /**
     * @brief 从 JSON 文件加载配置
     * @param path 配置文件路径
     * @return 配置对象，加载失败返回 nullopt
     */
    static std::optional<Config> LoadFromFile(const std::string& path);
    
    /**
     * @brief 保存配置到 JSON 文件
     * @param path 配置文件路径
     * @return true 成功，false 失败
     */
    bool SaveToFile(const std::string& path) const;
    
    /**
     * @brief 验证配置有效性
     * @return true 有效，false 无效
     */
    bool Validate() const;
    
    /**
     * @brief 获取默认配置
     */
    static Config Default();
    
    /**
     * @brief 自动检测最优配置
     */
    static Config AutoDetect();
};

} // namespace core
} // namespace vpn
