/**
 * @file main.cpp
 * @brief VPN Proxy Server 主程序入口
 * @version 2.0.0
 * @date 2026-01-16
 */

#include "core/VpnServer.h"
#include "core/Config.h"
#include "util/Logger.h"
#include <iostream>
#include <csignal>
#include <atomic>
#include <memory>

using namespace vpn::core;
using namespace vpn::util;

// 全局服务器实例（用于信号处理）
std::unique_ptr<VpnServer> g_server;
std::atomic<bool> g_shutdownRequested{false};

/**
 * @brief 信号处理函数
 */
void SignalHandler(int signal) {
    const char* signalName = (signal == SIGINT) ? "SIGINT" : "SIGTERM";
    std::cout << "\nReceived " << signalName << ", shutting down gracefully..." << std::endl;
    
    g_shutdownRequested.store(true);
    
    if (g_server) {
        g_server->Stop();
    }
}

/**
 * @brief 设置信号处理
 */
void SetupSignalHandlers() {
    signal(SIGINT, SignalHandler);   // Ctrl+C
    signal(SIGTERM, SignalHandler);  // kill
    
    // 忽略 SIGPIPE（避免写入已关闭的 socket 导致崩溃）
    signal(SIGPIPE, SIG_IGN);
}

/**
 * @brief 打印使用帮助
 */
void PrintUsage(const char* programName) {
    std::cout << "Usage: " << programName << " [OPTIONS]\n\n"
              << "Options:\n"
              << "  -c, --config FILE    Configuration file path\n"
              << "  -p, --port PORT      Listen port (default: 8888)\n"
              << "  -a, --address ADDR   Listen address (default: 127.0.0.1)\n"
              << "  -t, --threads NUM    Number of worker threads (default: auto)\n"
              << "  -l, --log-level LVL  Log level (trace|debug|info|warn|error|fatal)\n"
              << "  -h, --help           Show this help message\n"
              << "  -v, --version        Show version information\n"
              << "\n"
              << "Examples:\n"
              << "  " << programName << " -c /etc/vpn/config.json\n"
              << "  " << programName << " -p 9999 -a 0.0.0.0 -t 8\n"
              << std::endl;
}

/**
 * @brief 打印版本信息
 */
void PrintVersion() {
    std::cout << "VPN Proxy Server v2.0.0\n"
              << "Built on " << __DATE__ << " " << __TIME__ << "\n"
              << "C++ Standard: " << __cplusplus << "\n"
#ifdef USE_BOOST_ASIO
              << "Network Backend: Boost.Asio\n"
#else
              << "Network Backend: epoll\n"
#endif
              << std::endl;
}

/**
 * @brief 解析命令行参数
 */
bool ParseCommandLine(int argc, char** argv, Config& config, std::string& configFile) {
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        
        if (arg == "-h" || arg == "--help") {
            PrintUsage(argv[0]);
            return false;
        }
        else if (arg == "-v" || arg == "--version") {
            PrintVersion();
            return false;
        }
        else if (arg == "-c" || arg == "--config") {
            if (i + 1 >= argc) {
                std::cerr << "Error: Missing config file path" << std::endl;
                return false;
            }
            configFile = argv[++i];
        }
        else if (arg == "-p" || arg == "--port") {
            if (i + 1 >= argc) {
                std::cerr << "Error: Missing port number" << std::endl;
                return false;
            }
            config.listenPort = static_cast<uint16_t>(std::stoi(argv[++i]));
        }
        else if (arg == "-a" || arg == "--address") {
            if (i + 1 >= argc) {
                std::cerr << "Error: Missing address" << std::endl;
                return false;
            }
            config.listenAddress = argv[++i];
        }
        else if (arg == "-t" || arg == "--threads") {
            if (i + 1 >= argc) {
                std::cerr << "Error: Missing thread count" << std::endl;
                return false;
            }
            config.numWorkerThreads = std::stoul(argv[++i]);
        }
        else if (arg == "-l" || arg == "--log-level") {
            if (i + 1 >= argc) {
                std::cerr << "Error: Missing log level" << std::endl;
                return false;
            }
            std::string level = argv[++i];
            if (level == "trace") config.logLevel = LogLevel::TRACE;
            else if (level == "debug") config.logLevel = LogLevel::DEBUG;
            else if (level == "info") config.logLevel = LogLevel::INFO;
            else if (level == "warn") config.logLevel = LogLevel::WARN;
            else if (level == "error") config.logLevel = LogLevel::ERROR;
            else if (level == "fatal") config.logLevel = LogLevel::FATAL;
            else {
                std::cerr << "Error: Invalid log level: " << level << std::endl;
                return false;
            }
        }
        else {
            std::cerr << "Error: Unknown option: " << arg << std::endl;
            PrintUsage(argv[0]);
            return false;
        }
    }
    
    return true;
}

/**
 * @brief 主函数
 */
int main(int argc, char** argv) {
    try {
        // 默认配置
        Config config = Config::Default();
        std::string configFile;
        
        // 解析命令行参数
        if (!ParseCommandLine(argc, argv, config, configFile)) {
            return 0;  // 打印帮助后正常退出
        }
        
        // 从文件加载配置（如果指定）
        if (!configFile.empty()) {
            auto loadedConfig = Config::LoadFromFile(configFile);
            if (loadedConfig) {
                config = *loadedConfig;
                std::cout << "Loaded configuration from: " << configFile << std::endl;
            } else {
                std::cerr << "Failed to load config file: " << configFile << std::endl;
                return 1;
            }
        }
        
        // 验证配置
        if (!config.Validate()) {
            std::cerr << "Invalid configuration" << std::endl;
            return 1;
        }
        
        // 初始化日志系统
        Logger::Initialize(config.logLevel, config.logFilePath);
        LOG_INFO("=================================================");
        LOG_INFO("VPN Proxy Server v2.0.0 Starting...");
        LOG_INFO("=================================================");
        
        // 打印配置信息
        LOG_INFO("Configuration:");
        LOG_INFO("  Listen: {}:{}", config.listenAddress, config.listenPort);
        LOG_INFO("  Worker threads: {}", 
                 config.numWorkerThreads > 0 ? std::to_string(config.numWorkerThreads) : "auto");
        LOG_INFO("  Max connections: {}", config.maxConnections);
        LOG_INFO("  Session timeout: {}s", config.sessionTimeout.count());
        LOG_INFO("  DNS cache: {}", config.enableDNSCache ? "enabled" : "disabled");
        LOG_INFO("  TCP forwarding: {}", config.enableTCPForwarding ? "enabled" : "disabled");
        LOG_INFO("  Metrics: {}", config.enableMetrics ? "enabled" : "disabled");
        
        // 设置信号处理
        SetupSignalHandlers();
        
        // 创建并启动服务器
        g_server = std::make_unique<VpnServer>(config);
        
        if (!g_server->Start()) {
            LOG_ERROR("Failed to start server");
            return 1;
        }
        
        LOG_INFO("=================================================");
        LOG_INFO("Server is running. Press Ctrl+C to stop.");
        LOG_INFO("=================================================");
        
        // 等待停止信号
        g_server->WaitForShutdown();
        
        // 打印最终统计信息
        auto stats = g_server->GetStats();
        LOG_INFO("=================================================");
        LOG_INFO("Server Statistics:");
        LOG_INFO("  Packets received: {}", stats.packetsReceived);
        LOG_INFO("  Packets sent: {}", stats.packetsSent);
        LOG_INFO("  Bytes received: {} MB", stats.bytesReceived / 1024.0 / 1024.0);
        LOG_INFO("  Bytes sent: {} MB", stats.bytesSent / 1024.0 / 1024.0);
        LOG_INFO("  Total connections: {}", stats.totalConnections);
        LOG_INFO("  Errors: {}", stats.errors);
        LOG_INFO("  Avg latency: {:.2f} ms", stats.avgLatencyMs);
        LOG_INFO("=================================================");
        LOG_INFO("Server stopped gracefully");
        
        return 0;
        
    } catch (const std::exception& e) {
        std::cerr << "Fatal error: " << e.what() << std::endl;
        LOG_FATAL("Fatal error: {}", e.what());
        return 1;
    } catch (...) {
        std::cerr << "Unknown fatal error" << std::endl;
        LOG_FATAL("Unknown fatal error");
        return 1;
    }
}
