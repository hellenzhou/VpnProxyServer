// 线程池容量优化配置
struct ThreadPoolConfig {
    // 基础配置
    int baseForwardWorkers = 2;
    int baseResponseWorkers = 2;
    int baseNetworkWorkers = 1;
    
    // 最大配置
    int maxForwardWorkers = 8;
    int maxResponseWorkers = 16;
    int maxNetworkWorkers = 8;
    
    // 动态调整参数
    int cpuCores = 4;  // 自动检测
    int memoryMB = 2048;  // 自动检测
    
    // 获取最优配置
    ThreadPoolConfig getOptimalConfig() {
        // 检测CPU核心数
        cpuCores = std::thread::hardware_concurrency();
        if (cpuCores == 0) cpuCores = 4;  // 默认值
        
        // 基于CPU核心数计算
        maxForwardWorkers = cpuCores;
        maxResponseWorkers = cpuCores * 2;
        maxNetworkWorkers = cpuCores;
        
        return *this;
    }
    
    // 获取总线程数
    int getTotalThreads() const {
        return maxForwardWorkers + maxResponseWorkers + maxNetworkWorkers;
    }
    
    // 验证配置合理性
    bool isValid() const {
        int total = getTotalThreads();
        return total <= 100 && total > 0;  // 移动设备建议不超过100个
    }
};

// 使用示例
ThreadPoolConfig config;
config.getOptimalConfig();

if (config.isValid()) {
    InitializeThreadPool(
        config.maxForwardWorkers,
        config.maxResponseWorkers, 
        config.maxNetworkWorkers
    );
    
    POOL_LOGI("Optimized thread pool: %d total threads (%dF+%dR+%dN)",
             config.getTotalThreads(),
             config.maxForwardWorkers,
             config.maxResponseWorkers,
             config.maxNetworkWorkers);
}
