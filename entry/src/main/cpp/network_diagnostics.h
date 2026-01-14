#ifndef NETWORK_DIAGNOSTICS_H
#define NETWORK_DIAGNOSTICS_H

#include <string>
#include <vector>

struct NetworkInterface {
    std::string name;
    std::string ipAddress;
    bool isUp;
    bool isLoopback;
};

class NetworkDiagnostics {
public:
    // 测试基本网络连通性
    static bool TestBasicConnectivity();
    
    // 测试DNS连通性
    static bool TestDNSConnectivity(const std::string& dnsServer = "8.8.8.8");
    
    // 测试TCP连接到特定服务器
    static bool TestTCPConnection(const std::string& host, int port, int timeoutSec = 5);
    
    // 测试UDP发送
    static bool TestUDPSend(const std::string& host, int port);
    
    // 列出所有网络接口
    static std::vector<NetworkInterface> ListNetworkInterfaces();
    
    // 检查防火墙状态（尝试检测常见端口）
    static void CheckFirewallStatus();
    
    // 完整的网络诊断报告
    static void RunFullDiagnostics();
    
    // 测试网关连通性
    static bool TestGatewayConnectivity();
};

#endif // NETWORK_DIAGNOSTICS_H
