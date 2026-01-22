#include "network_diagnostics.h"
#include <hilog/log.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <sys/select.h>
#include <netdb.h>

#define MAKE_FILE_NAME (strrchr(__FILE__, '/') ? (strrchr(__FILE__, '/') + 1) : __FILE__)

#define DIAG_LOGI(fmt, ...) \
  OH_LOG_Print(LOG_APP, LOG_INFO, 0x15b1, "VpnServer", "ZHOUB [NetworkDiag] [%{public}s %{public}d] " fmt, MAKE_FILE_NAME, __LINE__, ##__VA_ARGS__)
#define DIAG_LOGE(fmt, ...) \
  OH_LOG_Print(LOG_APP, LOG_ERROR, 0x15b1, "VpnServer", "ZHOUB [NetworkDiag] [%{public}s %{public}d] " fmt, MAKE_FILE_NAME, __LINE__, ##__VA_ARGS__)
#define DIAG_LOGW(fmt, ...) \
  OH_LOG_Print(LOG_APP, LOG_WARN, 0x15b1, "VpnServer", "ZHOUB [NetworkDiag] [%{public}s %{public}d] " fmt, MAKE_FILE_NAME, __LINE__, ##__VA_ARGS__)

bool NetworkDiagnostics::TestBasicConnectivity() {
    DIAG_LOGI("=== Testing Basic Network Connectivity ===");
    
    // 测试本地回环
    int sockFd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockFd < 0) {
        DIAG_LOGE("❌ Failed to create socket: %{public}s", strerror(errno));
        return false;
    }
    
    struct sockaddr_in loopbackAddr{};
    loopbackAddr.sin_family = AF_INET;
    loopbackAddr.sin_port = htons(12345);
    inet_pton(AF_INET, "127.0.0.1", &loopbackAddr.sin_addr);
    
    int bindResult = bind(sockFd, (struct sockaddr*)&loopbackAddr, sizeof(loopbackAddr));
    if (bindResult == 0) {
        DIAG_LOGI("✅ Loopback interface working (127.0.0.1)");
        close(sockFd);
        return true;
    } else {
        DIAG_LOGE("❌ Loopback interface bind failed: %{public}s", strerror(errno));
        close(sockFd);
        return false;
    }
}

bool NetworkDiagnostics::TestDNSConnectivity(const std::string& dnsServer) {
    DIAG_LOGI("=== Testing DNS Connectivity to %{public}s ===", dnsServer.c_str());
    
    int sockFd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockFd < 0) {
        DIAG_LOGE("❌ Failed to create UDP socket: %{public}s", strerror(errno));
        return false;
    }
    
    // 设置非阻塞
    int flags = fcntl(sockFd, F_GETFL, 0);
    fcntl(sockFd, F_SETFL, flags | O_NONBLOCK);
    
    struct sockaddr_in dnsAddr{};
    dnsAddr.sin_family = AF_INET;
    dnsAddr.sin_port = htons(53);
    if (inet_pton(AF_INET, dnsServer.c_str(), &dnsAddr.sin_addr) <= 0) {
        DIAG_LOGE("❌ Invalid DNS server address: %{public}s", dnsServer.c_str());
        close(sockFd);
        return false;
    }
    
    // 构造简单的DNS查询（查询google.com的A记录）
    uint8_t dnsQuery[] = {
        0x12, 0x34,  // Transaction ID
        0x01, 0x00,  // Flags: standard query
        0x00, 0x01,  // Questions: 1
        0x00, 0x00,  // Answer RRs: 0
        0x00, 0x00,  // Authority RRs: 0
        0x00, 0x00,  // Additional RRs: 0
        // Query: google.com
        0x06, 'g', 'o', 'o', 'g', 'l', 'e',
        0x03, 'c', 'o', 'm',
        0x00,        // End of name
        0x00, 0x01,  // Type: A
        0x00, 0x01   // Class: IN
    };
    
    ssize_t sent = sendto(sockFd, dnsQuery, sizeof(dnsQuery), 0, 
                          (struct sockaddr*)&dnsAddr, sizeof(dnsAddr));
    
    if (sent < 0) {
        DIAG_LOGE("❌ Failed to send DNS query: %{public}s", strerror(errno));
        close(sockFd);
        return false;
    }
    
    DIAG_LOGI("✅ DNS query sent (%{public}zd bytes), waiting for response...", sent);
    
    // 等待响应
    fd_set readfds;
    struct timeval timeout;
    timeout.tv_sec = 3;
    timeout.tv_usec = 0;
    
    FD_ZERO(&readfds);
    FD_SET(sockFd, &readfds);
    
    int selectResult = select(sockFd + 1, &readfds, nullptr, nullptr, &timeout);
    
    if (selectResult > 0) {
        uint8_t response[512];
        ssize_t received = recvfrom(sockFd, response, sizeof(response), 0, nullptr, nullptr);
        if (received > 0) {
            DIAG_LOGI("✅ DNS response received (%{public}zd bytes)", received);
            DIAG_LOGI("✅ DNS connectivity OK");
            close(sockFd);
            return true;
        } else {
            DIAG_LOGE("❌ Failed to receive DNS response: %{public}s", strerror(errno));
        }
    } else if (selectResult == 0) {
        DIAG_LOGE("❌ DNS query timeout (3 seconds)");
    } else {
        DIAG_LOGE("❌ select() failed: %{public}s", strerror(errno));
    }
    
    close(sockFd);
    return false;
}

bool NetworkDiagnostics::TestTCPConnection(const std::string& host, int port, int timeoutSec) {
    DIAG_LOGI("=== Testing TCP Connection to %{public}s:%{public}d ===", host.c_str(), port);
    
    int sockFd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockFd < 0) {
        DIAG_LOGE("❌ Failed to create TCP socket: %{public}s", strerror(errno));
        return false;
    }
    
    // 设置非阻塞
    int flags = fcntl(sockFd, F_GETFL, 0);
    fcntl(sockFd, F_SETFL, flags | O_NONBLOCK);
    
    struct sockaddr_in serverAddr{};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);
    
    // 尝试解析主机名或直接使用IP
    if (inet_pton(AF_INET, host.c_str(), &serverAddr.sin_addr) <= 0) {
        // 可能是主机名，尝试解析
        struct hostent* he = gethostbyname(host.c_str());
        if (he == nullptr) {
            DIAG_LOGE("❌ Failed to resolve hostname: %{public}s", host.c_str());
            close(sockFd);
            return false;
        }
        memcpy(&serverAddr.sin_addr, he->h_addr_list[0], he->h_length);
        
        char resolvedIP[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &serverAddr.sin_addr, resolvedIP, INET_ADDRSTRLEN);
        DIAG_LOGI("✅ Resolved %{public}s to %{public}s", host.c_str(), resolvedIP);
    }
    
    int connectResult = connect(sockFd, (struct sockaddr*)&serverAddr, sizeof(serverAddr));
    
    if (connectResult < 0) {
        if (errno == EINPROGRESS) {
            DIAG_LOGI("⏳ Connection in progress, waiting...");
            
            fd_set writefds;
            struct timeval timeout;
            timeout.tv_sec = timeoutSec;
            timeout.tv_usec = 0;
            
            FD_ZERO(&writefds);
            FD_SET(sockFd, &writefds);
            
            int selectResult = select(sockFd + 1, nullptr, &writefds, nullptr, &timeout);
            
            if (selectResult > 0) {
                int error = 0;
                socklen_t len = sizeof(error);
                if (getsockopt(sockFd, SOL_SOCKET, SO_ERROR, &error, &len) == 0 && error == 0) {
                    DIAG_LOGI("✅ TCP connection successful to %{public}s:%{public}d", host.c_str(), port);
                    close(sockFd);
                    return true;
                } else {
                    DIAG_LOGE("❌ TCP connection failed: %{public}s", strerror(error));
                }
            } else if (selectResult == 0) {
                DIAG_LOGE("❌ TCP connection timeout (%{public}d seconds)", timeoutSec);
            } else {
                DIAG_LOGE("❌ select() failed: %{public}s", strerror(errno));
            }
        } else {
            DIAG_LOGE("❌ Connect failed immediately: %{public}s", strerror(errno));
        }
    } else {
        DIAG_LOGI("✅ TCP connection successful (immediate) to %{public}s:%{public}d", host.c_str(), port);
        close(sockFd);
        return true;
    }
    
    close(sockFd);
    return false;
}

bool NetworkDiagnostics::TestUDPSend(const std::string& host, int port) {
    DIAG_LOGI("=== Testing UDP Send to %{public}s:%{public}d ===", host.c_str(), port);
    
    int sockFd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockFd < 0) {
        DIAG_LOGE("❌ Failed to create UDP socket: %{public}s", strerror(errno));
        return false;
    }
    
    struct sockaddr_in serverAddr{};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);
    
    if (inet_pton(AF_INET, host.c_str(), &serverAddr.sin_addr) <= 0) {
        DIAG_LOGE("❌ Invalid IP address: %{public}s", host.c_str());
        close(sockFd);
        return false;
    }
    
    const char* testData = "PING";
    ssize_t sent = sendto(sockFd, testData, strlen(testData), 0,
                          (struct sockaddr*)&serverAddr, sizeof(serverAddr));
    
    if (sent > 0) {
        DIAG_LOGI("✅ UDP send successful (%{public}zd bytes)", sent);
        close(sockFd);
        return true;
    } else {
        DIAG_LOGE("❌ UDP send failed: %{public}s", strerror(errno));
        close(sockFd);
        return false;
    }
}

std::vector<NetworkInterface> NetworkDiagnostics::ListNetworkInterfaces() {
    DIAG_LOGI("=== Listing Network Interfaces ===");
    std::vector<NetworkInterface> interfaces;
    
    struct ifaddrs* ifAddrStruct = nullptr;
    if (getifaddrs(&ifAddrStruct) == -1) {
        DIAG_LOGE("❌ getifaddrs() failed: %{public}s", strerror(errno));
        return interfaces;
    }
    
    for (struct ifaddrs* ifa = ifAddrStruct; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == nullptr) continue;
        
        // 只处理IPv4地址
        if (ifa->ifa_addr->sa_family == AF_INET) {
            NetworkInterface iface;
            iface.name = ifa->ifa_name;
            
            char addressBuffer[INET_ADDRSTRLEN];
            void* tmpAddrPtr = &((struct sockaddr_in*)ifa->ifa_addr)->sin_addr;
            inet_ntop(AF_INET, tmpAddrPtr, addressBuffer, INET_ADDRSTRLEN);
            iface.ipAddress = addressBuffer;
            
            iface.isUp = (ifa->ifa_flags & IFF_UP) != 0;
            iface.isLoopback = (ifa->ifa_flags & IFF_LOOPBACK) != 0;
            
            interfaces.push_back(iface);
            
            DIAG_LOGI("📡 Interface: %{public}s", iface.name.c_str());
            DIAG_LOGI("   - IP: %{public}s", iface.ipAddress.c_str());
            DIAG_LOGI("   - Status: %{public}s", iface.isUp ? "UP" : "DOWN");
            DIAG_LOGI("   - Type: %{public}s", iface.isLoopback ? "Loopback" : "Physical");
        }
    }
    
    if (ifAddrStruct != nullptr) {
        freeifaddrs(ifAddrStruct);
    }
    
    return interfaces;
}

void NetworkDiagnostics::CheckFirewallStatus() {
    DIAG_LOGI("=== Checking Firewall Status (Testing Common Ports) ===");
    
    struct TestTarget {
        std::string host;
        int port;
        std::string description;
    };
    
    std::vector<TestTarget> targets = {
        {"8.8.8.8", 53, "Google DNS"},
        {"1.1.1.1", 53, "Cloudflare DNS"},
        {"8.8.8.8", 443, "Google HTTPS"},
        {"www.baidu.com", 80, "Baidu HTTP"},
        {"www.baidu.com", 443, "Baidu HTTPS"}
    };
    
    for (const auto& target : targets) {
        DIAG_LOGI("Testing: %{public}s (%{public}s:%{public}d)", 
                  target.description.c_str(), target.host.c_str(), target.port);
        
        bool result = TestTCPConnection(target.host, target.port, 3);
        if (!result) {
            DIAG_LOGW("⚠️ Cannot reach %{public}s - may be blocked", target.description.c_str());
        }
    }
}

bool NetworkDiagnostics::TestGatewayConnectivity() {
    DIAG_LOGI("=== Testing Gateway Connectivity ===");
    
    // 尝试连接到常见的公共DNS服务器作为网关测试
    std::vector<std::string> publicDNS = {"8.8.8.8", "1.1.1.1", "114.114.114.114"};
    
    for (const auto& dns : publicDNS) {
        DIAG_LOGI("Testing connectivity to %{public}s...", dns.c_str());
        if (TestDNSConnectivity(dns)) {
            DIAG_LOGI("✅ Internet gateway appears to be working (reached %{public}s)", dns.c_str());
            return true;
        }
    }
    
    DIAG_LOGE("❌ Cannot reach any public DNS servers - Internet gateway may be down");
    return false;
}

void NetworkDiagnostics::RunFullDiagnostics() {
    DIAG_LOGI("\n");
    DIAG_LOGI("╔════════════════════════════════════════════════════════════╗");
    DIAG_LOGI("║         FULL NETWORK DIAGNOSTICS REPORT                   ║");
    DIAG_LOGI("╚════════════════════════════════════════════════════════════╝");
    DIAG_LOGI("\n");
    
    // 1. 基本连通性测试
    bool basicOK = TestBasicConnectivity();
    DIAG_LOGI("1. Basic Connectivity: %{public}s\n", basicOK ? "✅ OK" : "❌ FAILED");
    
    // 2. 列出网络接口
    DIAG_LOGI("2. Network Interfaces:");
    auto interfaces = ListNetworkInterfaces();
    if (interfaces.empty()) {
        DIAG_LOGE("   ❌ No network interfaces found!\n");
    } else {
        DIAG_LOGI("   Found %{public}zu interface(s)\n", interfaces.size());
    }
    
    // 3. 网关连通性
    DIAG_LOGI("3. Gateway/Internet Connectivity:");
    bool gatewayOK = TestGatewayConnectivity();
    DIAG_LOGI("   Result: %{public}s\n", gatewayOK ? "✅ OK" : "❌ FAILED");
    
    // 4. DNS测试
    DIAG_LOGI("4. DNS Connectivity:");
    bool dnsOK = TestDNSConnectivity("8.8.8.8");
    DIAG_LOGI("   Result: %{public}s\n", dnsOK ? "✅ OK" : "❌ FAILED");
    
    // 5. 防火墙检查
    DIAG_LOGI("5. Firewall/Port Accessibility:");
    CheckFirewallStatus();
    DIAG_LOGI("\n");
    
    // 总结
    DIAG_LOGI("╔════════════════════════════════════════════════════════════╗");
    DIAG_LOGI("║                    DIAGNOSTIC SUMMARY                      ║");
    DIAG_LOGI("╚════════════════════════════════════════════════════════════╝");
    
    if (!basicOK) {
        DIAG_LOGE("❌ CRITICAL: Basic network stack not working");
    }
    
    if (interfaces.empty() || interfaces.size() == 1) {
        DIAG_LOGW("⚠️  WARNING: No physical network interfaces found (only loopback)");
    }
    
    if (!gatewayOK) {
        DIAG_LOGE("❌ CRITICAL: No internet connectivity");
        DIAG_LOGE("   Possible causes:");
        DIAG_LOGE("   - Machine not connected to network");
        DIAG_LOGE("   - Firewall blocking all outbound traffic");
        DIAG_LOGE("   - Network driver issues");
        DIAG_LOGE("   - HarmonyOS sandbox restrictions");
    }
    
    if (!dnsOK) {
        DIAG_LOGW("⚠️  WARNING: DNS not working properly");
    }
    
    if (basicOK && gatewayOK && dnsOK) {
        DIAG_LOGI("✅ All network tests passed - VPN proxy should work");
    } else {
        DIAG_LOGE("❌ Network issues detected - VPN proxy will NOT work until resolved");
    }
    
    DIAG_LOGI("\n");
}
