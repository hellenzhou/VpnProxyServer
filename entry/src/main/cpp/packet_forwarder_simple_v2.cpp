/*
 * 极简VPN服务器转发器 - 专注于让基本功能工作
 * 目标：确保单个PC的网络访问能被代理
 */

#include "packet_forwarder.h"
#include "vpn_server_globals.h"
#include "packet_builder.h"
#include "nat_table.h"
#include <hilog/log.h>
#include <thread>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <cstring>
#include <arpa/inet.h>
#include <sys/socket.h>

#define MAKE_FILE_NAME (strrchr(__FILE__, '/') ? (strrchr(__FILE__, '/') + 1) : __FILE__)
#define LOG(fmt, ...) \
  OH_LOG_Print(LOG_APP, LOG_INFO, 0x15b1, "VpnServer", "[%{public}s:%{public}d] " fmt, MAKE_FILE_NAME, __LINE__, ##__VA_ARGS__)

// ========== 主转发函数 ==========
int PacketForwarder::ForwardPacket(const uint8_t* data, int dataSize, 
                                  const PacketInfo& packetInfo, 
                                  const sockaddr_in& originalPeer) {
    LOG("📦 转发: %s:%d -> %s:%d (%s, %d字节)",
        packetInfo.sourceIP.c_str(), packetInfo.sourcePort,
        packetInfo.targetIP.c_str(), packetInfo.targetPort,
        ProtocolHandler::GetProtocolName(packetInfo.protocol).c_str(),
        dataSize);
    
    // 1. 提取payload
    const uint8_t* payload = nullptr;
    int payloadSize = 0;
    if (!PacketBuilder::ExtractPayload(data, dataSize, packetInfo, &payload, &payloadSize)) {
        LOG("❌ 提取payload失败");
        return -1;
    }
    
    if (payloadSize <= 0) {
        LOG("⚠️ payload为空，跳过");
        return 0;
    }
    
    LOG("✅ 提取payload: %d字节", payloadSize);
    
    // 2. 创建socket
    int sockFd = socket(AF_INET, (packetInfo.protocol == PROTOCOL_UDP) ? SOCK_DGRAM : SOCK_STREAM, 0);
    if (sockFd < 0) {
        LOG("❌ 创建socket失败: %s", strerror(errno));
        return -1;
    }
    LOG("✅ 创建socket: fd=%d", sockFd);
    
    // 3. 先创建NAT映射（重要！必须在启动响应线程之前）
    std::string natKey = NATTable::GenerateKey(packetInfo);
    NATTable::CreateMapping(natKey, originalPeer, packetInfo, sockFd);
    LOG("✅ NAT映射已创建: %s", natKey.c_str());
    
    // 4. 配置目标地址
    struct sockaddr_in targetAddr{};
    targetAddr.sin_family = AF_INET;
    targetAddr.sin_port = htons(packetInfo.targetPort);
    inet_pton(AF_INET, packetInfo.targetIP.c_str(), &targetAddr.sin_addr);
    
    // 5. 根据协议转发
    if (packetInfo.protocol == PROTOCOL_UDP) {
        // UDP：直接发送
        ssize_t sent = sendto(sockFd, payload, payloadSize, 0, 
                             (struct sockaddr*)&targetAddr, sizeof(targetAddr));
        if (sent < 0) {
            LOG("❌ UDP发送失败: %s", strerror(errno));
            NATTable::RemoveMapping(natKey);
            close(sockFd);
            return -1;
        }
        LOG("✅ UDP发送成功: %zd字节", sent);
        
        // 启动响应线程
        std::thread([sockFd, originalPeer, packetInfo]() {
            HandleUdpResponseSimple(sockFd, originalPeer, packetInfo);
        }).detach();
        
    } else {
        // TCP：先连接再发送
        LOG("🔌 TCP连接中...");
        if (connect(sockFd, (struct sockaddr*)&targetAddr, sizeof(targetAddr)) < 0) {
            LOG("❌ TCP连接失败: %s", strerror(errno));
            NATTable::RemoveMapping(natKey);
            close(sockFd);
            return -1;
        }
        LOG("✅ TCP连接成功");
        
        if (payloadSize > 0) {
            ssize_t sent = send(sockFd, payload, payloadSize, 0);
            if (sent < 0) {
                LOG("❌ TCP发送失败: %s", strerror(errno));
                NATTable::RemoveMapping(natKey);
                close(sockFd);
                return -1;
            }
            LOG("✅ TCP发送成功: %zd字节", sent);
        }
        
        // 启动响应线程
        std::thread([sockFd, originalPeer, packetInfo]() {
            HandleTcpResponseSimple(sockFd, originalPeer, packetInfo);
        }).detach();
    }
    
    return sockFd;
}

// 静态辅助函数声明
static void HandleUdpResponseSimple(int sockFd, sockaddr_in originalPeer, const PacketInfo& packetInfo);
static void HandleTcpResponseSimple(int sockFd, sockaddr_in originalPeer, const PacketInfo& packetInfo);

// ========== UDP响应处理（简化版）==========
static void HandleUdpResponseSimple(int sockFd, sockaddr_in originalPeer, const PacketInfo& packetInfo) {
    LOG("📥 UDP响应线程启动: socket=%d", sockFd);
    
    // 查找NAT映射
    NATConnection conn;
    if (!NATTable::FindMappingBySocket(sockFd, conn)) {
        LOG("❌ 找不到NAT映射，退出");
        close(sockFd);
        return;
    }
    LOG("✅ 找到NAT映射");
    
    // 接收响应
    uint8_t responsePayload[4096];
    struct sockaddr_in responseAddr{};
    socklen_t addrLen = sizeof(responseAddr);
    
    // 设置超时
    struct timeval timeout = {5, 0};
    setsockopt(sockFd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    
    ssize_t received = recvfrom(sockFd, responsePayload, sizeof(responsePayload), 0,
                                (struct sockaddr*)&responseAddr, &addrLen);
    
    if (received <= 0) {
        LOG("❌ UDP响应接收失败: %s", strerror(errno));
        goto cleanup;
    }
    
    LOG("✅ 收到UDP响应: %zd字节", received);
    
    // 封装成IP包
    uint8_t ipPacket[4096 + 60];
    int packetLen = PacketBuilder::BuildResponsePacket(
        ipPacket, sizeof(ipPacket),
        responsePayload, received,
        conn.originalRequest
    );
    
    if (packetLen < 0) {
        LOG("❌ 构建响应包失败");
        goto cleanup;
    }
    
    LOG("✅ 构建IP包: %d字节", packetLen);
    
    // 发送给客户端
    ssize_t sent = sendto(g_sockFd, ipPacket, packetLen, 0,
                         (struct sockaddr*)&conn.clientPhysicalAddr, 
                         sizeof(conn.clientPhysicalAddr));
    
    if (sent > 0) {
        LOG("✅ 发送给客户端成功: %zd字节", sent);
    } else {
        LOG("❌ 发送给客户端失败: %s", strerror(errno));
    }
    
cleanup:
    std::string natKey = NATTable::GenerateKey(conn.originalRequest);
    NATTable::RemoveMapping(natKey);
    close(sockFd);
    LOG("🔒 清理完成");
}

// ========== TCP响应处理（简化版）==========
static void HandleTcpResponseSimple(int sockFd, sockaddr_in originalPeer, const PacketInfo& packetInfo) {
    LOG("📥 TCP响应线程启动: socket=%d", sockFd);
    
    // 查找NAT映射
    NATConnection conn;
    if (!NATTable::FindMappingBySocket(sockFd, conn)) {
        LOG("❌ 找不到NAT映射，退出");
        close(sockFd);
        return;
    }
    LOG("✅ 找到NAT映射");
    
    // 设置超时
    struct timeval timeout = {30, 0};
    setsockopt(sockFd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    
    uint8_t responsePayload[4096];
    
    while (true) {
        ssize_t received = recv(sockFd, responsePayload, sizeof(responsePayload), 0);
        
        if (received <= 0) {
            if (received == 0) {
                LOG("🔚 TCP连接关闭");
            } else {
                LOG("❌ TCP响应接收失败: %s", strerror(errno));
            }
            break;
        }
        
        LOG("✅ 收到TCP响应: %zd字节", received);
        
        // 封装成IP包
        uint8_t ipPacket[4096 + 60];
        int packetLen = PacketBuilder::BuildResponsePacket(
            ipPacket, sizeof(ipPacket),
            responsePayload, received,
            conn.originalRequest
        );
        
        if (packetLen < 0) {
            LOG("❌ 构建响应包失败");
            break;
        }
        
        LOG("✅ 构建IP包: %d字节", packetLen);
        
        // 发送给客户端
        ssize_t sent = sendto(g_sockFd, ipPacket, packetLen, 0,
                             (struct sockaddr*)&conn.clientPhysicalAddr,
                             sizeof(conn.clientPhysicalAddr));
        
        if (sent > 0) {
            LOG("✅ 发送给客户端成功: %zd字节", sent);
        } else {
            LOG("❌ 发送给客户端失败: %s", strerror(errno));
            break;
        }
        
        // 更新活动时间
        std::string natKey = NATTable::GenerateKey(conn.originalRequest);
        NATTable::UpdateActivity(natKey);
    }
    
    // 清理
    std::string natKey = NATTable::GenerateKey(conn.originalRequest);
    NATTable::RemoveMapping(natKey);
    close(sockFd);
    LOG("🔒 清理完成");
}

// ========== 辅助函数 ==========
int PacketForwarder::CreateSocket(int addressFamily, uint8_t protocol) {
    int sockType = (protocol == PROTOCOL_UDP) ? SOCK_DGRAM : SOCK_STREAM;
    return socket(addressFamily, sockType, 0);
}

// 兼容旧接口
int PacketForwarder::HandleUDPForwarding(int sockFd, const uint8_t* payload, int payloadSize,
                                        const PacketInfo& packetInfo,
                                        int addressFamily, const sockaddr_in& originalPeer) {
    return sockFd;  // 在ForwardPacket中已处理
}

int PacketForwarder::HandleTCPForwarding(int sockFd, const uint8_t* payload, int payloadSize,
                                        const PacketInfo& packetInfo,
                                        int addressFamily, const sockaddr_in& originalPeer) {
    return sockFd;  // 在ForwardPacket中已处理
}

void PacketForwarder::HandleUdpResponse(int sockFd, sockaddr_in originalPeer, const PacketInfo& packetInfo) {
    HandleUdpResponseSimple(sockFd, originalPeer, packetInfo);
}

void PacketForwarder::HandleTcpResponse(int sockFd, sockaddr_in originalPeer, const PacketInfo& packetInfo) {
    HandleTcpResponseSimple(sockFd, originalPeer, packetInfo);
}

bool PacketForwarder::IsDNSQuery(const std::string& targetIP, int targetPort) {
    return targetPort == 53;
}

bool PacketForwarder::TestNetworkConnectivity() {
    return true;
}
