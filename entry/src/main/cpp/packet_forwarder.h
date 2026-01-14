#pragma once

#include <cstdint>
#include <string>
#include <sys/socket.h>
#include <netinet/in.h>
#include "protocol_handler.h"

// 数据包转发器类
class PacketForwarder {
public:
    // 转发数据包到真实服务器
    static int ForwardPacket(const uint8_t* data, int dataSize, 
                           const PacketInfo& packetInfo, 
                           const sockaddr_in& originalPeer);
    
private:
    // 创建socket
    static int CreateSocket(int addressFamily, uint8_t protocol);
    
    // 处理UDP转发
    static int HandleUDPForwarding(int sockFd, const uint8_t* data, int dataSize,
                                  const PacketInfo& packetInfo,
                                  int addressFamily, const sockaddr_in& originalPeer);
    
    // 处理TCP转发
    static int HandleTCPForwarding(int sockFd, const uint8_t* data, int dataSize,
                                  const PacketInfo& packetInfo,
                                  int addressFamily, const sockaddr_in& originalPeer);
    
    // 处理UDP响应
    static void HandleUdpResponse(int sockFd, sockaddr_in originalPeer, const PacketInfo& packetInfo);
    
    // 处理TCP响应
    static void HandleTcpResponse(int sockFd, sockaddr_in originalPeer, const PacketInfo& packetInfo);
    
    // 检查是否为DNS查询
    static bool IsDNSQuery(const std::string& targetIP, int targetPort);
    
public:
    // 测试网络连接
    static bool TestNetworkConnectivity();
};
