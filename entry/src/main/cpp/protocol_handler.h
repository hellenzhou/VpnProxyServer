#pragma once

#include <cstdint>
#include <string>

// 协议常量
constexpr uint8_t PROTOCOL_TCP = 6;
constexpr uint8_t PROTOCOL_UDP = 17;

// 数据包解析结果
struct PacketInfo {
    std::string targetIP;      // 目标IP（数据包中的目标IP）
    int targetPort;            // 目标端口
    std::string sourceIP;      // 源IP（数据包中的源IP，即VPN虚拟IP）
    int sourcePort;            // 源端口（客户端端口）
    uint8_t protocol;
    int addressFamily;
    bool isValid;
    
    PacketInfo() : targetPort(0), sourcePort(0), protocol(0), addressFamily(0), isValid(false) {}
};

// 协议处理器类
class ProtocolHandler {
public:
    // 解析IP数据包
    static PacketInfo ParseIPPacket(const uint8_t* data, int dataSize);
    
    // 验证数据包有效性
    static bool ValidatePacket(const PacketInfo& info);
    
    // 获取协议名称
    static std::string GetProtocolName(uint8_t protocol);
    
    // 获取地址族名称
    static std::string GetAddressFamilyName(int family);
};
