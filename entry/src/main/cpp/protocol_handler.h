#pragma once

#include <cstdint>
#include <string>

// 协议常量
constexpr uint8_t PROTOCOL_ICMP = 1;      // IPv4 ICMP (ping)
constexpr uint8_t PROTOCOL_TCP = 6;
constexpr uint8_t PROTOCOL_UDP = 17;
constexpr uint8_t PROTOCOL_ICMPV6 = 58;   // IPv6 ICMPv6 (ping6)

// ICMPv6 消息类型（常见的核心消息）
constexpr uint8_t ICMPV6_DEST_UNREACHABLE = 1;    // 目标不可达
constexpr uint8_t ICMPV6_PACKET_TOO_BIG = 2;      // 数据包过大
constexpr uint8_t ICMPV6_TIME_EXCEEDED = 3;       // 超时
constexpr uint8_t ICMPV6_PARAM_PROBLEM = 4;       // 参数问题
constexpr uint8_t ICMPV6_ECHO_REQUEST = 128;      // Echo 请求（ping6）
constexpr uint8_t ICMPV6_ECHO_REPLY = 129;        // Echo 响应
constexpr uint8_t ICMPV6_ROUTER_SOLICITATION = 133;  // 路由器请求
constexpr uint8_t ICMPV6_ROUTER_ADVERTISEMENT = 134; // 路由器广告
constexpr uint8_t ICMPV6_NEIGHBOR_SOLICITATION = 135; // 邻居请求（类似ARP）
constexpr uint8_t ICMPV6_NEIGHBOR_ADVERTISEMENT = 136; // 邻居通告
constexpr uint8_t ICMPV6_MLDV2_REPORT = 143; // 多播监听报告 (MLDv2)

// 数据包解析结果
struct PacketInfo {
    std::string targetIP;      // 目标IP（数据包中的目标IP）
    int targetPort;            // 目标端口
    std::string sourceIP;      // 源IP（数据包中的源IP，即VPN虚拟IP）
    int sourcePort;            // 源端口（客户端端口）
    uint8_t protocol;
    int addressFamily;
    bool isValid;
    
    // ICMPv6 专用字段
    uint8_t icmpv6Type;        // ICMPv6 消息类型
    uint8_t icmpv6Code;        // ICMPv6 消息代码
    
    PacketInfo() : targetPort(0), sourcePort(0), protocol(0), addressFamily(0), isValid(false), 
                   icmpv6Type(0), icmpv6Code(0) {}
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
    
    // 获取 ICMPv6 消息类型名称
    static std::string GetICMPv6TypeName(uint8_t type);
};
