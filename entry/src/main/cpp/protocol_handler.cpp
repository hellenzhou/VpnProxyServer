#include "protocol_handler.h"
#include <hilog/log.h>
#include <arpa/inet.h>
#include <cstring>

#define MAKE_FILE_NAME (strrchr(__FILE__, '/') ? (strrchr(__FILE__, '/') + 1) : __FILE__)

#define PROTOCOL_LOGI(fmt, ...) \
  OH_LOG_Print(LOG_APP, LOG_INFO, 0x15b1, "VpnServer", "ZBQ protocol [%{public}s %{public}d] " fmt, MAKE_FILE_NAME, __LINE__, ##__VA_ARGS__)

PacketInfo ProtocolHandler::ParseIPPacket(const uint8_t* data, int dataSize) {
    PacketInfo info;
    
    if (!data || dataSize < 20) {
        PROTOCOL_LOGI("Invalid packet: null data or too small");
        return info;
    }
    
    uint8_t version = (data[0] >> 4);
    
    if (version == 4) {
        // IPv4处理
        if (dataSize < 20) {
            PROTOCOL_LOGI("IPv4 packet too small: %{public}d bytes", dataSize);
            return info;
        }
        
        uint8_t ipHeaderLen = (data[0] & 0x0F) * 4;
        if (ipHeaderLen < 20 || ipHeaderLen > dataSize) {
            PROTOCOL_LOGI("Invalid IPv4 header length: %{public}d bytes", ipHeaderLen);
            return info;
        }
        
        info.protocol = data[9];
        info.addressFamily = AF_INET;
        
        // 只处理TCP、UDP和ICMPv6
        if (info.protocol != PROTOCOL_TCP && info.protocol != PROTOCOL_UDP && info.protocol != PROTOCOL_ICMPV6) {
            PROTOCOL_LOGI("Unsupported protocol: %{public}d", info.protocol);
            return info;
        }
        
        // 获取源IP和目标IP
        char srcIP[INET_ADDRSTRLEN], dstIP[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &data[12], srcIP, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &data[16], dstIP, INET_ADDRSTRLEN);
        info.sourceIP = srcIP;  // 保存源IP（VPN虚拟IP）
        info.targetIP = dstIP;  // 保存目标IP
        
        // 记录源IP（TUN IP）用于排查
        PROTOCOL_LOGI("🔍 [TUN IP检查] 数据包源IP: %{public}s (这是VPN虚拟网络IP，不是客户端物理IP)", srcIP);
        
        // 获取端口
        int payloadOffset = ipHeaderLen;
        if (info.protocol == PROTOCOL_TCP) {
            if (dataSize < payloadOffset + 20) {
                PROTOCOL_LOGI("TCP packet too small");
                return info;
            }
            info.sourcePort = (data[payloadOffset + 0] << 8) | data[payloadOffset + 1];  // 源端口
            info.targetPort = (data[payloadOffset + 2] << 8) | data[payloadOffset + 3];  // 目标端口
        } else if (info.protocol == PROTOCOL_UDP) {
            if (dataSize < payloadOffset + 8) {
                PROTOCOL_LOGI("UDP packet too small");
                return info;
            }
            info.sourcePort = (data[payloadOffset + 0] << 8) | data[payloadOffset + 1];  // 源端口
            info.targetPort = (data[payloadOffset + 2] << 8) | data[payloadOffset + 3];  // 目标端口
        }
        
        info.isValid = true;
        PROTOCOL_LOGI("Parsed packet: %{public}s:%{public}d (protocol=%{public}d)", 
                      info.targetIP.c_str(), info.targetPort, info.protocol);
        
    } else if (version == 6) {
        // IPv6处理
        if (dataSize < 40) {
            PROTOCOL_LOGI("IPv6 packet too small: %{public}d bytes (minimum 40 required)", dataSize);
            return info;
        }
        
        // IPv6头部固定40字节
        uint8_t nextHeader = data[6];
        
        // 跳过扩展头，找到TCP/UDP/ICMPv6头
        int payloadOffset = 40;
        int maxHops = 8;  // 最多处理8个扩展头，防止无限循环
        int hops = 0;
        
        while (nextHeader != PROTOCOL_TCP && nextHeader != PROTOCOL_UDP && nextHeader != PROTOCOL_ICMPV6 && hops < maxHops) {
            switch (nextHeader) {
                case 0:  // Hop-by-Hop Options
                case 43: // Routing
                case 44: // Fragment
                case 50: // ESP
                case 51: // AH
                case 60: { // Destination Options
                    if (payloadOffset + 2 > dataSize) {
                        PROTOCOL_LOGI("IPv6 extension header too small");
                        return info;
                    }
                    // 扩展头长度单位是8字节，不包括第一个8字节
                    uint8_t extHeaderLen = data[payloadOffset + 1];
                    payloadOffset += (extHeaderLen + 1) * 8;
                    if (payloadOffset + 1 > dataSize) {
                        PROTOCOL_LOGI("IPv6 extension header extends beyond packet");
                        return info;
                    }
                    nextHeader = data[payloadOffset];
                    hops++;
                    break;
                }
                default:
                    // 其他协议（除了 TCP/UDP/ICMPv6 之外的扩展/封装协议），不支持
                    // 常见的不支持值: 143=Ethernet-within-IP, 135=Mobility Header
                    PROTOCOL_LOGI("IPv6 next header %{public}d not supported (only TCP=6, UDP=17, ICMPv6=58, and common extension headers supported)", nextHeader);
                    PROTOCOL_LOGI("🔍 Note: This packet will be dropped as VPN only forwards TCP/UDP/ICMPv6 traffic");
                    return info;
            }
        }
        
        if (hops >= maxHops) {
            PROTOCOL_LOGI("IPv6 too many extension headers");
            return info;
        }
        
        if (nextHeader != PROTOCOL_TCP && nextHeader != PROTOCOL_UDP && nextHeader != PROTOCOL_ICMPV6) {
            PROTOCOL_LOGI("IPv6 next header not TCP/UDP/ICMPv6: %{public}d", nextHeader);
            return info;
        }
        
        info.protocol = nextHeader;
        info.addressFamily = AF_INET6;
        
        // 获取目标IPv6地址（16字节，从偏移24开始）
        char dstIP[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &data[24], dstIP, INET6_ADDRSTRLEN);
        info.targetIP = dstIP;
        
        // 获取源IPv6地址（16字节，从偏移8开始）
        char srcIP[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &data[8], srcIP, INET6_ADDRSTRLEN);
        info.sourceIP = srcIP;
        
        // 获取端口（TCP/UDP头部）或解析ICMPv6消息
        if (info.protocol == PROTOCOL_TCP) {
            if (dataSize < payloadOffset + 20) {
                PROTOCOL_LOGI("IPv6 TCP packet too small: %{public}d bytes (need at least %{public}d)", 
                             dataSize, payloadOffset + 20);
                return info;
            }
            info.sourcePort = (data[payloadOffset + 0] << 8) | data[payloadOffset + 1];
            info.targetPort = (data[payloadOffset + 2] << 8) | data[payloadOffset + 3];
        } else if (info.protocol == PROTOCOL_UDP) {
            if (dataSize < payloadOffset + 8) {
                PROTOCOL_LOGI("IPv6 UDP packet too small: %{public}d bytes (need at least %{public}d)", 
                             dataSize, payloadOffset + 8);
                return info;
            }
            info.sourcePort = (data[payloadOffset + 0] << 8) | data[payloadOffset + 1];
            info.targetPort = (data[payloadOffset + 2] << 8) | data[payloadOffset + 3];
        } else if (info.protocol == PROTOCOL_ICMPV6) {
            // ICMPv6 头部: Type(1) + Code(1) + Checksum(2) + ...
            if (dataSize < payloadOffset + 4) {
                PROTOCOL_LOGI("IPv6 ICMPv6 packet too small: %{public}d bytes (need at least %{public}d)", 
                             dataSize, payloadOffset + 4);
                return info;
            }
            info.icmpv6Type = data[payloadOffset + 0];
            info.icmpv6Code = data[payloadOffset + 1];
            // ICMPv6 没有端口概念，设置为 0
            info.sourcePort = 0;
            info.targetPort = 0;
            PROTOCOL_LOGI("🔍 [ICMPv6] Parsed ICMPv6 message: Type=%{public}d (%{public}s), Code=%{public}d, Src=%{public}s, Dst=%{public}s", 
                         info.icmpv6Type, GetICMPv6TypeName(info.icmpv6Type).c_str(), info.icmpv6Code,
                         srcIP, dstIP);
        }
        
        info.isValid = true;
        if (info.protocol == PROTOCOL_ICMPV6) {
            PROTOCOL_LOGI("Parsed IPv6 ICMPv6 packet: %{public}s (Type=%{public}d, %{public}s)", 
                          info.targetIP.c_str(), info.icmpv6Type, GetICMPv6TypeName(info.icmpv6Type).c_str());
        } else {
            PROTOCOL_LOGI("Parsed IPv6 packet: %{public}s:%{public}d (protocol=%{public}d)", 
                          info.targetIP.c_str(), info.targetPort, info.protocol);
        }
        
    } else {
        PROTOCOL_LOGI("Unsupported IP version: %{public}d", version);
    }
    
    return info;
}

bool ProtocolHandler::ValidatePacket(const PacketInfo& info) {
    if (!info.isValid) {
        return false;
    }
    
    if (info.targetIP.empty()) {
        return false;
    }
    
    // ICMPv6 没有端口的概念，不需要验证端口
    if (info.protocol == PROTOCOL_ICMPV6) {
        return true;
    }
    
    // TCP/UDP 需要验证端口
    if (info.targetPort <= 0 || info.targetPort > 65535) {
        return false;
    }
    
    if (info.protocol != PROTOCOL_TCP && info.protocol != PROTOCOL_UDP) {
        return false;
    }
    
    return true;
}

std::string ProtocolHandler::GetProtocolName(uint8_t protocol) {
    switch (protocol) {
        case PROTOCOL_TCP:
            return "TCP";
        case PROTOCOL_UDP:
            return "UDP";
        case PROTOCOL_ICMPV6:
            return "ICMPv6";
        default:
            return "UNKNOWN";
    }
}

std::string ProtocolHandler::GetAddressFamilyName(int family) {
    switch (family) {
        case AF_INET:
            return "IPv4";
        case AF_INET6:
            return "IPv6";
        default:
            return "UNKNOWN";
    }
}

std::string ProtocolHandler::GetICMPv6TypeName(uint8_t type) {
    switch (type) {
        case ICMPV6_DEST_UNREACHABLE:
            return "Destination Unreachable";
        case ICMPV6_PACKET_TOO_BIG:
            return "Packet Too Big";
        case ICMPV6_TIME_EXCEEDED:
            return "Time Exceeded";
        case ICMPV6_PARAM_PROBLEM:
            return "Parameter Problem";
        case ICMPV6_ECHO_REQUEST:
            return "Echo Request (Ping)";
        case ICMPV6_ECHO_REPLY:
            return "Echo Reply (Pong)";
        case ICMPV6_ROUTER_SOLICITATION:
            return "Router Solicitation";
        case ICMPV6_ROUTER_ADVERTISEMENT:
            return "Router Advertisement";
        case ICMPV6_NEIGHBOR_SOLICITATION:
            return "Neighbor Solicitation";
        case ICMPV6_NEIGHBOR_ADVERTISEMENT:
            return "Neighbor Advertisement";
        default:
            return "Unknown Type " + std::to_string(type);
    }
}
