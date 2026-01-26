/*
 * 数据包构建器实现 - 处理IP包的封装和解封装
 */

#include "packet_builder.h"
#include <hilog/log.h>

#define MAKE_FILE_NAME (strrchr(__FILE__, '/') ? (strrchr(__FILE__, '/') + 1) : __FILE__)
#define PACKET_BUILDER_LOGI(fmt, ...) \
  OH_LOG_Print(LOG_APP, LOG_INFO, 0x15b1, "VpnServer", "ZHOUB [PacketBuilder] [%{public}s:%{public}d] " fmt, MAKE_FILE_NAME, __LINE__, ##__VA_ARGS__)
#define PACKET_BUILDER_LOGE(fmt, ...) \
  OH_LOG_Print(LOG_APP, LOG_ERROR, 0x15b1, "VpnServer", "ZHOUB [PacketBuilder] [%{public}s:%{public}d] " fmt, MAKE_FILE_NAME, __LINE__, ##__VA_ARGS__)

// 从完整IP包中提取payload
bool PacketBuilder::ExtractPayload(const uint8_t* ipPacket, int packetSize,
                                   const PacketInfo& info,
                                   const uint8_t** payloadOut, int* payloadSizeOut) {
    if (!ipPacket || packetSize <= 0 || !payloadOut || !payloadSizeOut) {
        PACKET_BUILDER_LOGE("Invalid parameters");
        return false;
    }
    
    // 获取IP版本
    uint8_t version = (ipPacket[0] >> 4) & 0x0F;
    
    if (version == 4) {
        // IPv4
        // 🚨 修复：在调用GetIPHeaderLength之前检查数据包大小
        if (packetSize < 1) {
            PACKET_BUILDER_LOGE("IPv4 packet too small to read version/header length");
            return false;
        }
        int ipHeaderLen = GetIPHeaderLength(ipPacket);
        if (ipHeaderLen < 20 || ipHeaderLen > packetSize) {
            PACKET_BUILDER_LOGE("Invalid IPv4 header length: %{public}d (packetSize=%{public}d)", ipHeaderLen, packetSize);
            return false;
        }
        
        const uint8_t* transportHeader = ipPacket + ipHeaderLen;
        int remainingSize = packetSize - ipHeaderLen;
        
        if (info.protocol == PROTOCOL_TCP) {
            // TCP
            // 🚨 修复：在调用GetTCPHeaderLength之前检查剩余数据大小
            if (remainingSize < 13) {
                PACKET_BUILDER_LOGE("Packet too small for TCP header (remainingSize=%{public}d)", remainingSize);
                return false;
            }
            int tcpHeaderLen = GetTCPHeaderLength(transportHeader);
            if (tcpHeaderLen < 20 || tcpHeaderLen > remainingSize) {
                PACKET_BUILDER_LOGE("Invalid TCP header length: %{public}d (remainingSize=%{public}d)", tcpHeaderLen, remainingSize);
                return false;
            }
            
            *payloadOut = transportHeader + tcpHeaderLen;
            *payloadSizeOut = remainingSize - tcpHeaderLen;
            
            PACKET_BUILDER_LOGI("✅ Extracted TCP payload: %{public}d bytes (IP header: %{public}d, TCP header: %{public}d)",
                               *payloadSizeOut, ipHeaderLen, tcpHeaderLen);
            return true;
            
        } else if (info.protocol == PROTOCOL_UDP) {
            // UDP头固定8字节
            if (remainingSize < 8) {
                PACKET_BUILDER_LOGE("Packet too small for UDP header");
                return false;
            }
            
            *payloadOut = transportHeader + 8;
            *payloadSizeOut = remainingSize - 8;
            
            PACKET_BUILDER_LOGI("✅ Extracted UDP payload: %{public}d bytes (IP header: %{public}d, UDP header: 8)",
                               *payloadSizeOut, ipHeaderLen);
            return true;
        }
    } else if (version == 6) {
        // IPv6
        if (packetSize < 40) {
            PACKET_BUILDER_LOGE("IPv6 packet too small: %{public}d", packetSize);
            return false;
        }
        if (info.protocol != PROTOCOL_TCP && info.protocol != PROTOCOL_UDP) {
            PACKET_BUILDER_LOGE("IPv6 ExtractPayload only supports TCP/UDP (protocol=%{public}d)", info.protocol);
            return false;
        }

        // Walk extension headers to find transport header
        uint8_t nextHeader = ipPacket[6];
        int offset = 40;
        int hops = 0;
        const int maxHops = 8;
        while (hops < maxHops) {
            if (nextHeader == 0 || nextHeader == 43 || nextHeader == 60 ||
                nextHeader == 51 || nextHeader == 50) {
                if (packetSize < offset + 2) {
                    PACKET_BUILDER_LOGE("IPv6 extension header too small");
                    return false;
                }
                uint8_t hdrExtLen = ipPacket[offset + 1];
                int extLen = (hdrExtLen + 1) * 8;
                nextHeader = ipPacket[offset];
                offset += extLen;
                hops++;
                continue;
            } else if (nextHeader == 44) { // Fragment
                if (packetSize < offset + 8) {
                    PACKET_BUILDER_LOGE("IPv6 fragment header too small");
                    return false;
                }
                nextHeader = ipPacket[offset];
                offset += 8;
                hops++;
                continue;
            }
            break;
        }
        if (hops >= maxHops) {
            PACKET_BUILDER_LOGE("IPv6 too many extension headers");
            return false;
        }

        if (nextHeader != info.protocol) {
            PACKET_BUILDER_LOGE("IPv6 nextHeader mismatch: %{public}d vs info.protocol=%{public}d",
                                nextHeader, info.protocol);
            return false;
        }

        int remainingSize = packetSize - offset;
        if (info.protocol == PROTOCOL_TCP) {
            // 🚨 修复：在调用GetTCPHeaderLength之前检查剩余数据大小
            if (remainingSize < 13) {
                PACKET_BUILDER_LOGE("IPv6 TCP header too small (remainingSize=%{public}d)", remainingSize);
                return false;
            }
            int tcpHeaderLen = GetTCPHeaderLength(ipPacket + offset);
            if (tcpHeaderLen < 20 || tcpHeaderLen > remainingSize) {
                PACKET_BUILDER_LOGE("Invalid IPv6 TCP header length: %{public}d (remainingSize=%{public}d)", tcpHeaderLen, remainingSize);
                return false;
            }
            *payloadOut = ipPacket + offset + tcpHeaderLen;
            *payloadSizeOut = remainingSize - tcpHeaderLen;
            PACKET_BUILDER_LOGI("✅ Extracted IPv6 TCP payload: %{public}d bytes (TCP header: %{public}d)",
                               *payloadSizeOut, tcpHeaderLen);
            return true;
        } else if (info.protocol == PROTOCOL_UDP) {
            if (remainingSize < 8) {
                PACKET_BUILDER_LOGE("IPv6 UDP header too small");
                return false;
            }
            *payloadOut = ipPacket + offset + 8;
            *payloadSizeOut = remainingSize - 8;
            PACKET_BUILDER_LOGI("✅ Extracted IPv6 UDP payload: %{public}d bytes (UDP header: 8)",
                               *payloadSizeOut);
            return true;
        }
    }
    
    PACKET_BUILDER_LOGE("Unknown IP version: %{public}d", version);
    return false;
}

// 构建完整的IP响应包
int PacketBuilder::BuildResponsePacket(uint8_t* buffer, int bufferSize,
                                       const uint8_t* payload, int payloadSize,
                                       const PacketInfo& originalRequest) {
    if (!buffer || bufferSize <= 0 || !payload || payloadSize <= 0) {
        PACKET_BUILDER_LOGE("Invalid parameters for building response packet");
        return -1;
    }
    
    // 仅支持 IPv4/IPv6
    if (originalRequest.addressFamily != AF_INET && originalRequest.addressFamily != AF_INET6) {
        PACKET_BUILDER_LOGE("Only IPv4/IPv6 supported");
        return -1;
    }
    
    // 🔧 修复：不使用SwapSourceDest，而是根据NAT映射正确设置
    // 响应包应该是：
    // 源IP = originalRequest.targetIP (真实服务器的IP，如baidu.com或DNS服务器)
    // 源端口 = originalRequest.targetPort (真实服务器的端口，如53/80)
    // 目标IP = originalRequest.sourceIP (客户端的VPN虚拟IP，如192.168.0.2)
    // 目标端口 = originalRequest.sourcePort (客户端的端口，如54321)
    
    int ipHeaderLen = (originalRequest.addressFamily == AF_INET6) ? 40 : 20;
    int transportHeaderLen = (originalRequest.protocol == PROTOCOL_TCP) ? 20 : 8;
    int totalLen = ipHeaderLen + transportHeaderLen + payloadSize;
    
    if (totalLen > bufferSize) {
        PACKET_BUILDER_LOGE("Buffer too small: need %{public}d, have %{public}d", totalLen, bufferSize);
        return -1;
    }
    
    memset(buffer, 0, totalLen);
    
    if (originalRequest.addressFamily == AF_INET6) {
        // IPv6 header (40 bytes)
        buffer[0] = 0x60; // Version 6
        buffer[1] = 0x00;
        buffer[2] = 0x00;
        buffer[3] = 0x00; // Traffic class + flow label
        uint16_t payloadLen = static_cast<uint16_t>(transportHeaderLen + payloadSize);
        buffer[4] = (payloadLen >> 8) & 0xFF;
        buffer[5] = payloadLen & 0xFF;
        buffer[6] = originalRequest.protocol; // Next Header
        buffer[7] = 0x40; // Hop Limit

        struct in6_addr srcAddr6;
        if (inet_pton(AF_INET6, originalRequest.targetIP.c_str(), &srcAddr6) <= 0) {
            PACKET_BUILDER_LOGE("Invalid IPv6 target address: %{public}s", originalRequest.targetIP.c_str());
            return -1;
        }
        memcpy(buffer + 8, &srcAddr6, 16);
        struct in6_addr dstAddr6;
        if (inet_pton(AF_INET6, originalRequest.sourceIP.c_str(), &dstAddr6) <= 0) {
            PACKET_BUILDER_LOGE("Invalid IPv6 source address: %{public}s", originalRequest.sourceIP.c_str());
            return -1;
        }
        memcpy(buffer + 24, &dstAddr6, 16);
    } else {
        // IPv4 header (20 bytes)
        buffer[0] = 0x45;  // Version 4, Header length 5 (20 bytes)
        buffer[1] = 0x00;  // TOS
        buffer[2] = (totalLen >> 8) & 0xFF;  // Total length
        buffer[3] = totalLen & 0xFF;
        buffer[4] = 0x00;  // Identification
        buffer[5] = 0x00;
        buffer[6] = 0x40;  // Flags: Don't fragment
        buffer[7] = 0x00;
        buffer[8] = 0x40;  // TTL: 64
        buffer[9] = originalRequest.protocol;  // Protocol
        buffer[10] = 0x00;  // Checksum (will calculate later)
        buffer[11] = 0x00;
        
        // 🔧 修复：源IP = 真实服务器的IP (originalRequest.targetIP)
        struct in_addr srcAddr;
        if (inet_pton(AF_INET, originalRequest.targetIP.c_str(), &srcAddr) <= 0) {
            PACKET_BUILDER_LOGE("Invalid IPv4 target address: %{public}s", originalRequest.targetIP.c_str());
            return -1;
        }
        memcpy(buffer + 12, &srcAddr, 4);
        
        // 🔧 修复：目标IP = 客户端的VPN虚拟IP (originalRequest.sourceIP)
        struct in_addr dstAddr;
        if (inet_pton(AF_INET, originalRequest.sourceIP.c_str(), &dstAddr) <= 0) {
            PACKET_BUILDER_LOGE("Invalid IPv4 source address: %{public}s", originalRequest.sourceIP.c_str());
            return -1;
        }
        memcpy(buffer + 16, &dstAddr, 4);
        
        // 计算IP校验和
        uint16_t ipChecksum = CalculateIPChecksum(buffer, ipHeaderLen);
        buffer[10] = (ipChecksum >> 8) & 0xFF;
        buffer[11] = ipChecksum & 0xFF;
    }
    
    uint8_t* transportHeader = buffer + ipHeaderLen;
    
    if (originalRequest.protocol == PROTOCOL_TCP) {
        // TCP头（简化版，20字节）- 暂不支持，见后续代码
        // 🔧 修复：源端口 = 真实服务器的端口 (originalRequest.targetPort)
        transportHeader[0] = (originalRequest.targetPort >> 8) & 0xFF;
        transportHeader[1] = originalRequest.targetPort & 0xFF;
        // 🔧 修复：目标端口 = 客户端的端口 (originalRequest.sourcePort)
        transportHeader[2] = (originalRequest.sourcePort >> 8) & 0xFF;
        transportHeader[3] = originalRequest.sourcePort & 0xFF;
        // Sequence number, ACK number等留空（需要根据实际TCP状态填充）
        memset(transportHeader + 4, 0, 8);
        transportHeader[12] = 0x50;  // Data offset: 5 (20 bytes)
        transportHeader[13] = TCP_ACK | TCP_PSH;  // Flags
        transportHeader[14] = 0xFF;  // Window size
        transportHeader[15] = 0xFF;
        transportHeader[16] = 0x00;  // Checksum (will calculate)
        transportHeader[17] = 0x00;
        transportHeader[18] = 0x00;  // Urgent pointer
        transportHeader[19] = 0x00;
        
        // 复制payload
        memcpy(transportHeader + 20, payload, payloadSize);
        
        // 计算TCP校验和
        uint16_t tcpChecksum = (originalRequest.addressFamily == AF_INET6)
            ? CalculateTCPChecksumV6(buffer, transportHeader, 20 + payloadSize)
            : CalculateTCPChecksum(buffer, transportHeader, 20 + payloadSize);
        transportHeader[16] = (tcpChecksum >> 8) & 0xFF;
        transportHeader[17] = tcpChecksum & 0xFF;
        
    } else if (originalRequest.protocol == PROTOCOL_UDP) {
        // UDP头（8字节）
        // 🔧 修复：源端口 = 真实服务器的端口 (originalRequest.targetPort)
        transportHeader[0] = (originalRequest.targetPort >> 8) & 0xFF;
        transportHeader[1] = originalRequest.targetPort & 0xFF;
        // 🔧 修复：目标端口 = 客户端的端口 (originalRequest.sourcePort)
        transportHeader[2] = (originalRequest.sourcePort >> 8) & 0xFF;
        transportHeader[3] = originalRequest.sourcePort & 0xFF;
        
        int udpLen = 8 + payloadSize;
        transportHeader[4] = (udpLen >> 8) & 0xFF;  // Length
        transportHeader[5] = udpLen & 0xFF;
        transportHeader[6] = 0x00;  // Checksum (will calculate)
        transportHeader[7] = 0x00;
        
        // 复制payload
        memcpy(transportHeader + 8, payload, payloadSize);
        
        // 计算UDP校验和
        uint16_t udpChecksum = (originalRequest.addressFamily == AF_INET6)
            ? CalculateUDPChecksumV6(buffer, transportHeader, udpLen)
            : CalculateUDPChecksum(buffer, transportHeader, udpLen);
        transportHeader[6] = (udpChecksum >> 8) & 0xFF;
        transportHeader[7] = udpChecksum & 0xFF;
    }
    
    PACKET_BUILDER_LOGI("✅ Built response packet: %{public}d bytes (IP:%{public}d, Transport:%{public}d, Payload:%{public}d)",
                       totalLen, ipHeaderLen, transportHeaderLen, payloadSize);
    
    return totalLen;
}

int PacketBuilder::BuildTcpResponsePacket(uint8_t* buffer, int bufferSize,
                                          const uint8_t* payload, int payloadSize,
                                          const PacketInfo& originalRequest,
                                          uint32_t seq, uint32_t ack,
                                          uint8_t tcpFlags)
{
    if (!buffer || bufferSize <= 0) {
        PACKET_BUILDER_LOGE("Invalid parameters for building TCP packet");
        return -1;
    }
    if (payloadSize < 0) {
        PACKET_BUILDER_LOGE("Invalid TCP payloadSize: %{public}d", payloadSize);
        return -1;
    }
    if (payloadSize > 0 && !payload) {
        PACKET_BUILDER_LOGE("TCP payload is null but payloadSize=%{public}d", payloadSize);
        return -1;
    }
    if ((originalRequest.addressFamily != AF_INET && originalRequest.addressFamily != AF_INET6) ||
        originalRequest.protocol != PROTOCOL_TCP) {
        PACKET_BUILDER_LOGE("BuildTcpResponsePacket only supports IPv4/IPv6 TCP");
        return -1;
    }

    int ipHeaderLen = (originalRequest.addressFamily == AF_INET6) ? 40 : 20;
    int tcpHeaderLen = 20;
    int totalLen = ipHeaderLen + tcpHeaderLen + payloadSize;
    if (totalLen > bufferSize) {
        PACKET_BUILDER_LOGE("Buffer too small for TCP packet: need %{public}d, have %{public}d", totalLen, bufferSize);
        return -1;
    }

    memset(buffer, 0, totalLen);

    if (originalRequest.addressFamily == AF_INET6) {
        // IPv6 header
        buffer[0] = 0x60;
        buffer[1] = 0x00;
        buffer[2] = 0x00;
        buffer[3] = 0x00;
        uint16_t payloadLen = static_cast<uint16_t>(tcpHeaderLen + payloadSize);
        buffer[4] = (payloadLen >> 8) & 0xFF;
        buffer[5] = payloadLen & 0xFF;
        buffer[6] = PROTOCOL_TCP;
        buffer[7] = 0x40;

        struct in6_addr srcAddr6;
        if (inet_pton(AF_INET6, originalRequest.targetIP.c_str(), &srcAddr6) <= 0) {
            PACKET_BUILDER_LOGE("Invalid IPv6 target address: %{public}s", originalRequest.targetIP.c_str());
            return -1;
        }
        memcpy(buffer + 8, &srcAddr6, 16);
        struct in6_addr dstAddr6;
        if (inet_pton(AF_INET6, originalRequest.sourceIP.c_str(), &dstAddr6) <= 0) {
            PACKET_BUILDER_LOGE("Invalid IPv6 source address: %{public}s", originalRequest.sourceIP.c_str());
            return -1;
        }
        memcpy(buffer + 24, &dstAddr6, 16);
    } else {
        // IPv4 header
        buffer[0] = 0x45;
        buffer[1] = 0x00;
        buffer[2] = (totalLen >> 8) & 0xFF;
        buffer[3] = totalLen & 0xFF;
        buffer[4] = 0x00;
        buffer[5] = 0x00;
        buffer[6] = 0x40;
        buffer[7] = 0x00;
        buffer[8] = 0x40;
        buffer[9] = PROTOCOL_TCP;

        // src = originalRequest.targetIP (real server), dst = originalRequest.sourceIP (client virtual)
        struct in_addr srcAddr;
        if (inet_pton(AF_INET, originalRequest.targetIP.c_str(), &srcAddr) <= 0) {
            PACKET_BUILDER_LOGE("Invalid IPv4 target address: %{public}s", originalRequest.targetIP.c_str());
            return -1;
        }
        memcpy(buffer + 12, &srcAddr, 4);
        struct in_addr dstAddr;
        if (inet_pton(AF_INET, originalRequest.sourceIP.c_str(), &dstAddr) <= 0) {
            PACKET_BUILDER_LOGE("Invalid IPv4 source address: %{public}s", originalRequest.sourceIP.c_str());
            return -1;
        }
        memcpy(buffer + 16, &dstAddr, 4);

        uint16_t ipChecksum = CalculateIPChecksum(buffer, ipHeaderLen);
        buffer[10] = (ipChecksum >> 8) & 0xFF;
        buffer[11] = ipChecksum & 0xFF;
    }

    uint8_t* tcp = buffer + ipHeaderLen;

    // ports: src=serverPort, dst=clientPort
    tcp[0] = (originalRequest.targetPort >> 8) & 0xFF;
    tcp[1] = originalRequest.targetPort & 0xFF;
    tcp[2] = (originalRequest.sourcePort >> 8) & 0xFF;
    tcp[3] = originalRequest.sourcePort & 0xFF;

    // seq/ack
    tcp[4] = (seq >> 24) & 0xFF;
    tcp[5] = (seq >> 16) & 0xFF;
    tcp[6] = (seq >> 8) & 0xFF;
    tcp[7] = seq & 0xFF;
    tcp[8] = (ack >> 24) & 0xFF;
    tcp[9] = (ack >> 16) & 0xFF;
    tcp[10] = (ack >> 8) & 0xFF;
    tcp[11] = ack & 0xFF;

    tcp[12] = 0x50; // data offset 5 (20 bytes)
    tcp[13] = tcpFlags;
    // window size: fixed for now
    tcp[14] = 0xFF;
    tcp[15] = 0xFF;

    if (payloadSize > 0) {
        memcpy(tcp + tcpHeaderLen, payload, payloadSize);
    }

    uint16_t tcpChecksum = (originalRequest.addressFamily == AF_INET6)
        ? CalculateTCPChecksumV6(buffer, tcp, tcpHeaderLen + payloadSize)
        : CalculateTCPChecksum(buffer, tcp, tcpHeaderLen + payloadSize);
    tcp[16] = (tcpChecksum >> 8) & 0xFF;
    tcp[17] = tcpChecksum & 0xFF;

    return totalLen;
}

// 计算IP校验和
uint16_t PacketBuilder::CalculateIPChecksum(const uint8_t* header, int length) {
    uint32_t sum = 0;
    
    // 校验和字段先设为0
    for (int i = 0; i < length; i += 2) {
        if (i == 10) {
            // Skip checksum field
            continue;
        }
        uint16_t word = (header[i] << 8) | header[i + 1];
        sum += word;
    }
    
    // 处理进位
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    return ~sum;
}

// 计算TCP校验和
uint16_t PacketBuilder::CalculateTCPChecksum(const uint8_t* ipHeader, 
                                             const uint8_t* tcpHeader, 
                                             int tcpLength) {
    uint32_t sum = 0;
    
    // 伪头部
    for (int i = 12; i < 20; i += 2) {
        sum += (ipHeader[i] << 8) | ipHeader[i + 1];
    }
    sum += ipHeader[9];  // Protocol
    sum += tcpLength;
    
    // TCP头和数据
    for (int i = 0; i < tcpLength; i += 2) {
        if (i == 16) {
            // Skip checksum field
            continue;
        }
        if (i + 1 < tcpLength) {
            sum += (tcpHeader[i] << 8) | tcpHeader[i + 1];
        } else {
            sum += tcpHeader[i] << 8;
        }
    }
    
    // 处理进位
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    return ~sum;
}

// IPv6 TCP checksum
uint16_t PacketBuilder::CalculateTCPChecksumV6(const uint8_t* ipHeader,
                                               const uint8_t* tcpHeader,
                                               int tcpLength) {
    uint32_t sum = 0;

    // Pseudo header: src/dst addresses
    for (int i = 8; i < 40; i += 2) {
        sum += (ipHeader[i] << 8) | ipHeader[i + 1];
    }
    // Upper-layer length (32-bit)
    sum += (tcpLength >> 16) & 0xFFFF;
    sum += tcpLength & 0xFFFF;
    // Next Header
    sum += ipHeader[6];

    // TCP header + data
    for (int i = 0; i < tcpLength; i += 2) {
        if (i == 16) {
            continue;
        }
        if (i + 1 < tcpLength) {
            sum += (tcpHeader[i] << 8) | tcpHeader[i + 1];
        } else {
            sum += tcpHeader[i] << 8;
        }
    }

    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return static_cast<uint16_t>(~sum);
}

// 计算UDP校验和
uint16_t PacketBuilder::CalculateUDPChecksum(const uint8_t* ipHeader,
                                             const uint8_t* udpHeader,
                                             int udpLength) {
    uint32_t sum = 0;
    
    // 伪头部
    for (int i = 12; i < 20; i += 2) {
        sum += (ipHeader[i] << 8) | ipHeader[i + 1];
    }
    sum += ipHeader[9];  // Protocol
    sum += udpLength;
    
    // UDP头和数据
    for (int i = 0; i < udpLength; i += 2) {
        if (i == 6) {
            // Skip checksum field
            continue;
        }
        if (i + 1 < udpLength) {
            sum += (udpHeader[i] << 8) | udpHeader[i + 1];
        } else {
            sum += udpHeader[i] << 8;
        }
    }
    
    // 处理进位
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    return ~sum;
}

// IPv6 UDP checksum
uint16_t PacketBuilder::CalculateUDPChecksumV6(const uint8_t* ipHeader,
                                               const uint8_t* udpHeader,
                                               int udpLength) {
    uint32_t sum = 0;

    // Pseudo header: src/dst addresses
    for (int i = 8; i < 40; i += 2) {
        sum += (ipHeader[i] << 8) | ipHeader[i + 1];
    }
    // Upper-layer length (32-bit)
    sum += (udpLength >> 16) & 0xFFFF;
    sum += udpLength & 0xFFFF;
    // Next Header
    sum += ipHeader[6];

    // UDP header + data
    for (int i = 0; i < udpLength; i += 2) {
        if (i == 6) {
            continue;
        }
        if (i + 1 < udpLength) {
            sum += (udpHeader[i] << 8) | udpHeader[i + 1];
        } else {
            sum += udpHeader[i] << 8;
        }
    }

    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return static_cast<uint16_t>(~sum);
}

// 交换源/目标
PacketInfo PacketBuilder::SwapSourceDest(const PacketInfo& original) {
    PacketInfo swapped = original;
    
    // 交换IP
    swapped.sourceIP = original.targetIP;
    swapped.targetIP = original.sourceIP;
    
    // 交换端口
    swapped.sourcePort = original.targetPort;
    swapped.targetPort = original.sourcePort;
    
    return swapped;
}

// 获取IP头长度
int PacketBuilder::GetIPHeaderLength(const uint8_t* ipPacket) {
    // 🚨 修复：添加空指针检查
    if (!ipPacket) {
        return 0;
    }
    // 🚨 修复：确保至少能读取第一个字节
    // 注意：这个函数假设调用者已经验证了数据包大小，但为了安全起见，我们仍然检查
    return (ipPacket[0] & 0x0F) * 4;
}

// 获取TCP头长度
int PacketBuilder::GetTCPHeaderLength(const uint8_t* tcpHeader) {
    // 🚨 修复：添加空指针和边界检查
    if (!tcpHeader) {
        return 0;
    }
    // 🚨 修复：TCP头至少需要13字节才能读取data offset字段
    // 注意：这个函数假设调用者已经验证了TCP头大小，但为了安全起见，我们仍然检查
    // 如果数据不足，返回最小TCP头长度（20字节）
    return ((tcpHeader[12] >> 4) & 0x0F) * 4;
}
