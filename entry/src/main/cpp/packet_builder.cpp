/*
 * 数据包构建器实现 - 处理IP包的封装和解封装
 */

#include "packet_builder.h"
#include <hilog/log.h>

#define MAKE_FILE_NAME (strrchr(__FILE__, '/') ? (strrchr(__FILE__, '/') + 1) : __FILE__)
#define PACKET_BUILDER_LOGI(fmt, ...) \
  OH_LOG_Print(LOG_APP, LOG_INFO, 0x15b1, "PacketBuilder", "[%{public}s:%{public}d] " fmt, MAKE_FILE_NAME, __LINE__, ##__VA_ARGS__)
#define PACKET_BUILDER_LOGE(fmt, ...) \
  OH_LOG_Print(LOG_APP, LOG_ERROR, 0x15b1, "PacketBuilder", "[%{public}s:%{public}d] " fmt, MAKE_FILE_NAME, __LINE__, ##__VA_ARGS__)

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
        int ipHeaderLen = GetIPHeaderLength(ipPacket);
        if (ipHeaderLen < 20 || ipHeaderLen > packetSize) {
            PACKET_BUILDER_LOGE("Invalid IPv4 header length: %{public}d", ipHeaderLen);
            return false;
        }
        
        const uint8_t* transportHeader = ipPacket + ipHeaderLen;
        int remainingSize = packetSize - ipHeaderLen;
        
        if (info.protocol == PROTOCOL_TCP) {
            // TCP
            int tcpHeaderLen = GetTCPHeaderLength(transportHeader);
            if (tcpHeaderLen < 20 || tcpHeaderLen > remainingSize) {
                PACKET_BUILDER_LOGE("Invalid TCP header length: %{public}d", tcpHeaderLen);
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
        // IPv6 - 暂不支持
        PACKET_BUILDER_LOGE("IPv6 not supported yet");
        return false;
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
    
    // 交换源和目标（响应包方向相反）
    PacketInfo response = SwapSourceDest(originalRequest);
    
    // 只支持IPv4
    if (response.addressFamily != AF_INET) {
        PACKET_BUILDER_LOGE("Only IPv4 supported");
        return -1;
    }
    
    // 构建IPv4头（20字节）
    int ipHeaderLen = 20;
    int transportHeaderLen = (response.protocol == PROTOCOL_TCP) ? 20 : 8;
    int totalLen = ipHeaderLen + transportHeaderLen + payloadSize;
    
    if (totalLen > bufferSize) {
        PACKET_BUILDER_LOGE("Buffer too small: need %{public}d, have %{public}d", totalLen, bufferSize);
        return -1;
    }
    
    memset(buffer, 0, totalLen);
    
    // IPv4头
    buffer[0] = 0x45;  // Version 4, Header length 5 (20 bytes)
    buffer[1] = 0x00;  // TOS
    buffer[2] = (totalLen >> 8) & 0xFF;  // Total length
    buffer[3] = totalLen & 0xFF;
    buffer[4] = 0x00;  // Identification
    buffer[5] = 0x00;
    buffer[6] = 0x40;  // Flags: Don't fragment
    buffer[7] = 0x00;
    buffer[8] = 0x40;  // TTL: 64
    buffer[9] = response.protocol;  // Protocol
    buffer[10] = 0x00;  // Checksum (will calculate later)
    buffer[11] = 0x00;
    
    // Source IP (response.targetIP -> original source)
    struct in_addr srcAddr;
    inet_pton(AF_INET, response.targetIP.c_str(), &srcAddr);
    memcpy(buffer + 12, &srcAddr, 4);
    
    // Destination IP (response.sourceIP -> original target)
    struct in_addr dstAddr;
    inet_pton(AF_INET, response.sourceIP.c_str(), &dstAddr);
    memcpy(buffer + 16, &dstAddr, 4);
    
    // 计算IP校验和
    uint16_t ipChecksum = CalculateIPChecksum(buffer, ipHeaderLen);
    buffer[10] = (ipChecksum >> 8) & 0xFF;
    buffer[11] = ipChecksum & 0xFF;
    
    uint8_t* transportHeader = buffer + ipHeaderLen;
    
    if (response.protocol == PROTOCOL_TCP) {
        // TCP头（简化版，20字节）
        transportHeader[0] = (response.targetPort >> 8) & 0xFF;  // Source port
        transportHeader[1] = response.targetPort & 0xFF;
        transportHeader[2] = (response.sourcePort >> 8) & 0xFF;  // Dest port
        transportHeader[3] = response.sourcePort & 0xFF;
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
        uint16_t tcpChecksum = CalculateTCPChecksum(buffer, transportHeader, 20 + payloadSize);
        transportHeader[16] = (tcpChecksum >> 8) & 0xFF;
        transportHeader[17] = tcpChecksum & 0xFF;
        
    } else if (response.protocol == PROTOCOL_UDP) {
        // UDP头（8字节）
        transportHeader[0] = (response.targetPort >> 8) & 0xFF;  // Source port
        transportHeader[1] = response.targetPort & 0xFF;
        transportHeader[2] = (response.sourcePort >> 8) & 0xFF;  // Dest port
        transportHeader[3] = response.sourcePort & 0xFF;
        
        int udpLen = 8 + payloadSize;
        transportHeader[4] = (udpLen >> 8) & 0xFF;  // Length
        transportHeader[5] = udpLen & 0xFF;
        transportHeader[6] = 0x00;  // Checksum (will calculate)
        transportHeader[7] = 0x00;
        
        // 复制payload
        memcpy(transportHeader + 8, payload, payloadSize);
        
        // 计算UDP校验和
        uint16_t udpChecksum = CalculateUDPChecksum(buffer, transportHeader, udpLen);
        transportHeader[6] = (udpChecksum >> 8) & 0xFF;
        transportHeader[7] = udpChecksum & 0xFF;
    }
    
    PACKET_BUILDER_LOGI("✅ Built response packet: %{public}d bytes (IP:%{public}d, Transport:%{public}d, Payload:%{public}d)",
                       totalLen, ipHeaderLen, transportHeaderLen, payloadSize);
    
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
    return (ipPacket[0] & 0x0F) * 4;
}

// 获取TCP头长度
int PacketBuilder::GetTCPHeaderLength(const uint8_t* tcpHeader) {
    return ((tcpHeader[12] >> 4) & 0x0F) * 4;
}
