#pragma once

#include <cstdint>
#include <cstring>
#include <arpa/inet.h>
#include "protocol_handler.h"

// TCP标志位
constexpr uint8_t TCP_FIN = 0x01;
constexpr uint8_t TCP_SYN = 0x02;
constexpr uint8_t TCP_RST = 0x04;
constexpr uint8_t TCP_PSH = 0x08;
constexpr uint8_t TCP_ACK = 0x10;

// IP数据包构建和解析工具
class PacketBuilder {
public:
    // 从完整IP包中提取payload（应用层数据）
    static bool ExtractPayload(const uint8_t* ipPacket, int packetSize,
                               const PacketInfo& info,
                               const uint8_t** payloadOut, int* payloadSizeOut);
    
    // 构建完整的IP响应包
    static int BuildResponsePacket(uint8_t* buffer, int bufferSize,
                                   const uint8_t* payload, int payloadSize,
                                   const PacketInfo& originalRequest);

    // Build a TCP packet (including pure ACK/SYN-ACK/FIN etc.) as a full IPv4 packet.
    // - payload can be null if payloadSize==0
    // - seq/ack are absolute TCP sequence numbers
    static int BuildTcpResponsePacket(uint8_t* buffer, int bufferSize,
                                      const uint8_t* payload, int payloadSize,
                                      const PacketInfo& originalRequest,
                                      uint32_t seq, uint32_t ack,
                                      uint8_t tcpFlags);
    
    // 计算IP校验和
    static uint16_t CalculateIPChecksum(const uint8_t* header, int length);
    
    // 计算TCP校验和
    static uint16_t CalculateTCPChecksum(const uint8_t* ipHeader, 
                                         const uint8_t* tcpHeader, 
                                         int tcpLength);
    
    // 计算UDP校验和
    static uint16_t CalculateUDPChecksum(const uint8_t* ipHeader,
                                         const uint8_t* udpHeader,
                                         int udpLength);
    
    // 交换源/目标IP和端口（用于构建响应包）
    static PacketInfo SwapSourceDest(const PacketInfo& original);
    
    // 获取IP头长度
    static int GetIPHeaderLength(const uint8_t* ipPacket);
    
    // 获取TCP头长度
    static int GetTCPHeaderLength(const uint8_t* tcpHeader);
};
