#include "packet_builder.h"
#include <arpa/inet.h>
#include <string.h>
#include <hilog/log.h>

#define MAKE_FILE_NAME (strrchr(__FILE__, '/') ? (strrchr(__FILE__, '/') + 1) : __FILE__)
#define PACKET_BUILDER_LOGI(fmt, ...) \
  OH_LOG_Print(LOG_APP, LOG_INFO, 0x15b1, "VpnServer", "ZHOUB [Builder] [%{public}s:%{public}d] " fmt, MAKE_FILE_NAME, __LINE__, ##__VA_ARGS__)
#define PACKET_BUILDER_LOGE(fmt, ...) \
  OH_LOG_Print(LOG_APP, LOG_ERROR, 0x15b1, "VpnServer", "ZHOUB [Builder] [%{public}s:%{public}d] " fmt, MAKE_FILE_NAME, __LINE__, ##__VA_ARGS__)

int PacketBuilder::BuildResponsePacket(uint8_t* buffer, int bufferSize,
                                     const uint8_t* payload, int payloadSize,
                                     const PacketInfo& originalRequest)
{
    if (!buffer || bufferSize <= 0) return -1;
    if (originalRequest.protocol == PROTOCOL_UDP) {
        return BuildUdpResponsePacket(buffer, bufferSize, payload, payloadSize, originalRequest);
    } else if (originalRequest.protocol == PROTOCOL_TCP) {
        // TCP responses are usually built using the more specific BuildTcpResponsePacket
        return -1;
    }
    return -1;
}

int PacketBuilder::BuildUdpResponsePacket(uint8_t* buffer, int bufferSize,
                                        const uint8_t* payload, int payloadSize,
                                        const PacketInfo& originalRequest)
{
    if (!buffer || bufferSize <= 0 || payloadSize < 0) return -1;
    if (payloadSize > 0 && !payload) return -1;

    int ipHeaderLen = (originalRequest.addressFamily == AF_INET6) ? 40 : 20;
    int udpHeaderLen = 8;
    int totalLen = ipHeaderLen + udpHeaderLen + payloadSize;

    if (totalLen > bufferSize) return -1;

    memset(buffer, 0, totalLen);

    if (originalRequest.addressFamily == AF_INET6) {
        // IPv6
        buffer[0] = 0x60;
        uint16_t payloadLen = static_cast<uint16_t>(udpHeaderLen + payloadSize);
        buffer[4] = (payloadLen >> 8) & 0xFF;
        buffer[5] = payloadLen & 0xFF;
        buffer[6] = PROTOCOL_UDP;
        buffer[7] = 0x40;
        inet_pton(AF_INET6, originalRequest.targetIP.c_str(), buffer + 8);
        inet_pton(AF_INET6, originalRequest.sourceIP.c_str(), buffer + 24);
    } else {
        // IPv4
        buffer[0] = 0x45;
        buffer[2] = (totalLen >> 8) & 0xFF;
        buffer[3] = totalLen & 0xFF;
        buffer[8] = 0x40;
        buffer[9] = PROTOCOL_UDP;
        inet_pton(AF_INET, originalRequest.targetIP.c_str(), buffer + 12);
        inet_pton(AF_INET, originalRequest.sourceIP.c_str(), buffer + 16);
        uint16_t ipSum = CalculateIPChecksum(buffer, 20);
        buffer[10] = (ipSum >> 8) & 0xFF;
        buffer[11] = ipSum & 0xFF;
    }

    uint8_t* udp = buffer + ipHeaderLen;
    udp[0] = (originalRequest.targetPort >> 8) & 0xFF;
    udp[1] = originalRequest.targetPort & 0xFF;
    udp[2] = (originalRequest.sourcePort >> 8) & 0xFF;
    udp[3] = originalRequest.sourcePort & 0xFF;
    uint16_t udpLen = static_cast<uint16_t>(udpHeaderLen + payloadSize);
    udp[4] = (udpLen >> 8) & 0xFF;
    udp[5] = udpLen & 0xFF;
    
    if (payloadSize > 0) {
        memcpy(udp + 8, payload, payloadSize);
    }

    // UDP Checksum is optional in IPv4 but mandatory in IPv6. 
    // For simplicity and performance, we set it to 0 for IPv4.
    if (originalRequest.addressFamily == AF_INET6) {
        uint16_t udpSum = CalculateUDPChecksumV6(buffer, udp, udpLen);
        udp[6] = (udpSum >> 8) & 0xFF;
        udp[7] = udpSum & 0xFF;
    } else {
        udp[6] = 0;
        udp[7] = 0;
    }

    return totalLen;
}

int PacketBuilder::BuildTcpResponsePacket(uint8_t* buffer, int bufferSize,
                                          const uint8_t* payload, int payloadSize,
                                          const PacketInfo& originalRequest,
                                          uint32_t seq, uint32_t ack,
                                          uint8_t tcpFlags)
{
    if (!buffer || bufferSize <= 0 || payloadSize < 0) return -1;
    
    int ipHeaderLen = (originalRequest.addressFamily == AF_INET6) ? 40 : 20;
    bool isSyn = (tcpFlags & TCP_SYN) != 0;
    int tcpHeaderLen = isSyn ? 24 : 20; 
    int totalLen = ipHeaderLen + tcpHeaderLen + payloadSize;

    if (totalLen > bufferSize) return -1;

    memset(buffer, 0, totalLen);

    if (originalRequest.addressFamily == AF_INET6) {
        buffer[0] = 0x60;
        uint16_t pLen = static_cast<uint16_t>(tcpHeaderLen + payloadSize);
        buffer[4] = (pLen >> 8) & 0xFF;
        buffer[5] = pLen & 0xFF;
        buffer[6] = PROTOCOL_TCP;
        buffer[7] = 0x40;
        inet_pton(AF_INET6, originalRequest.targetIP.c_str(), buffer + 8);
        inet_pton(AF_INET6, originalRequest.sourceIP.c_str(), buffer + 24);
    } else {
        buffer[0] = 0x45;
        buffer[2] = (totalLen >> 8) & 0xFF;
        buffer[3] = totalLen & 0xFF;
        buffer[8] = 0x40;
        buffer[9] = PROTOCOL_TCP;
        inet_pton(AF_INET, originalRequest.targetIP.c_str(), buffer + 12);
        inet_pton(AF_INET, originalRequest.sourceIP.c_str(), buffer + 16);
        uint16_t ipSum = CalculateIPChecksum(buffer, 20);
        buffer[10] = (ipSum >> 8) & 0xFF;
        buffer[11] = ipSum & 0xFF;
    }

    uint8_t* tcp = buffer + ipHeaderLen;
    tcp[0] = (originalRequest.targetPort >> 8) & 0xFF;
    tcp[1] = originalRequest.targetPort & 0xFF;
    tcp[2] = (originalRequest.sourcePort >> 8) & 0xFF;
    tcp[3] = originalRequest.sourcePort & 0xFF;
    
    tcp[4] = (seq >> 24) & 0xFF; tcp[5] = (seq >> 16) & 0xFF;
    tcp[6] = (seq >> 8) & 0xFF;  tcp[7] = seq & 0xFF;
    tcp[8] = (ack >> 24) & 0xFF; tcp[9] = (ack >> 16) & 0xFF;
    tcp[10] = (ack >> 8) & 0xFF; tcp[11] = ack & 0xFF;

    tcp[12] = (static_cast<uint8_t>(tcpHeaderLen / 4) << 4);
    tcp[13] = tcpFlags;
    tcp[14] = 0xFF; tcp[15] = 0xFF; // Window

    if (isSyn) {
        tcp[20] = 2; tcp[21] = 4; // MSS Kind=2, Len=4
        uint16_t mss = 1200;
        tcp[22] = (mss >> 8) & 0xFF; tcp[23] = mss & 0xFF;
    }

    if (payloadSize > 0) {
        memcpy(tcp + tcpHeaderLen, payload, payloadSize);
    }

    uint16_t tcpSum = (originalRequest.addressFamily == AF_INET6)
        ? CalculateTCPChecksumV6(buffer, tcp, tcpHeaderLen + payloadSize)
        : CalculateTCPChecksum(buffer, tcp, tcpHeaderLen + payloadSize);
    tcp[16] = (tcpSum >> 8) & 0xFF;
    tcp[17] = tcpSum & 0xFF;

    return totalLen;
}

uint16_t PacketBuilder::CalculateIPChecksum(const uint8_t* header, int length) {
    uint32_t sum = 0;
    for (int i = 0; i < length; i += 2) {
        if (i == 10) continue;
        sum += (static_cast<uint16_t>(header[i]) << 8) | header[i + 1];
    }
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return ~static_cast<uint16_t>(sum);
}

uint16_t PacketBuilder::CalculateTCPChecksum(const uint8_t* ipHeader, const uint8_t* tcpHeader, int tcpLength) {
    uint32_t sum = 0;
    for (int i = 12; i < 20; i += 2) sum += (static_cast<uint16_t>(ipHeader[i]) << 8) | ipHeader[i + 1];
    sum += ipHeader[9];
    sum += static_cast<uint16_t>(tcpLength);
    for (int i = 0; i < tcpLength; i += 2) {
        if (i == 16) continue;
        uint16_t val = (i + 1 < tcpLength) ? ((static_cast<uint16_t>(tcpHeader[i]) << 8) | tcpHeader[i+1]) : (static_cast<uint16_t>(tcpHeader[i]) << 8);
        sum += val;
    }
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return ~static_cast<uint16_t>(sum);
}

uint16_t PacketBuilder::CalculateTCPChecksumV6(const uint8_t* ipHeader, const uint8_t* tcpHeader, int tcpLength) {
    uint32_t sum = 0;
    for (int i = 8; i < 40; i += 2) sum += (static_cast<uint16_t>(ipHeader[i]) << 8) | ipHeader[i + 1];
    sum += static_cast<uint16_t>(tcpLength);
    sum += ipHeader[6];
    for (int i = 0; i < tcpLength; i += 2) {
        if (i == 16) continue;
        uint16_t val = (i + 1 < tcpLength) ? ((static_cast<uint16_t>(tcpHeader[i]) << 8) | tcpHeader[i+1]) : (static_cast<uint16_t>(tcpHeader[i]) << 8);
        sum += val;
    }
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return ~static_cast<uint16_t>(sum);
}

uint16_t PacketBuilder::CalculateUDPChecksumV6(const uint8_t* ipHeader, const uint8_t* udpHeader, int udpLength) {
    uint32_t sum = 0;
    for (int i = 8; i < 40; i += 2) sum += (static_cast<uint16_t>(ipHeader[i]) << 8) | ipHeader[i + 1];
    sum += static_cast<uint16_t>(udpLength);
    sum += ipHeader[6];
    for (int i = 0; i < udpLength; i += 2) {
        if (i == 6) continue;
        uint16_t val = (i + 1 < udpLength) ? ((static_cast<uint16_t>(udpHeader[i]) << 8) | udpHeader[i+1]) : (static_cast<uint16_t>(udpHeader[i]) << 8);
        sum += val;
    }
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    uint16_t res = ~static_cast<uint16_t>(sum);
    return (res == 0) ? 0xFFFF : res;
}

bool PacketBuilder::ExtractPayload(const uint8_t* ipPacket, int packetSize, const PacketInfo& info, const uint8_t** payload, int* payloadSize) {
    if (!ipPacket || !payload || !payloadSize) return false;
    int ipHeaderLen = (info.addressFamily == AF_INET6) ? 40 : ((ipPacket[0] & 0x0F) * 4);
    int transportHeaderLen = (info.protocol == PROTOCOL_TCP) ? (((ipPacket[ipHeaderLen + 12] >> 4) & 0x0F) * 4) : 8;
    if (packetSize < ipHeaderLen + transportHeaderLen) return false;
    *payload = ipPacket + ipHeaderLen + transportHeaderLen;
    *payloadSize = packetSize - ipHeaderLen - transportHeaderLen;
    return true;
}

PacketInfo PacketBuilder::SwapSourceDest(const PacketInfo& original) {
    PacketInfo swapped = original;
    swapped.sourceIP = original.targetIP;
    swapped.sourcePort = original.targetPort;
    swapped.targetIP = original.sourceIP;
    swapped.targetPort = original.sourcePort;
    return swapped;
}

void PacketBuilder::LockTcpMss(uint8_t* tcpPacket, int tcpLength, uint16_t maxMss) {
    if (!tcpPacket || tcpLength < 20) return;
    int tcpHeaderLen = ((tcpPacket[12] >> 4) & 0x0F) * 4;
    if (tcpHeaderLen <= 20) return;
    uint8_t* options = tcpPacket + 20;
    int optionsLen = tcpHeaderLen - 20;
    for (int i = 0; i < optionsLen; ) {
        uint8_t opt = options[i];
        if (opt == 0) break;
        if (opt == 1) { i++; continue; }
        if (i + 1 >= optionsLen) break;
        uint8_t optLen = options[i + 1];
        if (optLen < 2 || i + optLen > optionsLen) break;
        if (opt == 2 && optLen == 4) {
            uint16_t currentMss = (options[i + 2] << 8) | options[i + 3];
            if (currentMss > maxMss) {
                options[i + 2] = (maxMss >> 8) & 0xFF;
                options[i + 3] = maxMss & 0xFF;
            }
            return;
        }
        i += optLen;
    }
}

int PacketBuilder::GetIPHeaderLength(const uint8_t* ipPacket) {
    if (!ipPacket) return 0;
    uint8_t version = (ipPacket[0] >> 4) & 0x0F;
    if (version == 4) return (ipPacket[0] & 0x0F) * 4;
    if (version == 6) return 40;
    return 0;
}
