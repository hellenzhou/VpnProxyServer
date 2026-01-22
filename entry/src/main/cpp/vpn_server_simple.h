// 🚀 极简版头文件
#pragma once

#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

// 🎯 极简转发函数
int ForwardPacket(const uint8_t* data, size_t size, const sockaddr_in& originalPeer);

// 🎯 极简服务器函数
int StartSimpleServer(int port);
void StopSimpleServer();
