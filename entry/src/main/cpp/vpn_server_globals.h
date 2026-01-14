#pragma once

#include <atomic>
#include <thread>

// 全局变量声明
extern std::atomic<bool> g_running;
extern int g_sockFd;
extern std::thread g_worker;

// 统计变量
extern std::atomic<uint64_t> g_packetsReceived;
extern std::atomic<uint64_t> g_packetsSent;
extern std::atomic<uint64_t> g_bytesReceived;
extern std::atomic<uint64_t> g_bytesSent;
extern std::string g_lastActivity;
