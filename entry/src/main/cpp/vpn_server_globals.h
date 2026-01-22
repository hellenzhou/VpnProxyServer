#pragma once

#include <atomic>
#include <thread>
#include <string>
#include <mutex>

// 全局变量声明
extern std::atomic<bool> g_running;
extern std::atomic<int> g_sockFd;  // 🔧 修复：改为atomic，确保多线程安全访问
extern std::thread g_worker;
// extern std::thread g_udpRetransmitThread;  // 🔄 替换为线程池管理

// 统计变量
extern std::atomic<uint64_t> g_packetsReceived;
extern std::atomic<uint64_t> g_packetsSent;
extern std::atomic<uint64_t> g_bytesReceived;
extern std::atomic<uint64_t> g_bytesSent;

// 🔧 修复：g_lastActivity需要互斥锁保护，因为std::string不是线程安全的
extern std::string g_lastActivity;
extern std::mutex g_lastActivityMutex;