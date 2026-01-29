#pragma once

#include <atomic>
#include <cstdint>

// Lightweight traffic counters for diagnosing starvation / throughput.
// These are "best effort" counters (no strict consistency required).
namespace TrafficStats {

inline std::atomic<uint64_t> fwdEnqueueTotal{0};
inline std::atomic<uint64_t> fwdEnqueueTcp{0};
inline std::atomic<uint64_t> fwdEnqueueUdp{0};
inline std::atomic<uint64_t> fwdEnqueueIcmp{0};
inline std::atomic<uint64_t> fwdEnqueueOther{0};

inline std::atomic<uint64_t> fwdPopTotal{0};
inline std::atomic<uint64_t> fwdPopTcp{0};
inline std::atomic<uint64_t> fwdPopUdp{0};
inline std::atomic<uint64_t> fwdPopIcmp{0};
inline std::atomic<uint64_t> fwdPopOther{0};

inline std::atomic<uint64_t> respEnqueueTotal{0};
inline std::atomic<uint64_t> respEnqueueTcp{0};
inline std::atomic<uint64_t> respEnqueueUdp{0};
inline std::atomic<uint64_t> respEnqueueOther{0};

inline std::atomic<uint64_t> quicDropped{0};

// 连接失败统计
inline std::atomic<uint64_t> tcpConnectFailTotal{0};        // TCP连接失败总数
inline std::atomic<uint64_t> tcpConnectFailTimeout{0};     // 连接超时
inline std::atomic<uint64_t> tcpConnectFailRefused{0};      // 连接被拒绝 (ECONNREFUSED)
inline std::atomic<uint64_t> tcpConnectFailUnreachable{0};  // 网络不可达 (ENETUNREACH/EHOSTUNREACH)
inline std::atomic<uint64_t> tcpConnectFailOther{0};         // 其他错误

} // namespace TrafficStats

