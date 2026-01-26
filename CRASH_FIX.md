# 崩溃修复总结

## 崩溃信息

- **信号**: SIGTRAP(TRAP_BRKPT)
- **位置**: `PacketForwarder::ForwardPacket` + 6816 字节偏移
- **线程**: Tid:29955, Name:ellen.vpnserver
- **设备**: HUAWEI MateBook Pro (ARM64)

## 修复的BUG

### 1. 数组越界访问 - ParseTcpFromIp

**问题**: 在访问 `data[off + 12]` 和 `data[off + 13]` 之前没有检查边界，可能导致数组越界。

**位置**: `packet_forwarder.cpp:179-180` (IPv4) 和 `packet_forwarder.cpp:232-233` (IPv6)

**修复前**:
```cpp
t.ack = ...;
t.flags = data[off + 13];  // ❌ 可能越界
uint8_t dataOffsetWords = (data[off + 12] >> 4) & 0x0F;  // ❌ 可能越界
int tcpHL = static_cast<int>(dataOffsetWords) * 4;
if (tcpHL < 20 || dataSize < off + tcpHL) return t;  // 检查太晚了
```

**修复后**:
```cpp
t.ack = ...;
// 🚨 修复：在访问 data[off + 12] 和 data[off + 13] 之前检查边界
if (dataSize < off + 14) return t;  // 至少需要14字节才能读取TCP头的基本字段
uint8_t dataOffsetWords = (data[off + 12] >> 4) & 0x0F;
int tcpHL = static_cast<int>(dataOffsetWords) * 4;
if (tcpHL < 20 || dataSize < off + tcpHL) return t;
t.flags = data[off + 13];
```

### 2. IPv6扩展头解析越界

**问题**: 在增加 `off` 之前没有检查边界，可能导致越界访问。

**位置**: `packet_forwarder.cpp:200-202`

**修复前**:
```cpp
uint8_t hdrExtLen = data[off + 1];
int extLen = (hdrExtLen + 1) * 8;
off += extLen;  // ❌ 可能越界
if (off > dataSize) return t;  // 检查太晚了
```

**修复后**:
```cpp
uint8_t hdrExtLen = data[off + 1];
int extLen = (hdrExtLen + 1) * 8;
// 🚨 修复：在增加 off 之前检查边界，避免越界
if (off + extLen > dataSize) return t;
off += extLen;
```

### 3. NAT映射不存在时的空指针访问

**问题**: `NATTable::WithConnection` 和 `WithConnectionBySocket` 可能返回 `false`（映射不存在），但代码没有检查返回值，导致在 lambda 中访问不存在的映射时崩溃。

**位置**: 多个位置

**修复前**:
```cpp
NATTable::WithConnection(natKey, [&](NATConnection& c) {
    // 访问 c 的成员，但如果映射不存在，c 是无效的
    c.tcpState = ...;
});
// ❌ 没有检查返回值
```

**修复后**:
```cpp
// 🚨 修复：检查WithConnection返回值，避免在映射不存在时崩溃
bool hasConn = NATTable::WithConnection(natKey, [&](NATConnection& c) {
    c.tcpState = ...;
});
if (!hasConn) {
    LOG_ERROR("❌ [TCP] NAT映射不存在，无法处理: key=%s", natKey.c_str());
    return -1;
}
```

**修复的位置**:
1. `packet_forwarder.cpp:1081` - TCP客户端包诊断
2. `packet_forwarder.cpp:1167` - TCP状态初始化（新映射）
3. `packet_forwarder.cpp:1217` - FIN包处理
4. `packet_forwarder.cpp:1245` - ACK包处理
5. `packet_forwarder.cpp:1287` - 数据包处理
6. `packet_forwarder.cpp:797` - TCP响应线程FIN处理
7. `packet_forwarder.cpp:849` - TCP响应线程数据处理

## 根本原因分析

1. **数组越界**: TCP头解析时没有充分检查边界，特别是在读取TCP头长度字段之前。
2. **竞态条件**: NAT映射可能在多线程环境下被删除，导致后续访问时映射不存在。
3. **错误处理不足**: 没有检查 `WithConnection` 的返回值，假设映射总是存在。

## 修复效果

- ✅ 防止数组越界访问
- ✅ 防止空指针解引用
- ✅ 提高代码健壮性
- ✅ 添加详细的错误日志

## 建议

1. **代码审查**: 检查所有数组访问是否有边界检查
2. **单元测试**: 添加边界条件测试（小数据包、无效数据包等）
3. **压力测试**: 测试高并发场景下的NAT映射管理
4. **内存检查**: 使用 AddressSanitizer (ASAN) 检测内存错误
