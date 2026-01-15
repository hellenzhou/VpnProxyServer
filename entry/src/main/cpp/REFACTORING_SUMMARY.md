# VPN代理服务器重构总结

## 🎯 核心问题
旧版本直接转发完整IP数据包，导致双重封装，所有TCP/UDP连接失败。

## ✅ 重构内容

### 1. **新增模块**

#### `packet_builder.h/cpp` - 数据包构建器
- `ExtractPayload()` - 从完整IP包中提取应用层数据
- `BuildResponsePacket()` - 将应用层响应重新封装成IP包
- `CalculateIPChecksum()` - 计算IP校验和
- `CalculateTCPChecksum()` - 计算TCP校验和
- `CalculateUDPChecksum()` - 计算UDP校验和

#### `nat_table.h/cpp` - NAT映射表
- `CreateMapping()` - 创建客户端到服务器的连接映射
- `FindMapping()` - 查找NAT映射
- `FindMappingBySocket()` - 通过socket查找映射（用于响应）
- `UpdateActivity()` - 更新连接活动时间
- `RemoveMapping()` - 移除映射
- `CleanupExpired()` - 清理过期连接

### 2. **重构逻辑**

#### 旧版本流程（错误）:
```
客户端 -> [完整IP包: IP头+UDP头+Payload]
    ↓
服务器 -> 用普通socket直接转发完整IP包
    ↓
OS自动添加IP头 -> [IP头+完整IP包] <- 双重封装！
    ↓
目标服务器 -> 收到畸形包，丢弃 ❌
```

#### 新版本流程（正确）:
```
客户端 -> [完整IP包: IP头+UDP头+Payload]
    ↓
服务器 -> PacketBuilder::ExtractPayload() -> [Payload]
    ↓
服务器 -> 普通socket转发payload
    ↓
OS自动添加IP头和UDP/TCP头 -> [IP头+UDP/TCP头+Payload] ✅
    ↓
目标服务器 -> 收到正常包，处理并响应
    ↓
服务器 <- 收到响应 [应用层数据]
    ↓
服务器 -> PacketBuilder::BuildResponsePacket() -> [完整IP包]
    ↓
客户端 <- 收到完整IP包 ✅
```

### 3. **关键改进**

#### ForwardPacket()
```cpp
// 旧版：转发完整IP包（错误）
sendto(sockFd, data, dataSize, 0, ...);  // data包含IP头

// 新版：只转发payload（正确）
const uint8_t* payload;
int payloadSize;
PacketBuilder::ExtractPayload(data, dataSize, packetInfo, &payload, &payloadSize);
sendto(sockFd, payload, payloadSize, 0, ...);  // 只发送payload
```

#### HandleUdpResponse()
```cpp
// 旧版：直接转发应用层数据（错误）
recv(sockFd, buffer, ...);  // 收到应用层数据
sendto(g_sockFd, buffer, ...);  // 直接发回客户端

// 新版：重新封装成IP包（正确）
recv(sockFd, responsePayload, ...);  // 收到应用层数据
PacketBuilder::BuildResponsePacket(ipPacket, ..., responsePayload, ...);
sendto(g_sockFd, ipPacket, ...);  // 发送完整IP包
```

#### 连接管理
```cpp
// 新版：使用NAT表管理连接状态
NATTable::CreateMapping(natKey, clientAddr, packetInfo, sockFd);
// ... 响应时 ...
NATConnection conn;
NATTable::FindMappingBySocket(sockFd, conn);
// 知道应该发给哪个客户端
```

## 🔧 需要注意的点

### 1. TCP连接复用
- 现在会查找现有NAT映射，复用已建立的TCP连接
- 避免每个数据包都创建新连接

### 2. 线程模型（待优化）
- 当前仍然每个连接创建响应线程
- TODO: 改用epoll/select事件驱动模型

### 3. NAT表清理
- 需要定期调用 `NATTable::CleanupExpired()` 清理过期连接
- 建议在主服务器循环中定期调用

## 📝 测试清单

- [ ] DNS查询能否正常解析
- [ ] HTTP请求能否正常返回
- [ ] HTTPS连接能否建立
- [ ] 长连接（WebSocket）是否工作
- [ ] 多客户端并发是否正常
- [ ] 连接复用是否生效
- [ ] NAT表是否正确管理

## 🚀 下一步优化

1. **线程模型** - 使用线程池或事件驱动替代每连接一线程
2. **TCP状态机** - 正确处理TCP的SYN、ACK、FIN等
3. **连接池** - 预先建立到常用服务器的连接
4. **性能优化** - 减少内存拷贝，使用零拷贝技术
5. **IPv6支持** - 扩展到IPv6

## ⚠️ 已知限制

1. TCP序列号和ACK号目前是简化处理
2. 不支持TCP分片重组
3. 不支持IPv6
4. ICMPv6等非TCP/UDP协议被忽略
