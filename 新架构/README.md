# VPN Proxy Server v2.0

## 🎯 项目概述

这是 VPN Proxy Server 的**完全重构版本**，采用现代 C++ 设计模式和异步 I/O 架构，提供高性能、可扩展的 VPN 代理服务。

### 主要特性

- ✅ **异步 I/O 模型** - 基于 epoll/Boost.Asio 的事件驱动架构
- ✅ **高并发性能** - 支持 10,000+ 并发连接
- ✅ **分段锁设计** - NAT 表高并发优化
- ✅ **零拷贝** - 数据包处理优化
- ✅ **RAII 资源管理** - 自动内存管理，无泄漏
- ✅ **线程池** - 固定大小线程池，资源可控
- ✅ **DNS 缓存** - 减少 DNS 查询延迟
- ✅ **性能监控** - 内置 Prometheus 指标导出
- ✅ **配置热重载** - 部分配置支持热更新
- ✅ **详细日志** - 分级日志，支持文件轮转

### 性能指标

| 指标 | 目标值 |
|-----|--------|
| 吞吐量 | 50,000 pps |
| 延迟 (P99) | < 5ms |
| 并发连接 | 10,000+ |
| CPU 使用 | < 50% |
| 内存使用 | < 500MB |

---

## 🚀 快速开始

### 依赖要求

**必需：**
- C++17 或更高版本
- CMake 3.15+
- Linux (支持 epoll)

**推荐：**
- Boost 1.70+ (提供 Boost.Asio)
- spdlog (高性能日志)
- Google Test (单元测试)

### 安装依赖

**Ubuntu/Debian:**
```bash
sudo apt install build-essential cmake
sudo apt install libboost-all-dev libspdlog-dev libgtest-dev
```

**CentOS/RHEL:**
```bash
sudo yum install gcc-c++ cmake
sudo yum install boost-devel spdlog-devel gtest-devel
```

**macOS:**
```bash
brew install cmake boost spdlog googletest
```

### 编译

```bash
# 克隆项目
cd VpnProxyServer/新架构

# 创建构建目录
mkdir build && cd build

# 配置
cmake ..

# 编译
cmake --build . -j$(nproc)

# 运行测试
ctest --output-on-failure

# 安装（可选）
sudo cmake --install .
```

### 运行

```bash
# 使用默认配置
./vpn_server

# 指定端口和地址
./vpn_server -p 9999 -a 0.0.0.0

# 使用配置文件
./vpn_server -c config.json

# 查看帮助
./vpn_server --help
```

---

## ⚙️ 配置

### 配置文件示例 (config.json)

```json
{
  "network": {
    "listenAddress": "127.0.0.1",
    "listenPort": 8888,
    "maxConnections": 10000,
    "socketRecvBufferSize": 2097152,
    "socketSendBufferSize": 2097152
  },
  "performance": {
    "numWorkerThreads": 0,
    "numIOThreads": 1,
    "sessionTimeout": 300,
    "dnsTimeout": 5,
    "natTableShards": 16,
    "packetBufferSize": 2048,
    "objectPoolSize": 1000
  },
  "features": {
    "enableDNSCache": true,
    "dnsCacheTTL": 300,
    "enableMetrics": true,
    "metricsPort": 9090,
    "enableTCPForwarding": false
  },
  "logging": {
    "logLevel": "info",
    "logFilePath": "/var/log/vpn-server.log",
    "logMaxSize": 104857600,
    "logMaxFiles": 5
  },
  "advanced": {
    "cleanupInterval": 30,
    "statsUpdateInterval": 1
  }
}
```

### 配置说明

#### 网络配置
- `listenAddress`: 监听地址（"0.0.0.0" 监听所有接口）
- `listenPort`: 监听端口
- `maxConnections`: 最大连接数
- `socketRecvBufferSize`: Socket 接收缓冲区（字节）
- `socketSendBufferSize`: Socket 发送缓冲区（字节）

#### 性能配置
- `numWorkerThreads`: 工作线程数（0 = 自动检测）
- `sessionTimeout`: 会话超时时间（秒）
- `natTableShards`: NAT 表分片数（2 的幂）

#### 功能开关
- `enableDNSCache`: 启用 DNS 缓存
- `enableMetrics`: 启用性能指标
- `enableTCPForwarding`: 启用 TCP 转发（实验性）

#### 日志配置
- `logLevel`: 日志级别（trace/debug/info/warn/error/fatal）
- `logFilePath`: 日志文件路径（空 = 仅控制台）

---

## 📊 监控

### Prometheus 指标

服务器在 `metricsPort` (默认 9090) 导出 Prometheus 格式的指标：

```bash
curl http://localhost:9090/metrics
```

**可用指标：**
```
# 数据包统计
vpn_packets_received_total
vpn_packets_sent_total
vpn_bytes_received_total
vpn_bytes_sent_total

# 连接统计
vpn_connections_active
vpn_connections_total

# 性能指标
vpn_latency_seconds_bucket
vpn_latency_seconds_sum
vpn_latency_seconds_count

# 错误统计
vpn_errors_total

# NAT 表
vpn_nat_mappings_active
vpn_nat_lookups_total
vpn_nat_lookups_success_total
```

### 日志

日志输出到控制台和文件（如果配置）：

```
2026-01-16 10:30:45.123 [INFO] [vpn_server.cpp:245] Server started on 127.0.0.1:8888
2026-01-16 10:30:46.456 [DEBUG] [packet_processor.cpp:89] Received 42 bytes from 192.168.1.100:54321
2026-01-16 10:30:46.457 [INFO] [forwarder.cpp:156] Forwarded UDP packet to 8.8.8.8:53
```

---

## 🧪 测试

### 运行单元测试

```bash
cd build
ctest --output-on-failure
```

### 运行性能测试

```bash
# 基准测试
./benchmark

# 压力测试
./stress_test --connections 1000 --duration 60
```

### 手动测试

```bash
# 终端 1：启动服务器
./vpn_server -l debug

# 终端 2：测试 DNS 查询
dig @127.0.0.1 -p 8888 google.com

# 终端 3：测试 HTTP 代理
curl --socks5 127.0.0.1:8888 http://example.com
```

---

## 🏗️ 架构

### 模块结构

```
新架构/
├── core/              # 核心模块
│   ├── VpnServer.*    # 服务器主类
│   ├── Config.*       # 配置管理
│   └── EventLoop.*    # 事件循环
├── network/           # 网络层
│   ├── UdpSocket.*    # UDP Socket
│   ├── AsyncReceiver.* # 异步接收
│   └── AsyncSender.*  # 异步发送
├── packet/            # 数据包处理
│   ├── PacketParser.* # 解析
│   ├── PacketBuilder.* # 构建
│   └── ProtocolHandler.* # 协议处理
├── forwarding/        # 转发层
│   ├── Forwarder.*    # 转发器
│   ├── NATTable.*     # NAT 表
│   └── DNSCache.*     # DNS 缓存
├── resource/          # 资源管理
│   ├── ThreadPool.*   # 线程池
│   └── ObjectPool.*   # 对象池
└── util/              # 工具类
    ├── Logger.*       # 日志
    ├── Error.*        # 错误处理
    └── Metrics.*      # 指标
```

### 数据流

```
客户端 UDP 包
    ↓
[AsyncReceiver] 异步接收
    ↓
[EventLoop] 事件分发
    ↓
[ThreadPool] 提交到工作线程
    ↓
[PacketParser] 解析数据包
    ↓
[PacketValidator] 验证
    ↓
[Forwarder] 转发到真实服务器
    ↓
[NATTable] 记录映射
    ↓
真实服务器响应
    ↓
[Forwarder] 接收响应
    ↓
[PacketBuilder] 构建响应包
    ↓
[AsyncSender] 异步发送
    ↓
返回给客户端
```

---

## 🔧 开发

### 代码规范

**格式化：**
```bash
make format  # 使用 clang-format
```

**静态分析：**
```bash
make analyze  # 使用 clang-tidy
```

**代码覆盖率：**
```bash
cmake .. -DCMAKE_BUILD_TYPE=Debug -DENABLE_COVERAGE=ON
make coverage
```

### 添加新功能

1. 在对应模块创建新类
2. 编写单元测试
3. 更新 CMakeLists.txt
4. 更新文档

### 调试

**调试模式编译：**
```bash
cmake .. -DCMAKE_BUILD_TYPE=Debug
cmake --build .
```

**使用 GDB：**
```bash
gdb ./vpn_server
(gdb) run -c config.json
(gdb) bt  # 查看堆栈
```

**使用 Valgrind 检测内存泄漏：**
```bash
valgrind --leak-check=full ./vpn_server
```

---

## 📚 文档

- [设计文档](重构设计文档.md) - 完整架构设计
- [迁移计划](迁移计划.md) - 从旧版本迁移
- [API 文档](docs/api/) - Doxygen 生成
- [性能调优指南](docs/performance.md)
- [故障排查](docs/troubleshooting.md)

---

## 🤝 贡献

欢迎贡献！请遵循以下步骤：

1. Fork 项目
2. 创建功能分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 开启 Pull Request

---

## 📝 许可证

MIT License

---

## 🆚 对比旧架构

| 特性 | 旧架构 | 新架构 |
|-----|--------|--------|
| I/O 模型 | 阻塞 + detach | 异步事件驱动 |
| 线程管理 | 无限制 | 线程池 |
| 资源管理 | 手动 | RAII 自动 |
| NAT 表 | 全局锁 | 分段锁 |
| TCP 支持 | ❌ | ✅ |
| DNS 缓存 | ❌ | ✅ |
| 性能监控 | ❌ | ✅ |
| 配置热重载 | ❌ | ✅ |
| 代码测试 | ❌ | ✅ |

---

## ❓ FAQ

**Q: 为什么要完全重构？**
A: 旧架构存在严重的资源管理和并发问题，维护成本高。新架构采用现代设计，更稳定、更高效。

**Q: 性能真的会更好吗？**
A: 是的。异步 I/O + 分段锁 + 零拷贝等优化，理论和实测性能都有显著提升。

**Q: 如何从旧版本迁移？**
A: 参考 [迁移计划](迁移计划.md)，我们提供了详细的迁移步骤和工具。

**Q: 支持 Windows 吗？**
A: 目前仅支持 Linux。Windows 支持计划中（需要 IOCP 实现）。

**Q: 如何报告 bug？**
A: 请在 GitHub Issues 中提交，包含日志、配置和复现步骤。

---

## 📞 联系方式

- **项目主页**: [GitHub](https://github.com/yourname/vpn-proxy-server)
- **问题反馈**: [Issues](https://github.com/yourname/vpn-proxy-server/issues)
- **文档**: [Wiki](https://github.com/yourname/vpn-proxy-server/wiki)

---

**最后更新**: 2026-01-16
**版本**: 2.0.0
