# VPN Proxy Server TCP 连接失败问题修复

## 问题现象

从日志中看到所有 TCP 连接都超时失败：

```
❌ TCP connection timeout: select() returned 0 (no file descriptors ready)
❌ Target server 49.4.33.161:443 may be unreachable or firewall blocked
🔍 [网络诊断] 连接超时 - 可能原因:
  1) 服务器机器没有互联网访问权限
  2) 防火墙阻止了出站连接
  3) 目标服务器不可达
  4) 网络路由配置问题
```

## 问题根因

**VPN 路由循环问题**

### 架构说明

```
[VPN Client]  ←→  [VPN Proxy Server]  ←→  [真实目标服务器]
(启动VPN)        (转发流量)              (百度/腾讯等)
```

### 问题分析

1. **VPN Client** (bundle: `com.samples.vpncontrol_case`) 启动 VPN 服务
2. VPN 配置中 `trustedApplications = []` （**空数组**）
3. VPN 路由表拦截**所有应用**的网络流量（包括 VPN Proxy Server）
4. **VPN Proxy Server** (bundle: `com.hellen.vpnserver`) 尝试连接真实服务器
5. 这个连接请求被 VPN 路由拦截，又发送回 VPN Client
6. 形成**路由循环**，导致 TCP 连接超时失败

### 关键日志

```cpp
// packet_forwarder.cpp:225
int PacketForwarder::CreateSocket(int addressFamily, uint8_t protocol) {
    // 代理服务器在trustedApplications中，socket不会被VPN路由表拦截
    // ❌ 但实际上trustedApplications是空数组！
    int sockFd = socket(addressFamily, SOCK_STREAM, 0);
    // ...
}
```

## 解决方案

### 1. 修改 VPN 配置，添加受信任应用

**文件：VpnClient/entry/src/main/ets/vpnability/VPNExtentionAbility.ets**

```typescript
// 修改前
this.trustedApplications = [];

// 修改后
this.trustedApplications = ['com.hellen.vpnserver'];
```

**文件：VpnClient/entry/src/main/ets/pages/SetupVpn.ets**

```typescript
// 修改前
this.trustedApplications = [];

// 修改后  
this.trustedApplications = ['com.hellen.vpnserver'];
```

### 2. 原理说明

- `trustedApplications` 列表中的应用，其网络流量**不会被 VPN 路由拦截**
- VPN Proxy Server 加入此列表后，可以直接访问真实网络
- 避免了路由循环问题

### 3. 流量路径（修复后）

```
[VPN Client]  →  [VPN Proxy Server]  →  [真实目标服务器]
   (VPN路由)       (直接路由，绕过VPN)      (百度/腾讯等)
      ↑                                          ↓
      └──────────────← 响应 ←─────────────────────┘
```

## 验证步骤

1. **重新编译并安装 VPN Client**
   ```bash
   # 清理构建
   # 重新安装 VPN Client 应用
   ```

2. **重启 VPN 服务**
   - 停止 VPN（如果正在运行）
   - 重新启动 VPN
   - 确保 VPN 配置生效

3. **查看日志**
   预期看到：
   ```
   ✅ TCP connection established successfully
   ✅ [客户端->目标服务器] TCP载荷发送成功
   ```

4. **测试网络诊断**
   预期看到：
   ```
   ✅ TCP连接成功 - 鸿蒙APP可以建立TCP连接！
   成功: 5/6 项测试通过
   状态: ✅ 网络连接正常，可以正常使用
   ```

## 技术细节

### trustedApplications 的作用

在 HarmonyOS VPN 中：

1. **默认行为**：VPN 启动后，所有应用的流量都走 VPN 路由
2. **trustedApplications**：列表中的应用流量绕过 VPN，直接访问真实网络
3. **使用场景**：
   - VPN 代理服务器（本例）
   - DNS 服务器
   - 本地服务
   - 系统关键服务

### 为什么需要这个配置

**VPN Proxy Server 的角色**：
- 接收客户端的加密流量（通过 VPN 隧道）
- 解密并转发到真实目标服务器
- 需要**直接访问真实网络**，不能再走 VPN 路由

如果不配置 `trustedApplications`：
```
客户端 → VPN → Proxy Server → [被VPN拦截] → VPN → Proxy Server → ...
                                    ↑______________|
                                    路由循环！
```

配置后：
```
客户端 → VPN → Proxy Server → [直接路由] → 真实服务器
```

## 相关文件

- `VpnClient/entry/src/main/ets/vpnability/VPNExtentionAbility.ets` - VPN 扩展能力配置
- `VpnClient/entry/src/main/ets/pages/SetupVpn.ets` - VPN 设置页面配置
- `VpnProxyServer/entry/src/main/cpp/packet_forwarder.cpp` - 数据包转发实现
- `VpnProxyServer/AppScope/app.json5` - Proxy Server 应用配置（bundle 名称）

## 参考资料

- HarmonyOS VPN Extension API 文档
- HarmonyOS 网络路由配置
- VPN 架构设计最佳实践

## 修复日期

2026-01-14

## 修复人员

AI Assistant (Claude Sonnet 4.5)
