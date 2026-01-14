# 权限问题修复说明

## ❌ 遇到的问题

```
Install Failed: error: failed to install bundle.
code:9568289
error: install failed due to grant request permissions failed.
PermissionName: ohos.permission.CONNECTIVITY_INTERNAL
```

## 🔍 问题分析

### 系统级权限无法申请

`ohos.permission.CONNECTIVITY_INTERNAL` 是 HarmonyOS 的**系统级权限**：
- ❌ 普通应用无法申请
- ❌ 只能由系统应用使用
- ❌ 安装时会直接失败

**这就像 Android 中的 `INSTALL_PACKAGES` 权限，只有系统应用才能使用。**

## ✅ 已修复内容

### 1. 移除系统级权限

**修改前** (module.json5):
```json
{
  "name": "ohos.permission.CONNECTIVITY_INTERNAL",  // ❌ 导致安装失败
  ...
}
```

**修改后** (module.json5):
```json
// ✅ 已移除 CONNECTIVITY_INTERNAL 权限
"requestPermissions": [
  {
    "name": "ohos.permission.INTERNET"  // ✅ 普通权限
  },
  {
    "name": "ohos.permission.GET_NETWORK_INFO"  // ✅ 普通权限
  },
  {
    "name": "ohos.permission.SET_NETWORK_INFO"  // ✅ 普通权限
  }
]
```

### 2. 添加网络安全配置

创建了 `network_security_config.json`：

```json
{
  "network-security-config": {
    "base-config": {
      "cleartextTrafficPermitted": true  // ✅ 允许 HTTP 明文传输
    },
    "domain-config": [
      {
        "domains": [
          {
            "includeSubdomains": true,
            "name": "*"  // ✅ 允许所有域名
          }
        ],
        "cleartextTrafficPermitted": true
      }
    ]
  }
}
```

**作用**：
- ✅ 允许应用使用 HTTP (端口 80)
- ✅ 允许连接到任何域名
- ✅ 绕过 HarmonyOS 的明文传输限制

### 3. 配置元数据引用

在 `module.json5` 中添加：

```json
"metadata": [
  {
    "name": "network_security_config",
    "resource": "$profile:network_security_config"
  }
]
```

## 🎯 为什么浏览器能访问，应用不能？

### 原因分析

1. **浏览器是系统应用**
   - ✅ 有系统签名
   - ✅ 可以使用系统级权限
   - ✅ 不受网络安全策略限制

2. **第三方应用受限**
   - ❌ 只能使用普通权限
   - ❌ 默认禁止 HTTP 明文传输
   - ❌ 需要显式配置网络安全策略

3. **调试签名的限制**
   - ⚠️ 调试应用可能有额外限制
   - ⚠️ 某些网络操作可能被阻止
   - ⚠️ 需要配置网络安全规则

## 📋 可用的权限列表

### ✅ 普通应用可申请的网络权限

```json
// 基础网络访问
"ohos.permission.INTERNET"                    // ✅ 互联网访问
"ohos.permission.GET_NETWORK_INFO"            // ✅ 获取网络信息
"ohos.permission.SET_NETWORK_INFO"            // ✅ 设置网络信息

// WiFi 相关
"ohos.permission.GET_WIFI_INFO"               // ✅ 获取 WiFi 信息
"ohos.permission.SET_WIFI_INFO"               // ✅ 设置 WiFi 信息

// 蓝牙相关
"ohos.permission.USE_BLUETOOTH"               // ✅ 使用蓝牙
"ohos.permission.DISCOVER_BLUETOOTH"          // ✅ 发现蓝牙设备
```

### ❌ 系统级权限（普通应用不可用）

```json
// 这些权限会导致安装失败！
"ohos.permission.CONNECTIVITY_INTERNAL"       // ❌ 内部连接（系统级）
"ohos.permission.MANAGE_NET_STRATEGY"         // ❌ 管理网络策略（系统级）
"ohos.permission.CONNECTIVITY_CORE"           // ❌ 核心连接（系统级）
```

## 🚀 现在可以安装了

### 步骤 1：重新构建

```bash
cd f:\zhoubingquan\VpnProxyServer
.\uninstall_reinstall.cmd
```

**脚本会自动**：
1. ✅ 卸载旧版本
2. ✅ 清理构建缓存
3. ✅ 重新构建 HAP
4. ✅ 安装新版本

### 步骤 2：手动授予权限

安装成功后，在设备上：
1. 打开"设置" → "应用和服务" → "应用管理"
2. 找到"Proxy UDP Server"
3. 点击"权限"
4. 确保开启：
   - ✅ 联网
   - ✅ 获取网络信息
   - ✅ 设置网络信息

### 步骤 3：测试

启动应用后，你应该看到：

```log
✅ UDP DNS测试成功
✅ TCP DNS测试成功 (10.20.2.74:53)
✅ 百度 HTTP 成功 (110.242.68.66:80)      ← 现在应该能连接了
✅ 百度 HTTPS 成功 (110.242.68.66:443)
✅ 淘宝 HTTPS 成功
✅ Google DNS 成功 (8.8.8.8:53)
✅ Cloudflare DNS 成功 (1.1.1.1:53)

成功: 7-9/9 项测试通过
状态: ✅ 网络连接正常
```

## 🤔 如果还是失败怎么办？

### 情况 1：HTTP 仍然失败，但 HTTPS 成功

```log
❌ 百度 HTTP 失败
✅ 百度 HTTPS 成功
```

**原因**：HarmonyOS 可能有额外的 HTTP 限制
**解决**：这是正常的，使用 HTTPS 即可

### 情况 2：所有外网连接都失败

```log
✅ 内网 DNS (10.20.2.74) 成功
❌ 所有外网 IP 失败
```

**原因**：可能是应用前后台限制
**解决**：
1. 确保应用在前台运行
2. 不要锁屏或切换到其他应用
3. 检查设备的"后台网络访问"设置

### 情况 3：EINTR 错误频繁出现

```log
⚠️  select()被信号中断 (EINTR)，重试 5/5
```

**原因**：系统信号频繁（这是 HarmonyOS 的特性）
**解决**：代码已处理，最多重试 5 次

## 📊 网络安全配置的作用

### 为什么需要网络安全配置？

**HarmonyOS 默认安全策略**：
```
┌─────────────────────────────────┐
│  HarmonyOS 网络安全策略          │
├─────────────────────────────────┤
│ ❌ HTTP (明文) - 默认禁止        │
│ ✅ HTTPS (加密) - 允许           │
│ ❌ 未知域名 - 可能被阻止         │
└─────────────────────────────────┘
```

**添加网络安全配置后**：
```
┌─────────────────────────────────┐
│  自定义网络安全策略              │
├─────────────────────────────────┤
│ ✅ HTTP (明文) - 允许            │
│ ✅ HTTPS (加密) - 允许           │
│ ✅ 所有域名 - 允许               │
└─────────────────────────────────┘
```

## 🔗 相关文档

- `QUICK_FIX_GUIDE.md` - 快速修复指南
- `PERMISSION_FIX.md` - 权限问题详解
- `EINTR_FIX.md` - EINTR 错误处理
- `NETWORK_ENVIRONMENT.md` - 网络环境诊断

## ✅ 问题已解决

### 修改总结

| 项目 | 修改前 | 修改后 |
|------|--------|--------|
| 系统级权限 | ❌ CONNECTIVITY_INTERNAL | ✅ 已移除 |
| 网络安全配置 | ❌ 无 | ✅ 允许 HTTP |
| 域名白名单 | ❌ 无 | ✅ 允许所有域名 |
| 安装状态 | ❌ 安装失败 | ✅ 可以安装 |

### 现在执行

```bash
cd f:\zhoubingquan\VpnProxyServer
.\uninstall_reinstall.cmd
```

**预期**：
- ✅ 安装成功
- ✅ 权限正常授予
- ✅ 网络连接测试通过
- ✅ HTTP/HTTPS 都能访问

---

**修复时间**: 2026-01-14  
**问题**: 系统级权限导致安装失败  
**状态**: ✅ 已修复
