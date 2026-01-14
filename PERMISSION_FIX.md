# 应用网络权限问题修复

## 🔍 问题现象

**关键发现**：
```
✅ 浏览器能访问 www.baidu.com
✅ 浏览器能访问 www.taobao.com
❌ 应用测试外网失败（百度/淘宝/腾讯）
```

## 📊 问题分析

### 不是网络环境问题

- ✅ 设备有外网连接
- ✅ 网络配置正常
- ✅ DNS 解析正常
- ✅ 内网连接成功

### 是应用权限问题

**浏览器能访问，应用不能** = **应用网络权限受限**！

## 🎯 根本原因

在 HarmonyOS 中，即使声明了 `INTERNET` 权限，应用的网络访问仍然可能受到限制：

1. **权限级别不足** - 普通 INTERNET 权限可能不够
2. **权限未授予** - 用户可能拒绝或系统未自动授予
3. **HarmonyOS 6.0 新限制** - 更严格的安全策略
4. **应用签名限制** - 调试签名可能有限制
5. **网络安全策略** - 默认可能阻止HTTP明文传输

## 🔧 解决方案

### 方案 1：添加额外权限（已应用）

已在 `module.json5` 中添加：

```json
{
  "name": "ohos.permission.CONNECTIVITY_INTERNAL",
  "reason": "$string:permission_reason",
  "usedScene": {
    "abilities": ["EntryAbility"],
    "when": "always"
  }
}
```

**说明**：
- `CONNECTIVITY_INTERNAL` - 内部连接权限
- 允许应用创建和管理网络连接
- 可能需要系统级别权限

### 方案 2：完全卸载重装

**重要**：权限配置更改后必须完全卸载重装！

```bash
# 1. 完全卸载应用
hdc uninstall com.hellen.vpnserver

# 2. 清理构建缓存
cd VpnProxyServer
hvigorw clean

# 3. 重新构建
hvigorw assembleHap

# 4. 重新安装
hdc install entry-default-signed.hap

# 5. 手动授予权限（如果系统提示）
# 在设备上打开应用，允许所有权限请求
```

### 方案 3：检查权限授予状态

```bash
# 查看应用信息和权限
hdc shell bm dump -n com.hellen.vpnserver

# 查看具体权限状态
hdc shell dumpsys permission | grep com.hellen.vpnserver

# 查看应用运行状态
hdc shell ps -ef | grep vpnserver
```

### 方案 4：在设置中手动授予权限

**HarmonyOS 设置**：
1. 打开"设置"
2. 进入"应用和服务" → "应用管理"
3. 找到"Proxy UDP Server"（VpnProxyServer）
4. 点击"权限"
5. 确保所有网络相关权限都已开启：
   - ✅ 联网
   - ✅ 获取网络信息
   - ✅ 设置网络信息

### 方案 5：检查应用运行模式

确保应用在前台运行：
- HarmonyOS 可能限制后台应用的网络访问
- 测试时保持应用在前台
- 不要锁屏或切换到其他应用

### 方案 6：使用 HTTPS 替代 HTTP

如果是网络安全策略问题：

```cpp
// 当前测试使用 HTTP (端口 80)
TestSimpleTCP("110.242.68.66", 80, "百度");  // ❌ 可能被阻止

// 改用 HTTPS (端口 443)
TestSimpleTCP("110.242.68.66", 443, "百度");  // ✅ 可能允许
```

让我更新测试代码：

<function_calls>
<invoke name="Read">
<parameter name="path">f:\zhoubingquan\VpnProxyServer\entry\src\main\cpp\packet_forwarder.cpp