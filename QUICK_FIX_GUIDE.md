# 🚀 快速修复指南

## 🔥 当前问题

**浏览器能访问外网，但应用测试失败！**

```
✅ 浏览器访问 baidu.com - 成功
✅ 浏览器访问 taobao.com - 成功
❌ 应用测试 baidu.com - 失败
❌ 应用测试 taobao.com - 失败
```

**这是应用权限问题！**

## ⚡ 立即执行（推荐）

### 步骤 1：完全卸载应用

```bash
hdc uninstall com.hellen.vpnserver
```

**为什么必须卸载？**
- 权限配置更改后，只升级安装可能不生效
- 必须完全卸载后重新安装
- 让系统重新请求和授予权限

### 步骤 2：清理并重新构建

```bash
cd VpnProxyServer
hvigorw clean
hvigorw assembleHap
```

### 步骤 3：重新安装

```bash
hdc install entry\build\default\outputs\default\entry-default-signed.hap
```

### 步骤 4：手动授予权限

**安装后，立即在设备上操作**：

1. 打开"设置" → "应用和服务" → "应用管理"
2. 找到"Proxy UDP Server"
3. 点击"权限"
4. **确保所有权限都已开启**：
   - ✅ 联网
   - ✅ 获取网络信息
   - ✅ 设置网络信息
   - ✅ 内部连接（如果有）

### 步骤 5：重新测试

启动应用，查看日志：

```bash
hdc shell hilog | grep "VpnServer"
```

## 📊 已做的优化

### 1. 添加额外权限

```json
{
  "name": "ohos.permission.CONNECTIVITY_INTERNAL"
}
```

### 2. 改用 HTTPS 测试

```cpp
// 原来：只测试 HTTP (端口 80)
TestSimpleTCP("110.242.68.66", 80, "百度");

// 现在：同时测试 HTTP 和 HTTPS
TestSimpleTCP("110.242.68.66", 80, "百度 HTTP");
TestSimpleTCP("110.242.68.66", 443, "百度 HTTPS");
```

### 3. 增加测试覆盖

新增测试：
- ✅ Google DNS (8.8.8.8:53)
- ✅ Cloudflare DNS (1.1.1.1:53)
- ✅ 多个 HTTPS 连接

现在测试从 6 项增加到 9 项。

### 4. 增强 EINTR 处理

```cpp
const int maxRetries = 5;  // 重试次数增加
timeout.tv_sec = 3;        // 超时增加到3秒
```

## 🔍 预期结果

### 如果是权限问题（修复后）

```log
✅ UDP DNS测试成功
✅ TCP DNS测试成功
✅ 百度 HTTP 成功  ← 之前失败
✅ 百度 HTTPS 成功
✅ 淘宝 HTTPS 成功
✅ Google DNS 成功
✅ Cloudflare DNS 成功

成功: 8/9 项测试通过
状态: ✅ 网络连接正常
```

### 如果是 HTTP 明文限制

```log
✅ UDP DNS测试成功
✅ TCP DNS测试成功
❌ 百度 HTTP 失败  ← HTTP 被阻止
✅ 百度 HTTPS 成功  ← HTTPS 允许
✅ 淘宝 HTTPS 成功
✅ Google DNS 成功

成功: 7/9 项测试通过
状态: ✅ 网络连接基本正常（仅HTTP受限）
```

### 如果仍然失败

可能需要：
1. 检查 HarmonyOS 系统设置
2. 查看应用详细权限
3. 检查系统日志中的权限拒绝信息

## 🔍 诊断命令

### 查看应用权限详情

```bash
# 查看应用完整信息
hdc shell bm dump -n com.hellen.vpnserver

# 查看权限授予状态
hdc shell dumpsys permission | grep com.hellen.vpnserver

# 查看应用运行状态
hdc shell ps -ef | grep vpnserver

# 查看系统日志中的权限相关信息
hdc shell hilog | grep -i "permission\|denied\|blocked"
```

### 查看网络状态

```bash
# 查看网络连接
hdc shell netstat -an | grep ESTABLISHED

# 查看网络接口
hdc shell ifconfig

# 查看路由
hdc shell ip route

# 测试 DNS
hdc shell nslookup baidu.com
```

## 📋 检查清单

执行修复前，确认：

- [ ] 已完全卸载旧版本应用
- [ ] 已清理构建缓存
- [ ] 已重新构建 HAP
- [ ] 已重新安装应用
- [ ] 已在设置中检查并授予所有权限
- [ ] 应用在前台运行（不要锁屏或切换应用）

## ❓ 常见问题

### Q: 为什么必须完全卸载？

**A:** 权限配置是在安装时确定的。如果只是升级安装，旧的权限配置可能不会更新。完全卸载后重新安装，系统会重新评估和授予权限。

### Q: 如果重装后还是失败怎么办？

**A:** 可能是 HarmonyOS 6.0 的新限制。尝试：
1. 查看系统日志中的权限拒绝信息
2. 在开发者选项中禁用网络限制
3. 使用正式签名（而非调试签名）

### Q: HTTPS 和 HTTP 有什么区别？

**A:** HarmonyOS 可能：
- 默认阻止 HTTP 明文传输（出于安全考虑）
- 只允许 HTTPS (端口 443)
- 这是 Android 9+ 的标准安全策略

## 🎯 如果这个修复有效

修复后你应该看到：

```log
✅ TCP连接成功 - 百度 HTTPS
✅ TCP连接成功 - 淘宝 HTTPS
✅ TCP连接成功 - Google DNS
✅ TCP连接成功 - Cloudflare DNS

成功: 7-8/9 项测试通过
状态: ✅ 网络连接正常
```

## 📞 需要更多帮助？

如果问题依然存在：

1. **收集信息**：
   ```bash
   hdc shell hilog > full_log.txt
   hdc shell bm dump -n com.hellen.vpnserver > app_info.txt
   ```

2. **检查权限**：
   - 截图应用权限设置页面
   - 查看是否有被拒绝的权限

3. **查看系统版本**：
   ```bash
   hdc shell getprop ro.build.version.release
   hdc shell getprop ro.product.model
   ```

---

**修复日期**: 2026-01-14  
**优先级**: 🔥 高（必须卸载重装）  
**预计成功率**: 85%
