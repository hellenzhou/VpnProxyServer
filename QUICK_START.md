# VPN Proxy Server - Quick Start Guide

## Prerequisites

### ✅ Essential Requirements

1. **HarmonyOS PC** with internet access (CRITICAL)
2. **DevEco Studio** installed and configured
3. **Network connectivity:**
   - Working internet connection
   - No firewall blocking outbound ports 80, 443, 53
   - Either Ethernet or WiFi connected

### ⚠️ Important: Internet Access Required

**The machine running the proxy server MUST have internet access!**

If your proxy server machine cannot reach the internet, the VPN will not work. Test first:

```powershell
# Windows - Test internet connectivity
Test-NetConnection 8.8.8.8 -Port 443
Test-NetConnection www.baidu.com -Port 80
```

Both should succeed. If they fail, fix your internet connection first.

## Step 1: Build the Project

1. Open DevEco Studio
2. Open the `VpnProxyServer` project
3. Wait for Gradle sync to complete
4. Build the project:
   ```
   Build → Make Module 'entry'
   ```
   Or run:
   ```powershell
   "F:\Huawei\DevEco Studio\tools\node\node.exe" ^
   "F:\Huawei\DevEco Studio\tools\hvigor\bin\hvigorw.js" ^
   --mode module -p module=entry@default ^
   -p product=default ^
   -p requiredDeviceType=2in1 ^
   assembleHap --analyze=normal --parallel --incremental --daemon
   ```

## Step 2: Install and Run

1. **Connect your HarmonyOS device** or start emulator
2. **Click "Run"** in DevEco Studio
3. The app will install and start automatically

## Step 3: Start the Proxy Server

1. In the HarmonyOS app, click **"Start Server"**
2. Wait for confirmation: "Proxy Server Started"
3. **Check logs for diagnostics:**

Open Hilog console and look for:

```
╔════════════════════════════════════════════════════════════╗
║         FULL NETWORK DIAGNOSTICS REPORT                   ║
╚════════════════════════════════════════════════════════════╝

1. Basic Connectivity: ✅ OK
2. Network Interfaces: Found 2 interface(s)
3. Gateway/Internet Connectivity: ✅ OK
4. DNS Connectivity: ✅ OK
5. Firewall/Port Accessibility: Testing...

✅ All network tests passed - VPN proxy should work
```

### ❌ If Diagnostics Fail

If you see:
```
❌ CRITICAL: No internet connectivity
❌ Network issues detected - VPN proxy will NOT work until resolved
```

**Stop here and fix the network issues first!** See [NETWORK_TROUBLESHOOTING.md](NETWORK_TROUBLESHOOTING.md).

## Step 4: Configure VPN Client

1. **Get the proxy server's IP and port:**
   - Default port: `9999` (or as configured)
   - IP address: The machine's local network IP (e.g., `192.168.1.100`)
   
   Find your IP:
   ```powershell
   # Windows
   ipconfig
   # Look for "IPv4 Address" under your active network adapter
   ```

2. **On the VPN client device:**
   - Open VPN client app
   - Enter proxy server IP: `192.168.1.100`
   - Enter proxy server port: `9999`
   - Click "Connect"

3. **Verify connection in proxy logs:**
   ```
   📡 Client connected: 192.168.1.50:54321
   Forwarding packet to www.baidu.com:443
   ✅ TCP connection successful
   ```

## Step 5: Test VPN Connectivity

On the VPN client device:

1. **Open a web browser**
2. **Navigate to:** `http://www.baidu.com`
3. **Expected:** Page loads successfully

### If it doesn't work:

Check proxy server logs for errors:

```
❌ TCP connection timeout
❌ Target server 140.210.206.7:443 may be unreachable
```

This means the proxy server machine cannot reach the internet → See troubleshooting guide.

## Step 6: Monitor Traffic

In the HarmonyOS app:

1. View **Statistics** tab:
   - Packets received/sent
   - Bytes transferred
   - Connected clients

2. View **Logs** tab:
   - Real-time traffic logs
   - Connection status
   - Error messages

## Common Setup Issues

### Issue: "Failed to start server on port 9999"

**Solution:**
- Port is already in use
- Try a different port (e.g., 9998, 10000)
- Check for other apps using the port:
  ```powershell
  netstat -ano | findstr :9999
  ```

### Issue: "Cannot connect from VPN client"

**Solution:**
1. Verify proxy server is running
2. Check firewall allows incoming connections on port 9999
3. Ensure both devices are on same network
4. Ping proxy server from client:
   ```bash
   ping 192.168.1.100
   ```

### Issue: "Connection timeout" errors in logs

**Solution:**
- Proxy server machine has no internet access
- Firewall blocking outbound traffic
- See [NETWORK_TROUBLESHOOTING.md](NETWORK_TROUBLESHOOTING.md)

## Verification Checklist

Before reporting issues, verify:

- [ ] Proxy server machine has internet (test with browser)
- [ ] Diagnostics report shows "✅ All tests passed"
- [ ] Firewall allows inbound port 9999
- [ ] Firewall allows outbound ports 80, 443, 53
- [ ] VPN client can ping proxy server
- [ ] Both devices on same network (or routed correctly)
- [ ] INTERNET permission granted in `module.json5`

## Architecture Overview

```
┌─────────────┐         VPN Tunnel        ┌──────────────┐
│             │   (Encrypted Packets)     │              │
│ VPN Client  │◄────────────────────────►│Proxy Server  │
│ (Mobile)    │   192.168.1.50:54321      │(HarmonyOS PC)│
│             │                           │192.168.1.100 │
└─────────────┘                           └───────┬──────┘
                                                  │
                                                  │ Internet
                                                  │ (Direct Connection)
                                                  │
                                          ┌───────▼────────┐
                                          │                │
                                          │ Target Servers │
                                          │ (www.baidu.com)│
                                          │ (8.8.8.8)      │
                                          │                │
                                          └────────────────┘
```

**Key Points:**
1. VPN Client encrypts packets, sends through tunnel to Proxy Server
2. Proxy Server decrypts, creates real connections to target servers
3. Proxy Server forwards responses back through tunnel
4. **Proxy Server MUST have internet to reach target servers**

## Performance Tips

1. **Use wired Ethernet** for proxy server (more stable than WiFi)
2. **Close unused applications** to free up network resources
3. **Monitor logs** for connection errors
4. **Restart server** if experiencing issues (stops old connections)

## Next Steps

- **Test different websites** to ensure routing works
- **Monitor statistics** to track usage
- **Check diagnostics** periodically
- **Read troubleshooting guide** if issues arise

## Support

For issues:

1. **Check diagnostics:** Look for ❌ in diagnostic report
2. **Review logs:** Filter by `VpnServer`, `NetworkDiag` tags
3. **Test internet:** Verify proxy server machine has internet
4. **Consult guide:** See [NETWORK_TROUBLESHOOTING.md](NETWORK_TROUBLESHOOTING.md)

---

**Note:** If the proxy server machine does not have internet access, **nothing will work**. This is the #1 most common issue. Always verify internet connectivity first!
