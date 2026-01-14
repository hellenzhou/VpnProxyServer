# VPN Proxy Server - Network Troubleshooting Guide

## Overview

This HarmonyOS VPN Proxy Server forwards network traffic from VPN clients to the internet. For it to work correctly, **the machine running the proxy server MUST have internet access**.

## Architecture

```
[VPN Client] <--VPN Tunnel--> [Proxy Server] <--Internet--> [Target Servers]
    |                              |                              |
    | Sends encrypted packets      | Decrypts & forwards          | Responds to
    | through VPN tunnel           | to real servers              | requests
```

**Critical Requirement**: The Proxy Server machine needs working internet connectivity to reach target servers.

## Common Issues and Solutions

### ❌ Issue 1: TCP Connection Timeout

**Symptoms:**
```
❌ TCP connection timeout: select() returned 0 (no file descriptors ready)
❌ Target server 140.210.206.7:443 may be unreachable or firewall blocked
```

**Root Cause:** The proxy server machine cannot establish outbound connections to the internet.

**Solutions:**

1. **Check Internet Connectivity**
   ```bash
   # On Windows (PowerShell)
   Test-NetConnection 8.8.8.8 -Port 443
   Test-NetConnection www.baidu.com -Port 80
   
   # On Linux/Mac
   ping 8.8.8.8
   curl -I https://www.google.com
   ```

2. **Check Firewall Settings**
   - **Windows Firewall:**
     - Open Windows Defender Firewall
     - Allow the HarmonyOS VPN Proxy app through the firewall
     - Ensure outbound connections are not blocked
   
   - **Corporate/Network Firewall:**
     - Contact your network administrator
     - Request that ports 80, 443, 53 (DNS) be allowed for outbound traffic
     - Check if HTTP/HTTPS proxy is required in your network

3. **Verify Network Adapter Status**
   ```powershell
   # Windows PowerShell
   Get-NetAdapter | Where-Object {$_.Status -eq "Up"}
   Get-NetIPAddress
   ```
   - Ensure at least one physical network adapter is UP and has an IP address
   - Verify you're not only on loopback (127.0.0.1)

4. **Check Proxy Settings** (if your network uses HTTP proxy)
   - Go to Windows Settings → Network & Internet → Proxy
   - Note down proxy server and port if configured
   - *Note: Current version doesn't support HTTP proxy chaining - this is a limitation*

5. **Test Direct Connectivity**
   ```powershell
   # Try to connect to common servers
   Test-NetConnection 8.8.8.8 -Port 53      # Google DNS
   Test-NetConnection 1.1.1.1 -Port 53      # Cloudflare DNS
   Test-NetConnection www.baidu.com -Port 443
   ```

### ❌ Issue 2: IPv6 Packets Being Dropped

**Symptoms:**
```
IPv6 next header not supported: 143 (only TCP=6, UDP=17 supported)
```

**Root Cause:** The packet contains IPv6 protocol header 143 (Ethernet-within-IP encapsulation) which is not TCP or UDP.

**Explanation:** This is EXPECTED behavior. The VPN proxy only forwards TCP and UDP traffic. Other protocols like:
- ICMPv6 (58)
- Ethernet-within-IP (143)
- Mobility Headers (135)
- ESP/AH (50/51)

...are not supported and will be dropped. This typically doesn't affect normal web browsing.

**Solutions:**
1. **For Web Browsing:** No action needed - IPv4 will be used instead
2. **If specific IPv6 connectivity is required:** Consider using a full VPN solution that supports all protocols

### ❌ Issue 3: DNS Resolution Failures

**Symptoms:**
```
🔍 [DNS] ❌ DNS connection FAILED - Timeout waiting for response
```

**Root Cause:** Cannot reach DNS servers or DNS port (53) is blocked.

**Solutions:**

1. **Test DNS Connectivity**
   ```powershell
   # Windows
   nslookup google.com 8.8.8.8
   nslookup baidu.com 114.114.114.114
   ```

2. **Check DNS Server Configuration**
   ```powershell
   # View current DNS servers
   Get-DnsClientServerAddress
   
   # Test DNS resolution
   Resolve-DnsName google.com
   ```

3. **Try Different DNS Servers**
   - The proxy uses system DNS by default
   - If system DNS is not working, configure alternative DNS:
     - Google DNS: 8.8.8.8, 8.8.4.4
     - Cloudflare DNS: 1.1.1.1, 1.0.0.1
     - Alibaba DNS: 223.5.5.5, 223.6.6.6

### ❌ Issue 4: HarmonyOS Sandbox Restrictions

**Symptoms:**
- Network diagnostics show "failed" even though the machine has internet
- Socket creation succeeds but connections always timeout

**Root Cause:** HarmonyOS sandbox may restrict network access for certain apps.

**Solutions:**

1. **Check HarmonyOS Permissions**
   - Ensure INTERNET permission is granted in `module.json5`:
   ```json
   "requestPermissions": [
     {"name": "ohos.permission.INTERNET"}
   ]
   ```

2. **Run Network Diagnostics**
   - The proxy server automatically runs diagnostics on startup
   - Check logs for detailed network status report
   - Look for "FULL NETWORK DIAGNOSTICS REPORT" in logs

3. **Verify Trusted Applications**
   - Ensure the proxy server is in the VPN's `trustedApplications` list
   - This prevents the VPN from routing the proxy's own traffic in a loop

## Diagnostic Tools

### Built-in Network Diagnostics

When the proxy server starts, it automatically runs comprehensive diagnostics:

```cpp
// Automatically called on startup
NetworkDiagnostics::RunFullDiagnostics();
```

The diagnostics check:
1. ✅ Basic network stack (loopback interface)
2. ✅ Network interfaces (lists all UP interfaces)
3. ✅ Gateway/Internet connectivity (tests public DNS servers)
4. ✅ DNS connectivity (sends test DNS query)
5. ✅ Firewall/Port accessibility (tests common ports)

**How to view diagnostic results:**
- Open DevEco Studio
- Go to "Hilog" console
- Filter by tag: `NetworkDiag`
- Look for diagnostic summary with ✅ or ❌ indicators

### Manual Testing

If you want to test manually:

```cpp
// In your C++ code
#include "network_diagnostics.h"

// Test specific connectivity
bool internetOK = NetworkDiagnostics::TestGatewayConnectivity();
bool dnsOK = NetworkDiagnostics::TestDNSConnectivity("8.8.8.8");
bool tcpOK = NetworkDiagnostics::TestTCPConnection("www.baidu.com", 80);

// List interfaces
auto interfaces = NetworkDiagnostics::ListNetworkInterfaces();
for (const auto& iface : interfaces) {
    LOG("Interface: %s, IP: %s, Status: %s", 
        iface.name.c_str(), 
        iface.ipAddress.c_str(),
        iface.isUp ? "UP" : "DOWN");
}
```

## Network Requirements

### Minimum Requirements

1. **Internet Connectivity:** REQUIRED
   - At least one network interface with internet access
   - Not restricted to loopback (127.0.0.1) only

2. **Outbound Port Access:**
   - Port 80 (HTTP)
   - Port 443 (HTTPS)
   - Port 53 (DNS)
   - Any other ports your applications need

3. **No Mandatory HTTP Proxy:**
   - Direct internet access (no corporate HTTP proxy)
   - *Or* ability to bypass proxy for VPN traffic

### Recommended Setup

1. **Network Configuration:**
   - Ethernet or WiFi connected
   - DHCP or static IP with valid gateway
   - DNS servers configured

2. **Firewall Configuration:**
   - Allow DevEco Studio/HarmonyOS apps outbound access
   - Specifically allow the proxy server executable
   - Whitelist ports: 80, 443, 53

3. **HarmonyOS Configuration:**
   - INTERNET permission granted
   - Proxy server in `trustedApplications` list
   - No conflicting VPN or network tools running

## Testing Checklist

Before starting the VPN proxy server, verify:

- [ ] Machine has internet access (can browse websites)
- [ ] Firewall allows outbound connections
- [ ] DNS resolution works (`nslookup google.com`)
- [ ] Can ping external servers (`ping 8.8.8.8`)
- [ ] No corporate HTTP proxy (or proxy is configured)
- [ ] INTERNET permission granted in HarmonyOS app
- [ ] Network adapter is UP and has valid IP

## Advanced Troubleshooting

### Enable Verbose Logging

All networking code includes detailed logging. To view:

1. Open DevEco Studio
2. View → Tool Windows → Hilog
3. Set log level to: DEBUG or INFO
4. Filter by tags:
   - `VpnServer` - Main server logs
   - `NetworkDiag` - Diagnostic logs
   - `VpnServer/forwarder` - Packet forwarding logs
   - `VpnServer/protocol` - Protocol parsing logs

### Common Log Patterns

**Good (Working):**
```
✅ TCP connection successful to www.baidu.com:443
✅ DNS response received (123 bytes)
✅ [服务端->客户端] UDP响应发送成功
```

**Bad (Not Working):**
```
❌ TCP connection timeout: select() returned 0
❌ Failed to send DNS query: Network is unreachable
❌ Cannot reach any public DNS servers
```

### If Still Not Working

1. **Simplify the setup:**
   - Try on a different machine with guaranteed internet
   - Test on mobile hotspot (to rule out network issues)
   - Use wired Ethernet instead of WiFi

2. **Check system routing:**
   ```powershell
   # Windows
   route print
   netstat -r
   ```

3. **Disable VPN temporarily:**
   - Stop any other VPN clients
   - Test the proxy server alone
   - Rule out VPN routing conflicts

4. **Contact support with:**
   - Full Hilog output
   - Network diagnostic results
   - `ipconfig /all` output (Windows)
   - Firewall settings screenshot

## FAQ

**Q: Can I run the proxy server on a machine without internet?**
A: No. The proxy server MUST have internet access to forward traffic to target servers.

**Q: Does the proxy support IPv6?**
A: Partially. IPv6 TCP and UDP are supported. Other IPv6 protocols (ICMPv6, etc.) are not supported and will be dropped.

**Q: Can I use this behind a corporate HTTP proxy?**
A: Currently no. The proxy creates direct TCP/UDP connections and doesn't support HTTP proxy chaining.

**Q: Why does it bind to 0.0.0.0 instead of a specific interface?**
A: `INADDR_ANY` (0.0.0.0) lets the OS choose the best network interface for each connection. This is the most flexible approach.

**Q: What if I see "select() returned 0" errors?**
A: This means connection timeout - the target server is unreachable. Check your internet connectivity and firewall.

## Architecture Notes

### How the VPN Proxy Works

1. **VPN Client** → Sends IP packets through VPN tunnel to proxy server
2. **Proxy Server** → Receives packets, extracts target IP/port
3. **Proxy Server** → Creates new socket, connects to real target server
4. **Target Server** → Responds to proxy server
5. **Proxy Server** → Wraps response in IP packet, sends back through tunnel
6. **VPN Client** → Receives response, delivers to application

### Why Internet Access is Critical

The proxy server is the "exit node" - it makes real connections on behalf of clients. Without internet:
- Cannot resolve DNS
- Cannot connect to target servers
- Cannot forward any traffic
- VPN tunnel is useless

### Performance Considerations

- Each connection creates a new socket
- Uses non-blocking I/O with select()
- Separate threads for handling responses
- Typical latency: VPN overhead + network latency

---

**Version:** 1.0  
**Last Updated:** 2026-01-14  
**Platform:** HarmonyOS (DevEco Studio)
