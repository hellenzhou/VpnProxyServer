# VPN Proxy Server for HarmonyOS

A high-performance VPN proxy server implementation for HarmonyOS that forwards TCP and UDP traffic from VPN clients to the internet.

## 🎯 Project Status

✅ **Build Status:** All compilation and linking errors resolved  
⚠️ **Network Status:** Requires internet connectivity to function  
📊 **Protocol Support:** TCP, UDP (IPv4/IPv6)

## 📋 Quick Links

- **[Quick Start Guide](QUICK_START.md)** - Get up and running in 5 minutes
- **[Network Troubleshooting](NETWORK_TROUBLESHOOTING.md)** - Solve connectivity issues
- **Project Structure** - See below

## 🚀 Features

### Implemented
- ✅ UDP and TCP packet forwarding
- ✅ IPv4 and IPv6 support (TCP/UDP only)
- ✅ DNS query handling and caching
- ✅ Non-blocking I/O with select()
- ✅ Multi-threaded response handling
- ✅ Comprehensive network diagnostics
- ✅ Real-time statistics and monitoring
- ✅ Client connection tracking
- ✅ Automatic network interface selection

### Diagnostics
- ✅ Basic connectivity testing
- ✅ Network interface enumeration
- ✅ Gateway/Internet connectivity testing
- ✅ DNS connectivity testing
- ✅ Firewall port accessibility checks
- ✅ Automatic diagnostics on server startup

## ⚠️ Critical Requirements

### INTERNET ACCESS IS REQUIRED

**The machine running the proxy server MUST have internet access!**

This is the #1 most common issue. The proxy server is an "exit node" that makes real connections to target servers on behalf of VPN clients. Without internet, nothing will work.

**Quick Test:**
```powershell
# Windows
Test-NetConnection 8.8.8.8 -Port 443
```

If this fails, fix your internet connection before proceeding.

### Minimum Requirements
- HarmonyOS PC with DevEco Studio
- **Active internet connection** (Ethernet or WiFi)
- Firewall allows outbound ports: 80, 443, 53
- INTERNET permission in `module.json5`

## 🏗️ Architecture

```
[VPN Client] ──VPN Tunnel──► [Proxy Server] ──Internet──► [Target Servers]
                              (HarmonyOS PC)
                              - Forwards packets
                              - Creates real sockets
                              - NEEDS internet!
```

## 📁 Project Structure

```
VpnProxyServer/
├── entry/src/main/
│   ├── cpp/
│   │   ├── vpn_server.cpp              # Main server & NAPI bindings
│   │   ├── packet_forwarder.cpp        # TCP/UDP forwarding logic
│   │   ├── protocol_handler.cpp        # IP packet parsing
│   │   ├── network_diagnostics.cpp     # Network testing utility
│   │   ├── simple_dns_cache.cpp        # DNS response caching
│   │   ├── vpn_server_globals.h        # Global variables
│   │   └── CMakeLists.txt              # Build configuration
│   ├── ets/                            # TypeScript UI code
│   └── module.json5                    # App manifest
├── QUICK_START.md                      # Setup guide
├── NETWORK_TROUBLESHOOTING.md          # Problem solving
└── README.md                           # This file
```

## 🔧 Building

### Option 1: DevEco Studio (Recommended)
1. Open project in DevEco Studio
2. Wait for Gradle sync
3. Click **Build → Make Module 'entry'**

### Option 2: Command Line
```powershell
"F:\Huawei\DevEco Studio\tools\node\node.exe" ^
"F:\Huawei\DevEco Studio\tools\hvigor\bin\hvigorw.js" ^
--mode module -p module=entry@default ^
-p product=default ^
-p requiredDeviceType=2in1 ^
assembleHap --analyze=normal --parallel --incremental --daemon
```

## 🎮 Usage

### Starting the Server

1. **Install the HAP** on your HarmonyOS device
2. **Launch the app**
3. **Click "Start Server"**
4. **Check diagnostics** in Hilog:

```
Filter by tag: NetworkDiag
Look for: "✅ All network tests passed - VPN proxy should work"
```

### Connecting a Client

1. Get proxy server IP: `ipconfig` (Windows)
2. Configure VPN client with server IP and port
3. Connect from client
4. Verify in proxy logs: "Client connected"

### Monitoring

View in the app:
- **Statistics**: Packets, bytes, clients
- **Logs**: Real-time connection events
- **Hilog Console**: Detailed diagnostic output

## 🐛 Troubleshooting

### "TCP connection timeout" in logs?

**Cause:** Proxy server has no internet access

**Fix:**
1. Check: `Test-NetConnection 8.8.8.8 -Port 443`
2. Verify firewall allows outbound connections
3. See [NETWORK_TROUBLESHOOTING.md](NETWORK_TROUBLESHOOTING.md)

### "IPv6 next header 143 not supported"?

**Cause:** Non-TCP/UDP IPv6 protocol (expected)

**Fix:** No action needed - this is normal. Only TCP/UDP are forwarded.

### "Failed to bind socket"?

**Cause:** Port already in use

**Fix:** Choose different port or stop other application using it

### Network diagnostics show failures?

**Cause:** Network connectivity issues

**Fix:** 
1. Check internet connection
2. Review firewall settings
3. Test with `ping 8.8.8.8`
4. See full troubleshooting guide

## 📊 Network Diagnostics

The server automatically runs comprehensive diagnostics on startup:

```cpp
NetworkDiagnostics::RunFullDiagnostics();
```

**Tests performed:**
1. ✅ Basic network stack (loopback)
2. ✅ Network interfaces (lists all adapters)
3. ✅ Gateway connectivity (tests internet)
4. ✅ DNS connectivity (queries public DNS)
5. ✅ Port accessibility (tests common ports)

**View results:**
- Open Hilog console
- Filter by tag: `NetworkDiag`
- Look for diagnostic summary

## 🔒 Security Considerations

- Proxy server listens on loopback (127.0.0.1) by default
- VPN tunnel provides encryption
- No authentication on proxy (use VPN tunnel auth)
- Firewall rules recommended for production

## 🚧 Limitations

- ❌ No HTTP proxy chaining (requires direct internet)
- ❌ Only TCP/UDP forwarding (no ICMP, ESP, etc.)
- ❌ IPv6 extension headers 143+ not supported
- ❌ No QUIC/HTTP3 optimization
- ⚠️ Requires internet on proxy server machine

## 📝 Recent Fixes

### Build Errors (Resolved ✅)
- ✅ Fixed `BuildIPv4Packet` → `BuildIPPacket` function name
- ✅ Fixed `g_serverSocket` → `g_sockFd` undefined symbol
- ✅ Corrected function argument order

### Network Issues (Improved ⚙️)
- ✅ Added comprehensive network diagnostics
- ✅ Improved error logging for troubleshooting
- ✅ Enhanced IPv6 protocol handling
- ✅ Better socket binding with INADDR_ANY

## 🛠️ Development

### Adding New Features

1. **Protocol support:** Modify `protocol_handler.cpp`
2. **Forwarding logic:** Edit `packet_forwarder.cpp`
3. **Diagnostics:** Extend `network_diagnostics.cpp`
4. **UI:** Update TypeScript in `ets/` directory

### Debugging

Enable verbose logging:
```typescript
// In DevEco Studio Hilog console
// Set log level: DEBUG or INFO
// Filter by tags: VpnServer, NetworkDiag, etc.
```

### Testing

```cpp
// Run diagnostics manually
NetworkDiagnostics::RunFullDiagnostics();

// Test specific connectivity
bool ok = NetworkDiagnostics::TestTCPConnection("www.baidu.com", 80);
```

## 📚 Documentation

- **[QUICK_START.md](QUICK_START.md)** - Step-by-step setup guide
- **[NETWORK_TROUBLESHOOTING.md](NETWORK_TROUBLESHOOTING.md)** - Comprehensive troubleshooting
- **Inline Comments** - Code is heavily documented

## 🤝 Contributing

When reporting issues, include:
- Full Hilog output (filter: VpnServer, NetworkDiag)
- Network diagnostic results
- `ipconfig /all` output (Windows)
- Build environment details

## 📄 License

Copyright © 2026. All rights reserved.

## 🔗 Related Projects

- VPN Client (Android/iOS) - connects to this proxy
- HarmonyOS VPN SDK - underlying VPN framework

---

## Quick Checklist Before Asking for Help

- [ ] Proxy server machine has internet (test: `ping 8.8.8.8`)
- [ ] Build succeeds without errors
- [ ] Network diagnostics show ✅ All tests passed
- [ ] Firewall allows outbound ports 80, 443, 53
- [ ] INTERNET permission granted
- [ ] Checked [NETWORK_TROUBLESHOOTING.md](NETWORK_TROUBLESHOOTING.md)

**Most Common Issue:** Proxy server has no internet access → Fix internet first!

---

**Version:** 1.0  
**Platform:** HarmonyOS  
**Build Tool:** DevEco Studio  
**Language:** C++ (Native), TypeScript (UI)
