@echo off
REM VPN Proxy Server Build Script for HarmonyOS
REM This script builds the VpnProxyServer module using hvigor

echo ╔════════════════════════════════════════════════════════════╗
echo ║    VPN Proxy Server - Build Script for HarmonyOS          ║
echo ╚════════════════════════════════════════════════════════════╝
echo.

REM Check if DevEco Studio tools exist
set DEVECO_NODE="F:\Huawei\DevEco Studio\tools\node\node.exe"
set HVIGOR_SCRIPT="F:\Huawei\DevEco Studio\tools\hvigor\bin\hvigorw.js"

if not exist %DEVECO_NODE% (
    echo ❌ ERROR: DevEco Studio Node.js not found!
    echo    Expected location: %DEVECO_NODE%
    echo    Please install DevEco Studio or update the path in this script.
    pause
    exit /b 1
)

if not exist %HVIGOR_SCRIPT% (
    echo ❌ ERROR: Hvigor script not found!
    echo    Expected location: %HVIGOR_SCRIPT%
    echo    Please install DevEco Studio or update the path in this script.
    pause
    exit /b 1
)

echo ✅ DevEco Studio tools found
echo.

REM Stop any existing hvigor daemon to clear cached environment variables
echo 🔄 Stopping existing hvigor daemon...
%DEVECO_NODE% %HVIGOR_SCRIPT% --stop-daemon >nul 2>&1
timeout /t 2 /nobreak >nul
echo ✅ Daemon stopped
echo.

REM Set required environment variables
set DEVECO_SDK_HOME=F:\Huawei\DevEco Studio\sdk
echo 🔧 Set DEVECO_SDK_HOME=%DEVECO_SDK_HOME%
echo.

echo 🔨 Starting build process...
echo    Module: entry@default
echo    Product: default
echo    Device Type: 2in1
echo    Build Mode: Incremental
echo.

REM Run the build command
%DEVECO_NODE% %HVIGOR_SCRIPT% --mode module -p module=entry@default -p product=default -p requiredDeviceType=2in1 assembleHap --analyze=normal --parallel --incremental --daemon

REM Check build result
if %ERRORLEVEL% EQU 0 (
    echo.
    echo ╔════════════════════════════════════════════════════════════╗
    echo ║            ✅ BUILD SUCCESSFUL                              ║
    echo ╚════════════════════════════════════════════════════════════╝
    echo.
    echo 📦 HAP file should be in: entry\build\default\outputs\default\
    echo.
    echo 🚀 Next steps:
    echo    1. Install the HAP on your HarmonyOS device
    echo    2. Launch the app and click "Start Server"
    echo    3. Check Hilog for network diagnostics:
    echo       - Filter by tag: NetworkDiag
    echo       - Look for: "✅ All network tests passed"
    echo    4. If diagnostics fail, see NETWORK_TROUBLESHOOTING.md
    echo.
) else (
    echo.
    echo ╔════════════════════════════════════════════════════════════╗
    echo ║            ❌ BUILD FAILED                                  ║
    echo ╚════════════════════════════════════════════════════════════╝
    echo.
    echo 🔍 Check the error messages above for details.
    echo.
    echo Common issues:
    echo    1. Compilation error - check C++ code syntax
    echo    2. Linker error - check undefined symbols
    echo    3. Permission error - run as administrator
    echo    4. Gradle sync error - restart DevEco Studio
    echo.
    echo 📚 For help, see:
    echo    - CHANGES_SUMMARY.md (recent fixes)
    echo    - NETWORK_TROUBLESHOOTING.md (network issues)
    echo    - README.md (project overview)
    echo.
    pause
    exit /b 1
)

echo Press any key to exit...
pause >nul
