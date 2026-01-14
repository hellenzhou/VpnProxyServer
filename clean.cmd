@echo off
REM VPN Proxy Server Clean Script
REM This script cleans the build artifacts

echo ╔════════════════════════════════════════════════════════════╗
echo ║    VPN Proxy Server - Clean Script                        ║
echo ╚════════════════════════════════════════════════════════════╝
echo.

set DEVECO_NODE="F:\Huawei\DevEco Studio\tools\node\node.exe"
set HVIGOR_SCRIPT="F:\Huawei\DevEco Studio\tools\hvigor\bin\hvigorw.js"

if not exist %DEVECO_NODE% (
    echo ❌ ERROR: DevEco Studio Node.js not found!
    pause
    exit /b 1
)

if not exist %HVIGOR_SCRIPT% (
    echo ❌ ERROR: Hvigor script not found!
    pause
    exit /b 1
)

echo 🧹 Cleaning build artifacts...
echo.

%DEVECO_NODE% %HVIGOR_SCRIPT% clean

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ✅ Clean completed successfully
    echo.
    echo You can now run build.cmd to rebuild the project.
    echo.
) else (
    echo.
    echo ❌ Clean failed
    echo.
    pause
    exit /b 1
)

echo Press any key to exit...
pause >nul
