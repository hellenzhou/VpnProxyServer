@echo off
REM 完全卸载并重新安装应用
REM 用于权限配置更改后的完整重装

echo ==========================================
echo    VPN Proxy Server 完整重装脚本
echo ==========================================
echo.

REM 尝试多个可能的 hdc 路径
set HDC_PATH=
for %%p in (
    "%LOCALAPPDATA%\Huawei\sdk\HarmonyOS-NEXT-DB2\openharmony\toolchains\hdc.exe"
    "%LOCALAPPDATA%\Huawei\sdk\HarmonyOS-NEXT\openharmony\toolchains\hdc.exe"
    "%ProgramFiles%\Huawei\DevEco Studio\sdk\HarmonyOS-NEXT\openharmony\toolchains\hdc.exe"
    "%ProgramFiles(x86)%\Huawei\DevEco Studio\sdk\HarmonyOS-NEXT\openharmony\toolchains\hdc.exe"
) do (
    if exist %%p (
        set HDC_PATH=%%p
        goto :found_hdc
    )
)

where hdc.exe >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    set HDC_PATH=hdc.exe
    goto :found_hdc
)

echo ❌ 找不到 hdc 工具！
pause
exit /b 1

:found_hdc
echo ✅ 找到 hdc: %HDC_PATH%
echo.

REM 检查设备连接
echo [1/4] 检查设备连接...
%HDC_PATH% list targets
if %ERRORLEVEL% NEQ 0 (
    echo ❌ 未检测到设备！
    pause
    exit /b 1
)
echo.

REM 卸载应用
echo [2/4] 卸载旧版本应用...
%HDC_PATH% uninstall com.hellen.vpnserver
if %ERRORLEVEL% EQU 0 (
    echo ✅ 卸载成功
) else (
    echo ⚠️  应用可能未安装（这是正常的）
)
echo.

REM 清理并构建
echo [3/4] 清理并重新构建...
echo.
call hvigorw.bat clean
if %ERRORLEVEL% NEQ 0 (
    echo ❌ 清理失败！
    pause
    exit /b 1
)
echo.

call hvigorw.bat assembleHap
if %ERRORLEVEL% NEQ 0 (
    echo ❌ 构建失败！
    pause
    exit /b 1
)
echo.

REM 查找并安装 HAP
echo [4/4] 安装应用...
set HAP_PATH=entry\build\default\outputs\default\entry-default-signed.hap

if not exist "%HAP_PATH%" (
    echo ❌ 找不到 HAP 文件: %HAP_PATH%
    echo.
    echo 请检查构建是否成功。
    pause
    exit /b 1
)

%HDC_PATH% install "%HAP_PATH%"
if %ERRORLEVEL% NEQ 0 (
    echo ❌ 安装失败！
    pause
    exit /b 1
)

echo.
echo ==========================================
echo    ✅ 重装成功！
echo ==========================================
echo.
echo 📱 接下来请在设备上操作：
echo.
echo    1. 打开"设置" → "应用和服务" → "应用管理"
echo    2. 找到"Proxy UDP Server"
echo    3. 点击"权限"
echo    4. 确保所有权限都已开启：
echo       ✅ 联网
echo       ✅ 获取网络信息
echo       ✅ 设置网络信息
echo.
echo    5. 启动应用进行测试
echo.
echo 💡 提示：应用启动后，查看日志确认网络连接是否正常
echo.
pause
