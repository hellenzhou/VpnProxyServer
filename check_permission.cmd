@echo off
REM 应用权限检查脚本
REM 自动查找 hdc 并执行诊断命令

echo ==========================================
echo    VPN Proxy Server 权限诊断工具
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

REM 如果找不到，尝试在系统 PATH 中查找
where hdc.exe >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    set HDC_PATH=hdc.exe
    goto :found_hdc
)

REM 找不到 hdc
echo ❌ 找不到 hdc 工具！
echo.
echo 请确认 DevEco Studio 已正确安装，或手动指定 hdc 路径。
echo.
echo 📍 通常 hdc 位于：
echo    %%LOCALAPPDATA%%\Huawei\sdk\HarmonyOS-NEXT\openharmony\toolchains\hdc.exe
echo.
pause
exit /b 1

:found_hdc
echo ✅ 找到 hdc: %HDC_PATH%
echo.

REM 检查设备连接
echo [1/5] 检查设备连接...
%HDC_PATH% list targets
if %ERRORLEVEL% NEQ 0 (
    echo ❌ 未检测到设备！请确保：
    echo    1. 设备已通过 USB 连接
    echo    2. 设备已开启开发者模式
    echo    3. 设备已允许 USB 调试
    pause
    exit /b 1
)
echo.

REM 检查应用是否已安装
echo [2/5] 检查应用安装状态...
%HDC_PATH% shell bm dump -a | findstr "com.hellen.vpnserver" >nul
if %ERRORLEVEL% NEQ 0 (
    echo ⚠️  应用未安装！
    echo.
    pause
    exit /b 1
)
echo ✅ 应用已安装
echo.

REM 查看应用详细信息
echo [3/5] 应用详细信息:
echo ==========================================
%HDC_PATH% shell bm dump -n com.hellen.vpnserver
echo ==========================================
echo.

REM 查看应用权限状态
echo [4/5] 权限授予状态:
echo ==========================================
%HDC_PATH% shell bm dump -n com.hellen.vpnserver | findstr "permissions"
echo ==========================================
echo.

REM 查看应用运行状态
echo [5/5] 应用运行状态:
echo ==========================================
%HDC_PATH% shell ps -ef | findstr "vpnserver"
if %ERRORLEVEL% NEQ 0 (
    echo ⚠️  应用当前未运行
) else (
    echo ✅ 应用正在运行
)
echo ==========================================
echo.

echo ==========================================
echo    诊断完成！
echo ==========================================
echo.
echo 💡 提示：
echo    - 如果看到权限被拒绝，请在设置中手动授予
echo    - 如果应用未运行，请先启动应用
echo    - 修改权限后，建议卸载重装应用
echo.
pause
