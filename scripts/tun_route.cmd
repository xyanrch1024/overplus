@echo off
chcp 65001 >nul
cd /d "%~dp0"

set TUN_NIC=tun2socks Tunnel #2
set PHYS_NIC=WLAN
set SERVER_IP=38.226.195.218
set DNS=8.8.8.8

>nul 2>&1 net session || (
    echo [-] 请右键 -> 以管理员身份运行
    pause & exit /b 1
)

echo [*] 获取 TUN 网卡 IP ...
for /f "tokens=2 delims=:" %%i in ('netsh interface ipv4 show addresses "%TUN_NIC%" ^| find "IP Address"') do set TUN_IP=%%i
set TUN_IP=%TUN_IP: =%
if "%TUN_IP%"=="" (
    echo [-] 找不到 TUN 网卡，请先启动 tun2socks
    pause & exit /b 1
)
echo [+] TUN IP: %TUN_IP%

if /i "%1"=="cleanup" goto cleanup

echo [*] 配置路由 ...
>nul netsh interface ipv4 add route 0.0.0.0/0 "%TUN_NIC%" %TUN_IP% metric=1
>nul netsh interface ipv4 add route %SERVER_IP%/32 "%PHYS_NIC%" metric=3
>nul netsh interface ipv4 set dns "%TUN_NIC%" static %DNS% register=primary
echo [+] 完成
goto show

:cleanup
echo [*] 清理路由 ...
>nul netsh interface ipv4 delete route 0.0.0.0/0 "%TUN_NIC%"
>nul netsh interface ipv4 delete route %SERVER_IP%/32 "%PHYS_NIC%"
>nul netsh interface ipv4 set dns "%TUN_NIC%" dhcp
echo [+] 清理完成

:show
route print -4 | findstr /I "0.0.0.0 %SERVER_IP%"
pause
