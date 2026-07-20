@echo off
cd /d "%~dp0"

set TUN=wintun
set PHYS=WLAN
set SRV=38.226.195.218
set DNS=8.8.8.8

net session >nul 2>&1 || (echo [-] 请以管理员身份运行 & pause & exit /b)

if /i "%1"=="cleanup" goto cleanup

echo [*] 配置路由 ...
netsh interface ipv4 add route 0.0.0.0/0 "%TUN%" metric=1
netsh interface ipv4 add route %SRV%/32 "%PHYS%" metric=3
netsh interface ipv4 set dnsserver "%TUN%" static %DNS% register=primary
echo [+] 完成 & goto show

:cleanup
echo [*] 清理路由 ...
netsh interface ipv4 delete route 0.0.0.0/0 "%TUN%" >nul 2>&1
netsh interface ipv4 delete route %SRV%/32 "%PHYS%" >nul 2>&1
netsh interface ipv4 set dnsserver "%TUN%" dhcp >nul 2>&1
echo [+] 完成

:show
route print -4 | findstr "0.0.0.0 %SRV%"
pause
