@echo off
chcp 65001 >nul
setlocal enabledelayedexpansion

set ACTION=%1
set TUN_NIC=%2
set PHYS_NIC=%3
set SERVER_IP=%4
set DNS=%5

if "%ACTION%"=="" (
    echo Usage:
    echo   setup_tun_routes.cmd configure ^<TUN_NIC^> ^<PHYS_NIC^> ^<SERVER_IP^> [DNS]
    echo   setup_tun_routes.cmd cleanup   ^<TUN_NIC^> ^<PHYS_NIC^> ^<SERVER_IP^>
    echo.
    echo Example:
    echo   setup_tun_routes.cmd configure "tun2socks Tunnel #2" WLAN 38.226.195.218 8.8.8.8
    echo   setup_tun_routes.cmd cleanup   "tun2socks Tunnel #2" WLAN 38.226.195.218
    exit /b 1
)

if "%DNS%"=="" set DNS=8.8.8.8

if /i "%ACTION%"=="configure" (
    echo [*] Configuring routes for tun2socks ...
    echo     TUN NIC:    %TUN_NIC%
    echo     PHYS NIC:   %PHYS_NIC%
    echo     SERVER IP:  %SERVER_IP%
    echo     DNS:        %DNS%
    echo.

    echo [+] Getting TUN adapter IP ...
    for /f %%i in ('netsh interface ipv4 show addresses "%TUN_NIC%" ^| findstr "IP Address"') do (
        set TUN_IP=%%i
    )
    if "!TUN_IP!"=="" (
        echo [-] Failed to get TUN IP
        exit /b 1
    )
    echo     TUN IP: !TUN_IP!

    netsh interface ipv4 add route 0.0.0.0/0 "%TUN_NIC%" !TUN_IP! metric=1 >nul 2>&1
    if !errorlevel! equ 0 (
        echo [+] Default route 0.0.0.0/0 -^> !TUN_NIC! added
    ) else (
        echo [!] Default route add failed or already exists
    )

    netsh interface ipv4 add route %SERVER_IP%/32 "%PHYS_NIC%" metric=3 >nul 2>&1
    if !errorlevel! equ 0 (
        echo [+] Bypass route %SERVER_IP%/32 -^> %PHYS_NIC% added
    ) else (
        echo [!] Bypass route add failed or already exists
    )

    netsh interface ipv4 set dns "%TUN_NIC%" static %DNS% register=primary >nul 2>&1
    if !errorlevel! equ 0 (
        echo [+] DNS set to %DNS% on %TUN_NIC%
    ) else (
        echo [!] DNS set failed
    )

    echo.
    echo [*] Routes configured !
    route print -4 ^| findstr /I "0.0.0.0 %SERVER_IP%"
)

if /i "%ACTION%"=="cleanup" (
    echo [*] Cleaning up tun2socks routes ...
    echo     TUN NIC:    %TUN_NIC%
    echo     PHYS NIC:   %PHYS_NIC%
    echo     SERVER IP:  %SERVER_IP%
    echo.

    netsh interface ipv4 delete route 0.0.0.0/0 "%TUN_NIC%" >nul 2>&1
    if !errorlevel! equ 0 (
        echo [+] Default route removed from %TUN_NIC%
    ) else (
        echo [!] Default route not found or already removed
    )

    netsh interface ipv4 delete route %SERVER_IP%/32 "%PHYS_NIC%" >nul 2>&1
    if !errorlevel! equ 0 (
        echo [+] Bypass route %SERVER_IP%/32 removed from %PHYS_NIC%
    ) else (
        echo [!] Bypass route not found or already removed
    )

    netsh interface ipv4 set dns "%TUN_NIC%" dhcp >nul 2>&1
    if !errorlevel! equ 0 (
        echo [+] DNS reset to DHCP on %TUN_NIC%
    ) else (
        echo [!] DNS reset failed
    )

    echo.
    echo [*] Routes cleaned up !
)
