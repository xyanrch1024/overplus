# tun2socks 路由配置/清理脚本
# 参数: configure（配置）/ cleanup（清理）
# 需要管理员权限运行

param([string]$Action = "configure")

$TunNic   = "tun2socks Tunnel #2"
$PhysNic  = "WLAN"
$ServerIp = "38.226.195.218"
$Dns      = "8.8.8.8"

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[-] 需要管理员权限，请右键 -> 以管理员身份运行" -ForegroundColor Red
    exit 1
}

if ($Action -eq "configure") {
    Write-Host "[*] 配置 tun2socks 路由 ..." -ForegroundColor Cyan
    Write-Host "    TUN NIC:   $TunNic"
    Write-Host "    PHYS NIC:  $PhysNic"
    Write-Host "    SERVER:    $ServerIp"
    Write-Host "    DNS:       $Dns"
    Write-Host ""

    $tunAddr = (Get-NetIPAddress -InterfaceAlias $TunNic -AddressFamily IPv4 -ErrorAction SilentlyContinue).IPAddress
    if (-not $tunAddr) {
        Write-Host "[-] 找不到 TUN 网卡: $TunNic，请先启动 tun2socks" -ForegroundColor Red
        exit 1
    }
    Write-Host "[+] TUN IP: $tunAddr" -ForegroundColor Green

    try { New-NetRoute -DestinationPrefix "0.0.0.0/0" -InterfaceAlias $TunNic -RouteMetric 1 -ErrorAction Stop | Out-Null
        Write-Host "[+] 默认路由 0.0.0.0/0 -> $TunNic 已添加" -ForegroundColor Green }
    catch { if ($_.Exception.Message -match "MSFT_NetRouteEntryAlreadyExists") {
        Write-Host "[!] 默认路由已存在" -ForegroundColor Yellow } else { Write-Host "[!] 添加默认路由失败: $_" -ForegroundColor Yellow } }

    try { New-NetRoute -DestinationPrefix "$ServerIp/32" -InterfaceAlias $PhysNic -RouteMetric 3 -ErrorAction Stop | Out-Null
        Write-Host "[+] 绕过路由 $ServerIp/32 -> $PhysNic 已添加" -ForegroundColor Green }
    catch { if ($_.Exception.Message -match "MSFT_NetRouteEntryAlreadyExists") {
        Write-Host "[!] 绕过路由已存在" -ForegroundColor Yellow } else { Write-Host "[!] 添加绕过路由失败: $_" -ForegroundColor Yellow } }

    try { Set-DnsClientServerAddress -InterfaceAlias $TunNic -ServerAddresses $Dns -ErrorAction Stop
        Write-Host "[+] DNS 已设为 $Dns" -ForegroundColor Green } catch { Write-Host "[!] 设置 DNS 失败: $_" -ForegroundColor Yellow }

    Write-Host "" ; Write-Host "[*] 完成！" -ForegroundColor Cyan
    Get-NetRoute -DestinationPrefix "0.0.0.0/0", "$ServerIp/32" | Format-Table DestinationPrefix, NextHop, InterfaceAlias, RouteMetric
}

if ($Action -eq "cleanup") {
    Write-Host "[*] 清理 tun2socks 路由 ..." -ForegroundColor Cyan
    Write-Host ""

    try { Remove-NetRoute -DestinationPrefix "0.0.0.0/0" -InterfaceAlias $TunNic -Confirm:$false -ErrorAction Stop | Out-Null
        Write-Host "[+] 默认路由已移除" -ForegroundColor Green }
    catch { if ($_.Exception.Message -match "route was not found") {
        Write-Host "[!] 默认路由不存在" -ForegroundColor Yellow } else { Write-Host "[!] 移除失败: $_" -ForegroundColor Yellow } }

    try { Remove-NetRoute -DestinationPrefix "$ServerIp/32" -InterfaceAlias $PhysNic -Confirm:$false -ErrorAction Stop | Out-Null
        Write-Host "[+] 绕过路由已移除" -ForegroundColor Green }
    catch { if ($_.Exception.Message -match "route was not found") {
        Write-Host "[!] 绕过路由不存在" -ForegroundColor Yellow } else { Write-Host "[!] 移除失败: $_" -ForegroundColor Yellow } }

    try { Set-DnsClientServerAddress -InterfaceAlias $TunNic -ResetServerAddresses -ErrorAction Stop
        Write-Host "[+] DNS 已恢复 DHCP" -ForegroundColor Green } catch { Write-Host "[!] DNS 恢复失败: $_" -ForegroundColor Yellow }

    Write-Host "" ; Write-Host "[*] 清理完成！" -ForegroundColor Cyan
    Get-NetRoute -DestinationPrefix "0.0.0.0/0", "$ServerIp/32" | Format-Table DestinationPrefix, NextHop, InterfaceAlias, RouteMetric -ErrorAction SilentlyContinue
}
