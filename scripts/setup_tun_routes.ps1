param(
    [ValidateSet('configure','cleanup')]
    [string]$Action,
    [string]$TunNic,
    [string]$PhysNic,
    [string]$ServerIp,
    [string]$Dns = "8.8.8.8"
)

function Write-Info  { Write-Host "[*] $args" -ForegroundColor Cyan }
function Write-Plus  { Write-Host "[+] $args" -ForegroundColor Green }
function Write-Minus { Write-Host "[-] $args" -ForegroundColor Red }
function Write-Warn  { Write-Host "[!] $args" -ForegroundColor Yellow }

if (-not $Action) {
    Write-Host @"
Usage:
  .\setup_tun_routes.ps1 -Action configure -TunNic "tun2socks Tunnel #2" -PhysNic WLAN -ServerIp 38.226.195.218 -Dns 8.8.8.8
  .\setup_tun_routes.ps1 -Action cleanup   -TunNic "tun2socks Tunnel #2" -PhysNic WLAN -ServerIp 38.226.195.218
"@
    exit 1
}

# Require admin
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Minus "This script requires Administrator privileges. Please run as Administrator."
    exit 1
}

if ($Action -eq "configure") {
    Write-Info "Configuring routes for tun2socks ..."
    Write-Info "TUN NIC:   $TunNic"
    Write-Info "PHYS NIC:  $PhysNic"
    Write-Info "SERVER:    $ServerIp"
    Write-Info "DNS:       $Dns"
    Write-Host ""

    $tunAddr = (Get-NetIPAddress -InterfaceAlias $TunNic -AddressFamily IPv4 -ErrorAction SilentlyContinue).IPAddress
    if (-not $tunAddr) {
        Write-Minus "Cannot find TUN interface: $TunNic"
        exit 1
    }
    Write-Plus "TUN IP: $tunAddr"

    $err = $null
    try {
        New-NetRoute -DestinationPrefix "0.0.0.0/0" -InterfaceAlias $TunNic -RouteMetric 1 -ErrorAction Stop | Out-Null
        Write-Plus "Default route 0.0.0.0/0 -> $TunNic added"
    } catch {
        if ($_.Exception.Message -match "MSFT_NetRouteEntryAlreadyExists") {
            Write-Warn "Default route already exists on $TunNic"
        } else {
            Write-Warn "Add default route failed: $_"
        }
    }

    try {
        New-NetRoute -DestinationPrefix "$ServerIp/32" -InterfaceAlias $PhysNic -RouteMetric 3 -ErrorAction Stop | Out-Null
        Write-Plus "Bypass route $ServerIp/32 -> $PhysNic added"
    } catch {
        if ($_.Exception.Message -match "MSFT_NetRouteEntryAlreadyExists") {
            Write-Warn "Bypass route already exists on $PhysNic"
        } else {
            Write-Warn "Add bypass route failed: $_"
        }
    }

    try {
        Set-DnsClientServerAddress -InterfaceAlias $TunNic -ServerAddresses $Dns -ErrorAction Stop
        Write-Plus "DNS set to $Dns on $TunNic"
    } catch {
        Write-Warn "Set DNS failed: $_"
    }

    Write-Host ""
    Write-Info "Routes configured!"
    Get-NetRoute -DestinationPrefix "0.0.0.0/0", "$ServerIp/32" | Format-Table DestinationPrefix, NextHop, InterfaceAlias, RouteMetric

} elseif ($Action -eq "cleanup") {
    Write-Info "Cleaning up tun2socks routes ..."
    Write-Info "TUN NIC:   $TunNic"
    Write-Info "PHYS NIC:  $PhysNic"
    Write-Info "SERVER:    $ServerIp"
    Write-Host ""

    try {
        Remove-NetRoute -DestinationPrefix "0.0.0.0/0" -InterfaceAlias $TunNic -Confirm:$false -ErrorAction Stop | Out-Null
        Write-Plus "Default route removed from $TunNic"
    } catch {
        if ($_.Exception.Message -match "route was not found") {
            Write-Warn "Default route not found on $TunNic"
        } else {
            Write-Warn "Remove default route failed: $_"
        }
    }

    try {
        Remove-NetRoute -DestinationPrefix "$ServerIp/32" -InterfaceAlias $PhysNic -Confirm:$false -ErrorAction Stop | Out-Null
        Write-Plus "Bypass route $ServerIp/32 removed from $PhysNic"
    } catch {
        if ($_.Exception.Message -match "route was not found") {
            Write-Warn "Bypass route not found on $PhysNic"
        } else {
            Write-Warn "Remove bypass route failed: $_"
        }
    }

    try {
        Set-DnsClientServerAddress -InterfaceAlias $TunNic -ResetServerAddresses -ErrorAction Stop
        Write-Plus "DNS reset to DHCP on $TunNic"
    } catch {
        Write-Warn "Reset DNS failed: $_"
    }

    Write-Host ""
    Write-Info "Routes cleaned up!"
}
