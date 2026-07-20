#include "TunManager.h"

#include "Shared/Log.h"
#include <QTimer>
#include <iphlpapi.h>
#include <netioapi.h>
#include <shellapi.h>
#include <ws2tcpip.h>
#include <string>

#define _WINSOCK_DEPRECATED_NO_WARNINGS
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

TunManager::TunManager() {}

TunManager::~TunManager() { stop(); }

void TunManager::log(const std::string& msg)
{
    NOTICE_LOG << "TunManager: " << msg;
    if (logCb_) logCb_(msg);
}

bool TunManager::findTunAdapter()
{
    ULONG bufLen = 15000;
    PIP_ADAPTER_ADDRESSES adapters = (PIP_ADAPTER_ADDRESSES)malloc(bufLen);
    if (!adapters) return false;

    DWORD ret = GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX,
                                     NULL, adapters, &bufLen);
    if (ret != NO_ERROR) {
        free(adapters);
        return false;
    }

    for (PIP_ADAPTER_ADDRESSES aa = adapters; aa; aa = aa->Next) {
        std::string desc = aa->AdapterName;
        if (aa->Description) {
            wchar_t* d = aa->Description;
            std::string tmp(d, d + wcslen(d));
            desc = tmp;
        }

        if (desc.find("tun2socks") == std::string::npos &&
            desc.find("Tun2socks") == std::string::npos &&
            desc.find("wintun") == std::string::npos)
            continue;

        if (aa->FirstUnicastAddress &&
            aa->FirstUnicastAddress->Address.lpSockaddr &&
            aa->FirstUnicastAddress->Address.lpSockaddr->sa_family == AF_INET) {

            sockaddr_in* sa = (sockaddr_in*)aa->FirstUnicastAddress->Address.lpSockaddr;
            char ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &sa->sin_addr, ip, sizeof(ip));

            tun_if_index_ = aa->IfIndex;
            tun_addr_ = ip;

            log("TUN adapter found: \"" + desc + "\" index=" +
                std::to_string(tun_if_index_) + " ip=" + tun_addr_);
            free(adapters);
            return true;
        }
    }

    free(adapters);
    return false;
}

bool TunManager::findPhysicalGateway()
{
    ULONG bufLen = 15000;
    PIP_ADAPTER_ADDRESSES adapters = (PIP_ADAPTER_ADDRESSES)malloc(bufLen);
    if (!adapters) return false;

    DWORD ret = GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX,
                                     NULL, adapters, &bufLen);
    if (ret != NO_ERROR) {
        free(adapters);
        return false;
    }

    for (PIP_ADAPTER_ADDRESSES aa = adapters; aa; aa = aa->Next) {
        std::string name;
        if (aa->FriendlyName) {
            name = std::string(aa->FriendlyName,
                               aa->FriendlyName + wcslen(aa->FriendlyName));
        }
        if (name != physical_nic_) continue;

        phys_if_index_ = aa->IfIndex;

        ULONG routeLen = 15000;
        PMIB_IPFORWARDTABLE routes = (PMIB_IPFORWARDTABLE)malloc(routeLen);
        if (!routes) break;

        ret = GetIpForwardTable(routes, &routeLen, TRUE);
        if (ret == NO_ERROR) {
            for (DWORD i = 0; i < routes->dwNumEntries; i++) {
                auto& r = routes->table[i];
                if (r.dwForwardIfIndex == phys_if_index_ &&
                    r.dwForwardDest == 0 &&
                    r.dwForwardMask == 0) {
                    sockaddr_in sa;
                    sa.sin_addr.S_un.S_addr = r.dwForwardNextHop;
                    char ip[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &sa.sin_addr, ip, sizeof(ip));
                    phys_gateway_ = ip;
                    log("physical gateway = " + phys_gateway_);
                    free(routes);
                    free(adapters);
                    return true;
                }
            }
        }
        free(routes);
        break;
    }

    free(adapters);
    return false;
}

bool TunManager::start(const std::string& tun2socks_path,
                       const std::string& proxy_port,
                       const std::string& physical_nic,
                       const std::string& tun_dns,
                       const std::string& server_addr)
{
    if (running_) {
        stop();
    }

    tun2socks_path_ = tun2socks_path;
    proxy_port_ = proxy_port;
    physical_nic_ = physical_nic;
    tun_dns_ = tun_dns.empty() ? "8.8.8.8" : tun_dns;
    server_addr_ = server_addr;

    if (!findPhysicalGateway()) {
        log("ERROR: cannot find gateway for NIC: " + physical_nic_);
        return false;
    }

    std::string args = "--device wintun --proxy socks5://127.0.0.1:" + proxy_port_ +
                       " --interface " + physical_nic_ + " --loglevel info";

    SHELLEXECUTEINFOA sei = {};
    sei.cbSize = sizeof(sei);
    sei.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_FLAG_NO_UI;
    sei.lpVerb = "open";
    sei.lpFile = tun2socks_path_.c_str();
    sei.lpParameters = args.c_str();
    sei.nShow = SW_HIDE;

    log("starting: " + tun2socks_path_ + " " + args);

    if (!ShellExecuteExA(&sei)) {
        DWORD err = GetLastError();
        if (err == ERROR_CANCELLED) {
            log("ERROR: UAC elevation denied by user");
        } else {
            log("ERROR: ShellExecuteEx failed, code=" + std::to_string(err));
        }
        return false;
    }

    hProcess_ = sei.hProcess;
    running_ = true;
    retryCount_ = 0;

    auto* poll = new QTimer();
    QObject::connect(poll, &QTimer::timeout, [this, poll]() {
        if (!hProcess_) {
            poll->stop();
            poll->deleteLater();
            pollTimer_ = nullptr;
            return;
        }
        DWORD exitCode = 0;
        if (GetExitCodeProcess(hProcess_, &exitCode) && exitCode != STILL_ACTIVE) {
            log("tun2socks exited with code " + std::to_string(exitCode));
            poll->stop();
            poll->deleteLater();
            pollTimer_ = nullptr;
            running_ = false;
        }
    });
    pollTimer_ = poll;
    poll->start(2000);

    auto* timer = new QTimer();
    QObject::connect(timer, &QTimer::timeout, [this, timer]() {
        retryCount_++;
        if (findTunAdapter()) {
            timer->stop();
            timer->deleteLater();
            waitTimer_ = nullptr;
            if (!configureRoutes()) {
                log("ERROR: failed to configure routes");
                stop();
            }
        } else if (retryCount_ >= 30) {
            timer->stop();
            timer->deleteLater();
            waitTimer_ = nullptr;
            log("ERROR: TUN adapter not found after 15s");
            stop();
        }
    });
    waitTimer_ = timer;
    timer->start(500);

    return true;
}

void TunManager::stop()
{
    if (waitTimer_) {
        auto* timer = static_cast<QTimer*>(waitTimer_);
        timer->stop();
        timer->deleteLater();
        waitTimer_ = nullptr;
    }

    if (pollTimer_) {
        auto* timer = static_cast<QTimer*>(pollTimer_);
        timer->stop();
        timer->deleteLater();
        pollTimer_ = nullptr;
    }

    if (running_) {
        cleanupRoutes();
    }

    if (hProcess_) {
        log("stopping tun2socks");
        TerminateProcess(hProcess_, 0);
        WaitForSingleObject(hProcess_, 3000);
        CloseHandle(hProcess_);
        hProcess_ = nullptr;
    }

    running_ = false;
    tun_if_index_ = 0;
    log("stopped");
}

static DWORD addRoute(const char* dest, const char* mask,
                      const char* nexthop, DWORD ifIndex, DWORD metric)
{
    MIB_IPFORWARDROW row = {};
    row.dwForwardDest = inet_addr(dest);
    row.dwForwardMask = inet_addr(mask);
    row.dwForwardPolicy = 0;
    row.dwForwardNextHop = inet_addr(nexthop);
    row.dwForwardIfIndex = ifIndex;
    row.dwForwardType = (row.dwForwardNextHop == 0)
        ? MIB_IPROUTE_TYPE_DIRECT : MIB_IPROUTE_TYPE_INDIRECT;
    row.dwForwardProto = MIB_IPPROTO_NETMGMT;
    row.dwForwardMetric1 = metric;
    return CreateIpForwardEntry(&row);
}

static DWORD delRoute(const char* dest, const char* mask,
                      const char* nexthop, DWORD ifIndex)
{
    MIB_IPFORWARDROW row = {};
    row.dwForwardDest = inet_addr(dest);
    row.dwForwardMask = inet_addr(mask);
    row.dwForwardPolicy = 0;
    row.dwForwardNextHop = inet_addr(nexthop);
    row.dwForwardIfIndex = ifIndex;
    row.dwForwardType = MIB_IPROUTE_TYPE_INDIRECT;
    row.dwForwardProto = MIB_IPPROTO_NETMGMT;
    return DeleteIpForwardEntry(&row);
}

bool TunManager::configureRoutes()
{
    if (tun_if_index_ <= 0 || tun_addr_.empty()) return false;

    bool ok = true;
    DWORD ret;

    ret = addRoute("0.0.0.0", "0.0.0.0", tun_addr_.c_str(), tun_if_index_, 2);
    log("add default route 0.0.0.0/0 -> " + tun_addr_ +
        " ret=" + std::to_string(ret));
    if (ret != NO_ERROR) ok = false;

    ret = addRoute(server_addr_.c_str(), "255.255.255.255",
                   phys_gateway_.c_str(), phys_if_index_, 5);
    log("add bypass route " + server_addr_ + "/32 -> " + phys_gateway_ +
        " ret=" + std::to_string(ret));
    if (ret != NO_ERROR) ok = false;

    return ok;
}

void TunManager::cleanupRoutes()
{
    if (tun_if_index_ <= 0) return;

    delRoute("0.0.0.0", "0.0.0.0", tun_addr_.c_str(), tun_if_index_);
    delRoute(server_addr_.c_str(), "255.255.255.255",
             phys_gateway_.c_str(), phys_if_index_);

    log("routes cleaned up");
}
