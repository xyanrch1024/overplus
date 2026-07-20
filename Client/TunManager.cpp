#include "TunManager.h"

#ifdef _WIN32

#include "Shared/Log.h"
#include <QProcess>
#include <QTimer>

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>
#include <netioapi.h>

#pragma comment(lib, "iphlpapi.lib")

static void slotStdout(TunManager* self, QProcess* proc)
{
    QByteArray data = proc->readAllStandardOutput();
    std::string line(data.constData(), data.size());
    self->log("[tun2socks] " + line);
}

static void slotStderr(TunManager* self, QProcess* proc)
{
    QByteArray data = proc->readAllStandardError();
    std::string line(data.constData(), data.size());
    self->log("[tun2socks] " + line);
}

static void slotFinished(TunManager* self, int exitCode)
{
    self->log("tun2socks exited with code " + std::to_string(exitCode));
}

TunManager::TunManager()
{
}

TunManager::~TunManager()
{
    stop();
}

void TunManager::log(const std::string& msg)
{
    NOTICE_LOG << "TunManager: " << msg;
    if (logCb_) logCb_(msg);
}

int TunManager::findInterfaceIndex(const std::string& name)
{
    std::wstring wname(name.begin(), name.end());
    NET_LUID luid;
    if (ConvertInterfaceAliasToLuid(wname.c_str(), &luid) != NO_ERROR)
        return 0;

    NET_IFINDEX idx = 0;
    if (ConvertInterfaceLuidToIndex(&luid, &idx) != NO_ERROR)
        return 0;

    return static_cast<int>(idx);
}

int TunManager::findTunInterfaceIndex()
{
    std::string output;
    std::string cmd = "(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | "
                      "Where-Object { $_.IPAddress -like '169.254.*' }).InterfaceIndex";
    if (!executePowerShell(cmd, output)) return 0;

    size_t start = output.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return 0;
    size_t end = output.find_last_not_of(" \t\r\n");
    std::string token = output.substr(start, end - start + 1);
    try { return std::stoi(token); }
    catch (...) { return 0; }
}

bool TunManager::findPhysicalGateway()
{
    std::string output;
    std::string cmd = "(Get-NetRoute -InterfaceAlias '" + physical_nic_ +
                      "' -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue).NextHop";
    if (!executePowerShell(cmd, output)) return false;

    size_t start = output.find_first_not_of(" \t\r\n");
    size_t end = output.find_last_not_of(" \t\r\n");
    if (start == std::string::npos) return false;
    phys_gateway_ = output.substr(start, end - start + 1);
    log("physical gateway = " + phys_gateway_);
    return !phys_gateway_.empty();
}

bool TunManager::executePowerShell(const std::string& cmd, std::string& output)
{
    std::string full = "powershell -NoProfile -Command \"" + cmd + "\"";
    FILE* pipe = _popen(full.c_str(), "r");
    if (!pipe) return false;

    char buf[512];
    while (fgets(buf, sizeof(buf), pipe))
        output += buf;
    _pclose(pipe);
    return true;
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

    phys_if_index_ = findInterfaceIndex(physical_nic_);
    if (phys_if_index_ == 0) {
        log("ERROR: cannot find physical NIC: " + physical_nic_);
        return false;
    }
    log("physical NIC " + physical_nic_ + " index=" + std::to_string(phys_if_index_));

    if (!findPhysicalGateway()) {
        log("ERROR: cannot find gateway for NIC: " + physical_nic_);
        return false;
    }

    auto* proc = new QProcess();
    QObject::connect(proc, &QProcess::readyReadStandardOutput,
        [this, proc]() { slotStdout(this, proc); });
    QObject::connect(proc, &QProcess::readyReadStandardError,
        [this, proc]() { slotStderr(this, proc); });
    QObject::connect(proc, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
        [this](int ec) { slotFinished(this, ec); });

    process_ = proc;

    QString exe = QString::fromStdString(tun2socks_path_);
    QStringList args;
    args << "--device" << "wintun"
         << "--proxy" << QString("socks5://127.0.0.1:%1").arg(QString::fromStdString(proxy_port_))
         << "--interface" << QString::fromStdString(physical_nic_)
         << "--loglevel" << "info";

    log("starting " + exe.toStdString() + " " + args.join(" ").toStdString());
    proc->start(exe, args);

    if (!proc->waitForStarted(5000)) {
        log("ERROR: failed to start tun2socks");
        delete proc;
        process_ = nullptr;
        return false;
    }

    running_ = true;

    auto* timer = new QTimer();
    QObject::connect(timer, &QTimer::timeout, [this, timer]() {
        tun_if_index_ = findTunInterfaceIndex();
        if (tun_if_index_ > 0) {
            timer->stop();
            timer->deleteLater();
            waitTimer_ = nullptr;
            log("TUN interface found, index=" + std::to_string(tun_if_index_));
            if (!configureRoutes()) {
                log("ERROR: failed to configure routes");
                stop();
            }
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

    if (running_) {
        cleanupRoutes();
    }

    if (process_) {
        auto* proc = static_cast<QProcess*>(process_);
        if (proc->state() != QProcess::NotRunning) {
            log("stopping tun2socks");
            proc->kill();
            proc->waitForFinished(3000);
        }
        delete proc;
        process_ = nullptr;
    }

    running_ = false;
    tun_if_index_ = 0;
    log("stopped");
}

bool TunManager::configureRoutes()
{
    if (tun_if_index_ <= 0) return false;

    std::string cmd;
    std::string output;

    std::string proxy_server = server_addr_ + "/32";

    cmd = "New-NetRoute -DestinationPrefix '0.0.0.0/0' -NextHop '" + tun_addr_ +
          "' -InterfaceIndex " + std::to_string(tun_if_index_) +
          " -RouteMetric 2 -ErrorAction SilentlyContinue";
    executePowerShell(cmd, output);
    log("add default route -> " + output);
    output.clear();

    cmd = "New-NetRoute -DestinationPrefix '" + proxy_server +
          "' -NextHop '" + phys_gateway_ +
          "' -InterfaceIndex " + std::to_string(phys_if_index_) +
          " -RouteMetric 5 -ErrorAction SilentlyContinue";
    executePowerShell(cmd, output);
    log("add bypass route -> " + output);
    output.clear();

    cmd = "Set-DnsClientServerAddress -InterfaceIndex " + std::to_string(tun_if_index_) +
          " -ServerAddresses '" + tun_dns_ + "' -ErrorAction SilentlyContinue";
    executePowerShell(cmd, output);
    log("set DNS -> " + output);
    output.clear();

    return true;
}

void TunManager::cleanupRoutes()
{
    if (tun_if_index_ <= 0) return;

    std::string output;

    executePowerShell(
        "Remove-NetRoute -DestinationPrefix '0.0.0.0/0' -InterfaceIndex " +
        std::to_string(tun_if_index_) + " -Confirm:$false -ErrorAction SilentlyContinue", output);

    executePowerShell(
        "Remove-NetRoute -DestinationPrefix '" + server_addr_ + "/32'" +
        " -InterfaceIndex " + std::to_string(phys_if_index_) +
        " -Confirm:$false -ErrorAction SilentlyContinue", output);

    executePowerShell(
        "Set-DnsClientServerAddress -InterfaceIndex " + std::to_string(tun_if_index_) +
        " -ResetServerAddresses -ErrorAction SilentlyContinue", output);

    log("routes cleaned up");
}

#endif
