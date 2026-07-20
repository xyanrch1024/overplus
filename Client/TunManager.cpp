#include "TunManager.h"
#include "Shared/Log.h"

#ifdef _WIN32

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <QCoreApplication>

#pragma comment(lib, "iphlpapi.lib")

TunManager::TunManager(QObject* parent)
    : QObject(parent)
{
}

TunManager::~TunManager()
{
    stop();
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

    // trim whitespace
    size_t start = output.find_first_not_of(" \t\r\n");
    size_t end = output.find_last_not_of(" \t\r\n");
    if (start == std::string::npos) return false;
    phys_gateway_ = output.substr(start, end - start + 1);
    NOTICE_LOG << "TunManager: physical gateway = " << phys_gateway_;
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
        ERROR_LOG << "TunManager: cannot find physical NIC: " << physical_nic_;
        return false;
    }
    NOTICE_LOG << "TunManager: physical NIC " << physical_nic_ << " index=" << phys_if_index_;

    if (!findPhysicalGateway()) {
        ERROR_LOG << "TunManager: cannot find gateway for NIC: " << physical_nic_;
        return false;
    }

    process_ = new QProcess(this);
    connect(process_, &QProcess::readyReadStandardOutput, this, &TunManager::onProcessReadyReadStdout);
    connect(process_, &QProcess::readyReadStandardError, this, &TunManager::onProcessReadyReadStderr);
    connect(process_, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
            this, &TunManager::onProcessFinished);

    QString exe = QString::fromStdString(tun2socks_path_);
    QStringList args;
    args << "--device" << "wintun"
         << "--proxy" << QString("socks5://127.0.0.1:%1").arg(QString::fromStdString(proxy_port_))
         << "--interface" << QString::fromStdString(physical_nic_)
         << "--loglevel" << "info";

    NOTICE_LOG << "TunManager: starting " << exe.toStdString() << " " << args.join(" ").toStdString();
    process_->start(exe, args);

    if (!process_->waitForStarted(5000)) {
        ERROR_LOG << "TunManager: failed to start tun2socks";
        delete process_;
        process_ = nullptr;
        return false;
    }

    running_ = true;

    waitTimer_ = new QTimer(this);
    connect(waitTimer_, &QTimer::timeout, this, [this]() {
        tun_if_index_ = findTunInterfaceIndex();
        if (tun_if_index_ > 0) {
            waitTimer_->stop();
            waitTimer_->deleteLater();
            waitTimer_ = nullptr;
            NOTICE_LOG << "TunManager: TUN interface found, index=" << tun_if_index_;
            if (!configureRoutes()) {
                ERROR_LOG << "TunManager: failed to configure routes";
                stop();
            }
        }
    });
    waitTimer_->start(500);

    return true;
}

void TunManager::stop()
{
    if (waitTimer_) {
        waitTimer_->stop();
        waitTimer_->deleteLater();
        waitTimer_ = nullptr;
    }

    if (running_) {
        cleanupRoutes();
    }

    if (process_) {
        if (process_->state() != QProcess::NotRunning) {
            NOTICE_LOG << "TunManager: stopping tun2socks";
            process_->kill();
            process_->waitForFinished(3000);
        }
        delete process_;
        process_ = nullptr;
    }

    running_ = false;
    tun_if_index_ = 0;
    NOTICE_LOG << "TunManager: stopped";
}

void TunManager::onProcessReadyReadStdout()
{
    QByteArray data = process_->readAllStandardOutput();
    std::string line(data.constData(), data.size());
    NOTICE_LOG << "[tun2socks] " << line;
}

void TunManager::onProcessReadyReadStderr()
{
    QByteArray data = process_->readAllStandardError();
    std::string line(data.constData(), data.size());
    NOTICE_LOG << "[tun2socks] " << line;
}

void TunManager::onProcessFinished(int exitCode)
{
    NOTICE_LOG << "TunManager: tun2socks exited with code " << exitCode;
    running_ = false;
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
    NOTICE_LOG << "TunManager: add default route -> " << output;
    output.clear();

    cmd = "New-NetRoute -DestinationPrefix '" + proxy_server +
          "' -NextHop '" + phys_gateway_ +
          "' -InterfaceIndex " + std::to_string(phys_if_index_) +
          " -RouteMetric 5 -ErrorAction SilentlyContinue";
    executePowerShell(cmd, output);
    NOTICE_LOG << "TunManager: add bypass route -> " << output;
    output.clear();

    cmd = "Set-DnsClientServerAddress -InterfaceIndex " + std::to_string(tun_if_index_) +
          " -ServerAddresses '" + tun_dns_ + "' -ErrorAction SilentlyContinue";
    executePowerShell(cmd, output);
    NOTICE_LOG << "TunManager: set DNS -> " << output;
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

    NOTICE_LOG << "TunManager: routes cleaned up";
}

#endif
