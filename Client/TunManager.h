#pragma once
#include <string>
#include <functional>
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>

class TunManager {
public:
    TunManager();
    ~TunManager();

    bool start(const std::string& tun2socks_path,
               const std::string& proxy_port,
               const std::string& physical_nic,
               const std::string& tun_dns,
               const std::string& server_addr);

    void stop();
    bool isRunning() const { return running_; }

    void setLogCallback(std::function<void(const std::string&)> cb) { logCb_ = cb; }
    void log(const std::string& msg);

private:
    bool configureRoutes();
    void cleanupRoutes();
    int  findInterfaceIndex(const std::string& name);
    int  findTunInterfaceIndex();
    std::string findTunIPAddress();
    bool findPhysicalGateway();
    bool executePowerShell(const std::string& cmd, std::string& output);
    bool executePowerShellElevated(const std::string& ps1Content);

    HANDLE hProcess_ = nullptr;
    void* waitTimer_ = nullptr;
    void* pollTimer_ = nullptr;
    bool running_ = false;
    std::function<void(const std::string&)> logCb_;

    std::string tun2socks_path_;
    std::string proxy_port_;
    std::string physical_nic_;
    std::string tun_dns_;
    std::string server_addr_;
    std::string tun_addr_;

    int tun_if_index_ = 0;
    int phys_if_index_ = 0;
    std::string phys_gateway_;
};
