#pragma once
#include <string>
#include <cstdint>

#ifdef _WIN32
#include <QProcess>
#include <QObject>
#include <QTimer>

class TunManager : public QObject {
    Q_OBJECT
public:
    explicit TunManager(QObject* parent = nullptr);
    ~TunManager();

    bool start(const std::string& tun2socks_path,
               const std::string& proxy_port,
               const std::string& physical_nic,
               const std::string& tun_dns,
               const std::string& server_addr);

    void stop();

    bool isRunning() const { return running_; }

signals:
    void logMessage(const std::string& msg);

private slots:
    void onProcessReadyReadStdout();
    void onProcessReadyReadStderr();
    void onProcessFinished(int exitCode);

private:
    bool configureRoutes();
    void cleanupRoutes();
    int  findInterfaceIndex(const std::string& name);
    int  findTunInterfaceIndex();
    bool findPhysicalGateway();
    bool executePowerShell(const std::string& cmd, std::string& output);

    QProcess* process_ = nullptr;
    QTimer*   waitTimer_ = nullptr;
    bool running_ = false;

    std::string tun2socks_path_;
    std::string proxy_port_;
    std::string physical_nic_;
    std::string tun_dns_;
    std::string server_addr_;
    std::string tun_addr_ = "192.168.123.1";

    int tun_if_index_ = 0;
    int phys_if_index_ = 0;
    std::string phys_gateway_;
};

#else

class TunManager {
public:
    bool start(const std::string&, const std::string&,
               const std::string&, const std::string&,
               const std::string&) { return false; }
    void stop() {}
    bool isRunning() const { return false; }
};

#endif
