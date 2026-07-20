#include "mainwindow.h"
#include "./ui_mainwindow.h"
#include <QMessageBox>
#include <QApplication>
#include <QPainter>
#include <QPixmap>
#include <QStyle>
#include "Shared/ConfigManage.h"
#include "Shared/Version.h"
#include "Shared/Log.h"
#include "Shared/LogFile.h"
#include "Shared/ProxyStats.h"
#ifdef _WIN32
#include "TunManager.h"
#endif
#include <QFileDialog>
#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/asio.hpp>
#include <chrono>
#include <thread>

static const QString ARROW_UP = QString::fromUtf8("\xe2\x86\x91");
static const QString ARROW_DOWN = QString::fromUtf8("\xe2\x86\x93");

static QString formatSpeed(uint64_t bytes_per_second) {
    uint64_t bits = bytes_per_second * 8;
    if (bits < 1000)
        return QString("%1 bps").arg(bits);
    else if (bits < 1000000)
        return QString("%1 Kbps").arg(bits / 1000.0, 0, 'f', 1);
    else
        return QString("%1 Mbps").arg(bits / 1000000.0, 0, 'f', 2);
}

static QString formatTotal(uint64_t bytes) {
    if (bytes < 1024ULL)
        return QString("%1 B").arg(bytes);
    else if (bytes < 1024ULL * 1024)
        return QString("%1 KB").arg(bytes / 1024.0, 0, 'f', 1);
    else if (bytes < 1024ULL * 1024 * 1024)
        return QString("%1 MB").arg(bytes / (1024.0 * 1024), 0, 'f', 1);
    else
        return QString("%1 GB").arg(bytes / (1024.0 * 1024 * 1024), 0, 'f', 2);
}

static QString formatDuration(int64_t seconds) {
    if (seconds < 60)
        return QString("%1s").arg(seconds);
    else if (seconds < 3600)
        return QString("%1m %2s").arg(seconds / 60).arg(seconds % 60);
    else if (seconds < 86400)
        return QString("%1h %2m").arg(seconds / 3600).arg((seconds % 3600) / 60);
    else
        return QString("%1d %2h").arg(seconds / 86400).arg((seconds % 86400) / 3600);
}

static QIcon createTrayIcon(const QColor& bg)
{
    QPixmap pix(64, 64);
    pix.fill(Qt::transparent);
    QPainter p(&pix);
    p.setRenderHint(QPainter::Antialiasing);
    p.setBrush(bg);
    p.setPen(Qt::NoPen);
    p.drawRoundedRect(4, 4, 56, 56, 8, 8);
    p.setPen(QPen(Qt::white, 2));
    p.setFont(QFont("Segoe UI", 28, QFont::Bold));
    p.drawText(pix.rect(), Qt::AlignCenter, "O");
    p.end();
    return QIcon(pix);
}

extern LogFile* g_logfile;

MainWindow::MainWindow(Server&s,QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
    ,server(s)
{

    ui->setupUi(this);
    setWindowTitle(QString("Overplus %1").arg(OVERPLUS_VERSION_STR));
    QApplication::setQuitOnLastWindowClosed(false);

    ui->DISCONNECT_BUTTON->setEnabled(false);

    trayIcon = new QSystemTrayIcon(this);
    trayIcon->setIcon(createTrayIcon(QColor(180, 0, 0)));
    trayIcon->setToolTip("overplus");
    trayIcon->setVisible(true);

    trayMenu = new QMenu(this);
    QAction* showAction = trayMenu->addAction("Show");
    QAction* quitAction = trayMenu->addAction("Quit");
    trayIcon->setContextMenu(trayMenu);

    connect(ui->CONNECT_BUTTON, SIGNAL(clicked()), this, SLOT(onConnect()));
    connect(ui->DISCONNECT_BUTTON, SIGNAL(clicked()), this, SLOT(onDisconnect()));
    connect(ui->PING_BUTTON, SIGNAL(clicked()), this, SLOT(onPing()));
    connect(ui->TUN_CHECKBOX, SIGNAL(toggled(bool)), this, SLOT(onTunCheckboxToggled(bool)));
    connect(ui->TUN_BROWSE_BUTTON, SIGNAL(clicked()), this, SLOT(onBrowseTun2socks()));
    connect(ui->LOG_BUTTON, SIGNAL(clicked()), this, SLOT(onToggleLog()));
    connect(ui->checkBox, SIGNAL(clicked()), this, SLOT(onCheckBoxClick()));
    connect(showAction, SIGNAL(triggered()), this, SLOT(onShowWindow()));
    connect(quitAction, SIGNAL(triggered()), this, SLOT(onQuit()));
    connect(trayIcon, SIGNAL(activated(QSystemTrayIcon::ActivationReason)), this, SLOT(onTrayActivated(QSystemTrayIcon::ActivationReason)));

    QMenu* helpMenu = ui->menubar->addMenu("Help");
    QAction* aboutAction = helpMenu->addAction("About");
    connect(aboutAction, SIGNAL(triggered()), this, SLOT(onAbout()));

    if(ConfigManage::instance().loaded)
    {    auto& config = ConfigManage::instance().client_cfg;
         ui->HOST_NAME->setText(QString::fromStdString(config.remote_addr));
         ui->HOST_PORT->setText(QString::fromStdString(config.remote_port));
         ui->HOST_PASSWD->setText(QString::fromStdString(config.text_password));
         ui->LOCAL_PORT->setText(QString::fromStdString(config.local_port.empty() ? "1080" : config.local_port));
         ui->DTLS_PORT->setText(QString::fromStdString(config.dtls_port.empty() ? "8443" : config.dtls_port));
         ui->UDP_CHECKBOX->setChecked(config.udp_enabled);
         ui->TUN_CHECKBOX->setChecked(config.tun2socks_enabled);
         ui->TUN_PATH->setText(QString::fromStdString(config.tun2socks_path));
         ui->TUN_NIC->setText(QString::fromStdString(config.tun_interface));
         ui->TUN_DNS->setText(QString::fromStdString(config.tun_dns));
         onTunCheckboxToggled(config.tun2socks_enabled);
    }
    statusBar()->showMessage(QString("Overplus %1").arg(OVERPLUS_VERSION_STR));

    logger::setOutput([this](std::string&& buf) {
        QString line = QString::fromUtf8(buf.c_str(), buf.size()).trimmed();
        if (g_logfile) {
            g_logfile->append(std::move(buf));
        }
        if (!line.isEmpty()) {
            QMetaObject::invokeMethod(this, [this, line]() {
                appendLog(line);
            }, Qt::QueuedConnection);
        }
    });

    statsTimer = new QTimer(this);
    connect(statsTimer, &QTimer::timeout, this, &MainWindow::updateStats);
    statsTimer->start(1000);

#ifdef _WIN32
    tunManager_ = new TunManager();
    tunManager_->setLogCallback([this](const std::string& msg) {
        QMetaObject::invokeMethod(this, [this, msg]() {
            appendLog(QString::fromStdString(msg));
        }, Qt::QueuedConnection);
    });
#endif
}

MainWindow::~MainWindow()
{
#ifdef _WIN32
    delete tunManager_;
#endif
    delete ui;
}

void MainWindow::appendLog(const QString& line)
{
    ui->LOG_VIEW->appendPlainText(line);
}

void MainWindow::updateDuration()
{
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now() - connectTime_).count();
    ui->DURATION_LABEL->setText(formatDuration(elapsed));
}

void MainWindow::autoSave()
{
    auto& config = ConfigManage::instance().client_cfg;
    config.remote_addr = ui->HOST_NAME->text().toStdString();
    config.remote_port = ui->HOST_PORT->text().toStdString();
    config.setPassword(ui->HOST_PASSWD->text().toStdString());
    config.local_port = ui->LOCAL_PORT->text().toStdString();
    config.dtls_port = ui->DTLS_PORT->text().toStdString();
    config.udp_enabled = ui->UDP_CHECKBOX->isChecked();
    config.tun2socks_enabled = ui->TUN_CHECKBOX->isChecked();
    config.tun2socks_path = ui->TUN_PATH->text().toStdString();
    config.tun_interface = ui->TUN_NIC->text().toStdString();
    config.tun_dns = ui->TUN_DNS->text().toStdString();

    boost::property_tree::ptree tree;
    tree.put("run_type", "client");
    tree.put("local_addr", config.local_addr);
    tree.put("local_port", config.local_port);
    tree.put("remote_addr", config.remote_addr);
    tree.put("remote_port", config.remote_port);
    tree.put("user_name", config.user_name);
    tree.put("password", config.text_password);
    tree.put("udp_enabled", config.udp_enabled);
    tree.put("dtls_port", config.dtls_port);
    tree.put("tun2socks_enabled", config.tun2socks_enabled);
    tree.put("tun2socks_path", config.tun2socks_path);
    tree.put("tun_interface", config.tun_interface);
    tree.put("tun_dns", config.tun_dns);

    try {
        boost::property_tree::write_json("client.json", tree);
    } catch (const std::exception& e) {
        ERROR_LOG << "auto save config failed: " << e.what();
    }
}

void MainWindow::updateStats()
{
    auto [up, down] = ProxyStats::instance().getAndResetDelta();
    ui->UPLOAD_LABEL->setText(ARROW_UP + " " + formatSpeed(up));
    ui->DOWNLOAD_LABEL->setText(ARROW_DOWN + " " + formatSpeed(down));

    auto [total_up, total_down] = ProxyStats::instance().getTotal();
    ui->TOTAL_LABEL->setText(ARROW_UP + " " + formatTotal(total_up) + "  " + ARROW_DOWN + " " + formatTotal(total_down));

    ui->SESSIONS_LABEL->setText(QString::number(ProxyStats::instance().sessionCount()));

    updateDuration();
}

void MainWindow::onConnect()
{
    ui->CONNECT_BUTTON->setEnabled(false);
    ui->DISCONNECT_BUTTON->setEnabled(true);
    ui->CONNECTION_STATUS->setText("CONNECTED");
    ui->CONNECTION_STATUS->setStyleSheet("color: green; font-weight: bold;");
    trayIcon->setIcon(createTrayIcon(QColor(0, 180, 0)));

    auto& config = ConfigManage::instance().client_cfg;
    config.remote_addr = ui->HOST_NAME->text().toStdString();
    config.remote_port = ui->HOST_PORT->text().toStdString();
    config.local_port = ui->LOCAL_PORT->text().toStdString();
    config.dtls_port = ui->DTLS_PORT->text().toStdString();
    config.udp_enabled = ui->UDP_CHECKBOX->isChecked();

    auto psswd = ui->HOST_PASSWD->text().toStdString();
    config.setPassword(psswd);
    NOTICE_LOG<<"Read config from user input:"<<config.remote_addr<<":"<< config.remote_port
              <<" dtls:"<<config.dtls_port<<" udp:"<<config.udp_enabled
              <<" tun2socks:"<<config.tun2socks_enabled;

    ui->UDP_STATUS->setText(config.udp_enabled ? "Active" : "Disabled");
    ui->UDP_STATUS->setStyleSheet(config.udp_enabled ?
        "color: green; font-weight: bold;" : "color: gray; font-weight: bold;");

    server.start_accept();
    connectTime_ = std::chrono::steady_clock::now();

#ifdef _WIN32
    if (config.tun2socks_enabled && !config.tun2socks_path.empty()) {
        NOTICE_LOG << "Starting tun2socks: " << config.tun2socks_path;
        if (!tunManager_->start(config.tun2socks_path,
                                config.local_port.empty() ? "1080" : config.local_port,
                                config.tun_interface.empty() ? "WLAN" : config.tun_interface,
                                config.tun_dns.empty() ? "8.8.8.8" : config.tun_dns,
                                config.remote_addr)) {
            ERROR_LOG << "Failed to start tun2socks";
            ui->CONNECTION_STATUS->setText("TUN FAILED");
            ui->CONNECTION_STATUS->setStyleSheet("color: red; font-weight: bold;");
        }
    }
#endif
}

void MainWindow::onDisconnect()
{
#ifdef _WIN32
    if (tunManager_ && tunManager_->isRunning()) {
        tunManager_->stop();
    }
#endif
    server.stop_accept();
    ui->CONNECT_BUTTON->setEnabled(true);
    ui->DISCONNECT_BUTTON->setEnabled(false);
    ui->CONNECTION_STATUS->setText("DISCONNECTED");
    ui->CONNECTION_STATUS->setStyleSheet("color: red; font-weight: bold;");
    ui->UDP_STATUS->setText("--");
    ui->UDP_STATUS->setStyleSheet("color: gray; font-weight: bold;");
    ui->DURATION_LABEL->setText("--");
    trayIcon->setIcon(createTrayIcon(QColor(180, 0, 0)));
}

void MainWindow::onPing()
{
    auto& config = ConfigManage::instance().client_cfg;
    std::string addr = ui->HOST_NAME->text().toStdString();
    std::string port = ui->HOST_PORT->text().toStdString();

    if (addr.empty() || port.empty()) {
        ui->LATENCY_LABEL->setText("N/A");
        return;
    }

    ui->PING_BUTTON->setEnabled(false);
    ui->LATENCY_LABEL->setText("Testing...");

    auto ioc = std::make_shared<boost::asio::io_context>();
    auto socket = std::make_shared<boost::asio::ip::tcp::socket>(*ioc);
    auto resolver = std::make_shared<boost::asio::ip::tcp::resolver>(*ioc);

    auto start = std::chrono::steady_clock::now();

    resolver->async_resolve(addr, port,
        [socket, resolver, start, ioc, this](
            const boost::system::error_code& ec, boost::asio::ip::tcp::resolver::results_type results) {
            if (ec || results.empty()) {
                QMetaObject::invokeMethod(this, [this]() {
                    ui->LATENCY_LABEL->setText("Failed");
                    ui->LATENCY_LABEL->setStyleSheet("color: red; font-weight: bold;");
                    ui->PING_BUTTON->setEnabled(true);
                }, Qt::QueuedConnection);
                return;
            }
            socket->async_connect(*results.begin(),
                [socket, start, ioc, this](
                    const boost::system::error_code& ec) {
                    auto end = std::chrono::steady_clock::now();
                    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

                    if (ec) {
                        QMetaObject::invokeMethod(this, [this]() {
                            ui->LATENCY_LABEL->setText("Timeout");
                            ui->LATENCY_LABEL->setStyleSheet("color: red; font-weight: bold;");
                            ui->PING_BUTTON->setEnabled(true);
                        }, Qt::QueuedConnection);
                    } else {
                        QMetaObject::invokeMethod(this, [this, ms]() {
                            QString text = QString("%1 ms").arg(ms);
                            QColor color = ms < 100 ? QColor(0, 150, 0) :
                                           ms < 300 ? QColor(180, 120, 0) :
                                           QColor(200, 0, 0);
                            ui->LATENCY_LABEL->setText(text);
                            ui->LATENCY_LABEL->setStyleSheet(
                                QString("color: %1; font-weight: bold;").arg(color.name()));
                            ui->PING_BUTTON->setEnabled(true);
                        }, Qt::QueuedConnection);
                        boost::system::error_code sec;
                        socket->shutdown(boost::asio::ip::tcp::socket::shutdown_both, sec);
                    }
                });
        });

    std::thread([ioc]() { ioc->run(); }).detach();
}

void MainWindow::onToggleLog()
{
    bool visible = ui->LOG_VIEW->isVisible();
    ui->LOG_VIEW->setVisible(!visible);
}

void MainWindow::onCheckBoxClick(){
    ui->HOST_PASSWD->setEchoMode(ui->checkBox->checkState() == Qt::Checked ? QLineEdit::Normal : QLineEdit::Password );
}

void MainWindow::closeEvent(QCloseEvent* event)
{
    autoSave();
    hide();
    event->ignore();
}

void MainWindow::onTrayActivated(QSystemTrayIcon::ActivationReason reason)
{
    if (reason == QSystemTrayIcon::DoubleClick) {
        onShowWindow();
    }
}

void MainWindow::onShowWindow()
{
    showNormal();
    activateWindow();
    raise();
}

void MainWindow::onQuit()
{
    trayIcon->setVisible(false);
    QApplication::quit();
}

void MainWindow::onAbout()
{
    QMessageBox::about(this, "About Overplus",
        QString("<h3>Overplus %1</h3>"
                "<p>Author: xyanrch / xyanrch1024</p>")
        .arg(OVERPLUS_VERSION_STR));
}

void MainWindow::onBrowseTun2socks()
{
    QString file = QFileDialog::getOpenFileName(this,
        "Select tun2socks executable", "",
        "Executable (*.exe);;All Files (*)");
    if (!file.isEmpty()) {
        ui->TUN_PATH->setText(file);
    }
}

void MainWindow::onTunCheckboxToggled(bool checked)
{
    ui->TUN_PATH->setEnabled(checked);
    ui->TUN_BROWSE_BUTTON->setEnabled(checked);
    ui->TUN_NIC->setEnabled(checked);
    ui->TUN_DNS->setEnabled(checked);
}
