#include "mainwindow.h"
#include "./ui_mainwindow.h"
#include<QMessageBox>
#include <QApplication>
#include <QPainter>
#include <QPixmap>
#include <QStyle>
#include "Shared/ConfigManage.h"
#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/ptree.hpp>

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

MainWindow::MainWindow(Server&s,QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
    ,server(s)
{

    ui->setupUi(this);
    setWindowTitle("overplus");
    QApplication::setQuitOnLastWindowClosed(false);

    trayIcon = new QSystemTrayIcon(this);
    trayIcon->setIcon(createTrayIcon(QColor(180, 0, 0)));
    trayIcon->setToolTip("overplus");
    trayIcon->setVisible(true);

    trayMenu = new QMenu(this);
    QAction* showAction = trayMenu->addAction("Show");
    QAction* quitAction = trayMenu->addAction("Quit");
    trayIcon->setContextMenu(trayMenu);

    connect(ui->SAVE_BUTTON, SIGNAL(clicked()), this, SLOT(onSave()));
    connect(ui->CONNECT_BUTTON, SIGNAL(clicked()), this, SLOT(onConnect()));
    connect(ui->DISCONNECT_BUTTON, SIGNAL(clicked()), this, SLOT(onDisconnect()));
    connect(ui->checkBox, SIGNAL(clicked()), this, SLOT(onCheckBoxClick()));
    connect(showAction, SIGNAL(triggered()), this, SLOT(onShowWindow()));
    connect(quitAction, SIGNAL(triggered()), this, SLOT(onQuit()));
    connect(trayIcon, SIGNAL(activated(QSystemTrayIcon::ActivationReason)), this, SLOT(onTrayActivated(QSystemTrayIcon::ActivationReason)));

    if(ConfigManage::instance().loaded)
    {    auto& config = ConfigManage::instance().client_cfg;
         ui->HOST_NAME->setText(QString::fromStdString(config.remote_addr));
         ui->HOST_PORT->setText(QString::fromStdString(config.remote_port));
         ui->HOST_PASSWD->setText(QString::fromStdString(config.text_password));
    }


}

MainWindow::~MainWindow()
{

    delete ui;

}
 void MainWindow::onConnect()
 {

     ui->CONNECT_BUTTON->setEnabled(false);
     ui->DISCONNECT_BUTTON->setEnabled(true);
    ui->CONNECTION_STATUS->setText("CONNECTED");
    trayIcon->setIcon(createTrayIcon(QColor(0, 180, 0)));

    auto& config = ConfigManage::instance().client_cfg;
    config.remote_addr = ui->HOST_NAME->text().toStdString();
    config.remote_port = ui->HOST_PORT->text().toStdString();

    auto psswd = ui->HOST_PASSWD->text().toStdString();
    config.setPassword(psswd);
    NOTICE_LOG<<"Read config frome user input:"<<config.remote_addr<<":"<< config.remote_port<<" password:"<<psswd;

    //config.password = ui->
    server.start_accept();



 }

 void MainWindow::onDisconnect()
 {
     server.stop_accept();
      ui->CONNECT_BUTTON->setEnabled(true);
      ui->DISCONNECT_BUTTON->setEnabled(false);
      ui->CONNECTION_STATUS->setText("DISCONNECTED");
      trayIcon->setIcon(createTrayIcon(QColor(180, 0, 0)));

 }
 void MainWindow::onCheckBoxClick(){

      ui->HOST_PASSWD->setEchoMode(ui->checkBox->checkState() == Qt::Checked ? QLineEdit::Normal : QLineEdit::Password );
 }

 void MainWindow::onSave()
 {
     auto& config = ConfigManage::instance().client_cfg;
     config.remote_addr = ui->HOST_NAME->text().toStdString();
     config.remote_port = ui->HOST_PORT->text().toStdString();
     config.setPassword(ui->HOST_PASSWD->text().toStdString());

     boost::property_tree::ptree tree;
     tree.put("run_type", "client");
     tree.put("local_addr", config.local_addr);
     tree.put("local_port", config.local_port);
     tree.put("remote_addr", config.remote_addr);
     tree.put("remote_port", config.remote_port);
     tree.put("user_name", config.user_name);
     tree.put("password", config.text_password);

     try {
         boost::property_tree::write_json("client.json", tree);
         NOTICE_LOG << "config saved to client.json";
     } catch (const std::exception& e) {
         ERROR_LOG << "save config failed: " << e.what();
     }
 }

 void MainWindow::closeEvent(QCloseEvent* event)
 {
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


