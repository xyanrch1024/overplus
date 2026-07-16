#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QSystemTrayIcon>
#include <QCloseEvent>
#include <QMenu>
#include"Server.h"

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(Server&s,QWidget *parent = nullptr);
    ~MainWindow();
protected:
    void closeEvent(QCloseEvent* event) override;
public slots:
    void onConnect();
    void onDisconnect();
    void onCheckBoxClick();
    void onSave();
    void onTrayActivated(QSystemTrayIcon::ActivationReason reason);
    void onShowWindow();
    void onQuit();
private:
    Ui::MainWindow *ui;
    Server& server;
    QSystemTrayIcon* trayIcon;
    QMenu* trayMenu;
};
#endif // MAINWINDOW_H
