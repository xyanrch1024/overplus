#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QDockWidget>
#include <QPlainTextEdit>
#include <QSystemTrayIcon>
#include <QCloseEvent>
#include <QMenu>
#include <QTimer>
#include <chrono>
#include "Server.h"

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
    void onPing();
    void onToggleLog();
    void onTrayActivated(QSystemTrayIcon::ActivationReason reason);
    void onShowWindow();
    void onQuit();
    void appendLog(const QString& line);
    void updateStats();
    void updateDuration();
    void autoSave();
    void onAbout();
private:
    Ui::MainWindow *ui;
    QDockWidget* logDock;
    QPlainTextEdit* logView;
    Server& server;
    QSystemTrayIcon* trayIcon;
    QMenu* trayMenu;
    QTimer* statsTimer;
    std::chrono::steady_clock::time_point connectTime_;
};
#endif // MAINWINDOW_H
