#pragma once

#include <QWidget>
#include <QPlainTextEdit>

class LogPanel : public QWidget {
    Q_OBJECT
public:
    explicit LogPanel(QWidget* parent);
    void appendLog(const QString& line);
    void toggle();

private:
    QPlainTextEdit* view_;
    static constexpr int MAX_HEIGHT = 300;
};
