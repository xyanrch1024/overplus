#pragma once

#include <QWidget>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QMouseEvent>
#include <QPaintEvent>
#include <QCloseEvent>
#include <QShowEvent>
#include <QEvent>

class LogPanel : public QWidget {
    Q_OBJECT
public:
    explicit LogPanel(QWidget* parent);
    void appendLog(const QString& line);
    void toggle();
    bool isLogVisible() const { return visible_; }

protected:
    void mousePressEvent(QMouseEvent* event) override;
    void mouseMoveEvent(QMouseEvent* event) override;
    void mouseReleaseEvent(QMouseEvent* event) override;
    void paintEvent(QPaintEvent* event) override;
    void closeEvent(QCloseEvent* event) override;
    void resizeEvent(QResizeEvent* event) override;
    bool eventFilter(QObject* obj, QEvent* event) override;

private:
    void snapToParent();
    bool inTitleBar(const QPoint& pos) const;

    QPlainTextEdit* view_;
    QPushButton* closeBtn_;
    bool dragging_ = false;
    bool snapped_ = true;
    bool visible_ = false;
    QPoint dragOffset_;

    static constexpr int WIDTH = 420;
    static constexpr int TITLE_HEIGHT = 28;
    static constexpr int SNAP_THRESHOLD = 30;
};
