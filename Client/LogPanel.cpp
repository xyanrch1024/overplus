#include "LogPanel.h"
#include <QPainter>
#include <QStyle>
#include <QStyleOption>

LogPanel::LogPanel(QWidget* parent)
    : QWidget(parent)
{
    setWindowFlags(Qt::FramelessWindowHint | Qt::Tool | Qt::WindowStaysOnTopHint);
    setFixedWidth(WIDTH);
    setMinimumHeight(120);
    setAttribute(Qt::WA_TranslucentBackground, false);
    setAttribute(Qt::WA_DeleteOnClose, false);

    closeBtn_ = new QPushButton(this);
    closeBtn_->setText(QStringLiteral("\u00d7"));
    closeBtn_->setFixedSize(22, 22);
    closeBtn_->setFocusPolicy(Qt::NoFocus);
    closeBtn_->setCursor(Qt::ArrowCursor);

    closeBtn_->setStyleSheet(
        "QPushButton { background: transparent; color: #888; font-size: 16px; font-weight: bold; border: none; }"
        "QPushButton:hover { color: #fff; background: #c44; border-radius: 3px; }"
    );
    connect(closeBtn_, &QPushButton::clicked, this, &LogPanel::toggle);

    view_ = new QPlainTextEdit(this);
    view_->setReadOnly(true);
    view_->setMaximumBlockCount(500);
    view_->setPlaceholderText("No log output yet");
    view_->setFont(QFont("Courier New", 9));
    view_->setFrameShape(QFrame::NoFrame);
    view_->setStyleSheet(
        "QPlainTextEdit { background: #1e1e1e; color: #d4d4d4; border: none; padding: 4px; }"
    );

    parent->installEventFilter(this);
}

void LogPanel::appendLog(const QString& line)
{
    view_->appendPlainText(line);
}

void LogPanel::toggle()
{
    if (visible_) {
        hide();
    } else {
        snapToParent();
        QWidget::show();
        visible_ = true;
    }
}

void LogPanel::closeEvent(QCloseEvent* event)
{
    hide();
    event->ignore();
}

void LogPanel::hide()
{
    QWidget::hide();
    visible_ = false;
}

bool LogPanel::inTitleBar(const QPoint& pos) const
{
    return pos.y() >= 0 && pos.y() < TITLE_HEIGHT;
}

void LogPanel::mousePressEvent(QMouseEvent* event)
{
    if (event->button() == Qt::LeftButton && inTitleBar(event->pos())) {
        dragging_ = true;
        dragOffset_ = event->globalPos() - frameGeometry().topLeft();
    }
}

void LogPanel::mouseMoveEvent(QMouseEvent* event)
{
    if (dragging_ && (event->buttons() & Qt::LeftButton)) {
        move(event->globalPos() - dragOffset_);
        QPoint pr = parentWidget()->mapToGlobal(QPoint(0, 0));
        QRect prRect(pr, parentWidget()->size());
        int rightEdge = prRect.right();
        int dx = qAbs(frameGeometry().left() - rightEdge);
        snapped_ = (dx < SNAP_THRESHOLD);
    }
}

void LogPanel::mouseReleaseEvent(QMouseEvent* event)
{
    if (dragging_) {
        dragging_ = false;
        QPoint pr = parentWidget()->mapToGlobal(QPoint(0, 0));
        QRect prRect(pr, parentWidget()->size());
        int rightEdge = prRect.right();
        int dx = qAbs(frameGeometry().left() - rightEdge);
        if (dx < SNAP_THRESHOLD) {
            snapToParent();
            snapped_ = true;
        }
    }
}

void LogPanel::resizeEvent(QResizeEvent* event)
{
    QWidget::resizeEvent(event);
    int bw = width();
    int bh = height();
    closeBtn_->move(bw - 26, 3);
    view_->setGeometry(1, TITLE_HEIGHT + 1, bw - 2, bh - TITLE_HEIGHT - 2);
}

void LogPanel::paintEvent(QPaintEvent*)
{
    QPainter p(this);
    int w = width();
    int h = height();

    // Border
    p.setPen(QPen(QColor("#555"), 1));
    p.setBrush(QColor("#252526"));
    p.drawRect(QRect(0, 0, w - 1, h - 1));

    // Title bar background
    p.fillRect(QRect(1, 1, w - 2, TITLE_HEIGHT), QColor("#2d2d2d"));

    // Bottom line of title bar
    p.setPen(QPen(QColor("#3c3c3c"), 1));
    p.drawLine(1, TITLE_HEIGHT, w - 2, TITLE_HEIGHT);

    // Title text
    p.setPen(QColor("#cccccc"));
    p.setFont(QFont("Segoe UI", 10, QFont::Bold));
    p.drawText(QRect(8, 1, w - 50, TITLE_HEIGHT), Qt::AlignVCenter, "Log");
}

bool LogPanel::eventFilter(QObject* obj, QEvent* event)
{
    if (obj == parentWidget()) {
        if (event->type() == QEvent::Move || event->type() == QEvent::Resize) {
            if (snapped_ && visible_) {
                snapToParent();
            }
        }
        if (event->type() == QEvent::WindowStateChange) {
            auto* w = static_cast<QWidget*>(parentWidget());
            if (!w->isMinimized() && !w->isMaximized() && visible_) {
                snapToParent();
                QWidget::show();
            }
        }
    }
    return QWidget::eventFilter(obj, event);
}

void LogPanel::snapToParent()
{
    QPoint pr = parentWidget()->mapToGlobal(QPoint(0, 0));
    QRect prRect(pr, parentWidget()->size());
    setGeometry(prRect.right(), prRect.y(), WIDTH, prRect.height());
}
