#include "LogPanel.h"
#include <QVBoxLayout>
#include <QLabel>

LogPanel::LogPanel(QWidget* parent)
    : QWidget(parent)
{
    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(0);

    auto* header = new QLabel("Log");
    header->setStyleSheet(
        "background: #2d2d2d; color: #cccccc; font-weight: bold;"
        "padding: 4px 8px; font-size: 10px;");
    layout->addWidget(header);

    view_ = new QPlainTextEdit(this);
    view_->setReadOnly(true);
    view_->setMaximumBlockCount(500);
    view_->setPlaceholderText("No log output yet");
    view_->setFont(QFont("Courier New", 9));
    view_->setFrameShape(QFrame::NoFrame);
    view_->setStyleSheet(
        "QPlainTextEdit { background: #1e1e1e; color: #d4d4d4; border: none; padding: 4px; }");
    layout->addWidget(view_);

    setMaximumHeight(300);
}

void LogPanel::appendLog(const QString& line)
{
    view_->appendPlainText(line);
}

void LogPanel::toggle()
{
    setVisible(!isVisible());
}
