#include "LogFile.h"
#include <assert.h>
#include <cstdio>
#include <mutex>
#include <cstring>
#include <algorithm>
#include <filesystem>

/*  FILE* fp_;
    char buffer_[64 * 1024];
    off_t writtenBytes_;
    */
AppendFile::AppendFile(const char* filename)
{
    fp_ = fopen(filename, "a");
    assert(fp_);
#ifdef _WIN32
    if (ftell(fp_) == 0) {
        const unsigned char bom[] = {0xEF, 0xBB, 0xBF};
        ::fwrite(bom, 1, 3, fp_);
    }
#endif
}

AppendFile::~AppendFile()
{
    // if (fp_) {
    ::fflush(fp_);
    ::fclose(fp_);
    // }
}

void AppendFile::append(const char* logline, size_t len)
{
    writtenBytes_ += len;
    ::fwrite(logline, len, 1, fp_);
}

void AppendFile::flush()
{
    ::fflush(fp_);
}

LogFile::LogFile(const std::string& basename,
    off_t rollSize,
    bool threadSafe,
    int flushInterval,
    int checkEveryN,
    int maxKeepDays)
    : basename_(basename)
    , rollSize_(rollSize)
    , flushInterval_(flushInterval)
    , checkEveryN_(checkEveryN)
    , maxKeepDays_(maxKeepDays)
    , count_(0)
    , muti_threads(threadSafe)
    // mutex_(threadSafe ? new MutexLock : NULL),
    , startOfPeriod_(0)
    , lastRoll_(0)
    , lastFlush_(0)
{
    assert(basename.find('/') == std::string::npos);
    cleanupOldLogs();
    rollFile();
}

void LogFile::append(std::string&& buf)
{
    if (muti_threads) {
        std::lock_guard<std::mutex> lock_guard(mutex_);
        append_unlocked(std::move(buf));
    } else {
        append_unlocked(std::move(buf));
    }
}

void LogFile::flush()
{
    if (muti_threads) {
        std::lock_guard<std::mutex> lock_guard(mutex_);
        file_->flush();
    } else {
        file_->flush();
    }
}

void LogFile::append_unlocked(std::string&& buf)
{
    file_->append(buf.data(), buf.length());

    if (file_->writtenBytes() > rollSize_) {
        rollFile();
    } else {
        ++count_;
        if (count_ >= checkEveryN_) {
            count_ = 0;
            time_t now = ::time(NULL);
            time_t today = now / kRollPerSeconds_ * kRollPerSeconds_;
            if (today != startOfPeriod_) {
                rollFile();
            } else if (now - lastFlush_ > flushInterval_) {
                lastFlush_ = now;
                file_->flush();
            }
        }
    }
}

bool LogFile::rollFile()
{
    time_t now = 0;
    std::string filename = getLogFileName(basename_, &now);
    time_t start = now / kRollPerSeconds_ * kRollPerSeconds_;

    if (now > lastRoll_) {
        lastRoll_ = now;
        lastFlush_ = now;
        startOfPeriod_ = start;
        file_.reset(new AppendFile(filename.c_str()));
        return true;
    }
    return false;
}

std::string LogFile::getLogFileName(const std::string& basename, time_t* now)
{
    std::string filename;
    filename.reserve(basename.size() + 64);
    filename = basename;

    char timebuf[32];
    struct tm tm;
    *now = time(NULL);
#ifdef _WIN32
    localtime_s(&tm, now);
#else
    localtime_r(now, &tm);
#endif
    strftime(timebuf, sizeof timebuf, ".%Y%m%d", &tm);
    filename += timebuf;

    /*filename += ProcessInfo::hostname();

    char pidbuf[32];
    snprintf(pidbuf, sizeof pidbuf, ".%d", ProcessInfo::pid());
    filename += pidbuf;
*/
    filename += ".log";

    return filename;
}

time_t LogFile::parseLogDate(const std::string& filename, const std::string& basename)
{
    std::string prefix = basename + ".";
    std::string suffix = ".log";
    if (filename.find(prefix) != 0 || filename.find(suffix) != filename.size() - suffix.size()) {
        return -1;
    }
    std::string dateStr = filename.substr(prefix.size(), filename.size() - prefix.size() - suffix.size());
    if (dateStr.size() != 8) {
        return -1;
    }
    struct tm tm = {};
    if (sscanf(dateStr.c_str(), "%4d%2d%2d", &tm.tm_year, &tm.tm_mon, &tm.tm_mday) != 3) {
        return -1;
    }
    tm.tm_year -= 1900;
    tm.tm_mon -= 1;
    return mktime(&tm);
}

void LogFile::cleanupOldLogs()
{
    if (maxKeepDays_ <= 0) return;

    time_t now = time(NULL);
    for (const auto& entry : std::filesystem::directory_iterator(".")) {
        if (!entry.is_regular_file()) continue;
        std::string name = entry.path().filename().string();
        time_t logDate = parseLogDate(name, basename_);
        if (logDate < 0) continue;
        double daysDiff = difftime(now, logDate) / (60 * 60 * 24);
        if (daysDiff > maxKeepDays_) {
            std::filesystem::remove(entry.path());
        }
    }
}
