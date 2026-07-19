#pragma once
#include <atomic>
#include <cstdint>

class SessionStats {
public:
    static SessionStats& instance() {
        static SessionStats s;
        return s;
    }
    void sessionCreated() { count_.fetch_add(1, std::memory_order_relaxed); }
    void sessionDestroyed() { count_.fetch_sub(1, std::memory_order_relaxed); }
    uint64_t currentCount() const { return count_.load(std::memory_order_relaxed); }

private:
    SessionStats() = default;
    std::atomic<uint64_t> count_{0};
};
