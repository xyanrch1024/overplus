#pragma once
#include <atomic>
#include <cstdint>
#include <utility>

class TrafficStats {
public:
    static TrafficStats& instance() {
        static TrafficStats s;
        return s;
    }

    void addUpstreamDelta(uint64_t bytes) {
        total_upstream_.fetch_add(bytes, std::memory_order_relaxed);
        delta_upstream_.fetch_add(bytes, std::memory_order_relaxed);
    }

    void addDownstreamDelta(uint64_t bytes) {
        total_downstream_.fetch_add(bytes, std::memory_order_relaxed);
        delta_downstream_.fetch_add(bytes, std::memory_order_relaxed);
    }

    std::pair<uint64_t, uint64_t> getAndResetDelta() {
        uint64_t raw_up = delta_upstream_.exchange(0, std::memory_order_relaxed);
        uint64_t raw_down = delta_downstream_.exchange(0, std::memory_order_relaxed);
        smoothed_up_ = static_cast<uint64_t>(0.3 * raw_up + 0.7 * smoothed_up_);
        smoothed_down_ = static_cast<uint64_t>(0.3 * raw_down + 0.7 * smoothed_down_);
        return {smoothed_up_, smoothed_down_};
    }

    std::pair<uint64_t, uint64_t> getTotal() {
        return {total_upstream_.load(std::memory_order_relaxed),
                total_downstream_.load(std::memory_order_relaxed)};
    }

private:
    TrafficStats() = default;
    std::atomic<uint64_t> total_upstream_{0};
    std::atomic<uint64_t> total_downstream_{0};
    std::atomic<uint64_t> delta_upstream_{0};
    std::atomic<uint64_t> delta_downstream_{0};
    uint64_t smoothed_up_{0};
    uint64_t smoothed_down_{0};
};
