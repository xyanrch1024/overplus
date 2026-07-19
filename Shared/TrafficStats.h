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
        uint64_t up = delta_upstream_.exchange(0, std::memory_order_relaxed);
        uint64_t down = delta_downstream_.exchange(0, std::memory_order_relaxed);
        return {up, down};
    }

private:
    TrafficStats() = default;
    std::atomic<uint64_t> total_upstream_{0};
    std::atomic<uint64_t> total_downstream_{0};
    std::atomic<uint64_t> delta_upstream_{0};
    std::atomic<uint64_t> delta_downstream_{0};
};
