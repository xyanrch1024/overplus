#pragma once
#include <boost/asio.hpp>
#include <boost/core/noncopyable.hpp>
#include <ctime>
#include <mutex>
#include <unordered_map>

class DnsCacheManager : private boost::noncopyable {
public:
    struct UdpEntry {
        boost::asio::ip::udp::endpoint endpoint;
        time_t expire_time;
    };
    struct TcpEntry {
        boost::asio::ip::tcp::endpoint endpoint;
        time_t expire_time;
    };

    static DnsCacheManager& instance();

    bool get_udp(const std::string& key, boost::asio::ip::udp::endpoint& ep);
    void put_udp(const std::string& key, const boost::asio::ip::udp::endpoint& ep, time_t ttl = 300);

    bool get_tcp(const std::string& key, boost::asio::ip::tcp::endpoint& ep);
    void put_tcp(const std::string& key, const boost::asio::ip::tcp::endpoint& ep, time_t ttl = 300);

    void cleanup_expired();

private:
    DnsCacheManager() = default;

    std::mutex mtx_;
    std::unordered_map<std::string, UdpEntry> udp_cache_;
    std::unordered_map<std::string, TcpEntry> tcp_cache_;
};
