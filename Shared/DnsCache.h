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

    void set_default_ttl(time_t ttl);

    bool get_udp(const std::string& key, boost::asio::ip::udp::endpoint& ep);
    void put_udp(const std::string& key, const boost::asio::ip::udp::endpoint& ep);

    bool get_tcp(const std::string& key, boost::asio::ip::tcp::endpoint& ep);
    void put_tcp(const std::string& key, const boost::asio::ip::tcp::endpoint& ep);

    void cleanup_expired();

private:
    DnsCacheManager() = default;

    time_t default_ttl_ = 600;
    std::mutex mtx_;
    std::unordered_map<std::string, UdpEntry> udp_cache_;
    std::unordered_map<std::string, TcpEntry> tcp_cache_;
};
