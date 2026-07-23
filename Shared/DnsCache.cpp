#include "DnsCache.h"

DnsCacheManager& DnsCacheManager::instance()
{
    static DnsCacheManager mgr;
    return mgr;
}

void DnsCacheManager::set_default_ttl(time_t ttl)
{
    std::lock_guard<std::mutex> lock(mtx_);
    default_ttl_ = ttl;
}

bool DnsCacheManager::get_udp(const std::string& key, boost::asio::ip::udp::endpoint& ep)
{
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = udp_cache_.find(key);
    if (it != udp_cache_.end() && time(nullptr) < it->second.expire_time) {
        ep = it->second.endpoint;
        return true;
    }
    return false;
}

void DnsCacheManager::put_udp(const std::string& key, const boost::asio::ip::udp::endpoint& ep)
{
    std::lock_guard<std::mutex> lock(mtx_);
    udp_cache_[key] = {ep, time(nullptr) + default_ttl_};
}

bool DnsCacheManager::get_tcp(const std::string& key, boost::asio::ip::tcp::endpoint& ep)
{
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = tcp_cache_.find(key);
    if (it != tcp_cache_.end() && time(nullptr) < it->second.expire_time) {
        ep = it->second.endpoint;
        return true;
    }
    return false;
}

void DnsCacheManager::put_tcp(const std::string& key, const boost::asio::ip::tcp::endpoint& ep)
{
    std::lock_guard<std::mutex> lock(mtx_);
    tcp_cache_[key] = {ep, time(nullptr) + default_ttl_};
}

void DnsCacheManager::cleanup_expired()
{
    std::lock_guard<std::mutex> lock(mtx_);
    time_t now = time(nullptr);
    for (auto it = udp_cache_.begin(); it != udp_cache_.end();) {
        if (now >= it->second.expire_time)
            it = udp_cache_.erase(it);
        else
            ++it;
    }
    for (auto it = tcp_cache_.begin(); it != tcp_cache_.end();) {
        if (now >= it->second.expire_time)
            it = tcp_cache_.erase(it);
        else
            ++it;
    }
}
