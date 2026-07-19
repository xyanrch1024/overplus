#pragma once
#include "Shared/DtlsChannel.h"
#include <boost/asio.hpp>
#include <boost/core/noncopyable.hpp>
#include <functional>
#include <string>
#include <queue>

class UdpRelay : private boost::noncopyable {
public:
    UdpRelay(boost::asio::io_context& io_ctx,
             const std::string& server_addr,
             uint16_t server_port,
             const std::string& password);
    ~UdpRelay();

    bool start(uint16_t& local_port);
    void stop();

    boost::asio::ip::udp::socket& socket() { return local_socket_; }

private:
    void do_receive_local();
    void on_dtls_data(const char* data, size_t len);
    void flush_pending();

    boost::asio::io_context& io_ctx_;
    boost::asio::ip::udp::socket local_socket_;
    boost::asio::ip::udp::endpoint sender_ep_;
    std::array<char, 65535> recv_buf_;

    std::unique_ptr<DtlsChannel> dtls_;
    std::queue<std::string> pending_frames_;
    bool running_ = false;
};
