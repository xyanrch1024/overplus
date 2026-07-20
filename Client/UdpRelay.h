#pragma once
#include "Shared/DtlsChannel.h"
#include <boost/asio.hpp>
#include <boost/core/noncopyable.hpp>
#include <functional>
#include <queue>
#include <string>

class UdpRelay : private boost::noncopyable {
public:
    UdpRelay(boost::asio::io_context& io_ctx);
    ~UdpRelay();

    bool start(uint16_t& local_port, DtlsChannel& dtls, uint16_t session_id);
    void stop();
    void on_dtls_data(const char* data, size_t len);
    void flush_pending();

    boost::asio::ip::udp::socket& socket() { return local_socket_; }

private:
    void do_receive_local();

    boost::asio::io_context& io_ctx_;
    boost::asio::ip::udp::socket local_socket_;
    boost::asio::ip::udp::endpoint sender_ep_;
    std::array<char, 65535> recv_buf_;

    DtlsChannel* dtls_ = nullptr;
    uint16_t session_id_ = 0;
    std::queue<std::string> pending_frames_;
    bool running_ = false;
};
