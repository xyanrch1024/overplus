#pragma once

#include <boost/asio.hpp>
#include <boost/core/noncopyable.hpp>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

class DtlsChannel : private boost::noncopyable {
public:
    using HandshakeCallback = std::function<void(bool success)>;
    using DataCallback = std::function<void(const char* data, size_t len)>;

    DtlsChannel(boost::asio::io_context& io_ctx,
                const std::string& server_addr,
                uint16_t server_port,
                const std::string& password);
    ~DtlsChannel();

    void start(HandshakeCallback on_handshake, DataCallback on_data);
    void stop();
    void send(const std::string& data);
    bool is_ready() const { return handshake_done_; }

private:
    void do_handshake();
    void drain_write_bio();
    void do_receive();
    void handle_timeout();
    void on_receive(boost::system::error_code ec, std::size_t len);

    boost::asio::io_context& io_ctx_;
    boost::asio::ip::udp::socket socket_;
    boost::asio::ip::udp::endpoint server_ep_;
    boost::asio::steady_timer timer_;
    boost::asio::ip::udp::endpoint sender_ep_;

    SSL* ssl_ = nullptr;
    BIO* read_bio_ = nullptr;
    BIO* write_bio_ = nullptr;

    std::string password_;
    bool handshake_done_ = false;
    bool running_ = false;

    std::array<char, 65535> recv_buf_;

    HandshakeCallback on_handshake_;
    DataCallback on_data_;
};
