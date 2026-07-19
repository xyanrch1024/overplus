
#pragma once
#include "Shared/Log.h"
#include <Protocol/http/http.h>
#include <Protocol/socks5/socks5.h>
#include <boost/asio.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/core/noncopyable.hpp>
#include <boost/system/error_code.hpp>
#include <memory>
#include <vector>
using boost::asio::ip::tcp;

class UdpRelay;

class Session : public std::enable_shared_from_this<Session>
    , private boost::noncopyable {
    enum State {
        HANDSHAKE,
        FORWARD
    };

public:
    Session(boost::asio::io_context& context, boost::asio::ssl::context& ssl);

    void start();
    boost::asio::ip::tcp::socket& socket();
    void read_packet(int);
    void write_sock5_hanshake_reply(AuthReq& req);
    void read_socks5_request();
    void do_resolve();
    void do_connect(tcp::endpoint endpoint);
    void write_socks5_response();
    void write_packet(int, size_t);
    void do_sent_v_req();
    void do_ssl_handshake();
    void destroy();
    void http_connect_handshake(const std::string& initial);
    void write_http_connect_response();
    void do_handle_socks5_udp_associate();
    void do_read_control();

private:
    void on_udp_data_to_server(const std::string& frame);

    static constexpr size_t MAX_BUFF_SIZE = 32 * 1024;
    boost::asio::io_context& context_;
    tcp::socket in_socket;

    std::string remote_host;
    std::string remote_port;
    std::string user_name_;
    std::string password_;
    tcp::resolver resolver_;
    std::vector<char> in_buf;
    std::vector<char> out_buf;
    std::string message_buf;
    Request socks5_req;
    HttpRequest http_req;
    State state_ { HANDSHAKE };
    bool response_sent_ = false;
    std::atomic<bool> destroyed_{false};
    boost::asio::ssl::context& ssl_ctx;
    boost::asio::ssl::stream<boost::asio::ip::tcp::socket> out_socket;
    std::shared_ptr<UdpRelay> udp_relay_;
};