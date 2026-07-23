
#pragma once
#include "Shared/Log.h"
#include <Protocol/http/http.h>
#include <Protocol/socks5/socks5.h>
#include <boost/asio.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/websocket/ssl.hpp>
#include <boost/core/noncopyable.hpp>
#include <boost/system/error_code.hpp>
#include <functional>
#include <memory>
#include <type_traits>
#include <vector>
using boost::asio::ip::tcp;

namespace beast = boost::beast;
namespace websocket = beast::websocket;

class Server;
class UdpRelay;

using TlsSocket = boost::asio::ssl::stream<boost::asio::ip::tcp::socket>;
using WsSocket = websocket::stream<boost::asio::ssl::stream<boost::asio::ip::tcp::socket>>;

template<class T>
struct SocketFactory;

template<>
struct SocketFactory<TlsSocket> {
    static TlsSocket make(boost::asio::io_context& ioc, boost::asio::ssl::context& ssl) {
        return TlsSocket(ioc, ssl);
    }
};

template<>
struct SocketFactory<WsSocket> {
    static WsSocket make(boost::asio::io_context& ioc, boost::asio::ssl::context& ssl) {
        return WsSocket(TlsSocket(ioc, ssl));
    }
};

template<class T>
class Session : public std::enable_shared_from_this<Session<T>>
    , private boost::noncopyable {
    enum State {
        HANDSHAKE,
        FORWARD
    };

public:
    Session(boost::asio::io_context& context, boost::asio::ssl::context& ssl, Server& server);

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

protected:
    virtual tcp::socket& get_out_raw_socket() = 0;
    virtual void perform_ssl_handshake(std::function<void(boost::system::error_code)> handler) = 0;
    virtual void after_ssl_handshake(std::shared_ptr<Session<T>> self) = 0;
    virtual void destroy_out_socket(boost::system::error_code& ec) = 0;

    using WriteHandler = std::function<void(boost::system::error_code, std::size_t)>;
    using ReadHandler = std::function<void(boost::system::error_code, std::size_t)>;

    void write_to_upstream(const char* data, size_t len, WriteHandler handler);
    void write_to_upstream_buf(size_t len, WriteHandler handler);
    void read_from_upstream(boost::asio::mutable_buffer buffer, ReadHandler handler);

    T out_socket;

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
    bool destroyed_ = false;
    boost::asio::ssl::context& ssl_ctx;
    Server& server_;
    std::shared_ptr<UdpRelay> udp_relay_;
    uint16_t session_id_ = 0;
    char control_recv_buf_[128];
};

class TlsClientSession : public Session<TlsSocket> {
public:
    TlsClientSession(boost::asio::io_context& context, boost::asio::ssl::context& ssl, Server& server);

protected:
    boost::asio::ip::tcp::socket& get_out_raw_socket() override { return out_socket.next_layer(); }
    void perform_ssl_handshake(std::function<void(boost::system::error_code)> handler) override;
    void after_ssl_handshake(std::shared_ptr<Session<TlsSocket>> self) override;
    void destroy_out_socket(boost::system::error_code& ec) override;
};

class WsClientSession : public Session<WsSocket> {
public:
    WsClientSession(boost::asio::io_context& context, boost::asio::ssl::context& ssl, Server& server);

protected:
    boost::asio::ip::tcp::socket& get_out_raw_socket() override { return out_socket.next_layer().next_layer(); }
    void perform_ssl_handshake(std::function<void(boost::system::error_code)> handler) override;
    void after_ssl_handshake(std::shared_ptr<Session<WsSocket>> self) override;
    void destroy_out_socket(boost::system::error_code& ec) override;

private:
    void do_ws_handshake(std::shared_ptr<Session<WsSocket>> self);
};


