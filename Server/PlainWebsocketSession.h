#pragma once
#include "Session.h"

class PlainWebsocketSession : public Session<websocket::stream<beast::tcp_stream>>{

public:
    PlainWebsocketSession(boost::asio::io_context&);
    ~PlainWebsocketSession(){
    }
    void start();

    void on_http_header(beast::error_code ec, std::size_t);
    void on_accept(beast::error_code ec);
    boost::asio::ip::tcp::socket& socket()
    {
        return beast::get_lowest_layer(upstream_socket).socket();
    }

    virtual void upstream_tcp_write(int direction, size_t len);
    virtual void upstream_tcp_write_send(const char* data, size_t len, SendCallback handler);
    virtual void upstream_udp_write(int direction, const std::string& packet);
    virtual void destroy();

private:
    beast::flat_buffer read_buffer_;
    beast::flat_buffer write_buffer_;
    http::request<http::string_body> http_request_;
};
