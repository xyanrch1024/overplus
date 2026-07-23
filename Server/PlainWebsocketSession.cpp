#include "PlainWebsocketSession.h"
#include "Shared/ConfigManage.h"
#include "Shared/Log.h"
PlainWebsocketSession::PlainWebsocketSession(boost::asio::io_context& io_ctx)
: Session<websocket::stream<beast::tcp_stream>>(io_ctx)
{
}
void PlainWebsocketSession::start()
{
    beast::get_lowest_layer(upstream_socket).expires_after(std::chrono::seconds(30));

    auto self = shared_from_this();
    http::async_read(upstream_socket.next_layer(), http_buffer_, http_request_,
        [this, self](beast::error_code ec, std::size_t len) {
            on_http_header(ec, len);
        });
}
void PlainWebsocketSession::on_http_header(beast::error_code ec, std::size_t)
{
    if (ec) {
        ERROR_LOG << "http read header failed: " << ec.message();
        destroy();
        return;
    }
    if (!http_request_.count(http::field::connection)) {
        http_request_.set(http::field::connection, "Upgrade");
    }
    if (!http_request_.count(http::field::upgrade)) {
        http_request_.set(http::field::upgrade, "websocket");
    }
    beast::get_lowest_layer(upstream_socket).expires_never();

    upstream_socket.set_option(
        websocket::stream_base::timeout::suggested(
            beast::role_type::server));

    upstream_socket.set_option(websocket::stream_base::decorator(
        [](websocket::response_type& res) {
            res.set(http::field::server,"overplus plain-websocket-server");
        }));

    auto self = shared_from_this();
    upstream_socket.async_accept(http_request_,
        [this, self](beast::error_code ec2) {
            on_accept(ec2);
        });
}
void PlainWebsocketSession::on_accept(beast::error_code ec)
{
    if (ec) {
        ERROR_LOG << "websocket accept failed: " << ec.message();
        destroy();
        return;
    }
    beast::get_lowest_layer(upstream_socket).expires_never();
    handle_custom_protocol();
}
void PlainWebsocketSession::upstream_tcp_write(int direction, size_t len)
{
    auto self(this->shared_from_this());
    upstream_socket.async_write(boost::asio::buffer(out_buf, len), [this, self, direction](boost::system::error_code ec, std::size_t length) {
        if (!ec)
            async_bidirectional_read(direction);
        else {
            if (ec != boost::asio::error::operation_aborted) {
                NOTICE_LOG << "write to client (TCP): " << ec.message();
            }
            destroy();
            return;
        }
    });
}

void PlainWebsocketSession::upstream_tcp_write_send(const char* data, size_t len, SendCallback handler)
{
    upstream_socket.async_write(
        boost::asio::buffer(data, len),
        [handler = std::move(handler)](boost::system::error_code ec, std::size_t length) {
            handler(ec, length);
        });
}

void PlainWebsocketSession::upstream_udp_write(int direction, const std::string& packet)
{
    auto self(this->shared_from_this());
    upstream_socket.async_write(boost::asio::buffer(packet),
        [this, self, direction](boost::system::error_code ec, std::size_t length) {
            if (!ec)
                udp_async_bidirectional_read(direction);
            else {
                if (ec != boost::asio::error::operation_aborted) {
                    NOTICE_LOG << "write to client (UDP): " << ec.message();
                }
                destroy();
                return;
            }
        });
}
void PlainWebsocketSession::destroy()
{
    if (state_ == DESTROY) {
        return;
    }
    state_ = DESTROY;
    boost::system::error_code ec;
    auto& lowest = beast::get_lowest_layer(upstream_socket);
    if (lowest.socket().is_open()) {
        lowest.socket().cancel(ec);
        lowest.socket().shutdown(tcp::socket::shutdown_both, ec);
        lowest.socket().close(ec);
    }
    Session<websocket::stream<beast::tcp_stream>>::destroy();
}
