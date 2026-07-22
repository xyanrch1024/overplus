
#include "Session.h"
#include "Server.h"
#include "UdpRelay.h"
#include "Shared/ConfigManage.h"
#include "Shared/Log.h"
#include "Shared/ProxyStats.h"
#include <Protocol/UdpFrame.h>
#include <Protocol/VProtocal/VRequest.h>
#include <Protocol/socks5/socks5.h>
#include <boost/asio/buffer.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ssl/verify_mode.hpp>
#include <cstddef>
#include <type_traits>

template<class T>
Session<T>::Session(boost::asio::io_context& context, boost::asio::ssl::context& ssl, Server& server)
    : context_(context)
    , in_socket(context_)
    , resolver_(context_)
    , in_buf(MAX_BUFF_SIZE)
    , out_buf(MAX_BUFF_SIZE)
    , ssl_ctx(ssl)
    , out_socket(SocketFactory<T>::make(context_, ssl))
    , server_(server)
{
    auto& config = ConfigManage::instance().client_cfg;
    remote_host = config.remote_addr;
    remote_port = config.remote_port;
    user_name_ = config.user_name;
    password_ = config.password;
}

template<class T>
void Session<T>::write_to_upstream(const char* data, size_t len, WriteHandler handler)
{
    if constexpr (std::is_same_v<T, WsSocket>) {
        out_socket.async_write(boost::asio::buffer(data, len), std::move(handler));
    } else {
        boost::asio::async_write(out_socket, boost::asio::buffer(data, len), std::move(handler));
    }
}

template<class T>
void Session<T>::write_to_upstream_buf(size_t len, WriteHandler handler)
{
    if constexpr (std::is_same_v<T, WsSocket>) {
        out_socket.async_write(boost::asio::buffer(out_buf, len), std::move(handler));
    } else {
        boost::asio::async_write(out_socket, boost::asio::buffer(out_buf, len), std::move(handler));
    }
}

template<class T>
void Session<T>::read_from_upstream(boost::asio::mutable_buffers_1 buffer, ReadHandler handler)
{
    if constexpr (std::is_same_v<T, WsSocket>) {
        out_socket.async_read_some(buffer, std::move(handler));
    } else {
        out_socket.async_read_some(buffer, std::move(handler));
    }
}

template<class T>
void Session<T>::start()
{
    auto self(this->shared_from_this());
    in_socket.async_read_some(boost::asio::buffer(in_buf),
        [this, self](const boost::system::error_code& ec, size_t len) {
            if (ec) {
                destroy();
                return;
            }
            if (in_buf[0] == (char)0x05) {
                AuthReq auth_req;
                if (!auth_req.unstream(in_buf)) {
                    ERROR_LOG << "Receive invalid message";
                    destroy();
                    return;
                }
                NOTICE_LOG << "receive message:" << auth_req;
                write_sock5_hanshake_reply(auth_req);
            } else if (in_buf[0] == 'C' || in_buf[0] == 'c') {
                http_connect_handshake(std::string(in_buf.data(), len));
            } else {
                ERROR_LOG << "unknown protocol, first byte: " << (int)in_buf[0];
                destroy();
            }
        });
}
template<class T>
void Session<T>::write_sock5_hanshake_reply(AuthReq& req)
{
    auto self(this->shared_from_this());
    auto it = std::find(req.methods.cbegin(), req.methods.cend(), AuthMethod::NO_AUTHENTICATION);
    if (it == req.methods.cend()) {
        ERROR_LOG << "Now only support no password auth";
        destroy();
        return;
    }
    {
        AuthRes authRes;
        authRes.version = 0x05;
        authRes.method = AuthMethod::NO_AUTHENTICATION;

        authRes.stream(message_buf);
    }
    boost::asio::async_write(in_socket, boost::asio::buffer(message_buf), // Always 2-byte according to RFC1928
        [this, self](boost::system::error_code ec, std::size_t length) {
            if (!ec) {
                if (in_buf[1] == (char)0xFF) {
                    destroy();
                    return;
                }
                read_socks5_request();
            } else {
                ERROR_LOG << "SOCKS5 handshake response write :" << ec.message();
                destroy();
            }
        });
}
template<class T>
void Session<T>::read_socks5_request()
{
    auto self(this->shared_from_this());

    in_socket.async_read_some(boost::asio::buffer(in_buf),
        [this, self](boost::system::error_code ec, std::size_t length) {
            if (!ec) {
                if (!socks5_req.unsteam(in_buf, length)) {
                    ERROR_LOG << "decode message error";
                    destroy();
                    return;
                }
                NOTICE_LOG<<"Receive socks5 message "<<socks5_req;
                if(socks5_req.cmd == Request::UDP_ASSOCIATE)
                {
                    auto& cfg = ConfigManage::instance().client_cfg;
                    if (!cfg.udp_enabled) {
                        ERROR_LOG << "UDP ASSOCIATE rejected: UDP proxy disabled in config";
                        Reply reply;
                        reply.version = 0x05;
                        reply.reserved = 0x00;
                        reply.addrtype = ADDRTYPE::V4;
                        reply.repResult = 0x02; // connection not allowed by ruleset
                        reply.realRemoteIP = INADDR_ANY;
                        reply.realRemotePort = 0;
                        message_buf.clear();
                        reply.stream(message_buf);
                        boost::asio::write(in_socket, boost::asio::buffer(message_buf));
                        destroy();
                        return;
                    }
                    do_handle_socks5_udp_associate();
                }
                else
                {
                    do_resolve();
                }
            } else {
                ERROR_LOG << "SOCKS5 request read:" << ec.message();
                destroy();
            }
        });
}

template<class T>
void Session<T>::do_resolve()
{
    auto self(this->shared_from_this());
    resolver_.async_resolve(remote_host, remote_port,
        [this, self](const boost::system::error_code& ec, tcp::resolver::results_type results) {
            if (!ec && !results.empty()) {
                do_connect(*results.begin());
            } else {
                ERROR_LOG << "failed to resolve " << remote_host << ":" << remote_port << " " << ec.message();
                destroy();
            }
        });
}
template<class T>
void Session<T>::do_connect(tcp::endpoint endpoint)
{
    auto self(this->shared_from_this());
    get_out_raw_socket().async_connect(endpoint,
        [ this, self](const boost::system::error_code& ec) {
            if (!ec) {
                DEBUG_LOG << "connected to " << remote_host << ":" << remote_port;
                do_ssl_handshake();
            } else {
                ERROR_LOG << "failed to connect " << remote_host << ":" << remote_port << " " << ec.message();
                destroy();
            }
        });
}
template<class T>
void Session<T>::do_ssl_handshake()
{
    auto self(this->shared_from_this());
    perform_ssl_handshake([this, self](const boost::system::error_code& ec) {
        if (!ec) {
            after_ssl_handshake(self);
        } else {
            ERROR_LOG << "ssl handshake failed :" << ec.message();
            destroy();
        }
    });
}
template<class T>
void Session<T>::do_sent_v_req()
{
    auto self(this->shared_from_this());
    message_buf.clear();
    VRequest request;

    request.header.version = 0x01;

    request.user_name = user_name_;
    request.password = password_;
    request.address = socks5_req.remote_host;
    request.port = socks5_req.remote_port;
    request.stream(message_buf);
    DEBUG_LOG << "v protocol request -> " << request.user_name << "@" << request.address << ":" << request.port;

    write_to_upstream(message_buf.data(), message_buf.size(),
        [this, self](boost::system::error_code ec, std::size_t length) {
            if (!ec) {
                state_ = FORWARD;
                if (response_sent_) {
                    read_packet(3);
                } else {
                    write_socks5_response();
                }
            } else {
                ERROR_LOG << "VProtocol request write failed " << ec.message();
                destroy();
            }
        });
}
template<class T>
void Session<T>::write_socks5_response()
{
    auto self(this->shared_from_this());

    {
        Reply reply;
        reply.version = 0x05;
        reply.reserved = 0x00;
        reply.addrtype = ADDRTYPE::V4;
        reply.repResult = 0x00;
        reply.realRemoteIP = get_out_raw_socket().remote_endpoint().address().to_v4().to_uint();
        reply.realRemotePort = get_out_raw_socket().remote_endpoint().port();
        message_buf.clear();
        reply.stream(message_buf);
    }

    boost::asio::async_write(in_socket, boost::asio::buffer(message_buf), // Always 10-byte according to RFC1928
        [this, self](boost::system::error_code ec, std::size_t length) {
            if (!ec) {
                state_ = FORWARD;
                read_packet(3); // Read both sockets
            } else {
                ERROR_LOG << "SOCKS5 response write:" << ec.message();
                destroy();
            }
        });
}
template<class T>
void Session<T>::http_connect_handshake(const std::string& initial)
{
    auto self(this->shared_from_this());
    auto buf = std::make_shared<std::string>(initial);
    boost::asio::async_read_until(in_socket, boost::asio::dynamic_buffer(*buf), "\r\n",
        [this, self, buf](const boost::system::error_code& ec, size_t) {
            if (ec) {
                ERROR_LOG << "HTTP handshake read error: " << ec.message();
                destroy();
                return;
            }
            if (!http_req.unstream(*buf)) {
                ERROR_LOG << "Invalid HTTP CONNECT request";
                destroy();
                return;
            }
            socks5_req.remote_host = http_req.host;
            socks5_req.remote_port = http_req.port;
            NOTICE_LOG << "HTTP CONNECT " << http_req.host << ":" << http_req.port;
            write_http_connect_response();
        });
}

template<class T>
void Session<T>::write_http_connect_response()
{
    auto self(this->shared_from_this());
    response_sent_ = true;
    message_buf.clear();
    HttpResponse::ok(message_buf);
    boost::asio::async_write(in_socket, boost::asio::buffer(message_buf),
        [this, self](boost::system::error_code ec, std::size_t length) {
            if (!ec) {
                do_resolve();
            } else {
                ERROR_LOG << "HTTP response write error: " << ec.message();
                destroy();
            }
        });
}

template<class T>
void Session<T>::read_packet(int direction)
{
    auto self(this->shared_from_this());

    // We must divide reads by direction to not permit second read call on the same socket.
    if (direction & 0x01)
        in_socket.async_read_some(boost::asio::buffer(in_buf),
            [this, self](boost::system::error_code ec, std::size_t length) {
                if (!ec) {
                    DEBUG_LOG << "--> upstream: " << std::to_string(length) << " bytes";
                    ProxyStats::instance().addUpstreamDelta(length);
                    write_packet(1, length);
                } else // if (ec != boost::asio::error::eof)
                {
                    ERROR_LOG << "closing session. read from local failed " << ec.message();
                    // Most probably client closed socket. Let's close both sockets and exit session.
                    destroy();
                    // context_.stop();
                }
            });

    if (direction & 0x2)
        read_from_upstream(boost::asio::buffer(out_buf),
            [this, self](boost::system::error_code ec, std::size_t length) {
                if (!ec) {

                    DEBUG_LOG << "<-- local: " << std::to_string(length) << " bytes";
                    ProxyStats::instance().addDownstreamDelta(length);
                    write_packet(2, length);
                } else // if (ec != boost::asio::error::eof)
                {
                    ERROR_LOG << "closing session. read from upstream server failed " << ec.message();
                    destroy();
                }
            });
}
template<class T>
void Session<T>::write_packet(int direction, size_t len)
{
    auto self(this->shared_from_this());

    switch (direction) {
    case 1:
        write_to_upstream(in_buf.data(), len,
            [this, self, direction](boost::system::error_code ec, std::size_t length) {
                if (!ec)
                    read_packet(direction);
                else {
                    ERROR_LOG << "closing session. write to upstream server failed " << ec.message();
                    // Most probably client closed socket. Let's close both sockets and exit session.
                    destroy();
                }
            });
        break;
    case 2:
        boost::asio::async_write(in_socket, boost::asio::buffer(out_buf, len),
            [this, self, direction](boost::system::error_code ec, std::size_t length) {
                if (!ec)
                    read_packet(direction);
                else {
                    ERROR_LOG << "closing session. write to local failed " << ec.message();
                    destroy();
                }
            });
        break;
    }
}
template<class T>
boost::asio::ip::tcp::socket& Session<T>::socket()
{
    return in_socket;
}
template<class T>
void Session<T>::destroy()
{
    if (destroyed_)
        return;
    destroyed_ = true;
    ProxyStats::instance().sessionDestroyed();
    NOTICE_LOG << "session destroyed";
    boost::system::error_code ec;
    resolver_.cancel();

    if (in_socket.is_open()) {
        in_socket.cancel(ec);
        in_socket.shutdown(tcp::socket::shutdown_both, ec);
        in_socket.close(ec);
    }

    destroy_out_socket(ec);

    if (session_id_) {
        server_.unregister_relay(session_id_);
    }
    if (udp_relay_) {
        udp_relay_->stop();
        udp_relay_.reset();
    }
}

template<class T>
void Session<T>::do_handle_socks5_udp_associate()
{
    auto self(this->shared_from_this());

    if (!server_.has_dtls()) {
        ERROR_LOG << "UDP ASSOCIATE rejected: DTLS not available";
        Reply reply;
        reply.version = 0x05;
        reply.reserved = 0x00;
        reply.addrtype = ADDRTYPE::V4;
        reply.repResult = 0x02;
        reply.realRemoteIP = INADDR_ANY;
        reply.realRemotePort = 0;
        message_buf.clear();
        reply.stream(message_buf);
        boost::asio::write(in_socket, boost::asio::buffer(message_buf));
        destroy();
        return;
    }

    session_id_ = server_.allocate_session_id();

    udp_relay_ = std::make_shared<UdpRelay>(context_);

    uint16_t local_port = 0;
    if (!udp_relay_->start(local_port, server_.dtls(), session_id_)) {
        ERROR_LOG << "failed to start UDP relay";
        server_.unregister_relay(session_id_);
        destroy();
        return;
    }

    server_.register_relay(session_id_, udp_relay_.get());

    message_buf.clear();
    {
        Reply reply;
        reply.version = 0x05;
        reply.reserved = 0x00;
        reply.addrtype = ADDRTYPE::V4;
        reply.repResult = 0x00;
        reply.realRemoteIP = INADDR_LOOPBACK;
        reply.realRemotePort = local_port;
        reply.stream(message_buf);
    }

    boost::asio::async_write(in_socket, boost::asio::buffer(message_buf),
        [this, self, local_port](boost::system::error_code ec, std::size_t) {
            if (ec) {
                ERROR_LOG << "SOCKS5 UDP ASSOCIATE response write failed: " << ec.message();
                destroy();
                return;
            }
            NOTICE_LOG << "SOCKS5 UDP ASSOCIATE ready, local port " << local_port;
            do_read_control();
        });
}

template<class T>
void Session<T>::do_read_control()
{
    auto self(this->shared_from_this());
    in_socket.async_read_some(boost::asio::buffer(control_recv_buf_),
        [this, self](boost::system::error_code ec, std::size_t) {
            if (ec) {
                NOTICE_LOG << "UDP ASSOCIATE TCP control closed: " << ec.message();
                destroy();
                return;
            }
            do_read_control();
        });
}

template<class T>
void Session<T>::on_udp_data_to_server(const std::string& frame)
{
    if (destroyed_) return;

    DEBUG_LOG << "UDP session --> server: " << frame.size() << " bytes";
    auto self(this->shared_from_this());

    if (get_out_raw_socket().is_open()) {
        write_to_upstream(frame.data(), frame.size(),
            [this, self](boost::system::error_code ec, std::size_t) {
                if (ec) {
                    DEBUG_LOG << "UDP relay: write to server failed: " << ec.message();
                }
            });
    }
}

// TlsClientSession
inline TlsClientSession::TlsClientSession(boost::asio::io_context& context, boost::asio::ssl::context& ssl, Server& server)
    : Session<TlsSocket>(context, ssl, server)
{
    out_socket.set_verify_mode(boost::asio::ssl::verify_none);
}

inline void TlsClientSession::perform_ssl_handshake(std::function<void(boost::system::error_code)> handler)
{
    out_socket.async_handshake(boost::asio::ssl::stream_base::client, [handler](const boost::system::error_code& ec) {
        handler(ec);
    });
}

inline void TlsClientSession::after_ssl_handshake(std::shared_ptr<Session<TlsSocket>> self)
{
    do_sent_v_req();
}

inline void TlsClientSession::destroy_out_socket(boost::system::error_code& ec)
{
    auto& sock = out_socket.next_layer();
    if (sock.is_open()) {
        sock.cancel(ec);
        sock.shutdown(tcp::socket::shutdown_both, ec);
        sock.close(ec);
    }
}

// WsClientSession
inline WsClientSession::WsClientSession(boost::asio::io_context& context, boost::asio::ssl::context& ssl, Server& server)
    : Session<WsSocket>(context, ssl, server)
{
    out_socket.next_layer().set_verify_mode(boost::asio::ssl::verify_none);
}

inline void WsClientSession::perform_ssl_handshake(std::function<void(boost::system::error_code)> handler)
{
    out_socket.next_layer().async_handshake(boost::asio::ssl::stream_base::client, [handler](const boost::system::error_code& ec) {
        handler(ec);
    });
}

inline void WsClientSession::after_ssl_handshake(std::shared_ptr<Session<WsSocket>> self)
{
    do_ws_handshake(self);
}

inline void WsClientSession::do_ws_handshake(std::shared_ptr<Session<WsSocket>> self)
{
    auto& config = ConfigManage::instance().client_cfg;
    out_socket.async_handshake(config.remote_addr, "/",
        [this, self](const boost::system::error_code& ec) {
            if (ec) {
                ERROR_LOG << "websocket handshake failed: " << ec.message();
                destroy();
                return;
            }
            do_sent_v_req();
        });
}

inline void WsClientSession::destroy_out_socket(boost::system::error_code& ec)
{
    auto& sock = out_socket.next_layer().next_layer();
    if (sock.is_open()) {
        sock.cancel(ec);
        sock.shutdown(tcp::socket::shutdown_both, ec);
        sock.close(ec);
    }
}
