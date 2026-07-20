
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
Session::Session(boost::asio::io_context& context, boost::asio::ssl::context& ssl, Server& server)
    : context_(context)
    , in_socket(context_)
    , resolver_(context_)
    , in_buf(MAX_BUFF_SIZE)
    , out_buf(MAX_BUFF_SIZE)
    , ssl_ctx(ssl)
    , out_socket(context_, ssl_ctx)
    , server_(server)
{
    out_socket.set_verify_mode(boost::asio::ssl::verify_none);
    auto& config = ConfigManage::instance().client_cfg;
    remote_host = config.remote_addr;
    remote_port = config.remote_port;
    user_name_ = config.user_name;
    password_ = config.password;
}

void Session::start()
{
    auto self(shared_from_this());
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
void Session::write_sock5_hanshake_reply(AuthReq& req)
{
    auto self(shared_from_this());
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
void Session::read_socks5_request()
{
    auto self(shared_from_this());

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

void Session::do_resolve()
{
    auto self(shared_from_this());
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
void Session::do_connect(tcp::endpoint endpoint)
{
    auto self(shared_from_this());
    //
    out_socket.lowest_layer().async_connect(endpoint,
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
void Session::do_ssl_handshake()
{
    auto self(shared_from_this());
    out_socket.async_handshake(boost::asio::ssl::stream_base::client, [this, self](const boost::system::error_code& error) {
        if (!error) {
            do_sent_v_req();
        } else {
            ERROR_LOG << "ssl handshake failed :" << error.message();
            destroy();
        }
    });
}
void Session::do_sent_v_req()
{
    auto self(shared_from_this());
    message_buf.clear();
    VRequest request;

    request.header.version = 0x01;

    request.user_name = user_name_;
    request.password = password_;
    request.address = socks5_req.remote_host;
    request.port = socks5_req.remote_port;
    request.stream(message_buf);
    DEBUG_LOG << "v protocol request -> " << request.user_name << "@" << request.address << ":" << request.port;

    boost::asio::async_write(out_socket, boost::asio::buffer(message_buf),
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
void Session::write_socks5_response()
{
    auto self(shared_from_this());

    {
        Reply reply;
        reply.version = 0x05;
        reply.reserved = 0x00;
        reply.addrtype = ADDRTYPE::V4;
        reply.repResult = 0x00;
        reply.realRemoteIP = out_socket.lowest_layer().remote_endpoint().address().to_v4().to_uint();
        reply.realRemotePort = out_socket.lowest_layer().remote_endpoint().port();
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
void Session::http_connect_handshake(const std::string& initial)
{
    auto self(shared_from_this());
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

void Session::write_http_connect_response()
{
    auto self(shared_from_this());
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

void Session::read_packet(int direction)
{
    auto self(shared_from_this());

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
        out_socket.async_read_some(boost::asio::buffer(out_buf),
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
void Session::write_packet(int direction, size_t len)
{
    auto self(shared_from_this());

    switch (direction) {
    case 1:
        boost::asio::async_write(out_socket, boost::asio::buffer(in_buf, len),
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
boost::asio::ip::tcp::socket& Session::socket()
{
    return in_socket;
}
void Session::destroy()
{
    if (destroyed_.exchange(true))
        return;
    ProxyStats::instance().sessionDestroyed();
    NOTICE_LOG << "session destroyed";
    // Log::log_with_endpoint(in_endpoint, "disconnected, " + to_string(recv_len) + " bytes received, " + to_string(sent_len) + " bytes sent, lasted for " + to_string(time(nullptr) - start_time) + " seconds", Log::INFO);
    boost::system::error_code ec;
    resolver_.cancel();

    if (in_socket.is_open()) {
        in_socket.cancel(ec);
        in_socket.shutdown(tcp::socket::shutdown_both, ec);
        in_socket.close(ec);
    }

    if (out_socket.lowest_layer().is_open()) {
        out_socket.lowest_layer().shutdown(tcp::socket::shutdown_both, ec);
        out_socket.lowest_layer().close(ec);
    }

    if (session_id_) {
        server_.unregister_relay(session_id_);
    }
    if (udp_relay_) {
        udp_relay_->stop();
        udp_relay_.reset();
    }
}

void Session::do_handle_socks5_udp_associate()
{
    auto self(shared_from_this());

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

void Session::do_read_control()
{
    auto self(shared_from_this());
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

void Session::on_udp_data_to_server(const std::string& frame)
{
    if (destroyed_) return;

    DEBUG_LOG << "UDP session --> server: " << frame.size() << " bytes";
    auto self(shared_from_this());

    if (out_socket.lowest_layer().is_open()) {
        boost::asio::async_write(out_socket, boost::asio::buffer(frame),
            [this, self](boost::system::error_code ec, std::size_t) {
                if (ec) {
                    DEBUG_LOG << "UDP relay: write to server failed: " << ec.message();
                }
            });
    }
}