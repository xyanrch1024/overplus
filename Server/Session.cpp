#include "Session.h"
#include "Protocol/trojan/UDPPacket.h"
#include "Shared/ConfigManage.h"
#include "Shared/Log.h"
#include <chrono>
#include <cstring>
#include <string>
template<class T>
Session<T>::Session(boost::asio::io_context& ioctx, boost::asio::ssl::context& sslctx)

    : io_context_(ioctx)
    , upstream_socket(ioctx, sslctx)
    , downstream_socket(ioctx)
    , resolver_(ioctx)
    , udp_resolver(ioctx)
    , downstream_udp_socket(ioctx)
    , in_buf(MAX_BUFF_SIZE)
    , out_buf(MAX_BUFF_SIZE)

{
}
template<class T>
void Session<T>::handle_custom_protocol()
{
    auto self = this->shared_from_this();
    upstream_socket.async_read_some(boost::asio::buffer(in_buf),
        [this, self](boost::system::error_code ec, std::size_t length) {
            if (ec) {
                NOTICE_LOG << "read protocol message failed: " << ec.message();
                destroy();
                return;
            }
            bool valid = false;
            if (VRequest::is_v_protocol(in_buf)) {

                valid = v_req.unstream(std::string(in_buf.data(), length));
                password = v_req.password;
                vprotocol = true;
                if (valid) {
                    DEBUG_LOG << "VRequest parsed: user=" << v_req.user_name
                              << " target=" << v_req.address << ":" << v_req.port
                              << " buflen=" << length;
                }
            } else {
                valid = trojanReq.parse(std::string(in_buf.data(), length)) != -1;
                password = trojanReq.password;
            }

            if (valid) {
                //
                if (!ConfigManage::instance().server_cfg.allowed_passwords.count(password)) {
                    ERROR_LOG << "unsupported password, closing session";
                    destroy();
                    return;
                }
                if (vprotocol) {
                    DEBUG_LOG << "password ok, target=" << v_req.address << ":" << v_req.port;
                } else {
                    DEBUG_LOG << "password ok, target=" << trojanReq.address.address << ":" << trojanReq.address.port;
                }

            } else {
                ERROR_LOG << "parse protocol request failed";
                destroy();
                return;
            }
            if (!vprotocol && trojanReq.command == TrojanReq::UDP_ASSOCIATE) {
                upstream_udp_buff = trojanReq.payload;
                handle_trojan_udp_proxy();

            } else {
                do_resolve();
            }
        });
}
template<class T>
void Session<T>::udp_upstream_read()
{
    auto self = this->shared_from_this();
    upstream_socket.async_read_some(boost::asio::buffer(in_buf),
        [this, self](boost::system::error_code ec, std::size_t length) {
            if (!ec) {
                upstream_udp_buff.append(in_buf.data(), length);
                handle_trojan_udp_proxy();

            } else {
                destroy();
            }
        });
}
template<class T>
void Session<T>::handle_trojan_udp_proxy()
{
    state_ = FORWARD;
    UDPPacket udp_packet;
    size_t packet_len;
    std::string remaining(upstream_udp_buff.data() + udp_buff_offset_, upstream_udp_buff.size() - udp_buff_offset_);
    bool is_packet_valid = udp_packet.parse(remaining, packet_len);
    if (!is_packet_valid) {
        if (upstream_udp_buff.size() - udp_buff_offset_ > MAX_BUFF_SIZE) {
            ERROR_LOG << "UDP packet too long, closing session";
            destroy();
            return;
        }
        udp_upstream_read();
        return;
    }
    udp_buff_offset_ += packet_len;
    if (udp_buff_offset_ > MAX_BUFF_SIZE / 2 && udp_buff_offset_ < upstream_udp_buff.size()) {
        upstream_udp_buff.erase(0, udp_buff_offset_);
        udp_buff_offset_ = 0;
    }
    DEBUG_LOG << "udp:" << udp_packet.address.address << ":" << udp_packet.address.port;
    auto self = this->shared_from_this();
    std::string dns_key = udp_packet.address.address + ":" + std::to_string(udp_packet.address.port);
    udp::endpoint cached_ep;
    if (DnsCacheManager::instance().get_udp(dns_key, cached_ep)) {
        auto ep = cached_ep;
        if (!downstream_udp_socket.is_open()) {
            boost::system::error_code ec;
            downstream_udp_socket.open(ep.protocol(), ec);
            if (ec) { destroy(); return; }
        }
        downstream_udp_socket.async_send_to(boost::asio::buffer(udp_packet.payload), ep,
            [this, self](boost::system::error_code ec, std::size_t length) {
                if (!ec)
                    udp_async_bidirectional_read(DIR_BOTH);
                else {
                    if (ec != boost::asio::error::operation_aborted) {
                        ERROR_LOG << "write to downstream (UDP): " << ec.message();
                    }
                    destroy();
                    return;
                }
            });
        return;
    }
    udp_resolver.async_resolve(udp_packet.address.address, std::to_string(udp_packet.address.port), [this, self, udp_packet, dns_key](const boost::system::error_code error, const udp::resolver::results_type& results) {
        if (error || results.empty()) {
            ERROR_LOG << "cannot resolve " << udp_packet.address.address << ": " << error.message();
            destroy();
            return;
        }
        auto iterator = results.begin();
        for (auto it = results.begin(); it != results.end(); ++it) {
            const auto& addr = it->endpoint().address();
            if (addr.is_v4()) {
                iterator = it;
                break;
            }
        }
        DnsCacheManager::instance().put_udp(dns_key, *iterator);
        if (!downstream_udp_socket.is_open()) {
            auto protocol = iterator->endpoint().protocol();
            boost::system::error_code ec;
            downstream_udp_socket.open(protocol, ec);
            if (ec) {
                destroy();
                return;
            }
        }
        downstream_udp_socket.async_send_to(boost::asio::buffer(udp_packet.payload), *iterator,
            [this, self](boost::system::error_code ec, std::size_t length) {
                if (!ec)
                    udp_async_bidirectional_read(DIR_BOTH);
                else {
                    if (ec != boost::asio::error::operation_aborted) {
                        ERROR_LOG << "write to downstream (UDP): " << ec.message();
                    }
                    destroy();
                    return;
                }
            });
        // udp_async_bidirectional_write(1, udp_packet.payload, iterator);
    });
}
template<class T>
void Session<T>::udp_async_bidirectional_read(Direction direction)
{
    auto self = this->shared_from_this();
    // We must divide reads by direction to not permit second read call on the same socket.
    if (direction & DIR_DOWN)
        upstream_socket.async_read_some(boost::asio::buffer(in_buf),
            [this, self](boost::system::error_code ec, std::size_t length) {
                if (!ec) {
                    DEBUG_LOG << "upstream -->: " << std::to_string(length) << " bytes";
                    UDPPacket udp_packet;
                    size_t packet_len;
                    upstream_udp_buff.append(in_buf.data(), length);
                    std::string remaining(upstream_udp_buff.data() + udp_buff_offset_, upstream_udp_buff.size() - udp_buff_offset_);
                    bool is_packet_valid = udp_packet.parse(remaining, packet_len);
                    if (is_packet_valid) {
                        udp_buff_offset_ += packet_len;
                        if (udp_buff_offset_ > MAX_BUFF_SIZE / 2 && udp_buff_offset_ < upstream_udp_buff.size()) {
                            upstream_udp_buff.erase(0, udp_buff_offset_);
                            udp_buff_offset_ = 0;
                        }

                        std::string dns_key = udp_packet.address.address + ":" + std::to_string(udp_packet.address.port);
                        udp::endpoint cached_ep;
                        if (DnsCacheManager::instance().get_udp(dns_key, cached_ep)) {
                            udp_async_bidirectional_write(DIR_DOWN, udp_packet.payload, cached_ep);
                            return;
                        }
                        udp_resolver.async_resolve(udp_packet.address.address, std::to_string(udp_packet.address.port), [this, self, udp_packet, dns_key](const boost::system::error_code error, const udp::resolver::results_type& results) {
                            if (error || results.empty()) {
                                ERROR_LOG << "cannot resolve " << udp_packet.address.address << ": " << error.message();
                                destroy();
                                return;
                            }
                            auto ep = results.begin()->endpoint();
                            for (auto it = results.begin(); it != results.end(); ++it) {
                                const auto& addr = it->endpoint().address();
                                if (addr.is_v4()) {
                                    ep = it->endpoint();
                                    break;
                                }
                            }
                            DnsCacheManager::instance().put_udp(dns_key, ep);
                            udp_async_bidirectional_write(DIR_DOWN, udp_packet.payload, ep);
                        });
                    } else {
                        if (upstream_udp_buff.size() - udp_buff_offset_ > MAX_BUFF_SIZE) {
                            ERROR_LOG << "UDP packet too long, closing session";
                            destroy();
                            return;
                        }
                        udp_async_bidirectional_read(DIR_DOWN);
                    }

                } else // if (ec != boost::asio::error::eof)
                {
                    if (ec != boost::asio::error::eof && ec != boost::asio::error::operation_aborted) {
                        ERROR_LOG << "read from client (UDP): " << ec.message();
                    }

                    destroy();
                    return;
                }
            });

    if (direction & DIR_UP) {
        udp::endpoint udp_sender_endpoint;
        downstream_udp_socket.async_receive_from(boost::asio::buffer(out_buf), udp_sender_endpoint,
            [this, self, udp_sender_endpoint](boost::system::error_code ec, std::size_t length) {
                if (!ec) {

                    DEBUG_LOG << "<-- downstream: " << std::to_string(length) << " bytes";
                    auto packet = UDPPacket::generate(udp_sender_endpoint, std::string(out_buf.data(), length));

                    udp_async_bidirectional_write(DIR_UP, packet, boost::asio::ip::udp::endpoint());
                } else // if (ec != boost::asio::error::eof)
                {
                    if (ec != boost::asio::error::eof && ec != boost::asio::error::operation_aborted) {
                        ERROR_LOG << "read from downstream (UDP): " << ec.message();
                    }


                    destroy();
                    return;
                }
            });
    }
}
template<class T>
void Session<T>::udp_async_bidirectional_write(Direction direction, const std::string& packet, boost::asio::ip::udp::endpoint udp_ep)
{
    auto self(this->shared_from_this());

    switch (direction) {
    case DIR_DOWN:
        downstream_udp_socket.async_send_to(boost::asio::buffer(packet), udp_ep,
            [this, self, direction](boost::system::error_code ec, std::size_t length) {
                if (!ec)
                    udp_async_bidirectional_read(direction);
                else {
                    if (ec != boost::asio::error::operation_aborted) {
                        ERROR_LOG << "write to downstream (UDP): " << ec.message();
                    }

                    destroy();
                    return;
                }
            });
        break;
    case DIR_UP:
        upstream_udp_write(direction, packet);
        break;
    }
}
template<class T>
void Session<T>::do_resolve()
{
    auto self(this->shared_from_this());
    remote_host = vprotocol ? v_req.address : trojanReq.address.address;
    remote_port = std::to_string(vprotocol ? v_req.port : trojanReq.address.port);

    std::string dns_key = remote_host + ":" + remote_port;
    tcp::endpoint cached_ep;
    if (DnsCacheManager::instance().get_tcp(dns_key, cached_ep)) {
        DEBUG_LOG << "dns cache hit: " << dns_key << " -> " << cached_ep;
        do_connect(cached_ep);
        return;
    }

    DEBUG_LOG << "resolving " << remote_host << ":" << remote_port;
    resolver_.async_resolve(remote_host, remote_port,
        [this, self, dns_key](const boost::system::error_code& ec, tcp::resolver::results_type results) {
            if (!ec && !results.empty()) {
                auto ep = *results.begin();
                DEBUG_LOG << "resolve ok: " << dns_key << " -> " << ep.endpoint();
                DnsCacheManager::instance().put_tcp(dns_key, ep);
                do_connect(ep);
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
    state_ = FORWARD;
    downstream_socket.async_connect(endpoint,
        [this, self](const boost::system::error_code& ec) {
            if (!ec) {
                boost::asio::socket_base::keep_alive option(true);
                downstream_socket.set_option(option);
                downstream_socket.set_option(boost::asio::ip::tcp::no_delay(true));
                DEBUG_LOG << "connected to " << remote_host << ":" << remote_port;

                if (vprotocol && !v_req.packed_buff.empty() || !vprotocol && !trojanReq.payload.empty()) {
                    DEBUG_LOG << "payload not empty";

                    boost::asio::async_write(downstream_socket, boost::asio::buffer(vprotocol ? v_req.packed_buff : trojanReq.payload),
                        [this, self](boost::system::error_code ec, std::size_t length) {
                            if (!ec)
                                async_bidirectional_read(DIR_BOTH);
                            else {
                                ERROR_LOG << "write payload to downstream failed " << ec.message();
                                destroy();
                                return;
                            }
                        });
                }
                // read packet from both direction
                else
                    async_bidirectional_read(DIR_BOTH);

            } else {
                ERROR_LOG << "failed to connect " << remote_host << ":" << remote_port << " " << ec.message();
                destroy();
            }
        });
}
template<class T>
void Session<T>::async_bidirectional_read(Direction direction)
{
    auto self = this->shared_from_this();
    // We must divide reads by direction to not permit second read call on the same socket.
    if (direction & DIR_DOWN)
        upstream_socket.async_read_some(boost::asio::buffer(in_buf),
            [this, self](boost::system::error_code ec, std::size_t length) {
                if (state_ == DESTROY)
                    return;
                if (!ec) {
                    async_bidirectional_write(DIR_DOWN, length);
                } else // if (ec != boost::asio::error::eof)
                {
                    if (ec != boost::asio::error::eof && ec != boost::asio::error::operation_aborted) {
                        DEBUG_LOG << "read from client: " << ec.message();
                    }
                    destroy();
                    return;
                }
            });

    if (direction & DIR_UP)
        downstream_socket.async_read_some(boost::asio::buffer(out_buf),
            [this, self](boost::system::error_code ec, std::size_t length) {
                if (state_ == DESTROY)
                    return;
                if (!ec) {
                    async_bidirectional_write(DIR_UP, length);
                } else // if (ec != boost::asio::error::eof)
                {
                    if (ec != boost::asio::error::eof && ec != boost::asio::error::operation_aborted) {
                        DEBUG_LOG << "read from downstream: " << ec.message();
                    }
                    destroy();
                    return;
                }
            });
}
template<class T>
void Session<T>::async_bidirectional_write(Direction direction, size_t len)
{
    switch (direction) {
    case DIR_DOWN:
        enqueue_write(DIR_DOWN, in_buf.data(), len);
        if (ring_down_.has_space(MAX_BUFF_SIZE)) {
            async_bidirectional_read(DIR_DOWN);
        } else {
            pausing_down_ = true;
        }
        break;
    case DIR_UP:
        enqueue_write(DIR_UP, out_buf.data(), len);
        if (ring_up_.has_space(MAX_BUFF_SIZE)) {
            async_bidirectional_read(DIR_UP);
        } else {
            pausing_up_ = true;
        }
        break;
    }
}

template<class T>
void Session<T>::enqueue_write(Direction direction, const char* data, size_t len)
{
    auto& ring = (direction == DIR_DOWN) ? ring_down_ : ring_up_;
    auto& sending = (direction == DIR_DOWN) ? sending_down_ : sending_up_;

    size_t remaining = len;
    size_t offset = 0;
    while (remaining > 0) {
        size_t n = remaining;
        auto buf = ring.prepare(n);
        if (n == 0) break;
        std::memcpy(buf.data(), data + offset, n);
        ring.commit(n);
        offset += n;
        remaining -= n;
    }

    if (!sending) {
        sending = true;
        direction == DIR_DOWN ? do_send_down() : do_send_up();
    }
}

template<class T>
void Session<T>::do_send_down()
{
    if (ring_down_.empty()) {
        sending_down_ = false;
        if (pausing_down_) {
            pausing_down_ = false;
            async_bidirectional_read(DIR_DOWN);
        }
        return;
    }

    auto self = this->shared_from_this();
    auto buf = ring_down_.peek();

    downstream_socket.async_send(buf,
        [this, self](boost::system::error_code ec, std::size_t bytes_sent) {
            if (ec) {
                if (ec != boost::asio::error::operation_aborted) {
                    DEBUG_LOG << "downstream send failed: " << ec.message();
                }
                destroy();
                return;
            }

            ring_down_.consume(bytes_sent);
            do_send_down();
        });
}

template<class T>
void Session<T>::do_send_up()
{
    if (ring_up_.empty()) {
        sending_up_ = false;
        if (pausing_up_) {
            pausing_up_ = false;
            async_bidirectional_read(DIR_UP);
        }
        return;
    }

    auto self = this->shared_from_this();
    auto buf = ring_up_.peek();

    upstream_tcp_write_send(
        reinterpret_cast<const char*>(buf.data()), buf.size(),
        [this, self](boost::system::error_code ec, std::size_t bytes_sent) {
            if (ec) {
                if (ec != boost::asio::error::operation_aborted) {
                    DEBUG_LOG << "upstream send failed: " << ec.message();
                }
                destroy();
                return;
            }

            ring_up_.consume(bytes_sent);
            do_send_up();
        });
}

template<class T>
void Session<T>::upstream_tcp_write(Direction direction, size_t len)
{
    assert(0);
}
template<class T>
void Session<T>::upstream_tcp_write_send(const char* data, size_t len, SendCallback handler)
{
    (void)data; (void)len; (void)handler;
    assert(0);
}
template<class T>
void Session<T>::upstream_udp_write(Direction direction, const std::string& packet)
{
    assert(0);
}
template<class T>
void Session<T>::destroy()
{
    DEBUG_LOG << "session destroyed";
    ring_down_.reset();
    ring_up_.reset();
    sending_down_ = false;
    sending_up_ = false;
    pausing_down_ = false;
    pausing_up_ = false;
    boost::system::error_code ec;
    if (downstream_udp_socket.is_open()) {
        downstream_udp_socket.cancel(ec);
        downstream_udp_socket.close();
    }
    if (downstream_socket.is_open()) {
        downstream_socket.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
        downstream_socket.cancel();
        downstream_socket.close();
    }
}