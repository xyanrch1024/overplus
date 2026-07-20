#include "DtlsServerSession.h"
#include "Protocol/UdpFrame.h"
#include "Shared/ConfigManage.h"
#include "Shared/DnsCache.h"
#include "Shared/Log.h"
#include <cstring>

using boost::asio::ip::udp;

DtlsServerSession::DtlsServerSession(boost::asio::io_context& io_ctx,
                                     SSL_CTX* dtls_ctx,
                                     udp::socket& shared_socket,
                                     const udp::endpoint& client_ep,
                                     DestroyCallback on_destroy)
    : io_ctx_(io_ctx)
    , shared_socket_(shared_socket)
    , client_ep_(client_ep)
    , target_socket_(io_ctx, udp::v4())
    , resolver_(io_ctx)
    , on_destroy_(std::move(on_destroy))
{
    ssl_ = SSL_new(dtls_ctx);
    rbio_ = BIO_new(BIO_s_mem());
    wbio_ = BIO_new(BIO_s_mem());
    SSL_set_bio(ssl_, rbio_, wbio_);

    NOTICE_LOG << "DTLS server session created for "
               << client_ep_.address().to_string() << ":" << client_ep_.port();
}

DtlsServerSession::~DtlsServerSession()
{
    stop();
}

void DtlsServerSession::stop()
{
    if (destroyed_) return;
    destroyed_ = true;
    state_ = DESTROY;

    boost::system::error_code ec;
    target_socket_.cancel(ec);
    target_socket_.close(ec);
    resolver_.cancel();

    if (ssl_) {
        SSL_shutdown(ssl_);
        SSL_free(ssl_);
        ssl_ = nullptr;
        rbio_ = nullptr;
        wbio_ = nullptr;
    }

    if (on_destroy_) {
        on_destroy_(client_ep_);
    }
}

void DtlsServerSession::on_datagram(const char* data, size_t len)
{
    if (state_ == DESTROY || !ssl_) return;

    BIO_write(rbio_, data, static_cast<int>(len));

    DEBUG_LOG << "DTLS on_datagram " << len << " bytes, state=" << (int)state_;

    if (state_ == HANDSHAKE) {
        process_handshake();
    } else if (state_ == AUTH) {
        try_read_app_data();
    } else if (state_ == PROXY) {
        try_read_app_data();
    }
}

void DtlsServerSession::process_handshake()
{
    if (!ssl_) return;

    int ret = SSL_accept(ssl_);
    drain_wbio();

    if (ret > 0) {
        NOTICE_LOG << "DTLS handshake completed with "
                   << client_ep_.address().to_string() << ":" << client_ep_.port();
        state_ = AUTH;
        try_read_app_data();
    } else {
        int err = SSL_get_error(ssl_, ret);
        if (err == SSL_ERROR_WANT_READ) {
            DEBUG_LOG << "DTLS handshake: want read, waiting for next packet";
        } else {
            ERROR_LOG << "DTLS handshake failed: " << err;
            destroy();
        }
    }
}

void DtlsServerSession::drain_wbio()
{
    char buf[65535];
    int n;
    while ((n = BIO_read(wbio_, buf, sizeof(buf))) > 0) {
        boost::system::error_code ec;
        shared_socket_.send_to(boost::asio::buffer(buf, n), client_ep_, 0, ec);
    }
}

void DtlsServerSession::try_read_app_data()
{
    if (!ssl_) return;

    char buf[65535];
    int n = SSL_read(ssl_, buf, sizeof(buf) - 1);
    if (n > 0) {
        buf[n] = '\0';
        DEBUG_LOG << "DTLS SSL_read returned " << n << " bytes, state=" << (int)state_;

        if (state_ == AUTH) {
            start_auth();
            auth_buf_.append(buf, n);
            size_t pos = auth_buf_.find('\n');
            if (pos != std::string::npos) {
                std::string password_line = auth_buf_.substr(0, pos);

                auto& cfg = ConfigManage::instance().server_cfg;
                std::string hashed;
                {
                    uint8_t digest[32];
                    char mdString[65];
                    unsigned int digest_len;
                    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
                    EVP_DigestInit_ex(ctx, EVP_sha224(), nullptr);
                    EVP_DigestUpdate(ctx, password_line.c_str(), password_line.size());
                    EVP_DigestFinal_ex(ctx, digest, &digest_len);
                    EVP_MD_CTX_free(ctx);
                    for (unsigned int i = 0; i < digest_len; ++i)
                        sprintf(mdString + (i << 1), "%02x", (unsigned int)digest[i]);
                    mdString[digest_len << 1] = '\0';
                    hashed = mdString;
                }

                if (cfg.allowed_passwords.count(hashed)) {
                    NOTICE_LOG << "DTLS auth success from "
                               << client_ep_.address().to_string() << ":" << client_ep_.port();
                    start_proxy();
                } else {
                    ERROR_LOG << "DTLS auth failed from "
                              << client_ep_.address().to_string() << ":" << client_ep_.port();
                    destroy();
                }
            }
        } else if (state_ == PROXY) {
            std::string data(buf, n);
            NOTICE_LOG << "DTLS PROXY recv " << n << " bytes";

            if (data.size() < 2) {
                DEBUG_LOG << "DTLS PROXY: too short for session_id";
                return;
            }
            uint16_t session_id = (static_cast<uint8_t>(data[0]) << 8)
                                | static_cast<uint8_t>(data[1]);
            std::string frame_data = data.substr(2);

            size_t frame_len = 0;
            UdpFrame frame;
            if (frame.parse(frame_data, frame_len)) {
                NOTICE_LOG << "DTLS recv UDP frame: session_id=" << session_id
                          << " " << frame.addr_str()
                          << " payload=" << frame.payload.size();

                if (frame.addr_type == UdpFrame::ADDR_DOMAIN) {
                    do_resolve_and_send(frame.address, frame.port, frame.payload, session_id);
                } else if (frame.addr_type == UdpFrame::ADDR_IPV4) {
                    const auto* p = reinterpret_cast<const uint8_t*>(frame.address.data());
                    uint32_t ip = (static_cast<uint32_t>(p[0]) << 24)
                                | (static_cast<uint32_t>(p[1]) << 16)
                                | (static_cast<uint32_t>(p[2]) << 8)
                                |  static_cast<uint32_t>(p[3]);
                    udp::endpoint ep(boost::asio::ip::address_v4(ip), frame.port);
                    do_send_to_target(ep, frame.payload, session_id);
                } else if (frame.addr_type == UdpFrame::ADDR_IPV6) {
                    boost::asio::ip::address_v6::bytes_type bytes;
                    std::memcpy(bytes.data(), frame.address.data(), 16);
                    udp::endpoint ep(boost::asio::ip::address_v6(bytes), frame.port);
                    do_send_to_target(ep, frame.payload, session_id);
                }
            } else {
                DEBUG_LOG << "DTLS: invalid UdpFrame from client";
            }
        }
    } else {
        int err = SSL_get_error(ssl_, n);
        if (err == SSL_ERROR_WANT_READ) {
            // normal, wait for next datagram
        } else if (err == SSL_ERROR_ZERO_RETURN) {
            NOTICE_LOG << "DTLS connection closed by client";
            destroy();
        } else {
            DEBUG_LOG << "DTLS SSL_read error: " << err;
        }
    }
}

void DtlsServerSession::start_auth()
{
    state_ = AUTH;
    auth_buf_.clear();
}

void DtlsServerSession::start_proxy()
{
    state_ = PROXY;
    do_read_target();
}

void DtlsServerSession::do_resolve_and_send(std::string domain, uint16_t port, const std::string& payload, uint16_t session_id)
{
    auto self(shared_from_this());

    udp::endpoint cached_ep;
    if (DnsCacheManager::instance().get_udp(domain + ":" + std::to_string(port), cached_ep)) {
        do_send_to_target(cached_ep, payload, session_id);
        return;
    }

    resolver_.async_resolve(domain, std::to_string(port),
        [this, self, domain, port, payload, session_id](boost::system::error_code ec, udp::resolver::results_type results) {
            if (ec) {
                DEBUG_LOG << "DTLS DNS resolve failed for " << domain << ": " << ec.message();
                return;
            }
            auto ep = *results.begin();
            DnsCacheManager::instance().put_udp(domain + ":" + std::to_string(port), ep);
            do_send_to_target(ep, payload, session_id);
        });
}

void DtlsServerSession::do_send_to_target(const udp::endpoint& target_ep, const std::string& payload, uint16_t session_id)
{
    target_ep_ = target_ep;
    if (session_id) {
        target_to_session_[target_ep] = session_id;
    }
    auto self(shared_from_this());

    NOTICE_LOG << "DTLS sending " << payload.size() << " bytes to target "
              << target_ep.address().to_string() << ":" << target_ep.port()
              << " session_id=" << session_id;

    target_socket_.async_send_to(
        boost::asio::buffer(payload), target_ep_,
        [this, self](boost::system::error_code ec, std::size_t) {
            if (ec) {
                DEBUG_LOG << "DTLS send to target failed: " << ec.message();
            }
        });
}

void DtlsServerSession::do_read_target()
{
    if (state_ == DESTROY) return;

    auto self(shared_from_this());
    auto sender_ep = std::make_shared<udp::endpoint>();

    target_socket_.async_receive_from(
        boost::asio::buffer(target_recv_buf_), *sender_ep,
        [this, self, sender_ep](boost::system::error_code ec, std::size_t len) {
            if (ec) {
                if (ec != boost::asio::error::operation_aborted) {
                    DEBUG_LOG << "DTLS target recv error: " << ec.message();
                }
                if (ec != boost::asio::error::operation_aborted) {
                    do_read_target();
                }
                return;
            }

            uint16_t session_id = 0;
            auto it = target_to_session_.find(*sender_ep);
            if (it != target_to_session_.end()) {
                session_id = it->second;
            }

            std::string frame = UdpFrame::generate(*sender_ep,
                std::string(target_recv_buf_.data(), len));

            std::string resp;
            resp += char(session_id >> 8);
            resp += char(session_id & 0xFF);
            resp += frame;
            send_to_client(resp);
            do_read_target();
        });
}

void DtlsServerSession::send_to_client(const std::string& data)
{
    if (!ssl_ || state_ == DESTROY) return;

    NOTICE_LOG << "DTLS send_to_client " << data.size() << " bytes";

    int ret = SSL_write(ssl_, data.data(), static_cast<int>(data.size()));
    if (ret <= 0) {
        int err = SSL_get_error(ssl_, ret);
        DEBUG_LOG << "DTLS SSL_write error: " << err;
        return;
    }

    drain_wbio();
}
