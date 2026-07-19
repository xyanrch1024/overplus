#include "DtlsChannel.h"
#include "Log.h"
#include <cstring>

DtlsChannel::DtlsChannel(boost::asio::io_context& io_ctx,
                           const std::string& server_addr,
                           uint16_t server_port,
                           const std::string& password)
    : io_ctx_(io_ctx)
    , socket_(io_ctx, boost::asio::ip::udp::endpoint(boost::asio::ip::udp::v4(), 0))
    , timer_(io_ctx)
    , password_(password)
{
    boost::asio::ip::address addr = boost::asio::ip::make_address(server_addr);
    server_ep_ = boost::asio::ip::udp::endpoint(addr, server_port);

    SSL_CTX* ctx = ::SSL_CTX_new(::DTLS_client_method());
    if (!ctx) {
        ERROR_LOG << "DTLS: failed to create SSL context";
        return;
    }

    ::SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);

    ssl_ = ::SSL_new(ctx);
    ::SSL_CTX_free(ctx);

    if (!ssl_) {
        ERROR_LOG << "DTLS: failed to create SSL object";
        return;
    }

    ::SSL_set_connect_state(ssl_);
    ::SSL_set_mtu(ssl_, 1400);

    read_bio_ = ::BIO_new(::BIO_s_mem());
    write_bio_ = ::BIO_new(::BIO_s_mem());
    ::SSL_set_bio(ssl_, read_bio_, write_bio_);
}

DtlsChannel::~DtlsChannel()
{
    stop();
    if (ssl_) {
        ::SSL_free(ssl_);
        ssl_ = nullptr;
    }
}

void DtlsChannel::start(HandshakeCallback on_handshake, DataCallback on_data)
{
    on_handshake_ = std::move(on_handshake);
    on_data_ = std::move(on_data);
    running_ = true;
    do_receive();
    do_handshake();
}

void DtlsChannel::stop()
{
    running_ = false;
    boost::system::error_code ec;
    timer_.cancel();
    socket_.cancel(ec);
    if (ssl_) {
        ::SSL_shutdown(ssl_);
    }
}

void DtlsChannel::do_handshake()
{
    if (!ssl_ || !running_ || handshake_done_) {
        return;
    }

    int ret = ::SSL_do_handshake(ssl_);
    drain_write_bio();

    if (ret <= 0) {
        int err = ::SSL_get_error(ssl_, ret);
        DEBUG_LOG << "DTLS handshake: SSL_do_handshake ret=" << ret << " err=" << err;
        if (err == SSL_ERROR_WANT_READ) {
            struct timeval timeout;
            std::memset(&timeout, 0, sizeof(timeout));
            ::DTLSv1_get_timeout(ssl_, &timeout);
            auto duration = std::chrono::seconds(timeout.tv_sec)
                          + std::chrono::microseconds(timeout.tv_usec);
            if (duration.count() == 0) {
                duration = std::chrono::milliseconds(500);
            }
            DEBUG_LOG << "DTLS handshake: setting timer " << duration.count() << "us";
            timer_.expires_after(duration);
            timer_.async_wait([this](boost::system::error_code ec) {
                if (!ec && running_) handle_timeout();
            });
        } else if (err == SSL_ERROR_WANT_WRITE) {
            timer_.expires_after(std::chrono::milliseconds(100));
            timer_.async_wait([this](boost::system::error_code ec) {
                if (!ec && running_) do_handshake();
            });
        } else {
            ERROR_LOG << "DTLS handshake failed: " << err;
            if (on_handshake_) on_handshake_(false);
        }
    } else {
        handshake_done_ = true;
        NOTICE_LOG << "DTLS handshake completed";

        std::string auth = password_ + "\n";
        send(auth);

        if (on_handshake_) on_handshake_(true);
    }
}

void DtlsChannel::drain_write_bio()
{
    char buf[65535];
    int n;
    while ((n = ::BIO_read(write_bio_, buf, sizeof(buf))) > 0) {
        DEBUG_LOG << "DTLS drain_write_bio: sending " << n << " bytes to " << server_ep_.address().to_string() << ":" << server_ep_.port();
        socket_.async_send_to(
            boost::asio::buffer(buf, n), server_ep_,
            [](boost::system::error_code ec, std::size_t sent) {
                if (ec) {
                    ERROR_LOG << "DTLS send failed: " << ec.message();
                }
            });
    }
}

void DtlsChannel::handle_timeout()
{
    if (!ssl_ || !running_) return;

    ::DTLSv1_handle_timeout(ssl_);
    do_handshake();
}

void DtlsChannel::do_receive()
{
    if (!running_) return;

    socket_.async_receive_from(
        boost::asio::buffer(recv_buf_), sender_ep_,
        [this](boost::system::error_code ec, std::size_t len) {
            on_receive(ec, len);
        });
}

void DtlsChannel::on_receive(boost::system::error_code ec, std::size_t len)
{
    if (ec || !running_) {
        if (ec != boost::asio::error::operation_aborted) {
            DEBUG_LOG << "DTLS receive error: " << ec.message();
        }
        return;
    }

    DEBUG_LOG << "DTLS recv " << len << " bytes, handshake_done=" << handshake_done_;
    ::BIO_write(read_bio_, recv_buf_.data(), len);

    if (!handshake_done_) {
        do_handshake();
    } else {
        char buf[65535];
        int n = ::SSL_read(ssl_, buf, sizeof(buf));
        if (n > 0) {
            if (on_data_) {
                on_data_(buf, n);
            }
        } else {
            int err = ::SSL_get_error(ssl_, n);
            if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_ZERO_RETURN) {
                DEBUG_LOG << "DTLS SSL_read error: " << err;
            }
        }
    }

    do_receive();
}

void DtlsChannel::send(const std::string& data)
{
    if (!ssl_ || !handshake_done_ || !running_) return;

    int ret = ::SSL_write(ssl_, data.data(), data.size());
    if (ret <= 0) {
        int err = ::SSL_get_error(ssl_, ret);
        DEBUG_LOG << "DTLS SSL_write error: " << err;
        return;
    }

    drain_write_bio();
}
