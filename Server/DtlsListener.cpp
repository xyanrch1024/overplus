#include "DtlsListener.h"
#include "Shared/Log.h"
#include <cstring>

using boost::asio::ip::udp;

DtlsListener::DtlsListener(boost::asio::io_context& io_ctx,
                           const std::string& cert_path,
                           const std::string& key_path,
                           const std::string& addr,
                           const std::string& port)
    : io_ctx_(io_ctx)
    , socket_(io_ctx)
{
    dtls_ctx_ = SSL_CTX_new(DTLS_server_method());
    if (!dtls_ctx_) {
        ERROR_LOG << "DTLS: failed to create SSL context";
        return;
    }

    SSL_CTX_set_options(dtls_ctx_, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);

    if (SSL_CTX_use_certificate_chain_file(dtls_ctx_, cert_path.c_str()) <= 0) {
        ERROR_LOG << "DTLS: failed to load certificate: " << cert_path;
        ERR_print_errors_fp(stderr);
        return;
    }

    if (SSL_CTX_use_PrivateKey_file(dtls_ctx_, key_path.c_str(), SSL_FILETYPE_PEM) <= 0) {
        ERROR_LOG << "DTLS: failed to load private key: " << key_path;
        ERR_print_errors_fp(stderr);
        return;
    }

    if (!SSL_CTX_check_private_key(dtls_ctx_)) {
        ERROR_LOG << "DTLS: private key does not match certificate";
        return;
    }

    udp::resolver resolver(io_ctx);
    udp::endpoint endpoint = *resolver.resolve(addr, port).begin();

    socket_.open(udp::v4());
    socket_.set_option(boost::asio::socket_base::reuse_address(true));
    socket_.bind(endpoint);

    NOTICE_LOG << "DTLS listener bound on "
               << endpoint.address().to_string() << ":" << endpoint.port();
}

DtlsListener::~DtlsListener()
{
    stop();
}

void DtlsListener::start()
{
    do_receive();
}

void DtlsListener::stop()
{
    boost::system::error_code ec;
    socket_.cancel(ec);
    socket_.close(ec);

    for (auto& [ep, session] : sessions_) {
        session->stop();
    }
    sessions_.clear();

    if (dtls_ctx_) {
        SSL_CTX_free(dtls_ctx_);
        dtls_ctx_ = nullptr;
    }
}

void DtlsListener::do_receive()
{
    socket_.async_receive_from(
        boost::asio::buffer(recv_buf_), sender_ep_,
        [this](boost::system::error_code ec, std::size_t len) {
            if (ec) {
                if (ec != boost::asio::error::operation_aborted) {
                    DEBUG_LOG << "DTLS listener receive error: " << ec.message();
                    do_receive();
                }
                return;
            }

            auto it = sessions_.find(sender_ep_);
            if (it != sessions_.end()) {
                it->second->on_datagram(recv_buf_.data(), len);
            } else {
                auto session = std::make_shared<DtlsServerSession>(
                    io_ctx_, dtls_ctx_, socket_, sender_ep_,
                    [this](const udp::endpoint& ep) { remove_session(ep); });
                sessions_[sender_ep_] = session;
                session->on_datagram(recv_buf_.data(), len);
            }

            do_receive();
        });
}

void DtlsListener::remove_session(const udp::endpoint& ep)
{
    sessions_.erase(ep);
    NOTICE_LOG << "DTLS session removed, total sessions: " << sessions_.size();
}
