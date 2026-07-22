#include "Server.h"
#include "UdpRelay.h"
#include "Shared/ConfigManage.h"
#include "Shared/ProxyStats.h"
#include <boost/asio/io_context.hpp>
#include <cstdlib>
#include <memory>

Server::Server(const std::string& address, const std::string& port)
    : io_context()
    , work_guard_(boost::asio::make_work_guard(io_context))
    , acceptor_(io_context)
    , ssl_ctx(boost::asio::ssl::context::tlsv13)
{
    ip::tcp::resolver resover(io_context);
    local_endpoint = *resover.resolve(address, port).begin();
    auto& cfg = ConfigManage::instance().client_cfg;
    useWebSocket_ = cfg.useWebSocket;
}

void Server::start_accept()
{
    boost::asio::post(io_context, [this]() {
        acceptor_.open(local_endpoint.protocol());
        acceptor_.set_option(ip::tcp::acceptor::reuse_address(true));
        acceptor_.bind(local_endpoint);
        acceptor_.listen();
        do_accept();
    });
}

void Server::start_dtls()
{
    auto& cfg = ConfigManage::instance().client_cfg;
    if (!cfg.udp_enabled) {
        NOTICE_LOG << "UDP disabled, skipping DTLS setup";
        return;
    }

    uint16_t dtls_port = static_cast<uint16_t>(
        std::stoi(cfg.dtls_port.empty() ? cfg.remote_port : cfg.dtls_port));

    dtls_ = std::make_unique<DtlsChannel>(io_context, cfg.remote_addr, dtls_port, cfg.text_password);

    dtls_->start(
        [this](bool ok) {
            if (ok) {
                NOTICE_LOG << "Shared DTLS connected";
                dtls_ready_ = true;
                for (auto& [sid, relay] : relays_) {
                    relay->flush_pending();
                }
            } else {
                ERROR_LOG << "Shared DTLS handshake failed";
            }
        },
        [this](const char* data, size_t len) {
            on_dtls_data(data, len);
        });
}

void Server::register_relay(uint16_t sid, UdpRelay* relay)
{
    relays_[sid] = relay;
}

void Server::unregister_relay(uint16_t sid)
{
    relays_.erase(sid);
}

void Server::on_dtls_data(const char* data, size_t len)
{
    if (len < 2) return;
    uint16_t sid = (static_cast<uint8_t>(data[0]) << 8) | static_cast<uint8_t>(data[1]);

    auto it = relays_.find(sid);
    if (it != relays_.end()) {
        it->second->on_dtls_data(data + 2, len - 2);
    } else {
        NOTICE_LOG << "Shared DTLS: no relay for session_id=" << sid;
    }
}

void Server::do_accept()
{
    if (useWebSocket_) {
        do_accept_ws();
    } else {
        do_accept_tls();
    }
}

void Server::do_accept_tls()
{
    tls_session_ = std::make_shared<TlsClientSession>(io_context, ssl_ctx, *this);
    acceptor_.async_accept(tls_session_->socket(), [this](const boost::system::error_code& ec) {
        if (!acceptor_.is_open()) {
            return;
        }
        if (ec == boost::asio::error::operation_aborted) {
            NOTICE_LOG << "got cancel signal, stop calling myself";
            return;
        }
        if (!ec) {
            boost::system::error_code error;
            auto ep = tls_session_->socket().remote_endpoint(error);
            NOTICE_LOG << "accept incoming connection :" << ep.address().to_string();
            tls_session_->start();
            ProxyStats::instance().sessionCreated();
        } else {
            NOTICE_LOG << "accept incoming connection fail:" << ec.message();
        }
        do_accept_tls();
    });
}

void Server::do_accept_ws()
{
    ws_session_ = std::make_shared<WsClientSession>(io_context, ssl_ctx, *this);
    acceptor_.async_accept(ws_session_->socket(), [this](const boost::system::error_code& ec) {
        if (!acceptor_.is_open()) {
            return;
        }
        if (ec == boost::asio::error::operation_aborted) {
            NOTICE_LOG << "got cancel signal, stop calling myself";
            return;
        }
        if (!ec) {
            boost::system::error_code error;
            auto ep = ws_session_->socket().remote_endpoint(error);
            NOTICE_LOG << "accept incoming connection :" << ep.address().to_string();
            ws_session_->start();
            ProxyStats::instance().sessionCreated();
        } else {
            NOTICE_LOG << "accept incoming connection fail:" << ec.message();
        }
        do_accept_ws();
    });
}

void Server::run()
{
    NOTICE_LOG << "Server start..." << std::endl;
    io_context.run();
}
void Server::stop()
{
    NOTICE_LOG << "Server stopped..." << std::endl;
    work_guard_.reset();
    io_context.stop();
}
void Server::stop_dtls()
{
    boost::asio::post(io_context, [this]() {
        if (dtls_) {
            dtls_->stop();
            dtls_.reset();
        }
        dtls_ready_ = false;
    });
}

void Server::stop_accept()
{
    boost::asio::post(io_context, [this]() {
        if (acceptor_.is_open()) {
            acceptor_.cancel();
            acceptor_.close();
        }
    });
}
