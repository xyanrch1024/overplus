#include "Server.h"
#include "UdpRelay.h"
#include "Shared/ConfigManage.h"
#include "Shared/ProxyStats.h"
#include <boost/asio/io_context.hpp>
#include <cstdlib>
#include <memory>

Server::Server(const std::string& address, const std::string& port)
    : context_pool(2)
    , io_context(context_pool.get_io_context())
    , acceptor_(io_context)
    , ssl_ctx(boost::asio::ssl::context::tlsv13)
{
    add_signals();
    ip::tcp::resolver resover(io_context);
    local_endpoint = *resover.resolve(address, port).begin();
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
    uint16_t dtls_port = static_cast<uint16_t>(
        std::stoi(cfg.dtls_port.empty() ? cfg.remote_port : cfg.dtls_port));

    dtls_ = std::make_unique<DtlsChannel>(io_context, cfg.remote_addr, dtls_port, cfg.text_password);

    dtls_->start(
        [this](bool ok) {
            if (ok) {
                NOTICE_LOG << "Shared DTLS connected";
                dtls_ready_ = true;
                std::lock_guard<std::mutex> lock(relays_mutex_);
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
    std::lock_guard<std::mutex> lock(relays_mutex_);
    relays_[sid] = relay;
}

void Server::unregister_relay(uint16_t sid)
{
    std::lock_guard<std::mutex> lock(relays_mutex_);
    relays_.erase(sid);
}

void Server::on_dtls_data(const char* data, size_t len)
{
    if (len < 2) return;
    uint16_t sid = (static_cast<uint8_t>(data[0]) << 8) | static_cast<uint8_t>(data[1]);

    std::lock_guard<std::mutex> lock(relays_mutex_);
    auto it = relays_.find(sid);
    if (it != relays_.end()) {
        it->second->on_dtls_data(data + 2, len - 2);
    } else {
        NOTICE_LOG << "Shared DTLS: no relay for session_id=" << sid;
    }
}
void Server::do_accept()
{
    std::shared_ptr<Session> new_session = std::make_shared<Session>(context_pool.get_io_context(), ssl_ctx, *this);
    acceptor_.async_accept(new_session->socket(), [this, new_session](const boost::system::error_code& ec) {
        if (!acceptor_.is_open()) {
            return;
        }
        if (ec == boost::asio::error::operation_aborted) {
            NOTICE_LOG << "got cancel signal, stop calling myself";
            return;
        }
        if (!ec) {
            boost::system::error_code error;
            auto ep = new_session->socket().remote_endpoint(error);
            NOTICE_LOG << "accept incoming connection :" << ep.address().to_string();
            new_session->start();
            ProxyStats::instance().sessionCreated();
        } else {
            NOTICE_LOG << "accept incoming connection fail:" << ec.message();
        }
        do_accept();
    });
}
void Server::run()
{
    NOTICE_LOG << "Server start..." << std::endl;
    context_pool.run();
}
void Server::stop()
{
    NOTICE_LOG << "Server stopped..." << std::endl;
    context_pool.stop();
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
void Server::add_signals()
{
   /* signals.add(SIGINT);
    signals.add(SIGTERM);
#ifdef SIGQUIT
    signals.add(SIGQUIT);
#endif
    signals.async_wait([this](const boost::system::error_code& ec, int sig) {
        acceptor_.close();

        NOTICE_LOG << "Server stopped..." << std::endl;
        exit(1);
    });*/
}
