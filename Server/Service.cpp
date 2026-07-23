#include "Service.h"
#include "Server/TlsSession.h"
#include "Shared/Log.h"
#include <boost/asio/io_context.hpp>
#include <boost/system/error_code.hpp>
#include <chrono>
#include <cstdlib>
#include <cstring>
//#include <filesystem>
#include <memory>
#include <string>
#include <thread>
#include <openssl/ssl.h>

static size_t get_thread_count() {
    auto &cfg = ConfigManage::instance().server_cfg;
    if (cfg.thread_count > 0) return cfg.thread_count;
    auto n = std::thread::hardware_concurrency();
    return n > 0 ? n : 4;
}

Service::Service()
        : context_pool(get_thread_count()), io_context(context_pool.get_io_context()), signals(io_context), acceptor_(io_context),
          ssl_context_(boost::asio::ssl::context::sslv23), dns_cleanup_timer_(io_context) {

    auto &config_manage = ConfigManage::instance();
    add_signals();
    start_dns_cleanup_timer();
    ip::tcp::resolver resover(io_context);
    ip::tcp::endpoint endpoint = *resover.resolve(config_manage.server_cfg.local_addr,
                                                  config_manage.server_cfg.local_port).begin();
    if (!config_manage.server_cfg.websocketNoSSL) {
        load_server_certificate(ssl_context_);
    }
    acceptor_.open(endpoint.protocol());
    acceptor_.set_option(tcp::acceptor::reuse_address(true));
    acceptor_.bind(endpoint);
    acceptor_.listen();
    if(config_manage.server_cfg.websocketEnabled)
    {
        if(config_manage.server_cfg.websocketNoSSL)
        {
            NOTICE_LOG << "listening for plain websocket connections (no SSL)";
            do_plain_websocket_accept();
        }
        else
        {
            NOTICE_LOG << "listening for websocket connections";
            do_websocket_accept();
        }
    }
    else
    {
        do_accept();
    }

    if (config_manage.server_cfg.dtls_enabled) {
        start_dtls_listener();
    }
}
void Service::do_websocket_accept()
{
    websocket_connection_.reset(new WebsocketSession(context_pool.get_io_context(), ssl_context_));
    acceptor_.async_accept(websocket_connection_->socket(), [this](const boost::system::error_code &ec) {
        if(!ec){
            boost::system::error_code error;
            auto ep = websocket_connection_->socket().remote_endpoint(error);
            if (!error) {
                NOTICE_LOG << "accept incoming connection " << ep.address().to_string()<<":"<<ep.port();
                websocket_connection_->start();
            } else {
                NOTICE_LOG << "get remote endpoint error: " << error.message();
            }
        }
        else
        {
            NOTICE_LOG << "accept failed: " << ec.message();

        }
        do_websocket_accept();

});
}
void Service::do_plain_websocket_accept()
{
    plain_websocket_connection_.reset(new PlainWebsocketSession(context_pool.get_io_context()));
    acceptor_.async_accept(plain_websocket_connection_->socket(), [this](const boost::system::error_code &ec) {
        if(!ec){
            boost::system::error_code error;
            auto ep = plain_websocket_connection_->socket().remote_endpoint(error);
            if (!error) {
                NOTICE_LOG << "accept incoming plain websocket connection " << ep.address().to_string()<<":"<<ep.port();
                plain_websocket_connection_->start();
            } else {
                NOTICE_LOG << "get remote endpoint error: " << error.message();
            }
        }
        else
        {
            NOTICE_LOG << "accept failed: " << ec.message();
        }
        do_plain_websocket_accept();
    });
}

void Service::load_server_certificate(boost::asio::ssl::context &ctx) {

    auto &config_manage = ConfigManage::instance();

    ctx.set_options(
            boost::asio::ssl::context::default_workarounds
            | boost::asio::ssl::context::no_sslv2
            | boost::asio::ssl::context::single_dh_use);
    SSL_CTX_set_session_cache_mode(ctx.native_handle(), SSL_SESS_CACHE_SERVER);
    ctx.use_certificate_chain_file(config_manage.server_cfg.certificate_chain);
    ctx.use_private_key_file(config_manage.server_cfg.server_private_key, boost::asio::ssl::context::pem);
}


void Service::do_accept() {
    new_connection_.reset(new TlsSession(context_pool.get_io_context(), ssl_context_));
    acceptor_.async_accept(new_connection_->socket(), [this](const boost::system::error_code &ec) {
        auto clean_up = [this]() {
            if (new_connection_->socket().is_open()) {
                new_connection_->socket().close();
            }
        };
        if (!acceptor_.is_open()) {
            NOTICE_LOG << "acceptor is closed, stopping accept loop";
            clean_up();
            return;
        }
        if (ec == boost::asio::error::operation_aborted) {
            NOTICE_LOG << "accept cancelled, stopping accept loop";
            clean_up();
            return;
        }
        if (!ec) {
            boost::system::error_code error;
            auto ep = new_connection_->socket().remote_endpoint(error);
            if (!error) {
                DEBUG_LOG << "accept incoming connection "<< ep.address().to_string()<<":"<<ep.port();
                new_connection_->socket().set_option(boost::asio::socket_base::keep_alive(true));
                new_connection_->socket().set_option(boost::asio::ip::tcp::no_delay(true));
                new_connection_->start();

            } else {
                NOTICE_LOG << "get remote endpoint error: " << error.message();
                clean_up();
            }
        } else {
            // dump_current_open_fd();
            NOTICE_LOG << "accept failed: " << ec.message();
            clean_up();
        }

        do_accept();
    });
}

void Service::run() {
    NOTICE_LOG << "Server start..." << std::endl;
    context_pool.run();
}

void Service::add_signals() {
    signals.add(SIGINT);
    signals.add(SIGTERM);
#ifdef SIGQUIT
    signals.add(SIGQUIT);
#endif
    signals.async_wait([this](const boost::system::error_code &ec, int sig) {
        // dump_current_open_fd();
        dns_cleanup_timer_.cancel();
        context_pool.stop();

        NOTICE_LOG << "received signal:" << sig << ", server stopped..." << std::endl;
    });
}

void Service::start_dns_cleanup_timer() {
    auto interval = ConfigManage::instance().server_cfg.dns_cleanup_interval;
    dns_cleanup_timer_.expires_after(std::chrono::seconds(interval));
    dns_cleanup_timer_.async_wait([this](const boost::system::error_code& ec) {
        if (ec) return;
        DnsCacheManager::instance().cleanup_expired();
        start_dns_cleanup_timer();
    });
}

void Service::start_dtls_listener() {
    auto& cfg = ConfigManage::instance().server_cfg;
    if (cfg.dtls_port.empty()) {
        ERROR_LOG << "DTLS enabled but dtls_port not configured";
        return;
    }

    dtls_listener_ = std::make_unique<DtlsListener>(
        context_pool.get_io_context(),
        cfg.certificate_chain,
        cfg.server_private_key,
        cfg.local_addr,
        cfg.dtls_port);
    dtls_listener_->start();
    NOTICE_LOG << "DTLS listener started on port " << cfg.dtls_port;
}