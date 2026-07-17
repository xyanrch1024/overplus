#pragma once
#include "TlsSession.h"
#include "WebsocketSession.h"
#include <Shared/ConfigManage.h>
#include <Shared/DnsCache.h>
#include <Shared/IoContextPool.h>
#include <Shared/Log.h>
#include <boost/asio.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/asio/ssl/context.hpp>
#include <boost/asio/steady_timer.hpp>
#include <cstdint>
#include <memory>
using namespace boost::asio;

class Service : private boost::noncopyable {
public:
    Service();
    void run();

private:
    void add_signals();
    void do_accept();
    void do_websocket_accept();
    void load_server_certificate(boost::asio::ssl::context& ctx);
    void start_dns_cleanup_timer();

private:
    IoContextPool context_pool;
    boost::asio::io_context& io_context;

    boost::asio::signal_set signals;
    boost::asio::ip::tcp::acceptor acceptor_;
    boost::asio::ssl::context ssl_context_;
    boost::asio::steady_timer dns_cleanup_timer_;
public: 
    std::shared_ptr<TlsSession> new_connection_;
    std::shared_ptr<WebsocketSession> websocket_connection_;
};
