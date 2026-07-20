#ifndef SERVER_H_
#define SERVER_H_
#include "Shared/DtlsChannel.h"
#include "Shared/IoContextPool.h"
#include "Shared/Log.h"
#include "Session.h"
#include <boost/asio.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/signal_set.hpp>
#include <atomic>
#include <memory>
#include <mutex>
#include <unordered_map>
using namespace boost::asio;

class UdpRelay;

class Server : private boost::noncopyable {
public:
    Server(const std::string& address, const std::string& port);
    void run();
    void stop();
    void start_accept();
    void stop_accept();

    void start_dtls();
    DtlsChannel& dtls() { return *dtls_; }
    uint16_t allocate_session_id() { return next_session_id_++; }
    void register_relay(uint16_t sid, UdpRelay* relay);
    void unregister_relay(uint16_t sid);

private:
    void add_signals();
    void do_accept();
    void on_dtls_data(const char* data, size_t len);

    IoContextPool context_pool;
    boost::asio::io_context& io_context;

    boost::asio::ip::tcp::acceptor acceptor_;

    boost::asio::ssl::context ssl_ctx;
    std::shared_ptr<Session> new_session;
    ip::tcp::endpoint local_endpoint;

    std::unique_ptr<DtlsChannel> dtls_;
    std::atomic<uint16_t> next_session_id_{1};
    std::mutex relays_mutex_;
    std::unordered_map<uint16_t, UdpRelay*> relays_;
    bool dtls_ready_ = false;
};
#endif
