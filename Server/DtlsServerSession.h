#pragma once
#include <boost/asio.hpp>
#include <boost/core/noncopyable.hpp>
#include <functional>
#include <memory>
#include <string>
#include <vector>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

class DtlsServerSession : public std::enable_shared_from_this<DtlsServerSession>,
                           private boost::noncopyable {
public:
    using DestroyCallback = std::function<void(const boost::asio::ip::udp::endpoint&)>;

    DtlsServerSession(boost::asio::io_context& io_ctx,
                      SSL_CTX* dtls_ctx,
                      boost::asio::ip::udp::socket& shared_socket,
                      const boost::asio::ip::udp::endpoint& client_ep,
                      DestroyCallback on_destroy);
    ~DtlsServerSession();

    void on_datagram(const char* data, size_t len);
    void stop();

private:
    enum State { HANDSHAKE, AUTH, PROXY, DESTROY };

    void process_handshake();
    void drain_wbio();
    void start_auth();
    void try_read_app_data();
    void start_proxy();
    void do_read_target();
    void do_resolve_and_send(std::string domain, uint16_t port, const std::string& payload);
    void do_send_to_target(const boost::asio::ip::udp::endpoint& target_ep, const std::string& payload);
    void send_to_client(const std::string& data);
    void destroy() { stop(); }

    boost::asio::io_context& io_ctx_;
    boost::asio::ip::udp::socket& shared_socket_;
    boost::asio::ip::udp::endpoint client_ep_;

    SSL* ssl_ = nullptr;
    BIO* rbio_ = nullptr;
    BIO* wbio_ = nullptr;

    boost::asio::ip::udp::socket target_socket_;
    boost::asio::ip::udp::resolver resolver_;
    boost::asio::ip::udp::endpoint target_ep_;
    std::array<char, 65535> target_recv_buf_;

    State state_ = HANDSHAKE;
    std::string auth_buf_;
    bool destroyed_ = false;

    DestroyCallback on_destroy_;
};
