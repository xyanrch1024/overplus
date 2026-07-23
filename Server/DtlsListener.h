#pragma once
#include "DtlsServerSession.h"
#include <boost/asio.hpp>
#include <boost/core/noncopyable.hpp>
#include <map>
#include <memory>
#include <openssl/ssl.h>

class DtlsListener : private boost::noncopyable {
public:
    DtlsListener(boost::asio::io_context& io_ctx,
                 const std::string& cert_path,
                 const std::string& key_path,
                 const std::string& addr,
                 const std::string& port);
    ~DtlsListener();

    void start();
    void stop();

private:
    void do_receive();
    void remove_session(const boost::asio::ip::udp::endpoint& ep);

    boost::asio::io_context& io_ctx_;
    boost::asio::ip::udp::socket socket_;
    SSL_CTX* dtls_ctx_ = nullptr;

    std::array<char, 65535> recv_buf_;
    boost::asio::ip::udp::endpoint sender_ep_;

    std::map<boost::asio::ip::udp::endpoint,
             std::shared_ptr<DtlsServerSession>> sessions_;
};
