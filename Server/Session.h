#ifndef SERVER_SESSION_H
#define SERVER_SESSION_H
#include "Protocol/trojan/TrojanReq.h"
#include "Protocol/trojan/UDPPacket.h"
#include "Shared/Log.h"
#include "Shared/DnsCache.h"
#include <Protocol/VProtocal/VRequest.h>
#include <atomic>
#include <boost/asio.hpp>
#include <cstring>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/ssl/context.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/websocket/ssl.hpp>
#include <boost/core/noncopyable.hpp>
#include <boost/optional.hpp>
#include <boost/system/error_code.hpp>
#include <cstdint>
#include <ctime>
#include <memory>
#include <unordered_map>

namespace beast = boost::beast;         // from <boost/beast.hpp>
namespace http = beast::http;           // from <boost/beast/http.hpp>
namespace websocket = beast::websocket; // from <boost/beast/websocket.hpp>
namespace net = boost::asio;            // from <boost/asio.hpp>
namespace ssl = boost::asio::ssl;       // from <boost/asio/ssl.hpp>
using  tcp = boost::asio::ip::tcp;       // from <boost/asio/ip/tcp.hpp>
using  udp =  boost::asio::ip::udp;

using SSLSocket = boost::asio::ssl::stream<boost::asio::ip::tcp::socket>;

class SessionBuffer {
public:
    explicit SessionBuffer(size_t cap = 256 * 1024) : buf_(cap), capacity_(cap) {}

    boost::asio::mutable_buffer prepare(size_t& len) {
        size_t avail = capacity_ - used_;
        if (avail == 0) { len = 0; return {buf_.data(), 0}; }
        size_t n = std::min(len, avail);
        size_t wpos = (read_pos_ + used_) % capacity_;
        n = std::min(n, capacity_ - wpos);
        len = n;
        return {buf_.data() + wpos, n};
    }

    void commit(size_t n) { used_ += n; }

    boost::asio::const_buffer peek() const {
        size_t n = std::min(used_, capacity_ - read_pos_);
        return {buf_.data() + read_pos_, n};
    }

    void consume(size_t n) {
        read_pos_ = (read_pos_ + n) % capacity_;
        used_ -= n;
    }

    bool empty() const { return used_ == 0; }
    size_t size() const { return used_; }

    void reset() { read_pos_ = 0; used_ = 0; }

private:
    std::vector<uint8_t> buf_;
    size_t capacity_;
    size_t read_pos_ = 0;
    size_t used_ = 0;
};

template<class T>
class Session :public std::enable_shared_from_this<Session<T>>
    , private boost::noncopyable
{
public:
    enum State {
        HANDSHAKE,
        FORWARD,
        DESTROY
    };
public:
    Session(boost::asio::io_context&, boost::asio::ssl::context&);

    virtual ~Session(){}


    void async_bidirectional_read(int direction);

    void handle_custom_protocol();

    void do_resolve();

    void do_connect(tcp::endpoint endpoint);
    void udp_upstream_read();

    void async_bidirectional_write(int, size_t);
    void handle_trojan_udp_proxy();
    void udp_async_bidirectional_read(int direction);
    void udp_async_bidirectional_write(int, const std::string&, boost::asio::ip::udp::endpoint);

    virtual void upstream_tcp_write(int direction, size_t len);
     virtual void upstream_udp_write(int direction, const std::string& packet);
     virtual void destroy();

     using SendCallback = std::function<void(boost::system::error_code, std::size_t)>;
     virtual void upstream_tcp_write_send(const char* data, size_t len, SendCallback handler);

protected:
    static constexpr size_t MAX_BUFF_SIZE = 64 * 1024;

    SessionBuffer ring_down_;
    SessionBuffer ring_up_;
    bool sending_down_ = false;
    bool sending_up_ = false;
    void enqueue_write(int direction, const char* data, size_t len);
    void do_send_down();
    void do_send_up();

    boost::asio::io_context& io_context_;
    T upstream_socket;
    tcp::socket downstream_socket;

    //
    tcp::resolver resolver_;
    udp::resolver udp_resolver;
    udp::socket downstream_udp_socket;    //

    State state_ { HANDSHAKE };
    TrojanReq trojanReq {};
    VRequest v_req {};
    std::string password;
    std::string upstream_udp_buff;
    size_t udp_buff_offset_ = 0;
    //
    std::vector<char> in_buf;
    std::vector<char> out_buf;
    std::string remote_host;
    std::string remote_port;
    bool vprotocol = false;

};
#include "Session.cpp"
#endif