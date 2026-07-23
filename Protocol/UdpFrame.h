#pragma once
#include <cstdint>
#include <string>

#ifdef _WIN32
#include <boost/asio/ip/udp.hpp>
#else
#include <boost/asio.hpp>
#endif

class UdpFrame {
public:
    enum AddrType {
        ADDR_IPV4   = 0x01,
        ADDR_DOMAIN = 0x03,
        ADDR_IPV6   = 0x06
    };

    static const uint16_t MAGIC;
    static const uint16_t HEADER_SIZE;

    uint8_t addr_type;
    std::string address;
    uint16_t port;
    std::string payload;

    UdpFrame() : addr_type(ADDR_IPV4), port(0) {}

    bool parse(const std::string& data, size_t& frame_len);

    static std::string generate(const boost::asio::ip::udp::endpoint& ep,
                                const std::string& payload);
    static std::string generate(const std::string& domain,
                                uint16_t port,
                                const std::string& payload);

    std::string addr_str() const;
};
