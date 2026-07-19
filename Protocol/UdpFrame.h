#pragma once
#include <boost/asio.hpp>
#include <cstdint>
#include <string>

class UdpFrame {
public:
    static constexpr uint16_t MAGIC = 0x0D0A;
    static constexpr size_t HEADER_SIZE = 4; // Magic(2) + Length(2)

    enum AddrType {
        IPv4   = 0x01,
        DOMAIN = 0x03,
        IPv6   = 0x06
    };

    uint8_t addr_type = IPv4;
    std::string address;
    uint16_t port = 0;
    std::string payload;

    bool parse(const std::string& data, size_t& frame_len);

    static std::string generate(const boost::asio::ip::udp::endpoint& ep,
                                const std::string& payload);
    static std::string generate(const std::string& domain,
                                uint16_t port,
                                const std::string& payload);

    std::string addr_str() const;
};
