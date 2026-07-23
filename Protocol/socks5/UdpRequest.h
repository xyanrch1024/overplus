#pragma once
#include <boost/asio.hpp>
#include <cstdint>
#include <string>

class UdpRequest {
public:
    bool parse(const char* data, size_t len);
    std::string serialize() const;

    boost::asio::ip::udp::endpoint dest_endpoint() const;
    std::string dest_addr_str() const;

    uint8_t rsv[2] = {0, 0};
    uint8_t frag = 0;
    uint8_t addr_type = 0;
    std::string dst_addr;
    uint16_t dst_port = 0;
    std::string payload;
};
