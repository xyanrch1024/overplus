#include "UdpRequest.h"
#include "socks5.h"

using boost::asio::ip::udp;

bool UdpRequest::parse(const char* data, size_t len)
{
    if (len < 4) return false;
    if (data[0] != 0x00 || data[1] != 0x00 || data[2] != 0x00)
        return false;

    rsv[0] = static_cast<uint8_t>(data[0]);
    rsv[1] = static_cast<uint8_t>(data[1]);
    frag = static_cast<uint8_t>(data[2]);
    addr_type = static_cast<uint8_t>(data[3]);

    const char* p = data + 4;
    size_t remain = len - 4;

    switch (addr_type) {
    case 0x01:
        if (remain < 6) return false;
        dst_addr.assign(p, 4);
        dst_port = (static_cast<uint8_t>(p[4]) << 8) | static_cast<uint8_t>(p[5]);
        payload.assign(p + 6, remain - 6);
        return true;
    case 0x03: {
        if (remain < 1) return false;
        uint8_t dlen = static_cast<uint8_t>(p[0]);
        if (remain < static_cast<size_t>(dlen) + 2 + 1) return false;
        dst_addr.assign(p + 1, dlen);
        dst_port = (static_cast<uint8_t>(p[1 + dlen]) << 8) | static_cast<uint8_t>(p[1 + dlen + 1]);
        payload.assign(p + 1 + dlen + 2, remain - 1 - dlen - 2);
        return true;
    }
    case 0x04:
        if (remain < 18) return false;
        dst_addr.assign(p, 16);
        dst_port = (static_cast<uint8_t>(p[16]) << 8) | static_cast<uint8_t>(p[17]);
        payload.assign(p + 18, remain - 18);
        return true;
    default:
        return false;
    }
}

std::string UdpRequest::serialize() const
{
    std::string buf;
    buf += char(rsv[0]);
    buf += char(rsv[1]);
    buf += char(frag);
    buf += char(addr_type);

    if (addr_type == 0x01) {
        buf += dst_addr;
    } else if (addr_type == 0x03) {
        buf += char(dst_addr.size());
        buf += dst_addr;
    } else if (addr_type == 0x04) {
        buf += dst_addr;
    }
    buf += char(dst_port >> 8);
    buf += char(dst_port & 0xFF);
    buf += payload;
    return buf;
}

udp::endpoint UdpRequest::dest_endpoint() const
{
    if (addr_type == 0x01) {
        boost::asio::ip::address_v4::bytes_type bytes;
        std::memcpy(bytes.data(), dst_addr.data(), 4);
        return udp::endpoint(boost::asio::ip::address_v4(bytes), dst_port);
    }
    if (addr_type == 0x04) {
        boost::asio::ip::address_v6::bytes_type bytes;
        std::memcpy(bytes.data(), dst_addr.data(), 16);
        return udp::endpoint(boost::asio::ip::address_v6(bytes), dst_port);
    }
    return {};
}

std::string UdpRequest::dest_addr_str() const
{
    if (addr_type == 0x01) {
        auto ep = dest_endpoint();
        return ep.address().to_string() + ":" + std::to_string(dst_port);
    }
    if (addr_type == 0x03) {
        return dst_addr + ":" + std::to_string(dst_port);
    }
    return {};
}
