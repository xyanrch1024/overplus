#include "UdpFrame.h"
#include <cstring>

using std::string;

static void put_u16_be(string& dst, uint16_t val) {
    dst += static_cast<char>(val >> 8);
    dst += static_cast<char>(val & 0xFF);
}

static uint16_t get_u16_be(const char* p) {
    return (static_cast<uint8_t>(p[0]) << 8) | static_cast<uint8_t>(p[1]);
}

bool UdpFrame::parse(const string& data, size_t& frame_len) {
    if (data.size() < HEADER_SIZE)
        return false;

    uint16_t magic = get_u16_be(data.data());
    if (magic != MAGIC)
        return false;

    uint16_t total_len = get_u16_be(data.data() + 2);
    if (total_len < HEADER_SIZE || data.size() < total_len)
        return false;

    const char* p = data.data() + HEADER_SIZE;
    size_t remaining = total_len - HEADER_SIZE;

    if (remaining < 1)
        return false;

    addr_type = static_cast<uint8_t>(p[0]);
    p++;
    remaining--;

    size_t addr_len = 0;
    switch (addr_type) {
    case IPv4:
        if (remaining < 4 + 2) return false;
        address.assign(p, 4);
        port = get_u16_be(p + 4);
        addr_len = 4 + 2;
        break;
    case DOMAIN:
        if (remaining < 1) return false;
        uint8_t dlen;
        dlen = static_cast<uint8_t>(p[0]);
        p++;
        remaining--;
        if (remaining < dlen + 2) return false;
        address.assign(p, dlen);
        port = get_u16_be(p + dlen);
        addr_len = 1 + dlen + 2;
        break;
    case IPv6:
        if (remaining < 16 + 2) return false;
        address.assign(p, 16);
        port = get_u16_be(p + 16);
        addr_len = 16 + 2;
        break;
    default:
        return false;
    }

    p += addr_len;
    remaining -= addr_len;

    if (remaining == 0) {
        payload.clear();
    } else {
        payload.assign(p, remaining);
    }

    frame_len = total_len;
    return true;
}

string UdpFrame::generate(const boost::asio::ip::udp::endpoint& ep,
                           const string& payload) {
    string frame;
    frame.reserve(HEADER_SIZE + 1 + 7 + payload.size());

    string addr_part;
    auto addr = ep.address();
    if (addr.is_v4()) {
        addr_part += static_cast<char>(IPv4);
        auto bytes = addr.to_v4().to_bytes();
        addr_part.append(reinterpret_cast<const char*>(bytes.data()), 4);
        addr_part += static_cast<char>(ep.port() >> 8);
        addr_part += static_cast<char>(ep.port() & 0xFF);
    } else {
        addr_part += static_cast<char>(IPv6);
        auto bytes = addr.to_v6().to_bytes();
        addr_part.append(reinterpret_cast<const char*>(bytes.data()), 16);
        addr_part += static_cast<char>(ep.port() >> 8);
        addr_part += static_cast<char>(ep.port() & 0xFF);
    }

    uint16_t total_len = HEADER_SIZE + addr_part.size() + payload.size();
    put_u16_be(frame, MAGIC);
    put_u16_be(frame, total_len);
    frame += addr_part;
    frame += payload;
    return frame;
}

string UdpFrame::generate(const string& domain,
                           uint16_t port,
                           const string& payload) {
    string frame;
    frame.reserve(HEADER_SIZE + 1 + 1 + domain.size() + 2 + payload.size());

    uint16_t total_len = HEADER_SIZE + 1 + 1 + domain.size() + 2 + payload.size();
    put_u16_be(frame, MAGIC);
    put_u16_be(frame, total_len);
    frame += static_cast<char>(DOMAIN);
    frame += static_cast<char>(domain.size());
    frame += domain;
    put_u16_be(frame, port);
    frame += payload;
    return frame;
}

string UdpFrame::addr_str() const {
    switch (addr_type) {
    case IPv4: {
        const auto* p = reinterpret_cast<const uint8_t*>(address.data());
        return std::to_string(p[0]) + "." + std::to_string(p[1]) + "."
             + std::to_string(p[2]) + "." + std::to_string(p[3])
             + ":" + std::to_string(port);
    }
    case DOMAIN:
        return address + ":" + std::to_string(port);
    case IPv6:
        return "[IPv6]:" + std::to_string(port);
    default:
        return "unknown";
    }
}
