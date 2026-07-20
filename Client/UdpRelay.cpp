#include "UdpRelay.h"
#include "Protocol/UdpFrame.h"
#include "Shared/Log.h"
#include "Shared/ProxyStats.h"
#include <Protocol/socks5/socks5.h>
#include <cstring>

using boost::asio::ip::udp;

UdpRelay::UdpRelay(boost::asio::io_context& io_ctx)
    : io_ctx_(io_ctx)
    , local_socket_(io_ctx, udp::endpoint(boost::asio::ip::address_v4::loopback(), 0))
{
}

UdpRelay::~UdpRelay()
{
    stop();
}

bool UdpRelay::start(uint16_t& local_port, DtlsChannel& dtls, uint16_t session_id)
{
    local_port = local_socket_.local_endpoint().port();
    dtls_ = &dtls;
    session_id_ = session_id;
    running_ = true;

    do_receive_local();
    NOTICE_LOG << "UDP relay started, local socket bound to "
               << local_socket_.local_endpoint().address().to_string()
               << ":" << local_socket_.local_endpoint().port()
               << " session_id=" << session_id_;
    return true;
}

void UdpRelay::stop()
{
    if (!running_) return;
    running_ = false;

    boost::system::error_code ec;
    local_socket_.cancel(ec);
    local_socket_.close(ec);

    NOTICE_LOG << "UDP relay stopped, session_id=" << session_id_;
}

void UdpRelay::flush_pending()
{
    if (!dtls_ || !dtls_->is_ready()) return;
    NOTICE_LOG << "UDP relay flushing " << pending_frames_.size() << " pending frames, session_id=" << session_id_;
    while (!pending_frames_.empty()) {
        std::string pkt;
        pkt += char(session_id_ >> 8);
        pkt += char(session_id_ & 0xFF);
        pkt += pending_frames_.front();
        dtls_->send(pkt);
        pending_frames_.pop();
    }
}

void UdpRelay::on_dtls_data(const char* data, size_t len)
{
    if (!running_) return;

    UdpFrame frame;
    size_t frame_len = 0;
    if (!frame.parse(std::string(data, len), frame_len)) {
        ERROR_LOG << "UDP relay: invalid frame from server, session_id=" << session_id_;
        return;
    }

    NOTICE_LOG << "UDP relay <-- server: " << frame.addr_str()
              << " " << frame.payload.size() << " bytes";

    ProxyStats::instance().addDownstreamDelta(len);

    std::string pkt;
    pkt += char(0x00);
    pkt += char(0x00);
    pkt += char(0x00);

    if (frame.addr_type == UdpFrame::ADDR_IPV4) {
        pkt += char(0x01);
        pkt += frame.address;
        pkt += char(frame.port >> 8);
        pkt += char(frame.port & 0xFF);
    } else if (frame.addr_type == UdpFrame::ADDR_DOMAIN) {
        pkt += char(0x03);
        pkt += char(frame.address.size());
        pkt += frame.address;
        pkt += char(frame.port >> 8);
        pkt += char(frame.port & 0xFF);
    } else if (frame.addr_type == UdpFrame::ADDR_IPV6) {
        pkt += char(0x04);
        pkt += frame.address;
        pkt += char(frame.port >> 8);
        pkt += char(frame.port & 0xFF);
    }

    pkt += frame.payload;

    boost::system::error_code sec;
    local_socket_.send_to(boost::asio::buffer(pkt), sender_ep_, 0, sec);
    if (sec) {
        NOTICE_LOG << "UDP relay send_to app failed: " << sec.message();
    }
}

void UdpRelay::do_receive_local()
{
    local_socket_.async_receive_from(
        boost::asio::buffer(recv_buf_), sender_ep_,
        [this](boost::system::error_code ec, std::size_t len) {
            if (!running_) {
                return;
            }
            if (ec) {
                NOTICE_LOG << "UDP local recv error: " << ec.message();
                do_receive_local();
                return;
            }
            if (len < 4) {
                do_receive_local();
                return;
            }

            ProxyStats::instance().addUpstreamDelta(len);
            NOTICE_LOG << "UDP relay --> server: " << len << " bytes from "
                      << sender_ep_.address().to_string() << ":" << sender_ep_.port()
                      << " session_id=" << session_id_;

            const char* p = recv_buf_.data();
            if (p[0] != 0x00 || p[1] != 0x00 || p[2] != 0x00) {
                do_receive_local();
                return;
            }

            uint8_t atyp = static_cast<uint8_t>(p[3]);
            p += 4;
            len -= 4;

            std::string target_addr;
            uint16_t target_port = 0;
            const char* payload = nullptr;
            size_t payload_len = 0;

            switch (atyp) {
            case 0x01: {
                if (len < 6) { do_receive_local(); return; }
                target_addr.assign(p, 4);
                target_port = (static_cast<uint8_t>(p[4]) << 8) | static_cast<uint8_t>(p[5]);
                payload = p + 6;
                payload_len = len - 6;
                break;
            }
            case 0x03: {
                if (len < 1) { do_receive_local(); return; }
                uint8_t dlen = static_cast<uint8_t>(p[0]);
                p++;
                len--;
                if (len < static_cast<size_t>(dlen) + 2) { do_receive_local(); return; }
                target_addr.assign(p, dlen);
                target_port = (static_cast<uint8_t>(p[dlen]) << 8) | static_cast<uint8_t>(p[dlen + 1]);
                payload = p + dlen + 2;
                payload_len = len - dlen - 2;
                break;
            }
            case 0x04: {
                if (len < 18) { do_receive_local(); return; }
                target_addr.assign(p, 16);
                target_port = (static_cast<uint8_t>(p[16]) << 8) | static_cast<uint8_t>(p[17]);
                payload = p + 18;
                payload_len = len - 18;
                break;
            }
            default:
                do_receive_local();
                return;
            }

            std::string frame;
            if (atyp == 0x03) {
                frame = UdpFrame::generate(target_addr, target_port,
                                           std::string(payload, payload_len));
            } else {
                udp::endpoint ep;
                if (atyp == 0x01) {
                    boost::asio::ip::address_v4::bytes_type bytes;
                    std::memcpy(bytes.data(), target_addr.data(), 4);
                    ep = udp::endpoint(boost::asio::ip::address_v4(bytes), target_port);
                } else {
                    boost::asio::ip::address_v6::bytes_type bytes;
                    std::memcpy(bytes.data(), target_addr.data(), 16);
                    ep = udp::endpoint(boost::asio::ip::address_v6(bytes), target_port);
                }
                frame = UdpFrame::generate(ep, std::string(payload, payload_len));
            }

            if (dtls_ && dtls_->is_ready()) {
                std::string pkt;
                pkt += char(session_id_ >> 8);
                pkt += char(session_id_ & 0xFF);
                pkt += frame;
                dtls_->send(pkt);
            } else {
                NOTICE_LOG << "UDP relay queuing pending frame, session_id=" << session_id_;
                pending_frames_.push(std::move(frame));
            }

            do_receive_local();
        });
}
