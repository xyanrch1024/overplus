#include "UdpRelay.h"
#include "Protocol/UdpFrame.h"
#include "Protocol/socks5/UdpRequest.h"
#include "Shared/Log.h"
#include "Shared/ProxyStats.h"
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

    UdpRequest udp_resp;
    udp_resp.addr_type = frame.addr_type;
    udp_resp.dst_addr = frame.address;
    udp_resp.dst_port = frame.port;
    udp_resp.payload = frame.payload;
    std::string pkt = udp_resp.serialize();

    std::string target_key = frame.address + ":" + std::to_string(frame.port);
    auto sit = target_to_sender_.find(target_key);
    udp::endpoint app_ep = sender_ep_;
    if (sit != target_to_sender_.end()) {
        app_ep = sit->second;
        target_to_sender_.erase(sit);
    }

    boost::system::error_code sec;
    local_socket_.send_to(boost::asio::buffer(pkt), app_ep, 0, sec);
    if (sec) {
        NOTICE_LOG << "UDP relay send_to app failed: " << sec.message();
    }
}

void UdpRelay::do_receive_local()
{
    local_socket_.async_receive_from(
        boost::asio::buffer(recv_buf_), sender_ep_,
        [self = shared_from_this()](boost::system::error_code ec, std::size_t len) {
            if (!self->running_) {
                return;
            }
            if (ec) {
                NOTICE_LOG << "UDP local recv error: " << ec.message();
                self->do_receive_local();
                return;
            }
            if (len < 4) {
                self->do_receive_local();
                return;
            }

            ProxyStats::instance().addUpstreamDelta(len);
            NOTICE_LOG << "UDP relay --> server: " << len << " bytes from "
                      << self->sender_ep_.address().to_string() << ":" << self->sender_ep_.port()
                      << " session_id=" << self->session_id_;

            UdpRequest udp_req;
            if (!udp_req.parse(self->recv_buf_.data(), len)) {
                self->do_receive_local();
                return;
            }

            self->target_to_sender_[udp_req.dst_addr + ":" + std::to_string(udp_req.dst_port)] = self->sender_ep_;

            std::string frame;
            if (udp_req.addr_type == 0x03) {
                frame = UdpFrame::generate(udp_req.dst_addr, udp_req.dst_port, udp_req.payload);
            } else {
                frame = UdpFrame::generate(udp_req.dest_endpoint(), udp_req.payload);
            }

            if (self->dtls_ && self->dtls_->is_ready()) {
                std::string pkt;
                pkt += char(self->session_id_ >> 8);
                pkt += char(self->session_id_ & 0xFF);
                pkt += frame;
                self->dtls_->send(pkt);
            } else {
                NOTICE_LOG << "UDP relay queuing pending frame, session_id=" << self->session_id_;
                self->pending_frames_.push(std::move(frame));
            }

            self->do_receive_local();
        });
}
