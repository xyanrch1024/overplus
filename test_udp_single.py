import socket
import struct
import time

PROXY_HOST = "127.0.0.1"
PROXY_PORT = 1080

DNS_QUERY = bytes([
    0x01, 0x00,  # TX ID
    0x01, 0x00,  # Flags: RD=1 (standard query)
    0x00, 0x01,  # QDCOUNT: 1 question
    0x00, 0x00,  # ANCOUNT: 0
    0x00, 0x00,  # NSCOUNT: 0
    0x00, 0x00,  # ARCOUNT: 0
    0x03, 0x77, 0x77, 0x77,  # www
    0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65,  # google
    0x03, 0x63, 0x6f, 0x6d,  # com
    0x00,
    0x00, 0x01,  # QTYPE: A
    0x00, 0x01   # QCLASS: IN
])
DNS_SERVER = ("8.8.8.8", 53)

def main():
    print("=== SOCKS5 UDP ASSOCIATE Single Channel Test ===\n")

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10)
    s.connect((PROXY_HOST, PROXY_PORT))
    s.sendall(b"\x05\x01\x00")
    assert s.recv(2) == b"\x05\x00", "auth method failed"
    s.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
    resp = s.recv(10)
    assert resp[0:2] == b"\x05\x00", f"UDP ASSOCIATE failed: {resp.hex()}"
    bind_port = struct.unpack("!H", resp[8:10])[0]
    relay_addr = (PROXY_HOST, bind_port)
    print(f"TCP ASSOCIATE established, relay on {relay_addr}\n")

    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.settimeout(30)
    udp_sock.bind(("0.0.0.0", 0))

    socks5_udp_header = b"\x00\x00\x00\x01" + socket.inet_aton(DNS_SERVER[0]) + struct.pack("!H", DNS_SERVER[1])
    packet = socks5_udp_header + DNS_QUERY
    udp_sock.sendto(packet, relay_addr)
    print(f"DNS query sent ({len(DNS_QUERY)} bytes) to {relay_addr}\n")

    tstart = time.time()
    try:
        data, addr = udp_sock.recvfrom(4096)
        elapsed = time.time() - tstart
        print(f"Response received after {elapsed:.1f}s from {addr}")
        if len(data) > 10:
            dns_resp = data[10:]
            print(f"DNS response: {len(dns_resp)} bytes")
            print(f"  TX ID: {dns_resp[0]:02x}{dns_resp[1]:02x}")
            flags = dns_resp[2:4]
            print(f"  Flags: {flags.hex()} (QR={flags[0]>>7})")
            if flags[0] & 0x80:
                print("  SUCCESS: QR=1 (response)")
            elif (time.time() - tstart) >= 28:
                print("  PARTIAL: got data but not a DNS response")
    except socket.timeout:
        elapsed = time.time() - tstart
        print(f"TIMEOUT after {elapsed:.1f}s - no response received")

    s.close()
    udp_sock.close()

if __name__ == "__main__":
    main()
