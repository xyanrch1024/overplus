import socket
import struct
import threading
import time
import sys

PROXY_HOST = "127.0.0.1"
PROXY_PORT = 1080
PROXY_RELAY_HOST = PROXY_HOST  # for UDP relay

DNS_QUERIES = [
    b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x06google\x03com\x00\x00\x01\x00\x01",
    b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x07\x62\x61\x69\x64\x75\x63\x6f\x6d\x00\x00\x01\x00\x01",
    b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x04api\x06github\x03com\x00\x00\x01\x00\x01",
]
DNS_SERVER = ("8.8.8.8", 53)

def socks5_connect_udp():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10)
    s.connect((PROXY_HOST, PROXY_PORT))
    s.sendall(b"\x05\x01\x00")
    assert s.recv(2) == b"\x05\x00", "auth method failed"
    s.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
    resp = s.recv(10)
    assert resp[0:2] == b"\x05\x00", f"UDP ASSOCIATE failed: {resp.hex()}"
    bind_port = struct.unpack("!H", resp[8:10])[0]
    return s, bind_port

def test_udp_channel(channel_id, dns_query):
    print(f"[Channel {channel_id}] Establishing UDP ASSOCIATE...")
    tcp_sock, relay_port = socks5_connect_udp()
    relay_addr = (PROXY_RELAY_HOST, relay_port)
    print(f"[Channel {channel_id}] Relay on {relay_addr}")

    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.settimeout(10)
    udp_sock.bind(("0.0.0.0", 0))

    socks5_udp_header = b"\x00\x00\x00\x01" + socket.inet_aton(DNS_SERVER[0]) + struct.pack("!H", DNS_SERVER[1])
    packet = socks5_udp_header + dns_query

    udp_sock.sendto(packet, relay_addr)
    print(f"[Channel {channel_id}] DNS query sent ({len(dns_query)} bytes)")

    try:
        data, addr = udp_sock.recvfrom(4096)
        if len(data) > 8:
            dns_resp = data[8:]
            print(f"[Channel {channel_id}] DNS response received ({len(dns_resp)} bytes)")
            print(f"[Channel {channel_id}] Transaction ID: {dns_resp[0]:02x}{dns_resp[1]:02x}")
            print(f"[Channel {channel_id}] Flags: {dns_resp[2]:02x}{dns_resp[3]:02x}")
            return True
    except socket.timeout:
        print(f"[Channel {channel_id}] TIMEOUT - no response")

    tcp_sock.close()
    udp_sock.close()
    return False

def main():
    print("=== SOCKS5 UDP ASSOCIATE Test ===")
    print(f"Proxy: {PROXY_HOST}:{PROXY_PORT}")
    print(f"DNS server: {DNS_SERVER[0]}:{DNS_SERVER[1]}")
    print()

    threads = []
    results = {}

    def run_channel(cid):
        results[cid] = test_udp_channel(cid, DNS_QUERIES[cid])

    for i in range(3):
        t = threading.Thread(target=run_channel, args=(i,))
        threads.append(t)
        t.start()
        time.sleep(0.3)

    for t in threads:
        t.join()

    print()
    print("=== Results ===")
    for cid in range(3):
        status = "PASS" if results.get(cid) else "FAIL"
        print(f"Channel {cid}: {status}")

    all_pass = all(results.get(cid) for cid in range(3))
    if all_pass:
        print("\nAll 3 UDP channels working correctly!")
    else:
        print("\nSome channels failed")
        sys.exit(1)

if __name__ == "__main__":
    main()
