import socket
import struct
import time
import threading

PROXY_HOST = "127.0.0.1"
PROXY_PORT = 1080

DOMAINS = ["www.google.com", "www.baidu.com", "www.github.com",
           "www.cloudflare.com", "www.amazon.com", "www.microsoft.com",
           "www.apple.com", "www.netflix.com", "www.wikipedia.org",
           "www.stackoverflow.com"]

def build_dns_query(domain, tx_id=0x0100):
    q = bytes([tx_id >> 8, tx_id & 0xFF, 0x01, 0x00, 0x00, 0x01,
               0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    for label in domain.split("."):
        q += bytes([len(label)]) + label.encode()
    q += b"\x00\x00\x01\x00\x01"
    return q

def test_sequential():
    print("=== Sequential DNS queries ===\n")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10)
    s.connect((PROXY_HOST, PROXY_PORT))
    s.sendall(b"\x05\x01\x00")
    assert s.recv(2) == b"\x05\x00"
    s.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
    resp = s.recv(10)
    assert resp[0:2] == b"\x05\x00"
    bind_port = struct.unpack("!H", resp[8:10])[0]
    relay_addr = (PROXY_HOST, bind_port)
    print(f"UDP ASSOCIATE relay on {relay_addr}\n")

    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.settimeout(5)
    udp.bind(("0.0.0.0", 0))

    ok, fail = 0, 0
    for i, domain in enumerate(DOMAINS):
        dns = build_dns_query(domain, tx_id=0x0100 + i)
        socks5_hdr = b"\x00\x00\x00\x01" + socket.inet_aton("8.8.8.8") + struct.pack("!H", 53)
        t0 = time.time()
        udp.sendto(socks5_hdr + dns, relay_addr)
        try:
            data, _ = udp.recvfrom(4096)
            elaps = time.time() - t0
            dns_resp = data[10:]
            flags = dns_resp[2:4]
            qr = (flags[0] >> 7) & 1
            if qr == 1:
                ok += 1
                print(f"  [{i+1:2d}] {domain:25s} {elaps*1000:6.1f}ms  OK")
            else:
                fail += 1
                print(f"  [{i+1:2d}] {domain:25s} {elaps*1000:6.1f}ms  FLAGS={flags.hex()}")
        except socket.timeout:
            fail += 1
            print(f"  [{i+1:2d}] {domain:25s}  TIMEOUT")

    s.close()
    udp.close()
    print(f"\n--- result: {ok}/{len(DOMAINS)} ok, {fail} failed ---\n")
    return ok == len(DOMAINS)

def test_concurrent():
    print("=== Concurrent DNS queries (all at once) ===\n")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10)
    s.connect((PROXY_HOST, PROXY_PORT))
    s.sendall(b"\x05\x01\x00")
    assert s.recv(2) == b"\x05\x00"
    s.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
    resp = s.recv(10)
    assert resp[0:2] == b"\x05\x00"
    bind_port = struct.unpack("!H", resp[8:10])[0]
    relay_addr = (PROXY_HOST, bind_port)
    print(f"UDP ASSOCIATE relay on {relay_addr}\n")

    results = {}

    def send_recv(idx, domain):
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.settimeout(5)
        udp.bind(("0.0.0.0", 0))
        dns = build_dns_query(domain, tx_id=0x0200 + idx)
        socks5_hdr = b"\x00\x00\x00\x01" + socket.inet_aton("8.8.8.8") + struct.pack("!H", 53)
        t0 = time.time()
        udp.sendto(socks5_hdr + dns, relay_addr)
        try:
            data, _ = udp.recvfrom(4096)
            elaps = time.time() - t0
            dns_resp = data[10:]
            flags = dns_resp[2:4]
            qr = (flags[0] >> 7) & 1
            results[idx] = (True, elaps, qr == 1)
        except socket.timeout:
            results[idx] = (False, 0, False)
        udp.close()

    threads = []
    for i, domain in enumerate(DOMAINS):
        t = threading.Thread(target=send_recv, args=(i, domain))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    ok, fail = 0, 0
    for i, domain in enumerate(DOMAINS):
        if i in results:
            success, elaps, qr_ok = results[i]
            if success and qr_ok:
                ok += 1
                print(f"  [{i+1:2d}] {domain:25s} {elaps*1000:6.1f}ms  OK")
            else:
                fail += 1
                status = "TIMEOUT" if not success else f"BAD FLAGS"
                print(f"  [{i+1:2d}] {domain:25s}  {status}")
        else:
            fail += 1
            print(f"  [{i+1:2d}] {domain:25s}  NO RESULT")

    s.close()
    print(f"\n--- result: {ok}/{len(DOMAINS)} ok, {fail} failed ---\n")
    return ok == len(DOMAINS)

if __name__ == "__main__":
    seq_ok = test_sequential()
    conc_ok = test_concurrent()
    print(f"Sequential: {'PASS' if seq_ok else 'FAIL'}")
    print(f"Concurrent: {'PASS' if conc_ok else 'FAIL'}")
