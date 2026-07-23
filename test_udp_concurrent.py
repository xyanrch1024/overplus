import socket
import struct
import time
import threading

PROXY_HOST = "127.0.0.1"
PROXY_PORT = 1080

def build_dns_query(domain, tx_id=0x0100):
    q = bytes([tx_id >> 8, tx_id & 0xFF, 0x01, 0x00, 0x00, 0x01,
               0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    for label in domain.split("."):
        q += bytes([len(label)]) + label.encode()
    q += b"\x00\x00\x01\x00\x01"
    return q

DNS_SERVERS = [
    ("8.8.8.8", "www.google.com"),
    ("8.8.4.4", "www.google.com"),
    ("1.1.1.1", "www.cloudflare.com"),
    ("1.0.0.1", "www.cloudflare.com"),
    ("208.67.222.222", "www.opendns.com"),
    ("208.67.220.220", "www.opendns.com"),
    ("114.114.114.114", "www.baidu.com"),
    ("9.9.9.9", "www.quad9.net"),
]

def test_concurrent_diff_targets():
    print("=== Concurrent to DIFFERENT targets ===\n")

    results = {}
    def worker(idx, dns_srv, domain):
        try:
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

            udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp.settimeout(5)
            udp.bind(("0.0.0.0", 0))

            dns = build_dns_query(domain, tx_id=0x0300 + idx)
            socks5_hdr = b"\x00\x00\x00\x01" + socket.inet_aton(dns_srv) + struct.pack("!H", 53)
            t0 = time.time()
            udp.sendto(socks5_hdr + dns, relay_addr)
            data, _ = udp.recvfrom(4096)
            elaps = time.time() - t0
            dns_resp = data[10:]
            flags = dns_resp[2:4]
            qr = (flags[0] >> 7) & 1
            results[idx] = (True, elaps, qr == 1)
            s.close()
            udp.close()
        except Exception as e:
            results[idx] = (False, 0, str(e))

    threads = []
    for i, (srv, dom) in enumerate(DNS_SERVERS):
        t = threading.Thread(target=worker, args=(i, srv, dom))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    ok, fail = 0, 0
    for i, (srv, dom) in enumerate(DNS_SERVERS):
        r = results.get(i)
        if r and r[0] and r[2]:
            ok += 1
            print(f"  [{i+1}] {srv:16s} {dom:20s} {r[1]*1000:6.1f}ms  OK")
        elif r and r[0]:
            fail += 1
            print(f"  [{i+1}] {srv:16s} {dom:20s}  bad flags")
        else:
            fail += 1
            err = r[2] if r else "no result"
            print(f"  [{i+1}] {srv:16s} {dom:20s}  FAIL: {err}")
    print(f"\n--- result: {ok}/{len(DNS_SERVERS)} ok, {fail} failed ---\n")
    return ok == len(DNS_SERVERS)

def test_concurrent_same_target():
    print("=== Concurrent to SAME target (8.8.8.8:53) ===\n")

    results = {}
    def worker(idx, domain):
        try:
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

            udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp.settimeout(5)
            udp.bind(("0.0.0.0", 0))

            dns = build_dns_query(domain, tx_id=0x0400 + idx)
            socks5_hdr = b"\x00\x00\x00\x01" + socket.inet_aton("8.8.8.8") + struct.pack("!H", 53)
            t0 = time.time()
            udp.sendto(socks5_hdr + dns, relay_addr)
            data, _ = udp.recvfrom(4096)
            elaps = time.time() - t0
            dns_resp = data[10:]
            flags = dns_resp[2:4]
            qr = (flags[0] >> 7) & 1
            results[idx] = (True, elaps, qr == 1)
            s.close()
            udp.close()
        except Exception as e:
            results[idx] = (False, 0, str(e))

    domains = ["www.google.com", "www.baidu.com", "www.github.com",
               "www.cloudflare.com", "www.amazon.com", "www.microsoft.com",
               "www.apple.com", "www.netflix.com"]

    threads = []
    for i, dom in enumerate(domains):
        t = threading.Thread(target=worker, args=(i, dom))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    ok, fail = 0, 0
    for i, dom in enumerate(domains):
        r = results.get(i)
        if r and r[0] and r[2]:
            ok += 1
            print(f"  [{i+1}] {dom:22s} {r[1]*1000:6.1f}ms  OK")
        elif r and r[0]:
            fail += 1
            print(f"  [{i+1}] {dom:22s}  bad flags")
        else:
            fail += 1
            err = r[2] if r else "no result"
            print(f"  [{i+1}] {dom:22s}  FAIL: {err}")
    print(f"\n--- result: {ok}/{len(domains)} ok, {fail} failed ---\n")
    return ok == len(domains)

if __name__ == "__main__":
    srv_ok = test_concurrent_same_target()
    print()
    diff_ok = test_concurrent_diff_targets()
    print(f"Same target:  {'PASS' if srv_ok else 'FAIL'}")
    print(f"Diff targets: {'PASS' if diff_ok else 'FAIL'}")
