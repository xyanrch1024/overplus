#!/usr/bin/env python3
"""
Overplus UDP ASSOCIATE Multi-Scenario Test Tool
Usage: python test_udp.py [socks5_host] [socks5_port] [duration_seconds]
Default: 127.0.0.1:1080, 60 seconds
"""

import socket
import struct
import time
import sys
import random
import threading

SOCKS_HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
SOCKS_PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 1080
DURATION = int(sys.argv[3]) if len(sys.argv) > 3 else 60

DNS_SERVERS = ["8.8.8.8", "8.8.4.4", "1.1.1.1"]
DOMAINS = [
    "google.com", "github.com", "youtube.com", "cloudflare.com",
    "amazon.com", "microsoft.com", "facebook.com", "twitter.com",
    "reddit.com", "baidu.com", "qq.com", "taobao.com",
    "bing.com", "wikipedia.org", "apple.com", "netflix.com",
]

stats_lock = threading.Lock()
stats = {
    "dns": {"sent": 0, "ok": 0, "fail": 0, "latencies": []},
    "size": {"sent": 0, "ok": 0, "fail": 0, "latencies": []},
    "burst": {"sent": 0, "ok": 0, "fail": 0, "latencies": []},
    "voip": {"sent": 0, "ok": 0, "fail": 0, "latencies": []},
    "large": {"sent": 0, "ok": 0, "fail": 0, "latencies": []},
}
start = 0


def udp_associate(host, port):
    s = socket.socket()
    s.settimeout(5)
    s.connect((host, port))
    s.send(b'\x05\x01\x00')
    s.recv(2)
    s.send(b'\x05\x03\x00\x01' + b'\x00' * 6)
    resp = s.recv(10)
    if resp[1] != 0x00:
        raise Exception(f"UDP ASSOCIATE failed: code={resp[1]:#04x}")
    return s, struct.unpack('!H', resp[8:10])[0]


def build_socksv5_udp_header(addr_str, port):
    ip = socket.inet_aton(addr_str)
    return b'\x00\x00\x00\x01' + ip + struct.pack('!H', port)


def make_dns_query(domain):
    txid = random.randint(0, 65535).to_bytes(2, 'big')
    header = txid + b'\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
    qname = b''
    for label in domain.split('.'):
        qname += struct.pack('!B', len(label)) + label.encode()
    qname += b'\x00'
    return header + qname + struct.pack('!HH', 1, 1)


def elapsed_str():
    return f"{time.time() - start:.0f}s"


# ======================== Scenario 1: DNS ========================
def scenario_dns(udp_sock, udp_port):
    while time.time() - start < DURATION:
        domain = random.choice(DOMAINS)
        dns_server = random.choice(DNS_SERVERS)
        try:
            hdr = build_socksv5_udp_header(dns_server, 53)
            dns = make_dns_query(domain)
            t0 = time.time()
            udp_sock.sendto(hdr + dns, (SOCKS_HOST, udp_port))
            udp_sock.settimeout(3)
            data, _ = udp_sock.recvfrom(1500)
            latency = (time.time() - t0) * 1000
            with stats_lock:
                stats["dns"]["sent"] += 1
                stats["dns"]["ok"] += 1
                stats["dns"]["latencies"].append(latency)
            print(f"  [{elapsed_str()}] [DNS]    {domain:25s} via {dns_server:12s} -> {latency:6.1f}ms  OK ({len(data)}B)")
        except socket.timeout:
            with stats_lock:
                stats["dns"]["sent"] += 1
                stats["dns"]["fail"] += 1
            print(f"  [{elapsed_str()}] [DNS]    {domain:25s} via {dns_server:12s} -> TIMEOUT")
        except Exception as e:
            with stats_lock:
                stats["dns"]["sent"] += 1
                stats["dns"]["fail"] += 1
            print(f"  [{elapsed_str()}] [DNS]    {domain:25s} via {dns_server:12s} -> ERROR: {e}")
        time.sleep(random.uniform(0.5, 2.0))


# ======================== Scenario 2: Payload sizes ========================
def scenario_sizes(udp_sock, udp_port):
    sizes = [32, 64, 128, 256, 512, 1024, 1400]
    while time.time() - start < DURATION:
        size = random.choice(sizes)
        dns_server = random.choice(DNS_SERVERS)
        try:
            payload = random.randbytes(size)
            hdr = build_socksv5_udp_header(dns_server, 53)
            t0 = time.time()
            udp_sock.sendto(hdr + payload, (SOCKS_HOST, udp_port))
            udp_sock.settimeout(3)
            data, _ = udp_sock.recvfrom(1500)
            latency = (time.time() - t0) * 1000
            with stats_lock:
                stats["size"]["sent"] += 1
                stats["size"]["ok"] += 1
                stats["size"]["latencies"].append(latency)
            print(f"  [{elapsed_str()}] [SIZE]   {size:5d}B payload -> {latency:6.1f}ms  OK ({len(data)}B)")
        except socket.timeout:
            with stats_lock:
                stats["size"]["sent"] += 1
                stats["size"]["fail"] += 1
            print(f"  [{elapsed_str()}] [SIZE]   {size:5d}B payload -> TIMEOUT")
        except Exception as e:
            with stats_lock:
                stats["size"]["sent"] += 1
                stats["size"]["fail"] += 1
            print(f"  [{elapsed_str()}] [SIZE]   {size:5d}B payload -> ERROR: {e}")
        time.sleep(random.uniform(0.3, 1.0))


# ======================== Scenario 3: Burst (game/video) ========================
def scenario_burst(udp_sock, udp_port):
    while time.time() - start < DURATION:
        burst_size = random.randint(10, 30)
        sent_ok = 0
        sent_fail = 0
        latencies = []
        t0 = time.time()
        for i in range(burst_size):
            try:
                size = random.randint(64, 512)
                payload = random.randbytes(size)
                hdr = build_socksv5_udp_header(random.choice(DNS_SERVERS), 53)
                udp_sock.sendto(hdr + payload, (SOCKS_HOST, udp_port))
                sent_ok += 1
                with stats_lock:
                    stats["burst"]["sent"] += 1
            except:
                sent_fail += 1
                with stats_lock:
                    stats["burst"]["sent"] += 1
                    stats["burst"]["fail"] += 1
        # drain responses
        time.sleep(0.3)
        recv_count = 0
        try:
            udp_sock.settimeout(1)
            while True:
                data, _ = udp_sock.recvfrom(1500)
                recv_count += 1
                with stats_lock:
                    stats["burst"]["ok"] += 1
        except:
            pass
        elapsed = (time.time() - t0) * 1000
        print(f"  [{elapsed_str()}] [BURST]  sent {sent_ok}/{burst_size} packets in {elapsed:.0f}ms, got {recv_count} replies  {'OK' if sent_fail == 0 else f'{sent_fail} FAILED'}")
        time.sleep(random.uniform(3, 6))


# ======================== Scenario 4: VOIP keepalive ========================
def scenario_voip(udp_sock, udp_port):
    while time.time() - start < DURATION:
        try:
            payload = random.randbytes(200)
            hdr = build_socksv5_udp_header(random.choice(DNS_SERVERS), 53)
            t0 = time.time()
            udp_sock.sendto(hdr + payload, (SOCKS_HOST, udp_port))
            udp_sock.settimeout(3)
            data, _ = udp_sock.recvfrom(1500)
            latency = (time.time() - t0) * 1000
            with stats_lock:
                stats["voip"]["sent"] += 1
                stats["voip"]["ok"] += 1
                stats["voip"]["latencies"].append(latency)
            print(f"  [{elapsed_str()}] [VOIP]   keepalive 200B -> {latency:6.1f}ms  OK")
        except socket.timeout:
            with stats_lock:
                stats["voip"]["sent"] += 1
                stats["voip"]["fail"] += 1
            print(f"  [{elapsed_str()}] [VOIP]   keepalive 200B -> TIMEOUT")
        except Exception as e:
            with stats_lock:
                stats["voip"]["sent"] += 1
                stats["voip"]["fail"] += 1
            print(f"  [{elapsed_str()}] [VOIP]   keepalive 200B -> ERROR: {e}")
        time.sleep(1)


# ======================== Scenario 5: Large packets (near MTU) ========================
def scenario_large(udp_sock, udp_port):
    sizes = [800, 1000, 1200, 1400]
    while time.time() - start < DURATION:
        size = random.choice(sizes)
        dns_server = random.choice(DNS_SERVERS)
        try:
            payload = random.randbytes(size)
            hdr = build_socksv5_udp_header(dns_server, 53)
            t0 = time.time()
            udp_sock.sendto(hdr + payload, (SOCKS_HOST, udp_port))
            udp_sock.settimeout(3)
            data, _ = udp_sock.recvfrom(2000)
            latency = (time.time() - t0) * 1000
            with stats_lock:
                stats["large"]["sent"] += 1
                stats["large"]["ok"] += 1
                stats["large"]["latencies"].append(latency)
            print(f"  [{elapsed_str()}] [LARGE]  {size:5d}B -> {latency:6.1f}ms  OK ({len(data)}B)")
        except socket.timeout:
            with stats_lock:
                stats["large"]["sent"] += 1
                stats["large"]["fail"] += 1
            print(f"  [{elapsed_str()}] [LARGE]  {size:5d}B -> TIMEOUT")
        except Exception as e:
            with stats_lock:
                stats["large"]["sent"] += 1
                stats["large"]["fail"] += 1
            print(f"  [{elapsed_str()}] [LARGE]  {size:5d}B -> ERROR: {e}")
        time.sleep(random.uniform(1, 3))


def print_stats():
    print(f"\n{'=' * 72}")
    print(f"  RESULTS")
    print(f"{'=' * 72}")
    total_sent = 0
    total_ok = 0
    total_fail = 0
    for name, s in stats.items():
        sent = s["sent"]
        ok = s["ok"]
        fail = s["fail"]
        total_sent += sent
        total_ok += ok
        total_fail += fail
        rate = (ok / sent * 100) if sent > 0 else 0
        if s["latencies"]:
            avg_lat = sum(s["latencies"]) / len(s["latencies"])
            max_lat = max(s["latencies"])
            min_lat = min(s["latencies"])
            lat_str = f"  avg={avg_lat:.0f}ms min={min_lat:.0f}ms max={max_lat:.0f}ms"
        else:
            lat_str = ""
        print(f"  {name:8s}  sent={sent:4d}  ok={ok:4d}  fail={fail:4d}  rate={rate:5.1f}%{lat_str}")
    total_rate = (total_ok / total_sent * 100) if total_sent > 0 else 0
    print(f"  {'─' * 68}")
    print(f"  {'TOTAL':8s}  sent={total_sent:4d}  ok={total_ok:4d}  fail={total_fail:4d}  rate={total_rate:5.1f}%")
    print(f"{'=' * 72}")


# ======================== Main ========================
print(f"{'=' * 72}")
print(f"  Overplus UDP ASSOCIATE Multi-Scenario Test")
print(f"  Proxy: {SOCKS_HOST}:{SOCKS_PORT}  Duration: {DURATION}s")
print(f"{'=' * 72}\n")

tcp, udp_port = udp_associate(SOCKS_HOST, SOCKS_PORT)
print(f"  UDP ASSociate OK! Relay port: {udp_port}\n")

udp_sock = socket.socket(type=socket.SOCK_DGRAM)
udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
start = time.time()

threads = [
    threading.Thread(target=scenario_dns, args=(udp_sock, udp_port), daemon=True, name="DNS"),
    threading.Thread(target=scenario_sizes, args=(udp_sock, udp_port), daemon=True, name="SIZE"),
    threading.Thread(target=scenario_burst, args=(udp_sock, udp_port), daemon=True, name="BURST"),
    threading.Thread(target=scenario_voip, args=(udp_sock, udp_port), daemon=True, name="VOIP"),
    threading.Thread(target=scenario_large, args=(udp_sock, udp_port), daemon=True, name="LARGE"),
]

for t in threads:
    t.start()

try:
    while time.time() - start < DURATION:
        time.sleep(1)
except KeyboardInterrupt:
    pass

udp_sock.close()
tcp.close()

print_stats()
