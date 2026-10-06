#!/usr/bin/env python3
"""Latency probes through the tunnel: small TCP request + UDP echo, run until a deadline.
usage: probe.py <label> <seconds> <tcp_host> <tcp_port> <udp_port>"""
import socket, sys, threading, time, statistics

label, secs, host, tport, uport = sys.argv[1], float(sys.argv[2]), sys.argv[3], int(sys.argv[4]), int(sys.argv[5])
end = time.time() + secs
tcp_lat, udp_lat, tcp_fail, udp_lost = [], [], 0, 0

def tcp_loop():
    global tcp_fail
    while time.time() < end:
        t0 = time.time()
        try:
            s = socket.create_connection((host, tport), timeout=10)
            s.sendall(b"GET /small HTTP/1.0\r\nHost: x\r\n\r\n")
            data = b""
            while b"\r\n\r\n" not in data:
                c = s.recv(4096)
                if not c: break
                data += c
            head, _, body = data.partition(b"\r\n\r\n")
            n = 0
            for line in head.split(b"\r\n"):
                if line.lower().startswith(b"content-length:"):
                    n = int(line.split(b":")[1])
            while len(body) < n:
                c = s.recv(4096)
                if not c: break
                body += c
            data = body
            s.close()
            if b"ok" in data:
                tcp_lat.append((time.time() - t0) * 1000)
            else:
                tcp_fail += 1
        except Exception:
            tcp_fail += 1
        time.sleep(0.2)

def udp_loop():
    global udp_lost
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3)
    seq = 0
    while time.time() < end:
        seq += 1
        t0 = time.time()
        s.sendto(b"%d" % seq, (host, uport))
        try:
            while True:
                d, _ = s.recvfrom(100)
                if d == b"%d" % seq:
                    udp_lat.append((time.time() - t0) * 1000)
                    break
        except socket.timeout:
            udp_lost += 1
        time.sleep(max(0, 0.1 - (time.time() - t0)))

th = [threading.Thread(target=tcp_loop), threading.Thread(target=udp_loop)]
[t.start() for t in th]; [t.join() for t in th]

def pct(v, p):
    if not v: return float("nan")
    v = sorted(v); return v[min(len(v) - 1, int(len(v) * p / 100))]

print(f"[{label}] TCP small req: n={len(tcp_lat)} fail={tcp_fail} p50={pct(tcp_lat,50):.0f}ms p95={pct(tcp_lat,95):.0f}ms p99={pct(tcp_lat,99):.0f}ms max={max(tcp_lat or [0]):.0f}ms")
print(f"[{label}] UDP echo     : n={len(udp_lat)} lost={udp_lost} p50={pct(udp_lat,50):.0f}ms p95={pct(udp_lat,95):.0f}ms p99={pct(udp_lat,99):.0f}ms max={max(udp_lat or [0]):.0f}ms")
