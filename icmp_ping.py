#!/usr/bin/env python3
"""
Simple ICMP Pinger (raw sockets)

Usage:
    sudo python3 icmp_ping.py 8.8.8.8
    sudo python3 icmp_ping.py google.com -c 10 -t 2 -i 1

On Windows: run VS Code (or the terminal) as Administrator, then:
    python icmp_ping.py 8.8.8.8
"""

import argparse
import os
import select
import socket
import struct
import sys
import time

ICMP_ECHO_REPLY = 0
ICMP_DEST_UNREACHABLE = 3
ICMP_ECHO_REQUEST = 8
ICMP_TIME_EXCEEDED = 11

UNREACHABLE_CODES = {
    0: "Destination network unreachable",
    1: "Destination host unreachable",
    2: "Destination protocol unreachable",
    3: "Destination port unreachable",
}


def checksum(data: bytes) -> int:
    """Internet checksum (RFC 1071)."""
    total = 0
    for i in range(0, len(data) - 1, 2):
        total += (data[i] << 8) + data[i + 1]
    if len(data) % 2:
        total += data[-1] << 8
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return ~total & 0xFFFF


def build_packet(ident: int, seq: int) -> bytes:
    """Build an ICMP Echo Request: header + timestamp + padding."""
    payload = struct.pack("!d", time.time()) + b"abcdefghijklmnopqrstuvwxyz012345"
    header = struct.pack("!BBHHH", ICMP_ECHO_REQUEST, 0, 0, ident, seq)
    chk = checksum(header + payload)
    header = struct.pack("!BBHHH", ICMP_ECHO_REQUEST, 0, chk, ident, seq)
    return header + payload


def receive_one(sock, ident: int, seq: int, timeout: float):
    """
    Wait for the reply to our request.
    Returns:
        None                                  -> timeout
        ("reply", rtt_ms, ttl, src_ip, size)  -> Echo Reply
        ("error", type, code, src_ip)         -> Destination Unreachable / Time Exceeded
    """
    deadline = time.time() + timeout
    while True:
        remaining = deadline - time.time()
        if remaining <= 0:
            return None
        ready = select.select([sock], [], [], remaining)
        if not ready[0]:
            return None

        packet, addr = sock.recvfrom(1024)
        recv_time = time.time()

        ihl = (packet[0] & 0x0F) * 4          # IP header length in bytes
        ttl = packet[8]
        icmp = packet[ihl:ihl + 8]
        if len(icmp) < 8:
            continue

        icmp_type, code, _, rid, rseq = struct.unpack("!BBHHH", icmp)

        # Normal echo reply that belongs to us
        if icmp_type == ICMP_ECHO_REPLY and rid == ident and rseq == seq:
            sent = struct.unpack("!d", packet[ihl + 8:ihl + 16])[0]
            return ("reply", (recv_time - sent) * 1000, ttl, addr[0], len(packet) - ihl)

        # Error messages carry the original IP header + first 8 bytes of our packet
        if icmp_type in (ICMP_DEST_UNREACHABLE, ICMP_TIME_EXCEEDED):
            inner = packet[ihl + 8:]
            if len(inner) >= 28:
                inner_ihl = (inner[0] & 0x0F) * 4
                orig = inner[inner_ihl:inner_ihl + 8]
                if len(orig) >= 8:
                    o_type, _, _, o_id, o_seq = struct.unpack("!BBHHH", orig)
                    if o_type == ICMP_ECHO_REQUEST and o_id == ident and o_seq == seq:
                        return ("error", icmp_type, code, addr[0])
        # Otherwise: not ours, keep waiting until the deadline


def ping(host: str, count: int, timeout: float, interval: float):
    try:
        dest_ip = socket.gethostbyname(host)
    except socket.gaierror:
        print(f"ping: cannot resolve {host}: Unknown host")
        return

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))
    except PermissionError:
        print("Permission denied: raw sockets need root/administrator privileges.")
        print("Linux/macOS: run with sudo.  Windows: run as Administrator.")
        sys.exit(1)

    ident = os.getpid() & 0xFFFF
    sent = received = 0
    rtts = []

    print(f"PING {host} ({dest_ip}): {len(build_packet(ident, 0)) - 8} data bytes")

    try:
        for seq in range(1, count + 1):
            sock.sendto(build_packet(ident, seq), (dest_ip, 1))
            sent += 1

            result = receive_one(sock, ident, seq, timeout)

            if result is None:
                print(f"Request timed out (seq={seq})")
            elif result[0] == "reply":
                _, rtt, ttl, src, size = result
                received += 1
                rtts.append(rtt)
                print(f"{size} bytes from {src}: seq={seq} ttl={ttl} time={rtt:.2f} ms")
            else:
                _, icmp_type, code, src = result
                if icmp_type == ICMP_DEST_UNREACHABLE:
                    msg = UNREACHABLE_CODES.get(code, f"Destination unreachable (code {code})")
                else:
                    msg = "Time to live exceeded"
                print(f"From {src}: seq={seq} {msg}")

            if seq < count:
                time.sleep(interval)
    except KeyboardInterrupt:
        print()
    finally:
        sock.close()

    loss = (sent - received) / sent * 100 if sent else 0
    print(f"\n--- {host} ping statistics ---")
    print(f"{sent} packets transmitted, {received} received, {loss:.0f}% packet loss")
    if rtts:
        print(f"rtt min/avg/max = {min(rtts):.2f}/{sum(rtts) / len(rtts):.2f}/{max(rtts):.2f} ms")


def main():
    parser = argparse.ArgumentParser(description="Simple ICMP pinger")
    parser.add_argument("host", help="hostname or IP address")
    parser.add_argument("-c", "--count", type=int, default=4, help="number of requests (default 4)")
    parser.add_argument("-t", "--timeout", type=float, default=1.0, help="timeout in seconds (default 1)")
    parser.add_argument("-i", "--interval", type=float, default=1.0, help="seconds between requests (default 1)")
    args = parser.parse_args()
    ping(args.host, args.count, args.timeout, args.interval)


if __name__ == "__main__":
    main()
