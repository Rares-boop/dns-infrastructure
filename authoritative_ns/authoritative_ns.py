import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import socket
import threading
import argparse
import json
from common.protocol import build_packet, parse_packet, QUERY, RESPONSE, OK, NXDOMAIN, A, AAAA, MX

def handle_resolve(sock, addr, data, records):
    request = parse_packet(data)
    print(f"[AUTH NS] Received request from {addr}: {request}")

    if request["type"] == QUERY:
        domain = request["payload"]
        qtype = request["qtype"]

        if qtype == A:
            result = records.get("A", {}).get(domain)
        elif qtype == AAAA:
            result = records.get("AAAA", {}).get(domain)
        elif qtype == MX:
            result = records.get("MX", {}).get(domain)
        else:
            result = None

        if result:
            print(f"[AUTH NS] {domain} -> {result}")
            response = build_packet(request["id"], RESPONSE, OK, qtype, result)
        else:
            print(f"[AUTH NS] NXDOMAIN: {domain}")
            response = build_packet(request["id"], RESPONSE, NXDOMAIN, qtype, "")

        sock.sendto(response, addr)

def start_server(port, name, zones_file):
    with open(zones_file, "r") as f:
        records = json.load(f)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", port))
    sock.settimeout(1.0)

    print(f"[{name}] started on port {port}...")

    try:
        while True:
            try:
                data, addr = sock.recvfrom(512)
                t = threading.Thread(target=handle_resolve, args=(sock, addr, data, records))
                t.daemon = True
                t.start()
            except socket.timeout:
                continue
    except KeyboardInterrupt:
        print(f"\n[!] Shutting down {name}...")
    finally:
        sock.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Authoritative NS")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--name", type=str, default="AUTH NS")
    parser.add_argument("--zones", type=str, required=True)
    args = parser.parse_args()
    start_server(args.port, args.name, args.zones)


