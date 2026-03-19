import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import socket
import threading
import argparse
import json
from common.protocol import build_packet, parse_packet, QUERY, RESPONSE, REFERRAL, OK, NXDOMAIN

def handle_resolve(sock, addr, data, AUTHORITATIVE_ZONES):
    resolver_query = parse_packet(data)
    print(f"[TLD NS] Received request from {addr}: {resolver_query}")

    if resolver_query["type"] == QUERY:
        domain = resolver_query["payload"]
        qtype = resolver_query["qtype"]

        authoritative_server = ".".join(domain.split(".")[-2:])
        auth_ns_port = AUTHORITATIVE_ZONES.get(authoritative_server)

        if auth_ns_port:
            print(f"[TLD NS] Sending referral to {addr} for Authoritative NS {authoritative_server} at port {auth_ns_port}")
            referral_response = build_packet(resolver_query["id"], REFERRAL, OK, qtype, str(auth_ns_port))
            sock.sendto(referral_response, addr)
        else:
            print(f"[TLD NS] Sending NXDOMAIN to {addr} for Authoritative NS {authoritative_server}")
            nxdomain_response = build_packet(resolver_query["id"], RESPONSE, NXDOMAIN, qtype, "")
            sock.sendto(nxdomain_response, addr)

def start_server(port, name, zones_file):
    with open(zones_file, "r") as f:
        authoritative_zones = json.load(f)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    sock.bind(("0.0.0.0", port))
    sock.settimeout(1.0)

    print(f"[{name}] started on port {port}...")
    print("Press Ctrl+C to stop the server.")

    try:
        while True:
            try:
                data, addr = sock.recvfrom(512)
                
                t = threading.Thread(target=handle_resolve, args=(sock, addr, data, authoritative_zones))
                t.daemon = True 
                t.start()
                
            except socket.timeout:
                continue

    except KeyboardInterrupt:
        print("\n[!] Shutting down the resolver...")

    finally:
        sock.close()
        print("TLD NS stopped...")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="TLD NS Server")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--name", type=str, default="TLD NS", help="Name of the TLD NS (e.g., .com, .ro)")
    parser.add_argument("--zones", type=str, required=True, help="Path to zones JSON file")
    args = parser.parse_args()
    PORT_TLD_NS = args.port
    TLD_NAME = args.name
    start_server(args.port, args.name, args.zones)
