import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import socket
import threading
import argparse
import sys
from common.protocol import build_packet, parse_packet, QUERY, RESPONSE, REFERRAL, OK, NXDOMAIN

PORT = 10000

def handle_resolve(sock, addr, data, tld_zones):
    resolver_query = parse_packet(data)
    print(f"[ROOT NS] Received request from {addr}: {resolver_query}")

    if resolver_query["type"] == QUERY:
        domain = resolver_query["payload"]
        qtype = resolver_query["qtype"]

        tld = domain.split(".")[-1]
        result = tld_zones.get(tld)

        if result:
            tld_ip, tld_port = result
            print(f"[ROOT NS] Sending referral to {addr} for TLD .{tld} at port {tld_port}")
            referral_response = build_packet(resolver_query["id"], REFERRAL, OK, qtype, f"{tld_ip}:{tld_port}")
            sock.sendto(referral_response, addr)
        else:
            print(f"[ROOT NS] Sending NXDOMAIN to {addr} for TLD .{tld}")
            nxdomain_response = build_packet(resolver_query["id"], RESPONSE, NXDOMAIN, qtype, "")
            sock.sendto(nxdomain_response, addr)

def start_server(tld_zones):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    sock.bind(("0.0.0.0", PORT))
    sock.settimeout(1.0)

    print(f"ROOT NS started on port {PORT}...")
    print("Press Ctrl+C to stop the server.")

    try:
        while True:
            try:
                data, addr = sock.recvfrom(512)
                
                t = threading.Thread(target=handle_resolve, args=(sock, addr, data, tld_zones))
                t.daemon = True 
                t.start()
                
            except socket.timeout:
                continue

    except KeyboardInterrupt:
        print("\n[!] Shutting down the resolver...")

    finally:
        sock.close()
        print("Root NS stopped...")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Root NS Server")  
    parser.add_argument("--tld-com-ip", type=str, default="127.0.0.1")
    parser.add_argument("--tld-ro-ip", type=str, default="127.0.0.1")
    args = parser.parse_args()

    tld_zones = {
        "com": (args.tld_com_ip, 6355),
        "ro":  (args.tld_ro_ip, 6360),
    }

    start_server(tld_zones)


