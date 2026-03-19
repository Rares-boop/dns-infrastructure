import argparse
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import socket
from common.protocol import build_packet, parse_packet, OK, NXDOMAIN
import secrets

def main(resolver_port, client_name):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2)

    while True:
        domain = input(f"\n[{client_name}] Enter a type of record (A, AAAA, MX) and a domain (e.g., A google.com), or 'exit' to quit: ")
        
        if domain.lower() == "exit":
            break

        parts = domain.split()
        if len(parts) != 2:
            print("[!] Wrong format! Please type: TYPE DOMAIN (e.g., A google.com)")
            continue

        qtype_str = parts[0].upper()
        payload = parts[1]

        pkt_id = secrets.randbits(16) 
        pkt_type = 0x01  # QUERY
        rcode = 0x00     # OK
        qtype = {"A": 0x01, "AAAA": 0x02, "MX": 0x03}.get(qtype_str)

        if qtype is None:
            print("Invalid record type. Please enter A, AAAA, or MX.")
            continue

        packet = build_packet(pkt_id, pkt_type, rcode, qtype, payload)
       
        sock.sendto(packet, ("127.0.0.1", resolver_port))
        
        try:
            data, _ = sock.recvfrom(512)
            
            parsed_response = parse_packet(data)
            
            if parsed_response["rcode"] == OK:
                print(f"[SUCCESS] Address for {payload}: {parsed_response['payload']}")
            elif parsed_response["rcode"] == NXDOMAIN:
                print(f"[ERROR] Domain {payload} does not exist (NXDOMAIN).")
            else:
                print(f"[UNKNOWN] Response code: {parsed_response['rcode']}")

        except socket.timeout:
            print("[!] Server did not respond in time. Is it running?")
        except Exception as e:
            print(f"[!] Error parsing packet: {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DNS Client")
    parser.add_argument("--resolver", type=int, default=9999, help="Port resolver")
    parser.add_argument("--name", type=str, default="Client", help="Client name for prompts")
    args = parser.parse_args()
    main(args.resolver, args.name)

