import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import socket
from common.protocol import build_packet, parse_packet, QUERY, RESPONSE, REFERRAL, OK, NXDOMAIN, A, AAAA, MX
import threading
import argparse
import time
import json
import secrets

CACHE_FILE = None
TTL = 60

HOST_ROOT_NS = None
PORT_ROOT_NS = None

def load_cache(cache_file):
    if os.path.exists(cache_file):
        with open(cache_file, "r") as f:
            data = json.load(f)
            return data.get("A", {}), data.get("AAAA", {}), data.get("MX", {})
    return {}, {}, {}

def save_cache(cache_file):
    with open(cache_file, "w") as f:
        json.dump({"A": CACHE_A_RECORD, "AAAA": CACHE_AAAA_RECORD, "MX": CACHE_MX_RECORD}, f, indent=2)

def cache_get(cache, domain):
    entry = cache.get(domain)
    if not entry:
        return None
    if entry["expires"] is not None and time.time() > entry["expires"]:
        print(f"[RESOLVER] Cache expired for {domain}")
        del cache[domain]
        return None
    return entry["ip"]

def cache_set(cache, domain, value):
    cache[domain] = {"ip": value, "expires": time.time() + TTL}

def query_upstream(host, port, pkt_id, qtype, domain):
    upstream_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    upstream_sock.settimeout(2.0)
    try:
        packet = build_packet(pkt_id, QUERY, OK, qtype, domain)
        upstream_sock.sendto(packet, (host, port))
        data, _ = upstream_sock.recvfrom(512)
        return parse_packet(data)
    except socket.timeout:
        print(f"[RESOLVER] Timeout at {host}:{port}")
        return None
    finally:
        upstream_sock.close()

def resolve_upstream(domain, qtype):
    # STEP 1: ask root NS
    print(f"[RESOLVER] Cache miss for {domain}. Asking Root NS...")
    root_response = query_upstream(HOST_ROOT_NS, PORT_ROOT_NS, secrets.randbits(16), qtype, domain)
    if not root_response or root_response["type"] != REFERRAL:
        print(f"[RESOLVER] Root NS did not respond or did not send referral.")
        return None

    # STEP 2: ask TLD NS
    tld_ip, tld_port = root_response["payload"].split(":")
    print(f"[RESOLVER] Root NS referred to TLD NS at {tld_ip} at port {tld_port}. Asking TLD NS...")
    tld_response = query_upstream(tld_ip, int(tld_port), secrets.randbits(16), qtype, domain)
    if not tld_response or tld_response["type"] != REFERRAL:
        print(f"[RESOLVER] TLD NS did not respond or did not send referral.")
        return None

    # STEP 3: ask Authoritative NS
    auth_ip, auth_port = tld_response["payload"].split(":")
    print(f"[RESOLVER] TLD NS referred to Auth NS at {auth_ip} at port {auth_port}. Asking Auth NS...")
    auth_response = query_upstream(auth_ip, int(auth_port), secrets.randbits(16), qtype, domain)
    if not auth_response or auth_response["rcode"] != OK:
        print(f"[RESOLVER] Auth NS did not respond or returned NXDOMAIN.")
        return None

    print(f"[RESOLVER] Resolved {domain} -> {auth_response['payload']}")
    return auth_response["payload"]

def handle_request(sock, addr, request):
    req_id = request["id"]
    req_type = request["type"]
    qtype = request["qtype"]
    domain = request["payload"]

    response = None

    if req_type == QUERY:
        if qtype == A:
            result = cache_get(CACHE_A_RECORD, domain)
            if result:
                print(f"[RESOLVER] Cache hit: {domain} -> {result}")
            else:
                result = resolve_upstream(domain, qtype)
                if result:
                    cache_set(CACHE_A_RECORD, domain, result)
                    save_cache(CACHE_FILE)
            response = build_packet(req_id, RESPONSE, OK if result else NXDOMAIN, A, result or "")

        elif qtype == AAAA:
            result = cache_get(CACHE_AAAA_RECORD, domain)
            if result:
                print(f"[RESOLVER] Cache hit: {domain} -> {result}")
            else:
                result = resolve_upstream(domain, qtype)
                if result:
                    cache_set(CACHE_AAAA_RECORD, domain, result)
                    save_cache(CACHE_FILE)
            response = build_packet(req_id, RESPONSE, OK if result else NXDOMAIN, AAAA, result or "")

        elif qtype == MX:
            result = cache_get(CACHE_MX_RECORD, domain)
            if result:
                print(f"[RESOLVER] Cache hit: {domain} -> {result}")
            else:
                result = resolve_upstream(domain, qtype)
                if result:
                    cache_set(CACHE_MX_RECORD, domain, result)
                    save_cache(CACHE_FILE)
            response = build_packet(req_id, RESPONSE, OK if result else NXDOMAIN, MX, result or "")

    if response:
        sock.sendto(response, addr)

def handle_client(sock, data, addr):
    request = parse_packet(data)
    print(f"[RESOLVER] Received request from {addr}: {request}")
    handle_request(sock, addr, request)

def start_server(port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", port))
    sock.settimeout(1.0)

    print(f"Resolver started on port {port}...")

    try:
        while True:
            try:
                data, addr = sock.recvfrom(512)
                t = threading.Thread(target=handle_client, args=(sock, data, addr))
                t.daemon = True
                t.start()
            except socket.timeout:
                continue
    except KeyboardInterrupt:
        print("\n[!] Shutting down the resolver...")
    finally:
        sock.close()
        print("Resolver stopped cleanly.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=9999)
    parser.add_argument("--root-ip", type=str, default="127.0.0.1")
    parser.add_argument("--root", type=int, default=10000)
    parser.add_argument("--cache", type=str, default="cache.json")
    args = parser.parse_args()
    HOST_ROOT_NS = args.root_ip
    PORT_ROOT_NS = args.root
    CACHE_FILE = args.cache
    CACHE_A_RECORD, CACHE_AAAA_RECORD, CACHE_MX_RECORD = load_cache(CACHE_FILE)
    start_server(args.port)

