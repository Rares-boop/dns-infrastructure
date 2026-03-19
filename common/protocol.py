import struct

# +--------+--------+--------+--------+--------+
# |   ID   |  TYPE  | RCODE  | QTYPE  |  LEN   |
# | 2 bytes| 1 byte | 1 byte | 1 byte | 2 bytes|
# +--------+--------+--------+--------+--------+
# |         PAYLOAD (domeniu/IP)               |
# +--------------------------------------------+

# client -> resolver -> root NS
#                           |
#           resolver <- "TLD NS e la X"
#                 |
#           resolver -> TLD NS
#                           |
#           resolver <- "Authoritative NS e la Y"
#                 |
#           resolver -> Authoritative NS
#                           |
#           resolver <- "IP e 1.2.3.4"
#                 |
# client <- resolver

# client1 ─┐
# client2 ──→ resolver1 ─┐
# client3 ─┘              │
#                         │
# client4 ─┐              ├──→ ROOT NS ──→ TLD NS .com ──→ AUTH NS .com
# client5 ──→ resolver2 ─┘              └→ TLD NS .ro  ──→ AUTH NS .ro
# client6 ─┘

# TYPE
QUERY    = 0x01
RESPONSE = 0x02
REFERRAL = 0x03

# RCODE
OK       = 0x00
NXDOMAIN = 0x03

# QTYPE
A    = 0x01
AAAA = 0x02
MX   = 0x03

HEADER_SIZE = 7  # 2+1+1+1+2

def build_packet(pkt_id, pkt_type, rcode, qtype, payload):
    payload_bytes = payload.encode()
     # > = big endian
    # H = unsigned short (2 bytes) -> ID
    # B = unsigned char (1 byte)   -> TYPE
    # B = unsigned char (1 byte)   -> RCODE
    # B = unsigned char (1 byte)   -> QTYPE
    # H = unsigned short (2 bytes) -> LEN
    header = struct.pack(">HBBBH", pkt_id, pkt_type, rcode, qtype, len(payload_bytes))
    return header + payload_bytes

def parse_packet(data):
    pkt_id, pkt_type, rcode, qtype, length = struct.unpack(">HBBBH", data[:HEADER_SIZE])
    payload = data[HEADER_SIZE:HEADER_SIZE+length].decode()
    return {
        "id": pkt_id,
        "type": pkt_type,
        "rcode": rcode,
        "qtype": qtype,
        "payload": payload
    }



