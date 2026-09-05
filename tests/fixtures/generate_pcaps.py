"""Deterministic PCAP fixture builder for Wireshark MCP integration tests.

Generates minimal valid pcap files using only Python standard library.
"""

import socket
import struct
from pathlib import Path


def _checksum(data: bytes) -> int:
    if len(data) % 2 == 1:
        data += b"\x00"
    s = sum(struct.unpack(f"!{len(data) // 2}H", data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def make_pcap_header() -> bytes:
    # magic, ver_major(2), ver_minor(4), thiszone(0), sigfigs(0), snaplen(65535), linktype_ethernet(1)
    return struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)


def make_pcap_packet(frame: bytes, sec: int = 0, usec: int = 0) -> bytes:
    return struct.pack("<IIII", sec, usec, len(frame), len(frame)) + frame


def make_ipv4_packet(src_ip: str, dst_ip: str, proto: int, payload: bytes) -> bytes:
    ihl_version = 0x45
    tos = 0
    tot_len = 20 + len(payload)
    ident = 0x1234
    flags_frag = 0x4000
    ttl = 64
    src_bytes = socket.inet_aton(src_ip)
    dst_bytes = socket.inet_aton(dst_ip)
    header_no_cs = struct.pack(
        "!BBHHHBBH4s4s", ihl_version, tos, tot_len, ident, flags_frag, ttl, proto, 0, src_bytes, dst_bytes
    )
    cs = _checksum(header_no_cs)
    header = struct.pack(
        "!BBHHHBBH4s4s", ihl_version, tos, tot_len, ident, flags_frag, ttl, proto, cs, src_bytes, dst_bytes
    )
    return header + payload


def make_ethernet_frame(payload: bytes, ethertype: int = 0x0800) -> bytes:
    dst_mac = b"\x00\x11\x22\x33\x44\x55"
    src_mac = b"\xaa\xbb\xcc\xdd\xee\xff"
    return dst_mac + src_mac + struct.pack("!H", ethertype) + payload


def make_tcp_packet(
    src_ip: str, dst_ip: str, src_port: int, dst_port: int, flags: int, payload: bytes = b"", seq: int = 1, ack: int = 0
) -> bytes:
    offset_res = 5 << 4
    window = 65535
    tcp_hdr_no_cs = struct.pack("!HHIIBBHHH", src_port, dst_port, seq, ack, offset_res, flags, window, 0, 0)
    # Pseudo header for TCP checksum
    pseudo = struct.pack(
        "!4s4sBBH", socket.inet_aton(src_ip), socket.inet_aton(dst_ip), 0, 6, len(tcp_hdr_no_cs) + len(payload)
    )
    cs = _checksum(pseudo + tcp_hdr_no_cs + payload)
    tcp_hdr = struct.pack("!HHIIBBHHH", src_port, dst_port, seq, ack, offset_res, flags, window, cs, 0)
    return make_ipv4_packet(src_ip, dst_ip, 6, tcp_hdr + payload)


def make_udp_packet(src_ip: str, dst_ip: str, src_port: int, dst_port: int, payload: bytes) -> bytes:
    length = 8 + len(payload)
    # UDP checksum 0 is valid in IPv4 (means not computed)
    udp_hdr = struct.pack("!HHHH", src_port, dst_port, length, 0)
    return make_ipv4_packet(src_ip, dst_ip, 17, udp_hdr + payload)


def encode_dns_name(domain: str) -> bytes:
    res = b""
    for part in domain.strip(".").split("."):
        b_part = part.encode("ascii")
        res += struct.pack("B", len(b_part)) + b_part
    res += b"\x00"
    return res


def make_dns_query(qname: str, qtype: int = 1, txid: int = 0x1234) -> bytes:
    flags = 0x0100  # standard query, recursion desired
    header = struct.pack("!HHHHHH", txid, flags, 1, 0, 0, 0)
    question = encode_dns_name(qname) + struct.pack("!HH", qtype, 1)
    return header + question


def build_all_fixtures(output_dir: Path) -> dict[str, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    generated: dict[str, Path] = {}

    # 1. empty.pcap
    p_empty = output_dir / "empty.pcap"
    p_empty.write_bytes(make_pcap_header())
    generated["empty"] = p_empty

    # 2. plaintext_credentials.pcap
    # Contains HTTP Basic Auth ("admin:secret") and FTP PASS ("PASS 123456")
    p_creds = output_dir / "plaintext_credentials.pcap"
    creds_bytes = bytearray(make_pcap_header())

    # HTTP packet (Basic YWRtaW46c2VjcmV0 = admin:secret)
    http_payload = (
        b"GET /login HTTP/1.1\r\n"
        b"Host: 10.0.0.1\r\n"
        b"Authorization: Basic YWRtaW46c2VjcmV0\r\n"
        b"User-Agent: Mozilla/5.0, TestAgent\r\n\r\n"
    )
    ip_tcp = make_tcp_packet("192.168.1.10", "10.0.0.1", 45678, 80, flags=0x18, payload=http_payload)
    frame = make_ethernet_frame(ip_tcp)
    creds_bytes.extend(make_pcap_packet(frame, sec=1000, usec=0))

    # FTP command: USER testuser\r\n
    ftp_user = b"USER testuser\r\n"
    ip_ftp_u = make_tcp_packet("192.168.1.10", "10.0.0.2", 45679, 21, flags=0x18, payload=ftp_user)
    creds_bytes.extend(make_pcap_packet(make_ethernet_frame(ip_ftp_u), sec=1001, usec=0))

    # FTP command: PASS 123456\r\n
    ftp_pass = b"PASS 123456\r\n"
    ip_ftp_p = make_tcp_packet(
        "192.168.1.10", "10.0.0.2", 45679, 21, flags=0x18, payload=ftp_pass, seq=1 + len(ftp_user), ack=1
    )
    creds_bytes.extend(make_pcap_packet(make_ethernet_frame(ip_ftp_p), sec=1002, usec=0))

    p_creds.write_bytes(creds_bytes)
    generated["credentials"] = p_creds

    # 3. syn_scan_burst.pcap
    # 25 SYN packets to different ports from 192.168.1.50 within 1 second
    p_scan = output_dir / "syn_scan_burst.pcap"
    scan_bytes = bytearray(make_pcap_header())
    for i in range(25):
        port = 8000 + i
        pkt = make_tcp_packet("192.168.1.50", "10.0.0.5", 50000 + i, port, flags=0x02)
        scan_bytes.extend(make_pcap_packet(make_ethernet_frame(pkt), sec=2000, usec=i * 20000))
    p_scan.write_bytes(scan_bytes)
    generated["syn_scan"] = p_scan

    # 4. dns_tunnel_candidate.pcap
    # Legitimate queries + 25 high-subdomain exfil queries (>50 chars, TXT)
    p_dns = output_dir / "dns_tunnel_candidate.pcap"
    dns_bytes = bytearray(make_pcap_header())

    # 2 normal queries
    for domain in ["www.google.com", "cdn.cloudflare.com"]:
        q = make_dns_query(domain, qtype=1)
        pkt = make_udp_packet("192.168.1.20", "8.8.8.8", 53001, 53, q)
        dns_bytes.extend(make_pcap_packet(make_ethernet_frame(pkt), sec=3000, usec=0))

    # 25 candidate exfil queries
    for i in range(25):
        qname = f"exfilpayloadpart{i:03d}somesecretdataandlargesubdomainstring.tunnel.attacker.org"
        q = make_dns_query(qname, qtype=16)  # TXT
        pkt = make_udp_packet("192.168.1.20", "8.8.8.8", 53002, 53, q)
        dns_bytes.extend(make_pcap_packet(make_ethernet_frame(pkt), sec=3001, usec=i * 10000))

    p_dns.write_bytes(dns_bytes)
    generated["dns_tunnel"] = p_dns

    # 5. multivalue_fields.pcap
    # HTTP requests with comma in User-Agent header
    p_multi = output_dir / "multivalue_fields.pcap"
    multi_bytes = bytearray(make_pcap_header())
    http_commas = (
        b"GET /index.html HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"User-Agent: Mozilla/5.0, CustomAgent/1.0, Token/2.0\r\n"
        b"Accept: text/html,application/xhtml+xml\r\n\r\n"
    )
    pkt = make_tcp_packet("10.1.1.5", "93.184.216.34", 41234, 80, flags=0x18, payload=http_commas)
    multi_bytes.extend(make_pcap_packet(make_ethernet_frame(pkt), sec=4000, usec=0))
    p_multi.write_bytes(multi_bytes)
    generated["multivalue"] = p_multi

    return generated


if __name__ == "__main__":
    fixtures_dir = Path(__file__).parent / "pcaps"
    res = build_all_fixtures(fixtures_dir)
    print(f"Generated {len(res)} fixture pcaps in {fixtures_dir}")
