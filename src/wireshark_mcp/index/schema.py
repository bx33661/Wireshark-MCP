"""Columns stored in the capture index and how each one compares in filters.

Every column holds tshark's own text for the field, exactly as
``tshark -T fields -E aggregator=,`` prints it. Keeping the text (rather than a
typed copy) is what lets indexed aggregation return the same groups, keys and
numeric results as a live tshark scan.
"""

from __future__ import annotations

from typing import Final, Literal

SCHEMA_VERSION: Final = 1

FieldKind = Literal["number", "bool", "ipv4", "ipv6", "mac", "string"]

# Ordered: this is also the column order of the `packets` table.
INDEX_FIELDS: Final[dict[str, FieldKind]] = {
    "frame.number": "number",
    "frame.time_epoch": "number",
    "frame.time_relative": "number",
    "frame.len": "number",
    "frame.protocols": "string",
    "eth.src": "mac",
    "eth.dst": "mac",
    "vlan.id": "number",
    "ip.src": "ipv4",
    "ip.dst": "ipv4",
    "ip.proto": "number",
    "ip.ttl": "number",
    "ip.len": "number",
    "ipv6.src": "ipv6",
    "ipv6.dst": "ipv6",
    "ipv6.nxt": "number",
    "tcp.stream": "number",
    "tcp.srcport": "number",
    "tcp.dstport": "number",
    "tcp.len": "number",
    "tcp.seq": "number",
    "tcp.ack": "number",
    "tcp.flags": "number",
    "tcp.flags.syn": "bool",
    "tcp.flags.ack": "bool",
    "tcp.flags.reset": "bool",
    "tcp.flags.fin": "bool",
    "tcp.flags.push": "bool",
    "tcp.window_size": "number",
    "udp.stream": "number",
    "udp.srcport": "number",
    "udp.dstport": "number",
    "udp.length": "number",
    "icmp.type": "number",
    "icmp.code": "number",
    "icmpv6.type": "number",
    "arp.opcode": "number",
    "arp.src.hw_mac": "mac",
    "arp.src.proto_ipv4": "ipv4",
    "arp.dst.proto_ipv4": "ipv4",
    "dns.id": "number",
    "dns.flags.response": "bool",
    "dns.flags.rcode": "number",
    "dns.qry.name": "string",
    "dns.qry.type": "number",
    "dns.a": "ipv4",
    "dns.aaaa": "ipv6",
    "dns.cname": "string",
    "http.request.method": "string",
    "http.host": "string",
    "http.request.uri": "string",
    "http.user_agent": "string",
    "http.response.code": "number",
    "http.content_type": "string",
    "tls.handshake.type": "number",
    "tls.handshake.extensions_server_name": "string",
    "tls.handshake.ja3": "string",
    "tls.handshake.ja4": "string",
    "tls.record.version": "number",
    "quic.version": "number",
    "dhcp.option.hostname": "string",
    "smb2.cmd": "number",
    "kerberos.CNameString": "string",
    "ntlmssp.auth.username": "string",
}

# Filter shorthands that test either side of a conversation.
FIELD_ALIASES: Final[dict[str, tuple[str, str]]] = {
    "eth.addr": ("eth.src", "eth.dst"),
    "ip.addr": ("ip.src", "ip.dst"),
    "ipv6.addr": ("ipv6.src", "ipv6.dst"),
    "tcp.port": ("tcp.srcport", "tcp.dstport"),
    "udp.port": ("udp.srcport", "udp.dstport"),
}

# Display filter protocol names whose frame.protocols token differs.
PROTOCOL_ALIASES: Final[dict[str, str]] = {"ssl": "tls", "bootp": "dhcp"}
