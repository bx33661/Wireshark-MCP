"""The single per-protocol analysis tool.

This replaces 21 near-identical `wireshark_analyze_<protocol>` tools. They were
consolidated rather than deleted because their value is the field lists, not the
code: `s7comm.param.item.dbnum` and `zbee_aps.cluster` are not names a caller
guesses, and a wrong guess passed to a generic field extractor returns an empty
result that reads like a clean capture. Keeping one tool per protocol paid ~4 KB
of prompt prefix on every request, and 21 similarly-worded entries competing at
tool-selection time, to carry knowledge that fits in an enum.

`protocol` is a Literal so the value set ships in the schema: the caller picks
from a closed list instead of guessing a string, and a typo fails at validation
rather than looking like an empty capture.
"""

from typing import Any, Literal, get_args

from ..tshark.client import TSharkClient
from .envelope import ProtocolHandler, error_response, normalize_tool_result
from .ics import make_ics_handlers
from .iot import make_iot_handlers
from .protocol import make_protocol_handlers

# Keep in sync with the handler dict below; tests assert the two match exactly.
# Most values name a protocol; `doh` and `icmp_tunnel` name a *heuristic* over one
# (DNS-over-HTTPS content types, ICMP payloads over 48 bytes) and are deliberately
# not called `http2`/`icmp`, which would imply they return all such traffic.
Protocol = Literal[
    "ble",
    "coap",
    "dhcp",
    "dnp3",
    "doh",
    "grpc",
    "icmp_tunnel",
    "kerberos",
    "modbus",
    "mqtt",
    "quic",
    "rtp",
    "s7comm",
    "smb",
    "smtp",
    "tls_handshakes",
    "websocket",
    "wifi",
    "wireguard",
    "zigbee",
]


def make_analyze_tools(client: TSharkClient) -> list[tuple[str, Any]]:
    """Build the consolidated protocol analysis tool."""

    async def _rtp(pcap_file: str, limit: int) -> str:
        # -z rtp,streams emits one row per stream; there is nothing to cap.
        return normalize_tool_result(await client.get_rtp_streams(pcap_file))

    async def _smb(pcap_file: str, limit: int) -> str:
        # -z smb,srt emits a fixed summary table; there is nothing to cap.
        return normalize_tool_result(await client.get_smb_stats(pcap_file))

    async def _kerberos(pcap_file: str, limit: int) -> str:
        return normalize_tool_result(await client.extract_kerberos(pcap_file, limit))

    handlers: dict[str, ProtocolHandler] = {
        **make_protocol_handlers(client),
        **make_ics_handlers(client),
        **make_iot_handlers(client),
        "rtp": _rtp,
        "smb": _smb,
        "kerberos": _kerberos,
    }

    async def wireshark_analyze_protocol(pcap_file: str, protocol: Protocol, limit: int = 100) -> str:
        """[Protocol] Analyze one protocol with preset fields and filter. Returns a summary and bounded rows; RTP/SMB use fixed tables."""
        handler = handlers.get(protocol)
        if handler is None:
            return error_response(
                f"Unknown protocol {protocol!r}. Supported: {', '.join(sorted(handlers))}.",
                error_type="ValueError",
            )
        return await handler(pcap_file, limit)

    return [("wireshark_analyze_protocol", wireshark_analyze_protocol)]


def supported_protocols() -> tuple[str, ...]:
    """The protocol values declared in the tool schema."""
    return get_args(Protocol)
