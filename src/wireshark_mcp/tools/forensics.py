"""Forensics tools for Wireshark MCP — TLS fingerprinting and file-signature scanning."""

import asyncio
import json
import logging
from pathlib import Path
from typing import Any

from ..tshark.client import TSharkClient
from .envelope import normalize_tool_result, parse_tool_result, success_response
from .formatting import CRIT, INFO, OK, WARN

logger = logging.getLogger("wireshark_mcp")

_FINGERPRINT_DB: list[dict[str, str]] | None = None


def _load_fingerprint_db() -> list[dict[str, str]]:
    """Load user-supplied JA3 fingerprints from ~/.wireshark-mcp/fingerprints/*.json.

    No list ships with the package. A JA3 hash is a digest of Client Hello parameters
    (cipher suites, extensions, curves), so every client built on the same TLS stack
    with the same configuration produces the same hash — the value identifies a
    configuration, not a program. Labelling one `CobaltStrike` therefore reports a
    confident attribution for traffic that may be any application sharing that stack,
    and a five-entry snapshot pinned in a released package cannot be kept current.

    Matching against a list the operator maintains is a different proposition: they
    own both the intel and its freshness, and they know what the labels mean.
    Expected shape: {"fingerprints": [{"ja3": "<md5>", "label": "...", "category": "..."}]}
    """
    global _FINGERPRINT_DB
    if _FINGERPRINT_DB is not None:
        return _FINGERPRINT_DB

    fingerprints: list[dict[str, str]] = []

    user_dir = Path.home() / ".wireshark-mcp" / "fingerprints"
    if user_dir.exists():
        for f in sorted(user_dir.glob("*.json")):
            try:
                db = json.loads(f.read_text(encoding="utf-8"))
                fingerprints.extend(db.get("fingerprints", []))
            except Exception:
                logger.warning("Could not load user fingerprint file: %s", f)

    _FINGERPRINT_DB = fingerprints
    return _FINGERPRINT_DB


def make_forensics_tools(client: TSharkClient) -> list[tuple[str, Any]]:
    """Build forensics tools."""

    async def wireshark_extract_fingerprints(pcap_file: str, limit: int = 100) -> str:
        """[Forensics] Extract JA3/JA3S TLS fingerprints and optionally match local user-maintained lists. Treat matches as leads."""
        # JA3 is computed from the Client Hello and JA3S from the Server Hello, so the
        # two need separate passes: filtering to type == 1 leaves the ja3s column empty
        # in every row, which is what this tool used to do while advertising both.
        client_fields = [
            "ip.src",
            "ip.dst",
            "tcp.dstport",
            "tls.handshake.ja3",
            "tls.handshake.extensions_server_name",
        ]
        result = await client.extract_fields(
            pcap_file, client_fields, display_filter="tls.handshake.type == 1", limit=limit
        )
        wrapped = parse_tool_result(result)
        if not wrapped["success"]:
            return normalize_tool_result(wrapped)

        output_parts = [f"{INFO} JA3 client fingerprints"]
        output_parts.append(wrapped.get("data", "No data"))

        server_result = await client.extract_fields(
            pcap_file,
            ["ip.src", "ip.dst", "tcp.srcport", "tls.handshake.ja3s"],
            display_filter="tls.handshake.type == 2",
            limit=limit,
        )
        server_wrapped = parse_tool_result(server_result)
        if server_wrapped["success"]:
            server_data = server_wrapped.get("data", "")
            if isinstance(server_data, str) and server_data.strip():
                output_parts.append(f"\n{INFO} JA3S server fingerprints")
                output_parts.append(server_data)

        db = _load_fingerprint_db()
        if db:
            matches = []
            raw_data = wrapped.get("data", "")
            if isinstance(raw_data, str):
                for line in raw_data.splitlines():
                    # Compare the JA3 column, not the whole row: a substring test against
                    # the line also fires when the hash appears in SNI or an address.
                    columns = [col.strip().strip('"') for col in line.split("\t")]
                    for fp in db:
                        if fp.get("ja3") and fp["ja3"] in columns:
                            matches.append(
                                f"{CRIT} MATCH: {fp['ja3']} -> "
                                f"{fp.get('label', 'unlabelled')} ({fp.get('category', 'uncategorised')})"
                            )
            if matches:
                output_parts.append(f"\n{CRIT} Matches against your fingerprint list")
                output_parts.extend(matches)
            else:
                output_parts.append(f"\n{OK} No matches in your fingerprint list ({len(db)} entries)")

        return success_response("\n".join(output_parts))

    async def wireshark_scan_file_signatures(pcap_file: str) -> str:
        """[Forensics] Count packets containing common file signatures. Hits require object extraction and verification."""
        MAGIC_BYTES = {
            "PE/EXE": "4d5a",
            "ELF": "7f454c46",
            "PDF": "255044462d",
            "ZIP/Office": "504b0304",
            "RAR": "526172211a07",
            "GZIP": "1f8b08",
            "PNG": "89504e470d0a1a0a",
            "JPEG": "ffd8ff",
        }

        async def _search(file_type: str, magic_hex: str) -> tuple[str, int]:
            result = await client.search_packet_contents(pcap_file, magic_hex, search_type="hex", limit=50)
            wrapped = parse_tool_result(result)
            if not wrapped["success"]:
                return file_type, 0
            data = wrapped.get("data", "")
            if not isinstance(data, str):
                return file_type, 0
            # Packet-list output is a header row plus one row per match; count real matches only.
            rows = [ln for ln in data.splitlines() if ln.strip()]
            return file_type, max(0, len(rows) - 1)

        tasks = [_search(ft, mh) for ft, mh in MAGIC_BYTES.items()]
        results = await asyncio.gather(*tasks)

        found = [(ft, hits) for ft, hits in results if hits > 0]

        if found:
            output_parts = [f"{WARN} Embedded files detected in traffic:"]
            for ft, hits in found:
                output_parts.append(f"  {WARN} {ft}: {hits} packet(s)")
            return success_response("\n".join(output_parts))

        return success_response(f"{OK} No embedded files detected via magic byte scan")

    return [
        ("wireshark_extract_fingerprints", wireshark_extract_fingerprints),
        ("wireshark_scan_file_signatures", wireshark_scan_file_signatures),
    ]
