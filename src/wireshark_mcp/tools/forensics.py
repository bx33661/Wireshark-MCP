"""Forensics tools for Wireshark MCP — file carving, fingerprinting, evidence chain."""

import asyncio
import json
import logging
from importlib import resources as importlib_resources
from pathlib import Path
from typing import Any

from ..tshark.client import TSharkClient
from .envelope import normalize_tool_result, parse_tool_result, success_response
from .formatting import CRIT, INFO, OK, WARN

logger = logging.getLogger("wireshark_mcp")

_FINGERPRINT_DB: list[dict[str, str]] | None = None


def _load_fingerprint_db() -> list[dict[str, str]]:
    """Load JA3 malware fingerprint database (bundled + user custom)."""
    global _FINGERPRINT_DB
    if _FINGERPRINT_DB is not None:
        return _FINGERPRINT_DB

    fingerprints: list[dict[str, str]] = []

    # Load bundled database
    try:
        data_ref = importlib_resources.files("wireshark_mcp") / "data" / "fingerprints" / "ja3_malware.json"
        with importlib_resources.as_file(data_ref) as fp:
            db = json.loads(fp.read_text())
            fingerprints.extend(db.get("fingerprints", []))
    except Exception:
        logger.warning("Could not load bundled JA3 fingerprint database")

    # Load user custom fingerprints
    user_dir = Path.home() / ".wireshark-mcp" / "fingerprints"
    if user_dir.exists():
        for f in user_dir.glob("*.json"):
            try:
                db = json.loads(f.read_text())
                fingerprints.extend(db.get("fingerprints", []))
            except Exception:
                logger.warning("Could not load user fingerprint file: %s", f)

    _FINGERPRINT_DB = fingerprints
    return _FINGERPRINT_DB


def make_contextual_forensics_tools(client: TSharkClient) -> list[tuple[str, Any]]:
    """Create contextual forensics tools."""

    async def wireshark_extract_fingerprints(pcap_file: str, limit: int = 100) -> str:
        """[Forensics] Extract JA3/JA3S TLS fingerprints and match against known malware database."""
        fields = [
            "ip.src",
            "ip.dst",
            "tcp.dstport",
            "tls.handshake.ja3",
            "tls.handshake.ja3s",
            "tls.handshake.extensions.server_name",
        ]
        result = await client.extract_fields(
            pcap_file, fields, display_filter="tls.handshake.type == 1", limit=limit
        )
        wrapped = parse_tool_result(result)
        if not wrapped["success"]:
            return normalize_tool_result(wrapped)

        output_parts = [f"{INFO} JA3/JA3S Fingerprints"]
        output_parts.append(wrapped.get("data", "No data"))

        # Match against known malware DB
        db = _load_fingerprint_db()
        if db:
            known_hashes = {fp["ja3"]: fp for fp in db}
            raw_data = wrapped.get("data", "")
            matches = []
            for line in raw_data.split("\n"):
                for ja3_hash, fp_info in known_hashes.items():
                    if ja3_hash in line:
                        matches.append(
                            f"{CRIT} MATCH: {ja3_hash} -> {fp_info['label']} ({fp_info['category']})"
                        )
            if matches:
                output_parts.append(f"\n{CRIT} Known Malware Fingerprint Matches")
                output_parts.extend(matches)
            else:
                output_parts.append(f"\n{OK} No known malware fingerprints matched")

        return success_response("\n".join(output_parts))

    async def wireshark_carve_files(pcap_file: str) -> str:
        """[Forensics] Detect embedded files in traffic by scanning for magic bytes (PE, ELF, PDF, Office, archives, images)."""
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

        async def _search(file_type: str, magic_hex: str) -> tuple[str, str]:
            result = await client.search_packet_contents(
                pcap_file, magic_hex, search_type="hex", limit=50
            )
            return file_type, result

        tasks = [_search(ft, mh) for ft, mh in MAGIC_BYTES.items()]
        results = await asyncio.gather(*tasks)

        found_types: list[str] = []
        for file_type, result in results:
            if result and "No packets" not in result:
                found_types.append(file_type)

        if found_types:
            output_parts = [f"{WARN} Embedded files detected in traffic:"]
            for ft in found_types:
                output_parts.append(f"  {WARN} {ft}")
            return success_response("\n".join(output_parts))

        return success_response(f"{OK} No embedded files detected via magic byte scan")

    return [
        ("wireshark_extract_fingerprints", wireshark_extract_fingerprints),
        ("wireshark_carve_files", wireshark_carve_files),
    ]
