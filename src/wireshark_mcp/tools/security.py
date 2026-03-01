"""Security analysis tools for Wireshark MCP."""

import asyncio
import logging
import time
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from ..tshark.client import TSharkClient
from .envelope import error_response, normalize_tool_result, parse_tool_result, success_response

logger = logging.getLogger("wireshark_mcp")

URLHAUS_URL = "https://urlhaus.abuse.ch/downloads/text/"
CACHE_DIR = Path.home() / ".cache" / "wireshark-mcp"
THREAT_CACHE_FILE = CACHE_DIR / "urlhaus_cache.txt"
CACHE_MAX_AGE_SECONDS = 24 * 60 * 60  # 24 hours


def _is_cache_valid() -> bool:
    """Check if the threat cache exists and is not expired."""
    if not THREAT_CACHE_FILE.exists():
        return False
    age = time.time() - THREAT_CACHE_FILE.stat().st_mtime
    return age < CACHE_MAX_AGE_SECONDS


async def _download_threat_feed() -> str:
    """Download threat feed in a non-blocking way using asyncio.to_thread."""
    import urllib.request

    def _fetch() -> str:
        with urllib.request.urlopen(URLHAUS_URL, timeout=30) as response:
            return response.read().decode("utf-8")

    data = await asyncio.to_thread(_fetch)

    # Ensure cache directory exists
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    THREAT_CACHE_FILE.write_text(data, encoding="utf-8")
    logger.info("Threat feed cached to %s", THREAT_CACHE_FILE)

    return data


async def _get_threat_data() -> str:
    """Get threat data from cache or download fresh."""
    if _is_cache_valid():
        logger.debug("Using cached threat feed")
        return THREAT_CACHE_FILE.read_text(encoding="utf-8")

    logger.info("Downloading fresh threat feed from %s", URLHAUS_URL)
    return await _download_threat_feed()


def register_security_tools(mcp: FastMCP, client: TSharkClient) -> None:
    """Register core security tools (always available)."""
    # No core security tools — all are contextual.
    # This function is kept for backward compatibility but does nothing.
    pass


def make_contextual_security_tools(client: TSharkClient) -> list[tuple[str, Any]]:
    """Create contextual security tools (registered on demand by the registry)."""

    async def wireshark_check_threats(pcap_file: str) -> str:
        """[Security] Check captured IPs against URLhaus threat intelligence (cached 24h).

        Args:
            pcap_file: Path to capture file

        Returns:
            Threat analysis summary or JSON error

        Example:
            wireshark_check_threats("suspicious.pcap")
        """
        # Extract unique IPs
        ips_str = await client.extract_fields(pcap_file, ["ip.src", "ip.dst"], separator=",", limit=10000)
        ips_result = parse_tool_result(ips_str)

        if not ips_result["success"]:
            return error_response(
                "Failed to extract IPs from pcap",
                error_type="DependencyError",
                details={"upstream_error": ips_result.get("error")},
            )

        ips_data = ips_result.get("data")
        if not isinstance(ips_data, str):
            return error_response(
                "Unexpected data format while extracting IPs",
                error_type="DependencyError",
                details={"expected": "string", "received": ips_data.__class__.__name__},
            )

        unique_ips: set[str] = set()
        for line in ips_data.splitlines()[1:]:
            parts = line.split(",")
            for p in parts:
                cleaned = p.strip().strip('"')
                if cleaned and not cleaned.startswith("["):
                    unique_ips.add(cleaned)

        if not unique_ips:
            return success_response({"ips_checked": 0, "threats": []})

        try:
            threat_data = await _get_threat_data()

            matches = [ip for ip in unique_ips if ip in threat_data]

            return success_response(
                {
                    "ips_checked": len(unique_ips),
                    "threats_found": len(matches),
                    "malicious_ips": matches,
                }
            )

        except Exception as e:
            logger.exception("Failed to fetch threat feed")
            return error_response(
                "Failed to fetch threat feed",
                error_type="NetworkError",
                details=str(e),
            )

    async def wireshark_extract_credentials(pcap_file: str) -> str:
        """[Security] Scan for plaintext credentials (HTTP Basic Auth, FTP passwords, Telnet).

        Args:
            pcap_file: Path to capture file

        Returns:
            Credential findings summary or JSON error

        Example:
            wireshark_extract_credentials("insecure.pcap")
        """
        findings: list[str] = []

        http_auth = await client.extract_fields(pcap_file, ["http.authbasic"], "http.authbasic", limit=50)
        http_auth_wrapped = parse_tool_result(http_auth)
        if not http_auth_wrapped["success"]:
            return normalize_tool_result(http_auth_wrapped)
        http_auth_data = http_auth_wrapped.get("data")
        if isinstance(http_auth_data, str) and len(http_auth_data.strip()) > 20:
            findings.append(f"HTTP Basic Auth:\n{http_auth_data[:500]}")

        ftp_pass = await client.extract_fields(pcap_file, ["ftp.request.arg"], "ftp.request.command == PASS", limit=50)
        ftp_pass_wrapped = parse_tool_result(ftp_pass)
        if not ftp_pass_wrapped["success"]:
            return normalize_tool_result(ftp_pass_wrapped)
        ftp_pass_data = ftp_pass_wrapped.get("data")
        if isinstance(ftp_pass_data, str) and len(ftp_pass_data.strip()) > 20:
            findings.append(f"FTP Passwords:\n{ftp_pass_data[:500]}")

        telnet_data = await client.search_packet_contents(pcap_file, "login", "string", limit=10)
        telnet_wrapped = parse_tool_result(telnet_data)
        if not telnet_wrapped["success"]:
            return normalize_tool_result(telnet_wrapped)
        telnet_payload = telnet_wrapped.get("data")
        if isinstance(telnet_payload, str) and ("Login" in telnet_payload or "Password" in telnet_payload):
            findings.append("Possible Telnet/cleartext authentication detected (use follow_stream to analyze)")

        if not findings:
            return success_response("No obvious plaintext credentials found.")

        return success_response("\n\n---\n".join(findings))

    return [
        ("wireshark_check_threats", wireshark_check_threats),
        ("wireshark_extract_credentials", wireshark_extract_credentials),
    ]
