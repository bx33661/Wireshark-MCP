"""Security analysis tools for Wireshark MCP."""

import asyncio
import logging
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from mcp.server.fastmcp import FastMCP

from ..tshark.client import TSharkClient
from .envelope import error_response, normalize_tool_result, parse_tool_result, success_response

logger = logging.getLogger("wireshark_mcp")

URLHAUS_URL = "https://urlhaus.abuse.ch/downloads/text/"
CACHE_DIR = Path.home() / ".cache" / "wireshark-mcp"
THREAT_CACHE_FILE = CACHE_DIR / "urlhaus_cache.txt"
CACHE_MAX_AGE_SECONDS = 24 * 60 * 60  # 24 hours


def _normalize_domain(value: str) -> str:
    """Normalize a domain or hostname for reproducible matching."""
    return value.strip().strip('"').strip().rstrip(".").lower()


def _normalize_url(value: str) -> str:
    """Normalize a URL for feed and capture matching."""
    candidate = value.strip().strip('"')
    if not candidate:
        return ""

    try:
        parsed = urlsplit(candidate)
    except ValueError:
        return ""

    if not parsed.scheme or not parsed.netloc:
        return ""

    hostname = _normalize_domain(parsed.hostname or "")
    if not hostname:
        return ""

    default_ports = {"http": 80, "https": 443}
    port = parsed.port
    netloc = hostname
    if port is not None and port != default_ports.get(parsed.scheme.lower()):
        netloc = f"{hostname}:{port}"

    path = parsed.path or "/"
    return urlunsplit((parsed.scheme.lower(), netloc, path, parsed.query, ""))


def _parse_tsv_rows(data: str) -> list[list[str]]:
    """Parse simple tshark field output into rows, skipping the header."""
    rows: list[list[str]] = []
    lines = [line for line in data.splitlines() if line.strip()]
    for line in lines[1:]:
        rows.append([cell.strip().strip('"') for cell in line.split("\t")])
    return rows


def _parse_urlhaus_feed(feed_data: str) -> tuple[set[str], set[str]]:
    """Parse URLhaus text feed into exact URL and hostname sets."""
    feed_urls: set[str] = set()
    feed_domains: set[str] = set()

    for line in feed_data.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        normalized_url = _normalize_url(stripped)
        if not normalized_url:
            continue

        feed_urls.add(normalized_url)
        hostname = _normalize_domain(urlsplit(normalized_url).hostname or "")
        if hostname:
            feed_domains.add(hostname)

    return feed_urls, feed_domains


async def _extract_http_indicators(client: TSharkClient, pcap_file: str) -> tuple[set[str], set[str]]:
    """Extract URLs and hostnames from HTTP requests."""
    result = await client.extract_fields(
        pcap_file,
        ["http.request.full_uri", "http.host", "http.request.uri"],
        display_filter="http.request",
        limit=5000,
    )
    wrapped = parse_tool_result(result)
    if not wrapped["success"]:
        return set(), set()

    data = wrapped.get("data", "")
    if not isinstance(data, str):
        return set(), set()

    urls: set[str] = set()
    domains: set[str] = set()
    for row in _parse_tsv_rows(data):
        full_uri = row[0] if len(row) > 0 else ""
        host = _normalize_domain(row[1] if len(row) > 1 else "")
        uri = row[2] if len(row) > 2 else ""

        normalized_full_uri = _normalize_url(full_uri)
        if normalized_full_uri:
            urls.add(normalized_full_uri)

        if host:
            domains.add(host)
            if uri and not normalized_full_uri:
                path = uri if uri.startswith("/") else f"/{uri}"
                normalized_built_url = _normalize_url(f"http://{host}{path}")
                if normalized_built_url:
                    urls.add(normalized_built_url)

    return urls, domains


async def _extract_domain_indicators(
    client: TSharkClient,
    pcap_file: str,
    *,
    fields: list[str],
    display_filter: str,
    limit: int = 5000,
) -> set[str]:
    """Extract normalized domain indicators from a tshark field query."""
    result = await client.extract_fields(
        pcap_file,
        fields,
        display_filter=display_filter,
        limit=limit,
    )
    wrapped = parse_tool_result(result)
    if not wrapped["success"]:
        return set()

    data = wrapped.get("data", "")
    if not isinstance(data, str):
        return set()

    domains: set[str] = set()
    for row in _parse_tsv_rows(data):
        for cell in row:
            domain = _normalize_domain(cell)
            if domain:
                domains.add(domain)
    return domains


async def _analyze_urlhaus_matches(client: TSharkClient, pcap_file: str) -> dict[str, Any]:
    """Extract capture indicators and match them against the cached URLhaus feed."""
    http_urls, http_domains = await _extract_http_indicators(client, pcap_file)
    dns_domains = await _extract_domain_indicators(
        client,
        pcap_file,
        fields=["dns.qry.name"],
        display_filter="dns.flags.response == 0",
    )
    tls_domains = await _extract_domain_indicators(
        client,
        pcap_file,
        fields=["tls.handshake.extensions.server_name"],
        display_filter="tls.handshake.type == 1 and tls.handshake.extensions.server_name",
    )

    candidate_urls = http_urls
    candidate_domains = http_domains | dns_domains | tls_domains

    threat_data = await _get_threat_data()
    feed_urls, feed_domains = _parse_urlhaus_feed(threat_data)

    malicious_urls = sorted(candidate_urls & feed_urls)
    malicious_domains = sorted(candidate_domains & feed_domains)

    return {
        "threat_feed": "URLhaus",
        "urls_checked": len(candidate_urls),
        "domains_checked": len(candidate_domains),
        "matches_found": len(malicious_urls) + len(malicious_domains),
        "malicious_urls": malicious_urls,
        "malicious_domains": malicious_domains,
        "evidence_sources": {
            "http_urls": len(http_urls),
            "http_domains": len(http_domains),
            "dns_queries": len(dns_domains),
            "tls_sni": len(tls_domains),
        },
    }


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
            payload = bytes(response.read())
            return payload.decode("utf-8")

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
    """Create contextual security tools for the stable contextual catalog."""

    async def wireshark_check_threats(pcap_file: str) -> str:
        """[Security] Match captured URLs and hostnames against cached URLhaus threat intelligence.

        Args:
            pcap_file: Path to capture file

        Returns:
            Threat analysis summary or JSON error

        Example:
            wireshark_check_threats("suspicious.pcap")
        """
        try:
            return success_response(await _analyze_urlhaus_matches(client, pcap_file))
        except Exception as exc:
            logger.exception("Failed to fetch threat feed")
            return error_response(
                "Failed to fetch threat feed",
                error_type="NetworkError",
                details=str(exc),
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
