"""GeoIP enrichment tools — IP geolocation and ASN lookup via MaxMind GeoLite2."""

import ipaddress
import logging
import os
from pathlib import Path
from typing import Any

from ..tshark.client import TSharkClient
from .envelope import error_response, parse_tool_result, success_response
from .formatting import INFO

logger = logging.getLogger("wireshark_mcp")

_GEOIP_AVAILABLE = False
_geoip2_reader: Any = None

try:
    import geoip2.database
    import geoip2.errors

    _GEOIP_AVAILABLE = True
except ImportError:
    pass


def _find_geoip_db() -> Path | None:
    """Search for GeoLite2 database in standard locations."""
    candidates = []

    env_path = os.environ.get("GEOIP_DB_PATH")
    if env_path:
        candidates.append(Path(env_path))

    user_dir = Path.home() / ".wireshark-mcp" / "geoip"
    candidates.extend(
        [
            user_dir / "GeoLite2-City.mmdb",
            user_dir / "GeoLite2-Country.mmdb",
            user_dir / "GeoLite2-ASN.mmdb",
        ]
    )

    system_paths = [
        Path("/usr/share/GeoIP"),
        Path("/usr/local/share/GeoIP"),
        Path("/opt/homebrew/share/GeoIP"),
    ]
    for sp in system_paths:
        candidates.append(sp / "GeoLite2-City.mmdb")

    for p in candidates:
        if p.exists():
            return p
    return None


def _get_reader() -> Any:
    """Get or create a GeoIP2 database reader (singleton)."""
    global _geoip2_reader
    if _geoip2_reader is not None:
        return _geoip2_reader

    db_path = _find_geoip_db()
    if db_path is None:
        return None

    _geoip2_reader = geoip2.database.Reader(str(db_path))
    logger.info("GeoIP database loaded: %s", db_path)
    return _geoip2_reader


def _is_private_ip(ip_str: str) -> bool:
    """Check if an IP address is private/reserved."""
    try:
        return ipaddress.ip_address(ip_str).is_private
    except ValueError:
        return False


def make_geoip_tools(client: TSharkClient) -> list[tuple[str, Any]]:
    """Build GeoIP enrichment tools."""

    async def wireshark_geoip_enrich(pcap_file: str, limit: int = 50) -> str:
        """[Enrichment] GeoIP lookup for unique IPs — country, city, ASN. Needs GeoLite2 DB."""
        if not _GEOIP_AVAILABLE:
            return error_response(
                "geoip2 library not installed. Install with: pip install wireshark-mcp[geoip]",
                error_type="DependencyMissing",
            )

        reader = _get_reader()
        if reader is None:
            return error_response(
                "GeoLite2 database not found. Place GeoLite2-City.mmdb in "
                "~/.wireshark-mcp/geoip/ or set GEOIP_DB_PATH environment variable. "
                "Download from https://dev.maxmind.com/geoip/geolite2-free-geolocation-data",
                error_type="DatabaseMissing",
            )

        result = await client.extract_fields(pcap_file, ["ip.src", "ip.dst"], display_filter="ip", limit=10000)
        wrapped = parse_tool_result(result)
        if not wrapped["success"]:
            return success_response(wrapped)

        data = wrapped.get("data", "")
        if not isinstance(data, str) or len(data.strip()) < 10:
            return success_response("No IP packets found in capture.")

        unique_ips: set[str] = set()
        for line in data.strip().splitlines()[1:]:
            parts = line.split("\t")
            for part in parts:
                ip = part.strip().strip('"')
                if ip and not _is_private_ip(ip):
                    unique_ips.add(ip)

        if not unique_ips:
            return success_response(f"{INFO} All IPs are private/reserved — no GeoIP data to enrich.")

        results: list[str] = []
        results.append(f"{'IP':<18} {'Country':<8} {'City':<20} {'ASN':<10} {'Org'}")
        results.append("-" * 80)

        enriched = 0
        for ip in sorted(unique_ips)[:limit]:
            country = city = asn = org = "—"
            try:
                resp = reader.city(ip)
                country = resp.country.iso_code or "—"
                city = resp.city.name or "—"
                if hasattr(resp, "traits") and resp.traits.autonomous_system_number:
                    asn = f"AS{resp.traits.autonomous_system_number}"
                    org = resp.traits.autonomous_system_organization or "—"
            except geoip2.errors.AddressNotFoundError:
                logger.debug("No GeoIP record for %s", ip)
            except Exception as exc:
                logger.warning("GeoIP lookup failed for %s: %s", ip, exc)

            results.append(f"{ip:<18} {country:<8} {city:<20} {asn:<10} {org}")
            enriched += 1

        header = f"{INFO} Enriched {enriched}/{len(unique_ips)} public IPs"
        if len(unique_ips) > limit:
            header += f" (showing first {limit})"
        results.insert(0, header + "\n")

        return success_response("\n".join(results))

    return [
        ("wireshark_geoip_enrich", wireshark_geoip_enrich),
    ]
