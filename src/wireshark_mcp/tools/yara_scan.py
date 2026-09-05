"""YARA-based malware scanning for exported network objects."""

import logging
import os
import shutil
from importlib import resources as importlib_resources
from pathlib import Path
from typing import Any

from ..tshark.client import TSharkClient
from .envelope import error_response, parse_tool_result, success_response
from .formatting import CRIT, INFO, OK, WARN

logger = logging.getLogger("wireshark_mcp")

_YARA_AVAILABLE = False
_yara_module: Any = None

try:
    import yara as _yara_mod

    _YARA_AVAILABLE = True
    _yara_module = _yara_mod
except ImportError:
    pass

_compiled_rules: Any = None


def _load_yara_rules() -> Any:
    """Load and compile YARA rules from bundled + user directories."""
    global _compiled_rules
    if _compiled_rules is not None:
        return _compiled_rules

    rule_sources: dict[str, str] = {}

    try:
        data_ref = importlib_resources.files("wireshark_mcp") / "data" / "yara" / "basic_rules.yar"
        with importlib_resources.as_file(data_ref) as fp:
            rule_sources["builtin_basic"] = fp.read_text(encoding="utf-8")
    except Exception:
        logger.warning("Could not load bundled YARA rules")

    user_dir = Path.home() / ".wireshark-mcp" / "yara"
    if user_dir.exists():
        for f in sorted(user_dir.glob("*.yar")):
            try:
                rule_sources[f"user_{f.stem}"] = f.read_text(encoding="utf-8")
            except Exception:
                logger.warning("Could not load user YARA rule: %s", f)
        for f in sorted(user_dir.glob("*.yara")):
            try:
                rule_sources[f"user_{f.stem}"] = f.read_text(encoding="utf-8")
            except Exception:
                logger.warning("Could not load user YARA rule: %s", f)

    if not rule_sources:
        return None

    try:
        _compiled_rules = _yara_module.compile(sources=rule_sources)
    except Exception as e:
        logger.error("Failed to compile YARA rules: %s", e)
        return None

    logger.info("YARA rules compiled: %d source(s)", len(rule_sources))
    return _compiled_rules


def _severity_icon(severity: str) -> str:
    """Map severity to formatting icon."""
    mapping = {"critical": CRIT, "high": WARN, "medium": INFO, "low": OK}
    return mapping.get(severity.lower(), INFO)


def make_yara_tools(client: TSharkClient) -> list[tuple[str, Any]]:
    """Build YARA scanning tools."""

    async def wireshark_yara_scan(
        pcap_file: str,
        protocol: str = "http",
        dest_dir: str = "",
    ) -> str:
        """[Security] YARA scan exported files. Detects malware, webshells, shellcode. protocol: http|smb|tftp."""
        if not _YARA_AVAILABLE:
            return error_response(
                "yara-python library not installed. Install with: pip install wireshark-mcp[yara]",
                error_type="DependencyMissing",
            )

        rules = _load_yara_rules()
        if rules is None:
            return error_response(
                "No YARA rules available. Place .yar files in ~/.wireshark-mcp/yara/",
                error_type="ConfigurationError",
            )

        use_temp = not dest_dir
        if use_temp:
            temp_result = client._create_temporary_output_dir("wireshark_yara_")
            if not temp_result["success"]:
                return error_response(
                    temp_result["error"]["message"],
                    error_type=temp_result["error"]["type"],
                )
            export_dir = str(temp_result["path"])
        else:
            export_dir = dest_dir

        try:
            export_result = await client.export_objects(pcap_file, protocol, export_dir)
            wrapped = parse_tool_result(export_result)
            if not wrapped["success"]:
                return error_response(
                    f"Failed to export {protocol} objects: {wrapped.get('error', {}).get('message', 'unknown')}",
                )

            export_path = Path(export_dir)
            files = [f for f in export_path.iterdir() if f.is_file()]

            if not files:
                return success_response(f"{OK} No files exported from {protocol} traffic — nothing to scan.")

            results: list[str] = []
            total_matches = 0
            severity_counts: dict[str, int] = {}
            scan_errors = 0

            for fpath in sorted(files):
                try:
                    matches = rules.match(str(fpath))
                except Exception as exc:
                    scan_errors += 1
                    logger.warning("YARA scan failed for exported object %s: %s", fpath.name, exc)
                    continue

                if matches:
                    for match in matches:
                        severity = "medium"
                        category = "unknown"
                        description = match.rule

                        if hasattr(match, "meta"):
                            severity = match.meta.get("severity", "medium")
                            category = match.meta.get("category", "unknown")
                            description = match.meta.get("description", match.rule)

                        icon = _severity_icon(severity)
                        results.append(f"{icon} {fpath.name} | {match.rule} | {description} | {severity} | {category}")
                        total_matches += 1
                        severity_counts[severity] = severity_counts.get(severity, 0) + 1

            output: list[str] = []
            if total_matches > 0:
                crit_high = severity_counts.get("critical", 0) + severity_counts.get("high", 0)
                if crit_high > 0:
                    output.append(f"{CRIT} {total_matches} YARA match(es) in {len(files)} file(s)")
                else:
                    output.append(f"{WARN} {total_matches} YARA match(es) in {len(files)} file(s)")

                breakdown = ", ".join(f"{k}: {v}" for k, v in sorted(severity_counts.items()))
                output.append(f"Severity breakdown: {breakdown}")
                output.append("")
                output.append(f"{'File':<30} {'Rule':<25} {'Description':<35} {'Sev':<10} {'Cat'}")
                output.append("-" * 110)
                output.extend(results)
            else:
                output.append(f"{OK} No YARA matches in {len(files)} exported {protocol} file(s)")

            if scan_errors:
                output.append(f"{WARN} {scan_errors} exported file(s) could not be scanned; result is incomplete")

            if use_temp:
                output.append(f"\nExported files: {export_dir} (temporary)")
            else:
                output.append(f"\nExported files saved to: {export_dir}")

            return success_response("\n".join(output))

        finally:
            if use_temp and os.path.exists(export_dir):
                shutil.rmtree(export_dir, ignore_errors=True)

    return [
        ("wireshark_yara_scan", wireshark_yara_scan),
    ]
