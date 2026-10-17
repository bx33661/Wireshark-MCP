"""Persistent investigation case files.

A case keeps what an investigation established outside the model's context:
the inputs (with their SHA-256), every tool result that was recorded into it,
the findings those results carried, and the analyst's verdict on each. It is a
plain JSON file under an allowed write root, so a long investigation survives
context compaction or a new session, and a report can be regenerated from it.

The store never runs tshark itself. ``record`` accepts a tool result exactly as
a ``wireshark_*`` tool returned it and keeps its digest, scope and coverage next
to the finding ids, the same binding the evaluation harness uses for traces.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .tools.findings import SEVERITY_ORDER

CASE_SCHEMA_VERSION = 1
CASE_ID_PATTERN = re.compile(r"^case-[0-9a-f]{12}$")
VERDICTS = ("open", "confirmed", "dismissed")
MAX_CAPTURES = 32
MAX_NOTE_CHARS = 4000
MAX_RECORD_BYTES = 2_000_000


class CaseError(ValueError):
    """A request the case store refuses, with a message safe to show the caller."""


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


class CaseStore:
    """Read and write case files in one directory."""

    def __init__(self, root: Path) -> None:
        self.root = root

    def _path(self, case_id: str) -> Path:
        if not CASE_ID_PATTERN.match(case_id):
            raise CaseError("case_id must look like case-<12 hex digits>.")
        return self.root / f"{case_id}.json"

    def load(self, case_id: str) -> dict[str, Any]:
        path = self._path(case_id)
        if not path.is_file():
            raise CaseError(f"Case not found: {case_id}")
        case: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
        return case

    def _save(self, case: dict[str, Any]) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        case["updated_at"] = _now()
        path = self._path(case["case_id"])
        fd, temporary = tempfile.mkstemp(prefix=".case-", suffix=".json", dir=self.root)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(case, handle, ensure_ascii=False, indent=2)
                handle.write("\n")
            os.replace(temporary, path)
        except BaseException:
            Path(temporary).unlink(missing_ok=True)
            raise

    def create(self, title: str, captures: list[Path]) -> dict[str, Any]:
        if not title.strip():
            raise CaseError("A case needs a title.")
        if len(captures) > MAX_CAPTURES:
            raise CaseError(f"At most {MAX_CAPTURES} captures per case.")
        now = _now()
        case: dict[str, Any] = {
            "schema_version": CASE_SCHEMA_VERSION,
            "case_id": f"case-{secrets.token_hex(6)}",
            "title": title.strip()[:200],
            "created_at": now,
            "updated_at": now,
            "captures": [
                {"path": str(path), "sha256": sha256_file(path), "bytes": path.stat().st_size} for path in captures
            ],
            "queries": [],
            "findings": {},
            "notes": [],
        }
        self._save(case)
        return case

    def record(self, case_id: str, tool_result: str, tool: str = "") -> dict[str, Any]:
        if len(tool_result.encode("utf-8")) > MAX_RECORD_BYTES:
            raise CaseError("Tool result is too large to record.")
        try:
            envelope = json.loads(tool_result)
        except json.JSONDecodeError as exc:
            raise CaseError("text must be the JSON result returned by a wireshark_* tool.") from exc
        if not isinstance(envelope, dict) or envelope.get("success") is not True:
            raise CaseError("Only successful tool results can be recorded.")
        case = self.load(case_id)
        data = envelope.get("data")
        raw_findings = data.get("findings", []) if isinstance(data, dict) else []
        findings = [item for item in raw_findings if isinstance(item, dict) and isinstance(item.get("id"), str)]
        if len(findings) != len(raw_findings):
            raise CaseError("Every recorded finding needs the id assigned by the producing tool.")
        tools = sorted({str(item["tool"]) for item in findings if item.get("tool")})
        scope = envelope.get("scope") if isinstance(envelope.get("scope"), dict) else {}
        warnings: list[str] = []
        pcap = scope.get("pcap_file") if isinstance(scope, dict) else None
        known = {entry["path"] for entry in case["captures"]}
        if isinstance(pcap, str) and known and str(Path(pcap).resolve()) not in known:
            warnings.append(f"Recorded result was produced from {pcap}, which is not one of this case's captures.")
        sequence = len(case["queries"]) + 1
        case["queries"].append(
            {
                "seq": sequence,
                "recorded_at": _now(),
                "tool": tool or (tools[0] if len(tools) == 1 else ""),
                "scope": scope,
                "coverage": envelope.get("coverage"),
                "truncated": envelope.get("truncated", False),
                "result_sha256": hashlib.sha256(tool_result.encode("utf-8")).hexdigest(),
                "finding_ids": [item["id"] for item in findings],
            }
        )
        new_ids: list[str] = []
        for item in findings:
            stored = case["findings"].get(item["id"])
            if stored is None:
                case["findings"][item["id"]] = {
                    "finding": item,
                    "verdict": "open",
                    "verdict_note": "",
                    "first_query": sequence,
                    "queries": [sequence],
                }
                new_ids.append(item["id"])
            elif sequence not in stored["queries"]:
                stored["queries"].append(sequence)
        self._save(case)
        return {
            "query": sequence,
            "new_findings": new_ids,
            "known_findings": len(findings) - len(new_ids),
            "warnings": warnings,
        }

    def set_verdict(self, case_id: str, finding_id: str, verdict: str, note: str = "") -> dict[str, Any]:
        if verdict not in VERDICTS:
            raise CaseError(f"verdict must be one of: {', '.join(VERDICTS)}.")
        case = self.load(case_id)
        stored = case["findings"].get(finding_id)
        if stored is None:
            raise CaseError(f"Finding {finding_id} is not in {case_id}; record the tool result first.")
        stored["verdict"] = verdict
        stored["verdict_note"] = note[:MAX_NOTE_CHARS]
        stored["verdict_at"] = _now()
        self._save(case)
        return {"finding_id": finding_id, "verdict": verdict}

    def add_note(self, case_id: str, note: str) -> dict[str, Any]:
        if not note.strip():
            raise CaseError("A note needs text.")
        case = self.load(case_id)
        case["notes"].append({"at": _now(), "text": note.strip()[:MAX_NOTE_CHARS]})
        self._save(case)
        return {"notes": len(case["notes"])}

    def list_cases(self) -> list[dict[str, Any]]:
        if not self.root.is_dir():
            return []
        cases = []
        for path in sorted(self.root.glob("case-*.json")):
            try:
                case = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            cases.append(
                {
                    "case_id": case.get("case_id"),
                    "title": case.get("title"),
                    "updated_at": case.get("updated_at"),
                    "findings": len(case.get("findings", {})),
                }
            )
        return sorted(cases, key=lambda item: str(item["updated_at"]), reverse=True)


def summarize_case(case: dict[str, Any]) -> dict[str, Any]:
    """Compact view for the model: ids and claims, not full evidence lists."""
    findings = []
    for finding_id, stored in _ordered_findings(case):
        finding = stored["finding"]
        findings.append(
            {
                "id": finding_id,
                "verdict": stored["verdict"],
                "severity": finding.get("severity"),
                "confidence": finding.get("confidence"),
                "tool": finding.get("tool"),
                "observation": finding.get("observation"),
            }
        )
    verdicts = {name: sum(1 for item in findings if item["verdict"] == name) for name in VERDICTS}
    return {
        "case_id": case["case_id"],
        "title": case["title"],
        "captures": case["captures"],
        "queries": len(case["queries"]),
        "partial_queries": sum(
            1 for query in case["queries"] if (query.get("coverage") or {}).get("status") not in (None, "complete")
        ),
        "verdicts": verdicts,
        "findings": findings,
        "notes": len(case["notes"]),
    }


def _ordered_findings(case: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    return sorted(
        case["findings"].items(),
        key=lambda item: (
            VERDICTS.index(item[1]["verdict"]) if item[1]["verdict"] in VERDICTS else 0,
            SEVERITY_ORDER.get(str(item[1]["finding"].get("severity")), 5),
            item[1]["first_query"],
        ),
    )


def render_case_markdown(case: dict[str, Any]) -> str:
    """Investigation report rendered only from what the case recorded."""
    lines = [f"# {case['title']}", "", f"Case `{case['case_id']}`, updated {case['updated_at']}.", "", "## Inputs", ""]
    for capture in case["captures"]:
        lines.append(f"- `{capture['path']}` ({capture['bytes']} bytes, SHA-256 `{capture['sha256']}`)")
    if not case["captures"]:
        lines.append("- No captures registered.")
    headings = {"confirmed": "Confirmed findings", "open": "Open findings", "dismissed": "Dismissed findings"}
    ordered = _ordered_findings(case)
    for verdict in ("confirmed", "open", "dismissed"):
        selected = [(fid, stored) for fid, stored in ordered if stored["verdict"] == verdict]
        if not selected:
            continue
        lines += ["", f"## {headings[verdict]}", ""]
        for finding_id, stored in selected:
            finding = stored["finding"]
            lines.append(
                f"### {finding.get('observation', '')}\n\n"
                f"- ID `{finding_id}`, {finding.get('severity')} severity, {finding.get('confidence')} confidence, "
                f"from `{finding.get('tool')}` (query {', '.join(str(q) for q in stored['queries'])})"
            )
            if stored.get("verdict_note"):
                lines.append(f"- Analyst note: {stored['verdict_note']}")
            for item in finding.get("evidence", [])[:5]:
                anchors = [f"{key} {item[key]}" for key in ("frame", "stream") if item.get(key) is not None]
                text = item.get("description") or item.get("value") or ""
                lines.append(f"- Evidence: {text}" + (f" ({', '.join(anchors)})" if anchors else ""))
            for command in finding.get("reproduce", []):
                lines.append(f"- Reproduce: `{command}`")
            if finding.get("mitre_attack"):
                lines.append(f"- ATT&CK candidates: {', '.join(finding['mitre_attack'])}")
            constraints = finding.get("constraints") or {}
            if constraints.get("truncated"):
                lines.append("- Limitation: the producing scan was truncated, so this may be incomplete.")
    if not ordered:
        lines += ["", "## Findings", "", "No findings have been recorded."]
    lines += ["", "## Query log", ""]
    for query in case["queries"]:
        coverage = (query.get("coverage") or {}).get("status", "unreported")
        lines.append(
            f"{query['seq']}. `{query['tool'] or 'unknown tool'}` at {query['recorded_at']}, coverage {coverage}, "
            f"{len(query['finding_ids'])} finding(s), result SHA-256 `{query['result_sha256'][:16]}…`"
        )
    if not case["queries"]:
        lines.append("No tool results recorded.")
    if case["notes"]:
        lines += ["", "## Notes", ""]
        lines += [f"- {note['at']}: {note['text']}" for note in case["notes"]]
    return "\n".join(lines) + "\n"
