"""Minimal Finding schema for evidence-backed security and anomaly analysis."""

from typing import Any, Literal, TypedDict


class FindingEvidence(TypedDict, total=False):
    frame: int | None
    stream: int | None
    protocol: str | None
    filter: str | None
    field: str | None
    value: str | None
    description: str | None


class FindingConstraints(TypedDict, total=False):
    scanned: int
    limit: int
    truncated: bool
    time_window_seconds: float | None
    single_sided: bool | None
    threshold: Any


class Finding(TypedDict, total=False):
    observation: str
    severity: Literal["info", "low", "medium", "high", "critical"]
    confidence: Literal["candidate", "likely", "confirmed"]
    evidence: list[FindingEvidence]
    constraints: FindingConstraints
    next_steps: list[str]


def mask_secret(secret: str, keep_chars: int = 1) -> str:
    """Mask sensitive credentials while preserving structure for investigation."""
    s = secret.strip()
    if not s:
        return ""
    if ":" in s:
        user, passw = s.split(":", 1)
        return f"{user}:{mask_secret(passw, keep_chars=keep_chars)}"
    if len(s) <= 2:
        return "**"
    visible = min(keep_chars, max(1, len(s) // 3))
    return s[:visible] + "*" * (len(s) - visible)
