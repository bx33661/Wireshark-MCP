"""Type stubs for mixin cross-references (TYPE_CHECKING only)."""

from __future__ import annotations

from typing import Any, Protocol


class _ClientProtocol(Protocol):
    """Shared interface that all tshark mixins can rely on at type-check time."""

    tshark_path: str
    VALID_ENDPOINT_TYPES: set[str]
    VALID_EXPORT_PROTOCOLS: set[str]
    VALID_STREAM_PROTOCOLS: set[str]

    def _validate_file(self, filepath: str) -> dict[str, Any]: ...
    def _validate_protocol(self, protocol: str, valid_set: set[str]) -> dict[str, Any]: ...
    def _validate_output_path(self, filepath: str) -> dict[str, Any]: ...
    def _require_tool(self, tool_name: str) -> dict[str, Any]: ...
    def _get_checked_tool_path(self, tool_name: str) -> str: ...
    def _select_capture_backend_path(self) -> str: ...
    async def _run_command(
        self,
        cmd: list[str],
        limit_lines: int = 0,
        offset_lines: int = 0,
        timeout: int = 30,
    ) -> str: ...
    async def get_packet_list(
        self,
        pcap_file: str,
        limit: int = 20,
        offset: int = 0,
        display_filter: str = "",
        custom_columns: list[str] | None = None,
    ) -> str: ...
