"""Type stubs for mixin cross-references (TYPE_CHECKING only)."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, Protocol, TypedDict

FieldRowConsumer = Callable[[list[str]], None]


class FieldStreamResult(TypedDict, total=False):
    success: bool
    rows: int
    bytes_read: int
    stderr: str
    error: dict[str, Any]


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
    @staticmethod
    def _ok(data: str, stderr: str = "", truncated: bool = False) -> str: ...
    @staticmethod
    def _unwrap(result: str) -> tuple[bool, str]: ...
    async def _run_command(
        self,
        cmd: list[str],
        limit_lines: int = 0,
        offset_lines: int = 0,
        timeout: int = 30,
        stream_limit: bool = False,
    ) -> str: ...
    async def _stream_field_rows(
        self,
        cmd: list[str],
        consumer: FieldRowConsumer,
        *,
        max_rows: int,
        timeout: int = 30,
    ) -> FieldStreamResult: ...
    async def get_packet_list(
        self,
        pcap_file: str,
        limit: int = 20,
        offset: int = 0,
        display_filter: str = "",
        custom_columns: list[str] | None = None,
    ) -> str: ...
    async def extract_fields(
        self,
        pcap_file: str,
        fields: list[str],
        display_filter: str = "",
        separator: str = "\t",
        limit: int = 100,
        offset: int = 0,
        aggregator: str = ",",
        stream_limit: bool = False,
    ) -> str: ...
    async def stream_fields(
        self,
        pcap_file: str,
        fields: list[str],
        consumer: FieldRowConsumer,
        display_filter: str = "",
        max_rows: int = 1_000_000,
        timeout: int = 30,
    ) -> FieldStreamResult: ...
