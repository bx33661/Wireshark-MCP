"""An MCPServer subclass that keeps the advertised tool surface small and stable.

Every request a client sends carries the full ``tools/list`` payload in its
prompt prefix, and every tool result stays in the conversation prefix for the
rest of the session. Two things therefore matter more than they look:

* **Prefix size.** MCPServer derives an ``outputSchema`` from each tool's ``-> str``
  annotation. For this server that schema is always ``{"result": {"type":
  "string"}}`` — it tells a model nothing, and because declaring it obliges the
  server to also emit ``structuredContent``, every result is sent *twice*.
  Pydantic also stamps a ``title`` onto the schema and onto every property
  (``"title": "Pcap File"`` beside ``pcap_file``). Dropping both roughly halves
  the payload.
* **Prefix stability.** A tool list that changes between restarts invalidates
  the client's cached prefix. Registration order is therefore fixed (see
  ``ToolRegistry.register``) and nothing here may introduce ordering that
  depends on set iteration, dict insertion, or ``PYTHONHASHSEED``.

Both fixes are applied at single choke points so they cannot drift as tools are
added: ``add_tool`` for the schema, ``call_tool`` for the result ceiling.
"""

from __future__ import annotations

import json
import logging
import os
from typing import TYPE_CHECKING, Any

from mcp.server import MCPServer
from mcp.types import CallToolResult, InputRequiredResult, TextContent

from .tool_annotations import annotations_for
from .tools.formatting import smart_truncate

if TYPE_CHECKING:
    from collections.abc import Callable

    from mcp.server.mcpserver.context import Context
    from mcp.types import Icon, ToolAnnotations

logger = logging.getLogger("wireshark_mcp")

MAX_RESULT_CHARS_ENV = "WIRESHARK_MCP_MAX_RESULT_CHARS"
# 2x the smart_truncate default, so output that already bounds itself is untouched.
DEFAULT_MAX_RESULT_CHARS = 8000
MIN_MAX_RESULT_CHARS = 512


def _resolve_max_result_chars() -> int:
    """Read the result ceiling from the environment, falling back to the default."""
    raw = os.environ.get(MAX_RESULT_CHARS_ENV, "").strip()
    if not raw:
        return DEFAULT_MAX_RESULT_CHARS
    try:
        value = int(raw)
    except ValueError:
        logger.warning("Ignoring non-integer %s=%r", MAX_RESULT_CHARS_ENV, raw)
        return DEFAULT_MAX_RESULT_CHARS
    if value < MIN_MAX_RESULT_CHARS:
        logger.warning("Clamping %s=%r to minimum %d", MAX_RESULT_CHARS_ENV, raw, MIN_MAX_RESULT_CHARS)
        return MIN_MAX_RESULT_CHARS
    return value


def strip_schema_titles(node: Any) -> Any:
    """Recursively drop ``title`` keys from a JSON Schema.

    Pydantic generates a title for the argument model and for every property;
    neither carries information the field name does not already give.
    """
    if isinstance(node, dict):
        return {key: strip_schema_titles(value) for key, value in node.items() if key != "title"}
    if isinstance(node, list):
        return [strip_schema_titles(item) for item in node]
    return node


def cap_result_text(text: str, max_chars: int) -> str:
    """Bound a tool result, truncating inside the envelope rather than around it.

    Tools return a JSON envelope (``{"success": true, "data": ...}``). Truncating
    that string directly would produce invalid JSON.

    Crucially, structured data types (list, dict) MUST maintain their types even when
    capped to respect the result contract:
    - If ``data`` is a list, the number of records is reduced (Top-K) and pagination/truncation
      metadata is added.
    - If ``data`` is a dict containing collection lists (e.g. ``groups``, ``records``),
      those lists are trimmed while keeping the dict structure and keys intact.
    - If ``data`` is free-form text, it is trimmed mid-way and marked with ``truncated: true``.
    """
    if len(text) <= max_chars:
        return text

    if max_chars <= 0:
        return ""

    try:
        payload = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return smart_truncate(text, max_chars)

    if not isinstance(payload, dict):
        if isinstance(payload, list):
            low, high = 0, len(payload)
            best_list: list[Any] = []
            while low <= high:
                mid = (low + high) // 2
                cand = json.dumps(payload[:mid], ensure_ascii=False, separators=(",", ":"))
                if len(cand) <= max_chars:
                    best_list = payload[:mid]
                    low = mid + 1
                else:
                    high = mid - 1
            return json.dumps(best_list, ensure_ascii=False, separators=(",", ":"))
        return smart_truncate(text, max_chars)

    # Payload is an envelope dict
    if "data" in payload:
        data = payload["data"]

        # Case 1: data is a list
        if isinstance(data, list):

            def render_list(k: int) -> str:
                env = dict(payload)
                env["data"] = data[:k]
                env["truncated"] = True
                pag = dict(env.get("pagination") or {})
                original_total = pag.get("total")
                if original_total is None or not isinstance(original_total, (int, float)):
                    pag["total"] = len(data)
                else:
                    pag["total"] = int(original_total)
                offset = int(pag.get("offset", 0)) if isinstance(pag.get("offset"), (int, float)) else 0
                pag["returned"] = k
                if k < len(data):
                    pag["next_offset"] = offset + k
                    pag["has_more"] = True
                else:
                    pag["has_more"] = bool(pag.get("has_more", False))
                env["pagination"] = pag
                return json.dumps(env, ensure_ascii=False, separators=(",", ":"))

            if len(render_list(0)) <= max_chars:
                low, high = 0, len(data)
                best = render_list(0)
                while low <= high:
                    mid = (low + high) // 2
                    cand = render_list(mid)
                    if len(cand) <= max_chars:
                        best = cand
                        low = mid + 1
                    else:
                        high = mid - 1
                return best

            minimal_env = {"success": bool(payload.get("success", True)), "data": [], "truncated": True}
            cand = json.dumps(minimal_env, ensure_ascii=False, separators=(",", ":"))
            if len(cand) <= max_chars:
                return cand
            return smart_truncate(text, max_chars)

        # Case 2: data is a dict
        if isinstance(data, dict):
            list_keys = [k for k, v in data.items() if isinstance(v, list) and v]
            if list_keys:
                pref = ["groups", "records", "packets", "findings", "items", "results"]
                target_key = next((k for k in pref if k in list_keys), list_keys[0])
                items = data[target_key]

                def render_dict_list(k: int) -> str:
                    env = dict(payload)
                    new_data = dict(data)
                    new_data[target_key] = items[:k]
                    new_data["truncated"] = True
                    for count_key in (f"{target_key}_returned", "groups_returned", "returned"):
                        if count_key in new_data:
                            new_data[count_key] = k
                    env["data"] = new_data
                    env["truncated"] = True
                    pag = dict(env.get("pagination") or {})
                    original_total = pag.get("total")
                    if original_total is None or not isinstance(original_total, (int, float)):
                        pag["total"] = len(items)
                    else:
                        pag["total"] = int(original_total)
                    offset = int(pag.get("offset", 0)) if isinstance(pag.get("offset"), (int, float)) else 0
                    pag["returned"] = k
                    if k < len(items):
                        pag["next_offset"] = offset + k
                        pag["has_more"] = True
                    else:
                        pag["has_more"] = bool(pag.get("has_more", False))
                    env["pagination"] = pag
                    return json.dumps(env, ensure_ascii=False, separators=(",", ":"))

                if len(render_dict_list(0)) <= max_chars:
                    low, high = 0, len(items)
                    best = render_dict_list(0)
                    while low <= high:
                        mid = (low + high) // 2
                        cand = render_dict_list(mid)
                        if len(cand) <= max_chars:
                            best = cand
                            low = mid + 1
                        else:
                            high = mid - 1
                    return best

            env = dict(payload)
            env["truncated"] = True
            new_data = dict(data)
            for k, v in new_data.items():
                if isinstance(v, str) and len(v) > 100:
                    new_data[k] = smart_truncate(v, 100)
            env["data"] = new_data
            cand = json.dumps(env, ensure_ascii=False, separators=(",", ":"))
            if len(cand) <= max_chars:
                return cand

            minimal_env = {"success": bool(payload.get("success", True)), "data": {}, "truncated": True}
            cand = json.dumps(minimal_env, ensure_ascii=False, separators=(",", ":"))
            if len(cand) <= max_chars:
                return cand
            return smart_truncate(text, max_chars)

        # Case 3: data is free-form string or primitive
        capped = dict(payload)
        capped["truncated"] = True
        source = data if isinstance(data, str) else str(data)

        def render_text(preview_chars: int, *, preserve_fields: bool = True) -> str:
            envelope = (
                dict(capped) if preserve_fields else {"success": bool(capped.get("success", True)), "truncated": True}
            )
            envelope["data"] = smart_truncate(source, preview_chars)
            return json.dumps(envelope, ensure_ascii=False, separators=(",", ":"))

        preserve_fields = len(render_text(0)) <= max_chars
        low, high = 0, min(len(source), max_chars)
        best = render_text(0, preserve_fields=preserve_fields)
        while low <= high:
            mid = (low + high) // 2
            cand = render_text(mid, preserve_fields=preserve_fields)
            if len(cand) <= max_chars:
                best = cand
                low = mid + 1
            else:
                high = mid - 1
        return best

    # Envelope without "data" (e.g. error envelope)
    capped = dict(payload)
    capped["truncated"] = True
    if "error" in capped or capped.get("success") is False:
        err_obj = capped.get("error")
        err_msg = ""
        if isinstance(err_obj, dict):
            err = dict(err_obj)
            err_msg = str(err.get("message") or "")
            if "details" in err and len(json.dumps(err["details"])) > max_chars // 2:
                err["details"] = "... [truncated]"
            if "message" in err and len(err["message"]) > max_chars // 2:
                err["message"] = smart_truncate(err["message"], max_chars // 2)
            capped["error"] = err
        elif isinstance(err_obj, str):
            err_msg = err_obj
            capped["error"] = smart_truncate(err_obj, max_chars // 2)
        else:
            err_msg = str(capped.get("message") or "Tool execution error")

        cand = json.dumps(capped, ensure_ascii=False, separators=(",", ":"))
        if len(cand) <= max_chars:
            return cand

        # Progressively strip heavy metadata (scope, warnings, details, stderr)
        for field in ("scope", "warnings", "stderr", "details"):
            capped.pop(field, None)
        if isinstance(capped.get("error"), dict):
            capped["error"].pop("details", None)
            capped["error"].pop("type", None)

        cand = json.dumps(capped, ensure_ascii=False, separators=(",", ":"))
        if len(cand) <= max_chars:
            return cand

        # Minimal valid JSON error structure
        prefix = '{"success":false,"error":{"message":"'
        suffix = '"},"truncated":true}'
        avail_msg = max(0, max_chars - len(prefix) - len(suffix))
        trimmed_msg = smart_truncate(err_msg, avail_msg) if avail_msg > 0 else "..."
        minimal_cand = json.dumps(
            {"success": False, "error": {"message": trimmed_msg}, "truncated": True},
            ensure_ascii=False,
            separators=(",", ":"),
        )
        if len(minimal_cand) <= max_chars:
            return minimal_cand
        tiny = '{"error":"truncated"}'
        if len(tiny) <= max_chars:
            return tiny
        return smart_truncate(text, max_chars)

    # General dict fallback without "data"
    for field in ("scope", "warnings", "stderr", "details"):
        capped.pop(field, None)
    cand = json.dumps(capped, ensure_ascii=False, separators=(",", ":"))
    if len(cand) <= max_chars:
        return cand
    minimal_cand = json.dumps(
        {"success": bool(payload.get("success", True)), "truncated": True},
        ensure_ascii=False,
        separators=(",", ":"),
    )
    if len(minimal_cand) <= max_chars:
        return minimal_cand
    return smart_truncate(text, max_chars)


class WiresharkMCP(MCPServer):
    """MCPServer with a minimal tool schema and a hard ceiling on result size."""

    def __init__(
        self,
        *args: Any,
        max_result_chars: int | None = None,
        excluded_tools: frozenset[str] | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(*args, **kwargs)
        self._max_result_chars = max_result_chars if max_result_chars is not None else _resolve_max_result_chars()
        # Filtering here rather than at each call site means a profile cannot be
        # bypassed by a registration path that forgets to check it.
        self._excluded_tools = excluded_tools or frozenset()

    @property
    def max_result_chars(self) -> int:
        """Character ceiling applied to every tool result."""
        return self._max_result_chars

    @property
    def excluded_tools(self) -> frozenset[str]:
        """Tool names this server will not advertise."""
        return self._excluded_tools

    def add_tool(
        self,
        fn: Callable[..., Any],
        name: str | None = None,
        title: str | None = None,
        description: str | None = None,
        annotations: ToolAnnotations | None = None,
        icons: list[Icon] | None = None,
        meta: dict[str, Any] | None = None,
        structured_output: bool | None = None,
    ) -> None:
        """Register a tool without the auto-derived output schema or schema titles.

        Both registration paths land here — ``MCPServer.tool()`` delegates to
        ``add_tool`` — so a tool cannot opt out by accident. ``structured_output``
        is only forced when the caller left it unset; passing ``True`` explicitly
        still works, and an explicit ``annotations`` argument likewise wins over
        the default read/write policy.

        A tool excluded by the active profile is dropped here, before the manager
        sees it, so it is absent from ``tools/list`` and uncallable rather than
        merely hidden.
        """
        resolved_name = name or getattr(fn, "__name__", "")
        if resolved_name in self._excluded_tools:
            return

        if structured_output is None:
            structured_output = False

        # MCPServer.add_tool returns None; the manager hands back the Tool we need.
        tool = self._tool_manager.add_tool(
            fn,
            name=name,
            title=title,
            description=description,
            annotations=annotations,
            icons=icons,
            meta=meta,
            structured_output=structured_output,
        )
        tool.parameters = strip_schema_titles(tool.parameters)
        if annotations is None:
            # Resolved name, not fn.__name__ — the two differ for registry-renamed tools.
            tool.annotations = annotations_for(tool.name)

    async def call_tool(
        self,
        name: str,
        arguments: dict[str, Any],
        context: Context[Any, Any] | None = None,
    ) -> CallToolResult | InputRequiredResult:
        result = await super().call_tool(name, arguments, context)
        if isinstance(result, CallToolResult):
            # Check is_error on original content BEFORE capping
            is_error = bool(getattr(result, "is_error", False))
            if not is_error and isinstance(result.content, (list, tuple)):
                for block in result.content:
                    if isinstance(block, TextContent):
                        try:
                            parsed = json.loads(block.text)
                            if isinstance(parsed, dict) and parsed.get("success") is False:
                                is_error = True
                                break
                        except (json.JSONDecodeError, ValueError):
                            pass

            capped_content = self._cap_content(result.content, name)
            return result.model_copy(update={"content": capped_content, "is_error": is_error})
        return result

    def _cap_content(self, result: Any, tool_name: str) -> Any:
        """Apply the ceiling to text blocks, leaving other content shapes alone."""
        # Structured tools return (content, structured_data); cap only the text side.
        if isinstance(result, tuple) and len(result) == 2:
            return (self._cap_content(result[0], tool_name), result[1])

        if not isinstance(result, (list, tuple)):
            return result

        capped: list[Any] = []
        for block in result:
            if isinstance(block, TextContent):
                text = cap_result_text(block.text, self._max_result_chars)
                if text != block.text:
                    logger.debug("Capped %s result from %d to %d chars", tool_name, len(block.text), len(text))
                    block = block.model_copy(update={"text": text})
            capped.append(block)
        return capped
