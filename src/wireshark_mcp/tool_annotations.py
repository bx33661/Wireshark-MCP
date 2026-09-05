"""Per-tool MCP annotations, so clients can tell reads from writes.

Clients use these hints to decide whether a call needs the user's confirmation.
The spec treats a tool with no ``readOnlyHint`` as potentially destructive, so
every tool gets an explicit hint instead of relying on the default — otherwise
the ~75 read-only analysis tools would each prompt.

The dangerous direction is the permissive one: a writer mislabelled read-only
could be auto-approved by a client. ``WRITE_TOOLS`` is therefore an explicit
allowlist rather than anything inferred at runtime, and a guard test in
``tests/test_prompt_cache.py`` fails if a tool grows an output-path parameter
without being listed here.
"""

from __future__ import annotations

from mcp.types import ToolAnnotations

# Tools that create or overwrite files on disk. Everything else only reads captures.
WRITE_TOOLS: frozenset[str] = frozenset(
    {
        "wireshark_capture",
        "wireshark_editcap_deduplicate",
        "wireshark_editcap_split",
        "wireshark_editcap_time_shift",
        "wireshark_editcap_trim",
        "wireshark_export_objects",
        "wireshark_extract_frames",
        "wireshark_filter_save",
        "wireshark_merge_pcaps",
        "wireshark_text2pcap_import",
        "wireshark_yara_scan",  # exports objects to dest_dir before scanning
    }
)

# Parameters naming a filesystem destination. The guard test uses these to catch a
# new writer that was never added above. `output_mode` is a format selector, not a
# path, and is deliberately absent.
OUTPUT_PATH_PARAMS: frozenset[str] = frozenset({"output_file", "output_prefix", "dest_dir"})

# Live capture observes an interface outside the capture file supplied by the caller.
OPEN_WORLD_TOOLS: frozenset[str] = frozenset({"wireshark_capture"})


def annotations_for(tool_name: str) -> ToolAnnotations:
    """Build the annotation set for a tool.

    ``destructiveHint`` is left unset for read-only tools rather than set to
    ``False``: it would be redundant next to ``readOnlyHint`` and unset fields are
    dropped from the wire payload, which keeps the prompt prefix smaller.
    """
    writes = tool_name in WRITE_TOOLS
    return ToolAnnotations(
        read_only_hint=not writes,
        destructive_hint=True if writes else None,
        open_world_hint=tool_name in OPEN_WORLD_TOOLS,
    )
