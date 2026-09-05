"""Opt-in tool profiles.

Every tool in ``tools/list`` costs prefix bytes on each request and, more
importantly, competes for the model's attention when it picks a tool. A client
that only ever reads existing captures pays for the live-capture and pcap-editing
tools on every turn.

Three rules keep this from becoming a liability:

* **``full`` is the default.** Selecting a profile is opt-in, so no existing
  client's surface changes when this ships.
* **Membership is enumerated, never inferred.** The sets below are literal, so a
  profile's payload is byte-identical across restarts and reviewable in a diff.
  Deriving membership by inspecting docstrings or annotations at startup would
  make the advertised surface depend on code the reader cannot see, and could
  reorder it between versions.
* **A profile may not strand the guidance.** The shipped prompts, resources, and
  skill files name tools for the model to call, and ``PROTOCOL_TOOL_MAP``
  recommends more. Anything reachable that way must exist in every profile, or a
  user on a reduced surface gets told to call a tool they do not have.
  ``tests/test_profiles.py`` enforces this against the real prose.
"""

from __future__ import annotations

from typing import Final, Literal

ProfileName = Literal["full", "core", "analysis"]

DEFAULT_PROFILE: Final[ProfileName] = "full"

# Live capture and interface enumeration: needs a machine with capture rights, and
# is useless for a client handed a pcap to read.
_CAPTURE: Final[frozenset[str]] = frozenset(
    {
        "wireshark_capture",
        "wireshark_list_interfaces",
    }
)

# Tools that write a new file: pcap surgery, format conversion, saved filters.
_WRITERS: Final[frozenset[str]] = frozenset(
    {
        "wireshark_editcap_deduplicate",
        "wireshark_editcap_split",
        "wireshark_editcap_time_shift",
        "wireshark_editcap_trim",
        "wireshark_export_objects",
        "wireshark_extract_frames",
        "wireshark_filter_save",
        "wireshark_merge_pcaps",
        "wireshark_text2pcap_import",
        "wireshark_yara_scan",
    }
)

# Dissection overrides, decryption, and low-level views. Real capabilities, but
# each one needs the caller to already know what they are doing — none is part of
# a normal triage path.
_ADVANCED: Final[frozenset[str]] = frozenset(
    {
        "wireshark_decode_as",
        "wireshark_decrypt_tls",
        "wireshark_decrypt_wpa",
        "wireshark_flow_graph",
        "wireshark_get_capabilities",
        "wireshark_get_packet_bytes",
        "wireshark_scan_file_signatures",
        "wireshark_set_protocol_prefs",
    }
)

# What each profile removes from the full surface. `full` removes nothing.
_EXCLUSIONS: Final[dict[str, frozenset[str]]] = {
    "full": frozenset(),
    "analysis": _CAPTURE | _WRITERS,
    "core": _CAPTURE | _WRITERS | _ADVANCED,
}

PROFILE_NAMES: Final[tuple[str, ...]] = ("full", "analysis", "core")


def excluded_tools(profile: str) -> frozenset[str]:
    """Tool names the given profile does not advertise.

    Unknown names fall back to `full` (nothing excluded) rather than raising: the
    CLI validates the choice, and a bad value should not leave a caller with an
    arbitrarily reduced surface.
    """
    return _EXCLUSIONS.get(profile, frozenset())


def profile_description(profile: str) -> str:
    """One-line summary for `--help` and startup logging."""
    return {
        "full": "every tool (default)",
        "analysis": "no live capture, no file-writing tools",
        "core": "analysis minus decryption, dissection overrides, and low-level views",
    }.get(profile, "unknown profile")
