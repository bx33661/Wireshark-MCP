"""Shared Wireshark suite tool metadata."""

from __future__ import annotations

from typing import Literal

ToolRequirement = Literal["required", "recommended", "optional"]

WIRESHARK_TOOL_ENV_VARS: dict[str, str] = {
    "tshark": "WIRESHARK_MCP_TSHARK_PATH",
    "capinfos": "WIRESHARK_MCP_CAPINFOS_PATH",
    "mergecap": "WIRESHARK_MCP_MERGECAP_PATH",
    "editcap": "WIRESHARK_MCP_EDITCAP_PATH",
    "dumpcap": "WIRESHARK_MCP_DUMPCAP_PATH",
    "text2pcap": "WIRESHARK_MCP_TEXT2PCAP_PATH",
}

WIRESHARK_TOOL_REQUIREMENTS: dict[str, ToolRequirement] = {
    "tshark": "required",
    "capinfos": "recommended",
    "mergecap": "recommended",
    "editcap": "optional",
    "dumpcap": "optional",
    "text2pcap": "optional",
}

WIRESHARK_TOOL_PURPOSES: dict[str, str] = {
    "tshark": "Core packet analysis and protocol dissection",
    "capinfos": "Capture-file metadata and summary statistics",
    "mergecap": "Capture-file merging",
    "editcap": "Capture trimming, splitting, time shifting, and deduplication",
    "dumpcap": "Preferred backend for live capture",
    "text2pcap": "Import ASCII/hex dumps into capture files",
}

WIRESHARK_CAPTURE_BACKEND_ORDER = ("dumpcap", "tshark")
WIRESHARK_TOOL_ORDER = tuple(WIRESHARK_TOOL_ENV_VARS.keys())
