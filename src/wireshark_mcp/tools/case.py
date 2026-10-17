"""`wireshark_case`: persistent investigation case files.

One action-dispatched tool rather than six: the case operations share their
arguments, and each extra tool would cost prefix bytes on every request. Cases
live in a server-managed directory under the first allowed write root (or
``WIRESHARK_MCP_CASE_DIR`` when it is inside an allowed root), so the caller
never chooses a write path and writes stay fail-closed without a configured root.
"""

import json
import os
from pathlib import Path

from mcp.server import MCPServer

from ..cases import CaseError, CaseStore, render_case_markdown, summarize_case
from ..tshark.client import TSharkClient
from .envelope import envelope_response, error_response

CASE_DIR_ENV = "WIRESHARK_MCP_CASE_DIR"
DEFAULT_CASE_SUBDIR = ".wireshark-mcp-cases"
CASE_ACTIONS = ("create", "record", "verdict", "note", "show", "report", "list")


def resolve_case_store(client: TSharkClient) -> CaseStore | str:
    """Return the store, or an error envelope when case writes are not permitted."""
    configured = os.environ.get(CASE_DIR_ENV, "").strip()
    allowed = getattr(client, "_allowed_dirs", None)
    if configured:
        validation = client._validate_output_path(configured)
        if not validation["success"]:
            return error_response(validation["error"]["message"], error_type=validation["error"]["type"])
        return CaseStore(Path(configured).resolve())
    if not allowed:
        return error_response(
            "Case files are disabled. Set WIRESHARK_MCP_ALLOWED_DIRS (and optionally "
            f"{CASE_DIR_ENV}) so cases can be stored under an allowed root.",
            error_type="PermissionDenied",
        )
    return CaseStore(Path(allowed[0]) / DEFAULT_CASE_SUBDIR)


def register_case_tools(mcp: MCPServer, client: TSharkClient) -> None:
    """Register the case-file tool and its read-only resource."""

    @mcp.tool()
    async def wireshark_case(
        action: str,
        case_id: str = "",
        text: str = "",
        target: str = "",
    ) -> str:
        """[Case] Saved investigation. create(text=title,target=pcaps) record(text=tool JSON) verdict(target=finding id,text=confirmed|dismissed|open: note) note show report list"""
        store = resolve_case_store(client)
        if isinstance(store, str):
            return store
        try:
            if action == "list":
                return envelope_response({"cases": store.list_cases()})
            if action == "create":
                captures: list[Path] = []
                for name in (part.strip() for part in target.split(",")):
                    if not name:
                        continue
                    validation = client._validate_file(name)
                    if not validation["success"]:
                        return error_response(validation["error"]["message"], error_type=validation["error"]["type"])
                    captures.append(Path(name).resolve())
                case = store.create(text, captures)
                return envelope_response(summarize_case(case), scope={"case_id": case["case_id"]})
            if action not in CASE_ACTIONS:
                return error_response(
                    f"action must be one of: {', '.join(CASE_ACTIONS)}", error_type="InvalidParameter"
                )
            if not case_id:
                return error_response(f"{action} needs case_id", error_type="InvalidParameter")
            scope = {"case_id": case_id}
            if action == "record":
                return envelope_response(store.record(case_id, text), scope=scope)
            if action == "verdict":
                # text is "<verdict>" or "<verdict>: <note>", keeping the schema to one free-text field.
                verdict, _, note = text.partition(":")
                return envelope_response(store.set_verdict(case_id, target, verdict.strip(), note.strip()), scope=scope)
            if action == "note":
                return envelope_response(store.add_note(case_id, text), scope=scope)
            case = store.load(case_id)
            if action == "show":
                return envelope_response(summarize_case(case), scope=scope)
            return envelope_response({"markdown": render_case_markdown(case)}, scope=scope)
        except CaseError as exc:
            return error_response(str(exc), error_type="InvalidParameter")
        except OSError as exc:
            return error_response(f"Case storage failed: {exc.strerror or exc}", error_type="IOError")

    @mcp.resource("wireshark://cases/{case_id}")
    def get_case(case_id: str) -> str:
        """Full JSON of one investigation case file."""
        store = resolve_case_store(client)
        if isinstance(store, str):
            return store
        try:
            return json.dumps(store.load(case_id), ensure_ascii=False, indent=2)
        except CaseError as exc:
            return error_response(str(exc), error_type="InvalidParameter")
