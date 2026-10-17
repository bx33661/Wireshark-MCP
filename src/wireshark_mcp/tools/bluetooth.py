"""Bluetooth Low Energy analysis tools (advertising inventory, scanners, ATT/GATT timeline)."""

import contextlib
import logging
from collections import Counter
from typing import Any

from ..tshark.client import TSharkClient
from .envelope import ProtocolHandler, envelope_response, normalize_tool_result, parse_tool_result
from .findings import Finding, FindingEvidence, finalize_findings
from .formatting import OK, WARN

logger = logging.getLogger("wireshark_mcp")

# btatt.opcode renders as hex ("0x12"); map to spec names (verified against
# tshark 4.6.8 dissections of a real GATT exchange).
OPCODE_NAMES: dict[int, str] = {
    0x01: "Error Response",
    0x02: "Exchange MTU Request",
    0x03: "Exchange MTU Response",
    0x04: "Find Information Request",
    0x05: "Find Information Response",
    0x06: "Find By Type Value Request",
    0x07: "Find By Type Value Response",
    0x08: "Read By Type Request",
    0x09: "Read By Type Response",
    0x0A: "Read Request",
    0x0B: "Read Response",
    0x0C: "Read Blob Request",
    0x0D: "Read Blob Response",
    0x0E: "Read Multiple Request",
    0x0F: "Read Multiple Response",
    0x10: "Read By Group Type Request",
    0x11: "Read By Group Type Response",
    0x12: "Write Request",
    0x13: "Write Response",
    0x14: "Prepare Write Request",
    0x15: "Prepare Write Response",
    0x16: "Execute Write Request",
    0x17: "Execute Write Response",
    0x1B: "Handle Value Notification",
    0x1D: "Handle Value Indication",
    0x1E: "Handle Value Confirmation",
    0x20: "Read Multiple Variable Length Request",
    0x21: "Read Multiple Variable Length Response",
    0x52: "Write Command",
    0xD2: "Signed Write Command",
}

# Legacy advertising PDU types (btle.advertising_header.pdu_type renders as hex).
PDU_NAMES: dict[int, str] = {
    0x00: "ADV_IND",
    0x01: "ADV_DIRECT_IND",
    0x02: "ADV_NONCONN_IND",
    0x03: "SCAN_REQ",
    0x04: "SCAN_RSP",
    0x05: "CONNECT_IND",
    0x06: "ADV_SCAN_IND",
    0x07: "ADV_EXTRA_IND",
}


def _strip(raw: str) -> str:
    """tshark quote=d wraps values in double quotes; multi-value cells split on
    the aggregator leave single-sided quotes on the first/last fragment, so
    peel whitespace and quote characters from both ends in one pass."""
    return raw.strip(' \t\r\n"')


def _pad(parts: list[str], size: int) -> list[str]:
    """tshark drops trailing tabs for empty tail fields; pad once so indexing is direct."""
    if len(parts) < size:
        parts.extend([""] * (size - len(parts)))
    return parts


def _col(parts: list[str], index: int) -> str:
    """Read a TSV column defensively: tshark drops trailing tabs for empty tail fields."""
    return parts[index] if len(parts) > index else ""


def _split_multivalue(raw: str) -> list[str]:
    """Split an aggregator-joined multi-instance field (names, company IDs, handles)."""
    return [s for s in (_strip(p) for p in raw.split(",")) if s]


def _pdu_name(raw: str) -> str:
    value = _strip(raw)
    try:
        key = int(value, 16)
    except ValueError:
        return value
    return PDU_NAMES.get(key, value)


def _address_type(txadd_values: set[str]) -> str:
    """Map observed TxAdd flag values to an address type label."""
    flags = {v for v in txadd_values if v in {"True", "False"}}
    if not flags:
        return "unknown"
    if len(flags) > 1:
        return "mixed"
    return "random" if flags == {"True"} else "public"


def _parse_opcode(raw: str) -> tuple[str, str]:
    """Return (opcode string, semantic operation name)."""
    opcode = _strip(raw)
    try:
        return opcode, OPCODE_NAMES.get(int(opcode, 16), f"Unknown ({opcode})")
    except ValueError:
        return opcode, f"Unknown ({opcode})"


# HCI error codes as seen in Disconnect Complete events (bthci_evt.reason).
REASON_CODES: dict[int, str] = {
    0x00: "Success",
    0x01: "Unknown HCI Command",
    0x02: "Unknown Connection Identifier",
    0x03: "Hardware Failure",
    0x05: "Authentication Failure",
    0x06: "PIN or Key Missing",
    0x07: "Memory Capacity Exceeded",
    0x08: "Connection Timeout",
    0x09: "Connection Limit Exceeded",
    0x0A: "Synchronous Connection Limit Exceeded",
    0x0B: "ACL Connection Already Exists",
    0x0C: "Command Disallowed",
    0x0D: "Connection Rejected Due To Limited Resources",
    0x0E: "Connection Rejected Due To Security Reasons",
    0x0F: "Connection Rejected Due To Unacceptable BD_ADDR",
    0x10: "Connection Accept Timeout Exceeded",
    0x11: "Unsupported Feature or Parameter Value",
    0x12: "Invalid HCI Command Parameters",
    0x13: "Remote User Terminated Connection",
    0x14: "Remote Device Terminated Connection Due To Low Resources",
    0x15: "Remote Device Terminated Connection Due To Power Off",
    0x16: "Connection Terminated By Local Host",
    0x17: "Repeated Attempts",
    0x18: "Pairing Not Allowed",
    0x1A: "Unsupported Remote Feature",
    0x1E: "Invalid LL Parameters",
    0x1F: "Unspecified Error",
    0x20: "Unsupported LL Parameter Value",
    0x21: "Role Change Not Allowed",
    0x22: "LL Response Timeout",
    0x23: "LL Procedure Collision",
    0x25: "Encryption Mode Not Acceptable",
    0x28: "Instant Passed",
    0x2C: "Parameter Out Of Mandatory Range",
    0x30: "QoS Unacceptable Parameter",
    0x34: "Host Occupied",
    0x35: "Host Busy",
    0x36: "Controller Busy",
    0x3C: "Unacceptable Connection Parameters",
    0x3E: "Connection Failed to be Established",
    0x3F: "MAC Connection Failed",
    0x40: "Coarse Clock Adjustment Rejected",
    0x44: "Remote Device Terminated Due To Subrating Not Supported",
}


def _reason_name(raw: str) -> str:
    """Map a bthci_evt.reason value ('0x13') to its spec name."""
    value = _strip(raw)
    try:
        code = int(value, 16)
    except ValueError:
        return f"Unknown ({value})"
    return f"{REASON_CODES.get(code, 'Unknown error code')} ({value})"


# SMP (Security Manager Protocol) opcodes as rendered in btsmp.opcode.
SMP_OPCODE_NAMES: dict[int, str] = {
    0x01: "Pairing Request",
    0x02: "Pairing Response",
    0x03: "Pairing Confirm",
    0x04: "Pairing Random",
    0x05: "Pairing Failed",
    0x06: "Encryption Information",
    0x07: "Master Identification",
    0x08: "Identity Information",
    0x09: "Identity Address Information",
    0x0A: "Signing Information",
    0x0B: "Security Request",
    0x0C: "Pairing Public Key",
    0x0D: "Pairing DHKey Check",
    0x0E: "Keypress Notification",
}

SMP_IO_CAP_NAMES: dict[int, str] = {
    0x00: "DisplayOnly",
    0x01: "DisplayYesNo",
    0x02: "KeyboardOnly",
    0x03: "NoInputNoOutput",
    0x04: "KeyboardDisplay",
}

# btsmp.reason values carried on Pairing Failed (SMP error codes).
SMP_FAIL_REASONS: dict[int, str] = {
    0x01: "Passkey Entry Failed",
    0x02: "OOB Not Available",
    0x03: "Authentication Requirements Not Met",
    0x04: "Confirm Value Failed",
    0x05: "Pairing Not Supported",
    0x06: "Encryption Key Size Not Acceptable",
    0x07: "Command Not Supported",
    0x08: "Unspecified Reason",
    0x09: "Repeated Attempts",
    0x0A: "Invalid Parameters",
    0x0B: "DHKey Check Failed",
    0x0C: "Numeric Comparison Failed",
    0x0D: "BR/EDR Pairing In Progress",
    0x0E: "CSRK Not Supported",
}


def _smp_io_cap_name(raw: str) -> str:
    value = _strip(raw)
    try:
        return SMP_IO_CAP_NAMES.get(int(value, 16), value)
    except ValueError:
        return value


def _smp_fail_reason(raw: str) -> str:
    value = _strip(raw)
    try:
        return f"{SMP_FAIL_REASONS.get(int(value, 16), 'Unknown error code')} ({value})"
    except ValueError:
        return value


def _key_distribution(raw: str) -> list[str]:
    """Expand a key-distribution flags byte (hex) into distributed key names."""
    value = _strip(raw)
    try:
        flags = int(value, 16)
    except ValueError:
        return []
    distributed = []
    if flags & 0x01:
        distributed.append("LTK (encryption)")
    if flags & 0x02:
        distributed.append("IRK + identity address")
    if flags & 0x04:
        distributed.append("CSRK (signing)")
    return distributed


def _infer_pairing_method(request: dict[str, Any] | None, response: dict[str, Any] | None) -> tuple[str, str]:
    """Infer the LE pairing method from the request/response exchange.

    Returns (method, note). Simplified from Vol 3 Part H Table 5.7; the note
    carries the raw flags so a reviewer can re-check the inference.
    """
    if request is None or response is None:
        return "unknown", "pairing request/response pair not both present in this capture"
    # Core Vol 3 Part H, Tables 2.6-2.8: SC is negotiated by both
    # devices, whereas either device can request MITM protection. Legacy
    # OOB requires both flags; SC OOB needs only one.
    secure_connections = request["sc"] == "True" and response["sc"] == "True"
    oob_req, oob_rsp = request["oob"] == "0x01", response["oob"] == "0x01"
    if (oob_req and oob_rsp) or (secure_connections and (oob_req or oob_rsp)):
        return "OOB", "OOB data flag set"
    mitm = request["mitm"] == "True" or response["mitm"] == "True"
    if not mitm:
        return "Just Works", "no MITM protection requested"
    io_req, io_rsp = request["io_capability"], response["io_capability"]
    displays = {"0x00", "0x01", "0x04"}
    keyboards = {"0x02", "0x04"}
    if io_req in ("0x01", "0x04") and io_rsp in ("0x01", "0x04") and secure_connections:
        return "Numeric Comparison", "MITM requested, both sides display-confirm capable, secure connections"
    if (io_req in keyboards and io_rsp in displays) or (io_rsp in keyboards and io_req in displays):
        return "Passkey Entry", "MITM requested, keyboard/display pairing"
    if io_req == io_rsp == "0x02":
        return "Passkey Entry", "MITM requested, user enters the same passkey on both keyboards"
    if io_req == "0x03" or io_rsp == "0x03":
        return "Just Works", "MITM requested but a side is NoInputNoOutput, so it degrades to Just Works"
    return "Just Works", "MITM requested, IO capabilities fall back to Just Works"


# Common Bluetooth assigned numbers for GATT services and characteristics.
UUID_NAMES: dict[int, str] = {
    # Services
    0x1800: "Generic Access",
    0x1801: "Generic Attribute",
    0x1802: "Immediate Alert",
    0x1803: "Link Loss",
    0x1804: "Tx Power",
    0x1805: "Pulse Oximeter",
    0x1808: "Glucose",
    0x1809: "Health Thermometer",
    0x180A: "Device Information",
    0x180D: "Heart Rate",
    0x180E: "Phone Alert Status",
    0x180F: "Battery",
    0x1810: "Blood Pressure",
    0x1811: "Alert Notification",
    0x1812: "Human Interface Device",
    0x1813: "Scan Parameters",
    0x1814: "Running Speed and Cadence",
    0x1815: "Automation IO",
    0x1816: "Cycling Speed and Cadence",
    0x1818: "Cycling Power",
    0x1819: "Location and Navigation",
    0x181A: "Environmental Sensing",
    0x181C: "User Data",
    0x1826: "Fitness Machine",
    # Characteristics
    0x2A00: "Device Name",
    0x2A01: "Appearance",
    0x2A19: "Battery Level",
    0x2A23: "System ID",
    0x2A24: "Model Number String",
    0x2A25: "Serial Number String",
    0x2A26: "Firmware Revision String",
    0x2A27: "Hardware Revision String",
    0x2A28: "Software Revision String",
    0x2A29: "Manufacturer Name String",
    0x2A37: "Heart Rate Measurement",
    0x2A50: "Pulse Oximetry Measurement",
    0x2A6E: "Temperature",
    0x2A6F: "Humidity",
    # Attribute types
    0x2800: "Primary Service",
    0x2801: "Secondary Service",
    0x2802: "Include",
    0x2803: "Characteristic Declaration",
    # Descriptors
    0x2900: "Characteristic Extended Properties",
    0x2901: "Characteristic User Description",
    0x2902: "Client Characteristic Configuration",
    0x2905: "Characteristic Aggregate Format",
    0x2906: "Valid Range",
}


def _uuid_label(hex_value: str) -> str:
    """Label a little-endian 16-bit UUID hex string ('0018') with its name."""
    value = _strip(hex_value).replace(",", "")
    try:
        uuid_int = int.from_bytes(bytes.fromhex(value), "little")
    except ValueError:
        return hex_value
    name = UUID_NAMES.get(uuid_int)
    return f"{name} (0x{uuid_int:04x})" if name else f"0x{uuid_int:04x}"


def _uuid_label_from_display(raw: str) -> str:
    """Label a tshark-rendered UUID ('0x290d' or '0x2a00') with its name."""
    value = _strip(raw)
    try:
        uuid_int = int(value, 16)
    except ValueError:
        return value
    name = UUID_NAMES.get(uuid_int)
    return f"{name} (0x{uuid_int:04x})" if name else value


def _split_handles(raw: str) -> list[int]:
    """Parse an aggregator-joined handle column ('0x0001,0x0006') into ints."""
    values: list[int] = []
    for part in _split_multivalue(raw):
        with contextlib.suppress(ValueError):
            values.append(int(part, 16))
    return values


def _gatt_context(parts: list[str], opcode: str) -> tuple[str, str]:
    """Capture-local link identity and ATT server, not a global attribute handle.

    connect_in distinguishes reused HCI handles. OTA links use their access
    address. Requests address the server; responses/notifications originate at
    it. HCI direction supplies the server side when BD_ADDRs are unavailable.
    """
    interface, handle, connected, access, src, dst, direction = map(_strip, parts[12:19])
    interface = interface or "0"
    if handle:
        connection = f"hci:{interface}:{handle}@{connected or '?'}"
    elif access:
        connection = f"aa:{interface}:{access}"
    elif src and dst:
        connection = f"peers:{interface}:" + ",".join(sorted((src, dst)))
    else:
        connection = f"unknown:{interface}"
    try:
        is_request = int(opcode, 16) in {
            0x02,
            0x04,
            0x06,
            0x08,
            0x0A,
            0x0C,
            0x0E,
            0x10,
            0x12,
            0x14,
            0x16,
            0x1E,
            0x20,
            0x52,
            0xD2,
        }
    except ValueError:
        return connection, "unknown"
    server = dst if is_request else src
    if not server and direction in ("0", "1"):
        source_side = int(direction)  # 0 sent (local), 1 received (remote)
        server_side = 1 - source_side if is_request else source_side
        server = "remote" if server_side else "local"
    return connection, server or "unknown"


def _resolve_gatt_discovery(
    parsed_rows: list[tuple[list[str], str, str]],
) -> tuple[list[dict[str, Any]], list[tuple[int, int, str]], dict[str, str]]:
    """Resolve one connection/server namespace; pending queries are per ATT bearer."""
    services: list[dict[str, Any]] = []
    service_ranges: list[tuple[int, int, str]] = []
    handle_labels: dict[str, str] = {}
    pending_types: dict[str, str] = {}
    for parts, opcode, _operation in parsed_rows:
        cid = _strip(parts[6])
        pending_rbt_type = pending_types.get(cid)
        if opcode == "0x01":  # ATT Error Response terminates the pending request
            pending_types.pop(cid, None)
        if opcode == "0x11":  # Read By Group Type Response: service table
            starts = _split_handles(parts[3])
            ends = _split_handles(parts[7])
            # Request correlation injects the queried type (0x2800/0x2801) as a
            # trailing uuid16 instance; drop it. 128-bit service UUIDs render
            # into btatt.uuid128 instead of uuid16. Uncorrelated responses
            # (synthetic captures) carry entry UUIDs in btatt.value as raw LE hex.
            uuid128_list = _split_multivalue(parts[9])
            uuid_display = [u for u in _split_multivalue(parts[8]) if u not in ("0x2800", "0x2801")]
            uuid_value = _split_multivalue(parts[4])
            if uuid128_list:
                uuid_pairs = [(u, f"0x{u}") for u in uuid128_list]
            elif uuid_display:
                uuid_pairs = [(uuid, _uuid_label_from_display(uuid)) for uuid in uuid_display]
            else:
                uuid_pairs = [(uuid_hex, _uuid_label(uuid_hex)) for uuid_hex in uuid_value]
            # zip truncates to the shortest list, absorbing leftover injections.
            for start, end, (uuid_raw, label) in zip(starts, ends, uuid_pairs, strict=False):
                services.append(
                    {
                        "start_handle": f"0x{start:04x}",
                        "end_handle": f"0x{end:04x}",
                        "uuid": uuid_raw,
                        "label": label,
                    }
                )
                service_ranges.append((start, end, label))
        elif opcode == "0x05":  # Find Information Response: handle -> UUID
            fit_handles = _split_handles(parts[3])
            fit_uuids = _split_multivalue(parts[8])
            # Correlated renderings inject extra uuid16 instances (service /
            # characteristic UUID lookups per handle), so the counts only match
            # for clean single-entry responses. Pair only when they do; the
            # 0x2803 declaration path provides labels otherwise.
            if len(fit_handles) == len(fit_uuids):
                for fit_handle, fit_uuid in zip(fit_handles, fit_uuids, strict=False):
                    handle_labels.setdefault(f"0x{fit_handle:04x}", _uuid_label_from_display(fit_uuid))
        elif opcode == "0x08":  # Read By Type Request: remember the queried type
            pending_types.pop(cid, None)
            queried_type = _strip(parts[8])
            if queried_type:
                pending_types[cid] = queried_type
        elif opcode == "0x09" and pending_rbt_type == "0x2803":
            # Read By Type Response to a Characteristic Declaration query.
            # tshark 4.6+ renders each entry as raw bytes in btatt.value:
            # properties(1) | value_handle(2) | uuid(2 or 16). Older releases
            # (the Linux CI's 4.2) render structured fields instead: the value
            # handle reuses btatt.handle (handles arrive as [decl, value_handle]
            # per entry) and the UUID arrives in btatt.characteristic_uuid16/128.
            entry_handles = _split_handles(parts[3])
            entry_values = _split_multivalue(parts[4])
            if entry_values:
                for _decl_handle, entry_value in zip(entry_handles, entry_values, strict=False):
                    try:
                        raw = bytes.fromhex(entry_value)
                    except ValueError:
                        continue
                    if len(raw) < 5:
                        continue
                    value_handle = int.from_bytes(raw[1:3], "little")
                    if len(raw) >= 19:  # 128-bit UUID
                        uuid_int = int.from_bytes(raw[3:19], "little")
                        handle_labels[f"0x{value_handle:04x}"] = f"0x{uuid_int:032x}"
                    else:
                        uuid_int = int.from_bytes(raw[3:5], "little")
                        name = UUID_NAMES.get(uuid_int)
                        handle_labels[f"0x{value_handle:04x}"] = (
                            f"{name} (0x{uuid_int:04x})" if name else f"0x{uuid_int:04x}"
                        )
            else:
                # Structured-field shape on tshark <= 4.2 (confirmed in the
                # release-4.2 dissector): the value handle reuses btatt.handle
                # (handles arrive as [declaration, value_handle] per entry) and
                # the entry UUID renders into btatt.uuid16 / btatt.uuid128,
                # trailed by the generated queried-type instance. Filter the
                # injection like the RBGT path. Guard against tshark 4.6's
                # correlation, which can duplicate one uuid across entries
                # ("0x2a00,0x2a00" for a two-entry response): pairing those
                # would mislabel handles, and a wrong label is worse than none.
                # Only pair when the uuid instances are distinct.
                # tshark 4.2.2 observed shape (from the CI debug dump):
                # uuid16 arrives as "0x2803,0x2a19,0x2803" - the declaration
                # type injected around the entry uuid - so filter the
                # declaration-type instances too, not just 0x2800/0x2801.
                char_uuids = _split_multivalue(parts[9]) or [
                    u for u in _split_multivalue(parts[8]) if u not in ("0x2800", "0x2801", "0x2803")
                ]
                if len(set(char_uuids)) == len(char_uuids):
                    for value_handle, char_uuid in zip(entry_handles[1::2], char_uuids, strict=False):
                        if char_uuid.startswith("0x"):
                            handle_labels[f"0x{value_handle:04x}"] = _uuid_label_from_display(char_uuid)
                        else:
                            handle_labels[f"0x{value_handle:04x}"] = f"0x{char_uuid}"
            pending_types.pop(cid, None)
        elif opcode == "0x09" and pending_rbt_type is not None:
            # Read By Type Response to a characteristic-UUID query: the entry
            # handle itself is the value handle of the queried characteristic.
            queried_label = _uuid_label_from_display(pending_rbt_type)
            for entry_handle in _split_handles(parts[3]):
                handle_labels.setdefault(f"0x{entry_handle:04x}", queried_label)
            pending_types.pop(cid, None)
    return services, service_ranges, handle_labels


def make_ble_protocol_handlers(client: TSharkClient) -> dict[str, ProtocolHandler]:
    """Build the BLE protocol handlers for wireshark_analyze_protocol.

    Each handler follows the shared (pcap_file, limit) -> envelope signature so
    the dispatcher can call every protocol uniformly. The deep aggregation lives
    here in Python — per-device grouping, scanner fan-out, service-table and
    handle-label resolution, per-handle session accounting — because a flat
    field extractor cannot express it.
    """

    async def ble_devices(pcap_file: str, limit: int = 100) -> str:
        """[Protocol] BLE advertising device inventory: devices by address with frame counts, names, company IDs, address type, dual-address same-name detection."""
        result = await client.extract_fields(
            pcap_file,
            [
                "frame.number",
                "btle.advertising_address",
                "btle.advertising_header.pdu_type",
                "btle.advertising_header.randomized_tx",
                "btcommon.eir_ad.entry.device_name",
                "btcommon.eir_ad.entry.company_id",
            ],
            display_filter="btle.advertising_address and not btle.scanning_address",
            limit=limit,
        )
        wrapped = parse_tool_result(result)
        if not wrapped["success"]:
            return normalize_tool_result(wrapped)

        data = wrapped.get("data", "")
        warnings: list[str] = []
        truncated = wrapped.get("truncated") is True
        if truncated:
            warnings.append(
                f"Advertising rows hit the limit of {limit}; frame counts are lower bounds. Raise limit for full inventory."
            )

        if not isinstance(data, str) or not data.strip():
            return envelope_response(
                data={
                    "devices": [],
                    "shared_name_groups": [],
                    "summary": (
                        f"{OK} No BLE over-the-air advertising frames found. "
                        "HCI-side captures (btsnoop/H4) expose GATT traffic via wireshark_extract_gatt_timeline instead."
                    ),
                },
                scope={"pcap_file": pcap_file, "filter": "btle.advertising_address and not btle.scanning_address"},
                coverage={"status": "complete", "frames_scanned": 0, "devices": 0, "limit": limit},
            )

        lines = data.strip().splitlines()
        start_idx = 1 if "frame.number" in lines[0] else 0

        # Per-advertiser aggregation: frame_count, PDU mix, names, company IDs, TxAdd.
        devices: dict[str, dict[str, Any]] = {}
        rows = 0
        for line in lines[start_idx:]:
            parts = _pad(line.split("\t"), 6)
            addr = _strip(parts[1])
            if not addr:
                continue
            rows += 1
            frame_raw = _strip(parts[0])
            frame = int(frame_raw) if frame_raw.isdigit() else None
            dev = devices.get(addr)
            if dev is None:  # build the row bucket once, not on every frame
                dev = devices[addr] = {
                    "frame_count": 0,
                    "pdu_types": Counter(),
                    "names": set(),
                    "company_ids": set(),
                    "txadd": set(),
                    "first_frame": frame,
                    "last_frame": frame,
                }
            dev["frame_count"] += 1
            dev["pdu_types"][_pdu_name(parts[2])] += 1
            for name in _split_multivalue(parts[4]):
                dev["names"].add(name)
            for company in _split_multivalue(parts[5]):
                dev["company_ids"].add(company)
            txadd = _strip(parts[3])
            if txadd:
                dev["txadd"].add(txadd)
            if frame is not None:
                if dev["first_frame"] is None or frame < dev["first_frame"]:
                    dev["first_frame"] = frame
                if dev["last_frame"] is None or frame > dev["last_frame"]:
                    dev["last_frame"] = frame

        device_rows: list[dict[str, Any]] = []
        for addr, dev in sorted(devices.items(), key=lambda kv: kv[1]["frame_count"], reverse=True):
            device_rows.append(
                {
                    "address": addr,
                    "address_type": _address_type(dev["txadd"]),
                    "frame_count": dev["frame_count"],
                    "pdu_types": dict(sorted(dev["pdu_types"].items(), key=lambda kv: kv[1], reverse=True)),
                    "names": sorted(dev["names"]),
                    "company_ids": sorted(dev["company_ids"]),
                    "first_frame": dev["first_frame"],
                    "last_frame": dev["last_frame"],
                    "filter": f"btle.advertising_address == {addr}",
                }
            )

        # Dual-address same-name detection: one device name advertised by 2+ addresses.
        name_to_addresses: dict[str, set[str]] = {}
        for row in device_rows:
            for name in row["names"]:
                name_to_addresses.setdefault(name, set()).add(row["address"])
        shared_name_groups = [
            {
                "device_name": name,
                "addresses": sorted(addresses),
                "frame_counts": {
                    row["address"]: row["frame_count"] for row in device_rows if row["address"] in addresses
                },
            }
            for name, addresses in sorted(name_to_addresses.items())
            if len(addresses) >= 2
        ]

        summary_lines = [f"BLE advertising devices ({len(device_rows)}) from {rows} frame(s):"]
        for row in device_rows:
            pdu_mix = ", ".join(f"{name} x{count}" for name, count in row["pdu_types"].items())
            names = f", names {row['names']}" if row["names"] else ""
            companies = f", company IDs {row['company_ids']}" if row["company_ids"] else ""
            summary_lines.append(
                f"- {row['address']} [{row['address_type']}]: {row['frame_count']} frame(s) ({pdu_mix}){names}{companies}"
            )
        for group in shared_name_groups:
            summary_lines.append(
                f"{WARN} {len(group['addresses'])} address(es) share the device name '{group['device_name']}' "
                f"(RPA rotation or cloned identity): {', '.join(group['addresses'])}"
            )

        return envelope_response(
            data={
                "devices": device_rows,
                "shared_name_groups": shared_name_groups,
                "summary": "\n".join(summary_lines),
            },
            scope={"pcap_file": pcap_file, "filter": "btle.advertising_address and not btle.scanning_address"},
            coverage={
                "status": "partial" if truncated else "complete",
                "frames_scanned": rows,
                "devices": len(device_rows),
                "limit": limit,
            },
            truncated=truncated or None,
            warnings=warnings or None,
        )

    async def ble_scan_activity(pcap_file: str, limit: int = 100) -> str:
        """[Protocol] Detect BLE active scanners: SCAN_REQ initiators with request counts and scanned-target distribution."""
        result = await client.extract_fields(
            pcap_file,
            [
                "frame.number",
                "btle.scanning_address",
                "btle.advertising_address",
                "btle.advertising_header.randomized_tx",
            ],
            display_filter="btle.advertising_header.pdu_type == 0x03",
            limit=limit,
        )
        wrapped = parse_tool_result(result)
        if not wrapped["success"]:
            return normalize_tool_result(wrapped)

        data = wrapped.get("data", "")
        warnings: list[str] = []
        truncated = wrapped.get("truncated") is True
        if truncated:
            warnings.append(
                f"SCAN_REQ rows hit the limit of {limit}; request counts are lower bounds. Raise limit for full activity."
            )

        if not isinstance(data, str) or not data.strip():
            return envelope_response(
                data={
                    "findings": [],
                    "scanners": [],
                    "summary": f"{OK} No BLE SCAN_REQ (active scanning) activity found.",
                },
                scope={"pcap_file": pcap_file, "filter": "btle.advertising_header.pdu_type == 0x03"},
                coverage={"status": "complete", "frames_scanned": 0, "scanners": 0, "limit": limit},
            )

        lines = data.strip().splitlines()
        start_idx = 1 if "frame.number" in lines[0] else 0

        scanners: dict[str, dict[str, Any]] = {}
        rows = 0
        for line in lines[start_idx:]:
            parts = line.split("\t")
            if len(parts) < 2:  # need at least the scanner address column
                continue
            scanner = _strip(parts[1])
            target = _strip(_col(parts, 2))
            if not scanner:
                continue
            rows += 1
            frame_raw = _strip(_col(parts, 0))
            frame = int(frame_raw) if frame_raw.isdigit() else None
            entry = scanners.get(scanner)
            if entry is None:  # build the scanner bucket once
                entry = scanners[scanner] = {
                    "scan_requests": 0,
                    "targets": Counter(),
                    "txadd": set(),
                    "first_frame": frame,
                    "last_frame": frame,
                }
            entry["scan_requests"] += 1
            if target:
                entry["targets"][target] += 1
            txadd = _strip(_col(parts, 3))
            if txadd:
                entry["txadd"].add(txadd)
            if frame is not None:
                if entry["first_frame"] is None or frame < entry["first_frame"]:
                    entry["first_frame"] = frame
                if entry["last_frame"] is None or frame > entry["last_frame"]:
                    entry["last_frame"] = frame

        scanner_rows: list[dict[str, Any]] = []
        for scanner, entry in sorted(scanners.items(), key=lambda kv: kv[1]["scan_requests"], reverse=True):
            top_targets = [{"address": addr, "requests": count} for addr, count in entry["targets"].most_common(10)]
            scanner_rows.append(
                {
                    "address": scanner,
                    "address_type": _address_type(entry["txadd"]),
                    "scan_requests": entry["scan_requests"],
                    "distinct_targets": len(entry["targets"]),
                    "top_targets": top_targets,
                    "first_frame": entry["first_frame"],
                    "last_frame": entry["last_frame"],
                }
            )

        total_requests = sum(entry["scan_requests"] for entry in scanners.values())
        total_targets = len({addr for entry in scanners.values() for addr in entry["targets"]})

        summary_lines = [
            f"Active BLE scanners ({len(scanner_rows)}) issuing {total_requests} SCAN_REQ against {total_targets} target(s):"
        ]
        for row in scanner_rows:
            top = ", ".join(f"{t['address']} x{t['requests']}" for t in row["top_targets"][:3])
            summary_lines.append(
                f"- {row['address']} [{row['address_type']}]: {row['scan_requests']} SCAN_REQ, "
                f"{row['distinct_targets']} target(s) ({top})"
            )

        evidence = [
            FindingEvidence(
                filter=f"btle.advertising_header.pdu_type == 0x03 and btle.scanning_address == {row['address']}",
                field="btle.scanning_address",
                description=f"{row['scan_requests']} SCAN_REQ against {row['distinct_targets']} target(s)",
                value=", ".join(t["address"] for t in row["top_targets"][:3]),
                frame=row["first_frame"],
            )
            for row in scanner_rows[:5]
        ]
        more = len(scanner_rows) - 5
        observation = f"{len(scanner_rows)} active BLE scanner(s) issued {total_requests} SCAN_REQ against {total_targets} target(s)."
        if more > 0:
            observation += f" …and {more} more scanner(s)."
        finding: Finding = {
            "observation": observation,
            "severity": "info",
            "confidence": "confirmed",
            "evidence": evidence,
        }

        return envelope_response(
            data={
                "findings": finalize_findings("wireshark_analyze_protocol", pcap_file, [finding], "ble_scan_activity")
                if scanner_rows
                else [],
                "scanners": scanner_rows,
                "summary": "\n".join(summary_lines),
            },
            scope={"pcap_file": pcap_file, "filter": "btle.advertising_header.pdu_type == 0x03"},
            coverage={
                "status": "partial" if truncated else "complete",
                "frames_scanned": rows,
                "scanners": len(scanner_rows),
                "limit": limit,
            },
            truncated=truncated or None,
            warnings=warnings or None,
        )

    async def ble_gatt_timeline(pcap_file: str, limit: int = 100) -> str:
        """[Protocol] ATT/GATT timeline: time, semantic opcode, handle(s), value, with services and handle labels resolved from discovery."""
        result = await client.extract_fields(
            pcap_file,
            [
                "frame.number",
                "frame.time_relative",
                "btatt.opcode",
                "btatt.handle",
                "btatt.value",
                "btatt.handles_info",
                "btl2cap.cid",
                "btatt.group_end_handle",
                "btatt.uuid16",
                "btatt.uuid128",
                "btatt.characteristic_uuid16",
                "btatt.characteristic_uuid128",
                "frame.interface_id",
                "bthci_acl.chandle",
                "bthci_acl.connect_in",
                "btle.access_address",
                "bluetooth.src",
                "bluetooth.dst",
                "frame.p2p_dir",
            ],
            display_filter="btatt",
            limit=limit,
        )
        wrapped = parse_tool_result(result)
        if not wrapped["success"]:
            return normalize_tool_result(wrapped)

        data = wrapped.get("data", "")
        warnings: list[str] = []
        truncated = wrapped.get("truncated") is True
        if truncated:
            warnings.append(f"ATT timeline hit the limit of {limit} events; raise limit for the rest.")

        if not isinstance(data, str) or not data.strip():
            return envelope_response(
                data={
                    "timeline": [],
                    "services": [],
                    "handle_map": {},
                    "handle_maps": {},
                    "operation_summary": {},
                    "summary": (
                        f"{OK} No ATT/GATT (btatt) traffic found in this capture "
                        "(works for over-the-air btle and HCI snoop/H4 sources)."
                    ),
                },
                scope={"pcap_file": pcap_file, "filter": "btatt"},
                coverage={"status": "complete", "events": 0, "limit": limit},
            )

        lines = data.strip().splitlines()
        start_idx = 1 if "frame.number" in lines[0] else 0

        # Parse each row once (split + pad + opcode); both passes below consume
        # this structure so splitting and opcode decoding never run twice.
        parsed_rows: list[tuple[list[str], str, str]] = []
        for line in lines[start_idx:]:
            parts = line.split("\t")
            if len(parts) < 3:  # need frame, time, opcode
                continue
            _pad(parts, 19)
            opcode, operation = _parse_opcode(parts[2])
            parsed_rows.append((parts, opcode, operation))

        # First pass: resolve services and handle -> attribute labels from the
        # discovery exchange itself (Read By Group Type responses give service
        # ranges, Find Information responses give handle/UUID pairs, and Read By
        # Type responses to 0x2803 give characteristic declarations).
        # Resolve each connection/server independently, including request state.
        context_rows: dict[tuple[str, str], list[tuple[list[str], str, str]]] = {}
        for row in parsed_rows:
            context_rows.setdefault(_gatt_context(row[0], row[1]), []).append(row)
        discoveries = {context: _resolve_gatt_discovery(rows) for context, rows in context_rows.items()}
        services = [
            {**service, "connection": connection, "server": server}
            for (connection, server), (resolved_services, _ranges, _labels) in discoveries.items()
            for service in resolved_services
        ]
        handle_maps = {f"{connection}/{server}": labels for (connection, server), (_, _, labels) in discoveries.items()}
        # Preserve the original flat map only when its namespace is unambiguous.
        handle_labels = next(iter(handle_maps.values())) if len(handle_maps) == 1 else {}
        if len(handle_maps) > 1 and (services or any(handle_maps.values())):
            warnings.append(
                "Multiple GATT servers: use handle_maps and each event's connection/server, not handle_map."
            )

        # Second pass: build the annotated timeline.
        timeline: list[dict[str, Any]] = []
        operation_counts: Counter[str] = Counter()
        for parts, opcode, operation in parsed_rows:
            frame_raw = _strip(parts[0])
            frame = int(frame_raw) if frame_raw.isdigit() else None
            try:
                time_value: float | None = float(_strip(_col(parts, 1)))
            except ValueError:
                time_value = None
            handle = _strip(parts[3]) or None
            value = _strip(parts[4]) or None
            handles_info = _strip(parts[5]) or None
            cid = _strip(parts[6]) or None
            connection, server = _gatt_context(parts, opcode)
            _services, service_ranges, labels = discoveries[(connection, server)]
            attribute = labels.get(handle) if handle else None
            service: str | None = None
            handle_ints = _split_handles(handle) if handle else []
            if handle_ints:
                for lo, hi, label in service_ranges:
                    if lo <= handle_ints[0] <= hi:
                        service = label
                        break
            timeline.append(
                {
                    "frame": frame,
                    "time": time_value,
                    "opcode": opcode,
                    "operation": operation,
                    "handle": handle,
                    "value": value,
                    "handles_info": handles_info,
                    "cid": cid,
                    "connection": connection,
                    "server": server,
                    "attribute": attribute,
                    "service": service,
                }
            )
            operation_counts[operation] += 1

        operation_summary = dict(sorted(operation_counts.items(), key=lambda kv: kv[1], reverse=True))
        mix = ", ".join(f"{name} x{count}" for name, count in operation_summary.items())
        summary = f"GATT timeline: {len(timeline)} ATT operation(s). Operation mix: {mix}"
        label_count = sum(len(labels) for labels in handle_maps.values())
        if services or label_count:
            summary += f" Resolved {len(services)} service(s) and {label_count} labeled handle(s)."

        return envelope_response(
            data={
                "timeline": timeline,
                "services": services,
                "handle_map": handle_labels,
                "handle_maps": handle_maps if len(handle_maps) > 1 else {},
                "operation_summary": operation_summary,
                "summary": summary,
            },
            scope={"pcap_file": pcap_file, "filter": "btatt"},
            coverage={
                "status": "partial" if truncated else "complete",
                "events": len(timeline),
                "limit": limit,
                "first_frame": timeline[0]["frame"] if timeline else None,
                "last_frame": timeline[-1]["frame"] if timeline else None,
            },
            truncated=truncated or None,
            warnings=warnings or None,
        )

    async def ble_connections(pcap_file: str, limit: int = 100) -> str:
        """[Protocol] BLE connection lifecycle: HCI sessions per handle with link params, duration, disconnect reasons; over-the-air CONNECT_IND."""
        # One tshark pass covers all three connection sources: reading the capture
        # dominates the cost, so a single process beats three filtered passes.
        conn_filter = "bthci_evt.code == 0x3e || bthci_evt.code == 0x05 || btle.advertising_header.pdu_type == 0x05"
        result = await client.extract_fields(
            pcap_file,
            [
                "frame.number",  # 0
                "frame.time_relative",  # 1
                "bthci_evt.code",  # 2  (HCI rows)
                "bthci_evt.le_meta_subevent",  # 3
                "bthci_evt.connection_handle",  # 4
                "bthci_evt.bd_addr",  # 5
                "bthci_evt.le_peer_address_type",  # 6
                "bthci_evt.le_con_interval",  # 7
                "bthci_evt.le_con_latency",  # 8
                "bthci_evt.le_supv_timeout",  # 9
                "bthci_evt.status",  # 10
                "bthci_evt.reason",  # 11
                "btle.advertising_header.pdu_type",  # 12 (over-the-air rows)
                "btle.initiator_address",  # 13
                "btle.advertising_address",  # 14
                "btle.link_layer_data.access_address",  # 15
                "btle.link_layer_data.crc_init",  # 16
                "btle.link_layer_data.interval",  # 17
                "btle.link_layer_data.timeout",  # 18
                "btle.link_layer_data.channel_map",  # 19
                "frame.interface_id",  # 20: connection handles are controller-local
            ],
            display_filter=conn_filter,
            limit=limit,
        )
        wrapped = parse_tool_result(result)
        if not wrapped["success"]:
            return normalize_tool_result(wrapped)

        data = wrapped.get("data", "")
        warnings: list[str] = []
        truncated = wrapped.get("truncated") is True
        if truncated:
            warnings.append(f"Connection rows hit the limit of {limit}; counts are lower bounds.")

        active_sessions: dict[tuple[str, str], dict[str, Any]] = {}
        sessions: list[dict[str, Any]] = []

        def new_session(interface: str, handle: str) -> dict[str, Any]:
            session: dict[str, Any] = {
                "interface_id": interface,
                "handle": handle,
                "connect": None,
                "updates": [],
                "disconnect": None,
            }
            sessions.append(session)
            return session

        ota_rows: list[dict[str, Any]] = []
        reason_counts: Counter[str] = Counter()
        rows = 0

        if isinstance(data, str) and data.strip():
            lines = data.strip().splitlines()
            start_idx = 1 if "frame.number" in lines[0] else 0
            for line in lines[start_idx:]:
                parts = _pad(line.split("\t"), 21)
                interface = _strip(parts[20]) or "0"
                rows += 1
                code = _strip(parts[2])
                if code == "0x3e":  # HCI LE meta: connection complete or parameter update
                    handle = _strip(parts[4])
                    if not handle:
                        continue
                    subevent = _strip(parts[3])
                    frame_raw = _strip(parts[0])
                    frame = int(frame_raw) if frame_raw.isdigit() else None
                    try:
                        time_value: float | None = float(_strip(parts[1]))
                    except ValueError:
                        time_value = None
                    # 0x01 LE Connection Complete, 0x0a Enhanced V1, 0x29 Enhanced V2
                    # (5.3 controllers like Zephyr SDC report the V2 event).
                    if subevent in ("0x01", "0x0a", "0x29"):
                        interval_raw = _strip(parts[7])
                        timeout_raw = _strip(parts[9])
                        entry = {
                            "handle": handle,
                            "frame": frame,
                            "time": time_value,
                            "subevent": subevent,
                            "peer_address": _strip(parts[5]) or None,
                            "peer_address_type": _strip(parts[6]) or None,
                            "interval": interval_raw or None,
                            "interval_ms": round(int(interval_raw) * 1.25, 2) if interval_raw.isdigit() else None,
                            "latency": _strip(parts[8]) or None,
                            "supervision_timeout": timeout_raw or None,
                            "supervision_timeout_ms": int(timeout_raw) * 10 if timeout_raw.isdigit() else None,
                            "status": _strip(parts[10]) or None,
                        }
                        # A handle can be reused immediately after disconnect.
                        # Keep each attempt/session as a separate historical row;
                        # failed attempts must not replace a still-active session.
                        session = new_session(interface, handle)
                        session["connect"] = entry
                        if entry["status"] == "0x00":
                            active_sessions[(interface, handle)] = session
                    elif subevent == "0x03":  # LE Connection Update Complete
                        update_interval = _strip(parts[7])
                        update = {
                            "frame": frame,
                            "time": time_value,
                            "interval": update_interval or None,
                            "latency": _strip(parts[8]) or None,
                            "supervision_timeout": _strip(parts[9]) or None,
                            "interval_ms": round(int(update_interval) * 1.25, 2) if update_interval.isdigit() else None,
                        }
                        key = (interface, handle)
                        if key not in active_sessions:
                            active_sessions[key] = new_session(interface, handle)
                        active_sessions[key]["updates"].append(update)
                elif code == "0x05":  # HCI Disconnect Complete: reason attribution
                    handle = _strip(parts[4])
                    if not handle:
                        continue
                    reason_name = _reason_name(parts[11])
                    reason_counts[reason_name] += 1
                    try:
                        time_value = float(_strip(parts[1]))
                    except ValueError:
                        time_value = None
                    # Closing removes the active association, not the history.
                    closed_session = active_sessions.pop((interface, handle), None)
                    session = closed_session if closed_session is not None else new_session(interface, handle)
                    session["disconnect"] = {"reason": reason_name, "time": time_value}
                    connect_time = session["connect"]["time"] if session["connect"] else None
                    if connect_time is not None and time_value is not None:
                        session["session_duration_s"] = round(time_value - connect_time, 6)
                elif _strip(parts[12]) == "0x05":  # over-the-air CONNECT_IND
                    initiator = _strip(parts[13])
                    advertiser = _strip(parts[14])
                    if not initiator and not advertiser:
                        continue
                    frame_raw = _strip(parts[0])
                    frame = int(frame_raw) if frame_raw.isdigit() else None
                    try:
                        time_value = float(_strip(parts[1]))
                    except ValueError:
                        time_value = None
                    interval_raw = _strip(parts[17])
                    timeout_raw = _strip(parts[18])
                    ota_rows.append(
                        {
                            "frame": frame,
                            "time": time_value,
                            "initiator_address": initiator or None,
                            "advertiser_address": advertiser or None,
                            "access_address": _strip(parts[15]) or None,
                            "crc_init": _strip(parts[16]) or None,
                            "interval": interval_raw or None,
                            "interval_ms": round(int(interval_raw) * 1.25, 2) if interval_raw.isdigit() else None,
                            "timeout": timeout_raw or None,
                            "timeout_ms": int(timeout_raw) * 10 if timeout_raw.isdigit() else None,
                            "channel_map": _strip(parts[19]) or None,
                        }
                    )

        connection_rows: list[dict[str, Any]] = []
        for session in sessions:
            row: dict[str, Any] = {
                "handle": session["handle"],
                "interface_id": session["interface_id"],
                "connect": session.get("connect"),
            }
            row["parameter_updates"] = session.get("updates", [])
            row["disconnect"] = session.get("disconnect")
            row["session_duration_s"] = session.get("session_duration_s")
            connection_rows.append(row)

        if not connection_rows and not ota_rows:
            return envelope_response(
                data={
                    "connections": [],
                    "over_air_connects": [],
                    "reason_summary": {},
                    "summary": (
                        f"{OK} No BLE connection activity found. HCI captures expose LE Connection/Disconnect "
                        "events; over-the-air captures expose CONNECT_IND frames."
                    ),
                },
                scope={"pcap_file": pcap_file, "filters": [conn_filter]},
                coverage={
                    "status": "partial" if truncated else "complete",
                    "connection_rows": 0,
                    "sessions": 0,
                    "ota_rows": 0,
                    "limit": limit,
                },
                truncated=truncated or None,
                warnings=warnings or None,
            )

        summary_lines: list[str] = []
        if connection_rows:
            summary_lines.append(f"BLE connections (HCI): {len(connection_rows)} session(s):")
            for row in connection_rows:
                connect = row["connect"]
                if connect is not None:
                    duration = row["session_duration_s"]
                    duration_text = f", {duration:.3f}s session" if duration is not None else ", no disconnect event"
                    interval_text = f", interval {connect['interval_ms']}ms" if connect.get("interval_ms") else ""
                    peer_text = connect.get("peer_address") or "?"
                    summary_lines.append(f"- handle {row['handle']} -> {peer_text}{interval_text}{duration_text}")
                disconnect = row["disconnect"]
                if disconnect is not None:
                    summary_lines.append(f"  disconnected: {disconnect['reason']}")
            if reason_counts:
                mix = ", ".join(f"{name} x{count}" for name, count in reason_counts.most_common())
                summary_lines.append(f"Disconnect reasons: {mix}")
        if ota_rows:
            summary_lines.append(f"Over-the-air CONNECT_IND: {len(ota_rows)} connection(s):")
            for row in ota_rows[:10]:
                summary_lines.append(
                    f"- {row['initiator_address']} -> {row['advertiser_address']} "
                    f"(AA {row['access_address']}, interval {row['interval_ms']}ms, CRCInit {row['crc_init']})"
                )
            if len(ota_rows) > 10:
                summary_lines.append(f"  …and {len(ota_rows) - 10} more")

        return envelope_response(
            data={
                "connections": connection_rows,
                "over_air_connects": ota_rows,
                "reason_summary": dict(reason_counts),
                "summary": "\n".join(summary_lines),
            },
            scope={"pcap_file": pcap_file, "filters": [conn_filter]},
            coverage={
                "status": "partial" if truncated else "complete",
                "connection_rows": rows,
                "sessions": len(connection_rows),
                "ota_rows": len(ota_rows),
                "limit": limit,
            },
            truncated=truncated or None,
            warnings=warnings or None,
        )

    async def ble_pairing(pcap_file: str, limit: int = 100) -> str:
        """[Protocol] BLE pairing analysis: SMP exchange timeline, pairing method inference, distributed key material (LTK/IRK/EDIV), failures."""
        result = await client.extract_fields(
            pcap_file,
            [
                "frame.number",
                "frame.time_relative",
                "btsmp.opcode",
                "btsmp.io_capability",
                "btsmp.oob_data_flags",
                "btsmp.authreq",
                "btsmp.mitm_flag",
                "btsmp.sc_flag",
                "btsmp.bonding_flags",
                "btsmp.max_enc_key_size",
                "btsmp.initiator_key_distribution",
                "btsmp.responder_key_distribution",
                "btsmp.reason",
                "btsmp.long_term_key",
                "btsmp.ediv",
                "btsmp.id_resolving_key",
            ],
            display_filter="btsmp",
            limit=limit,
        )
        wrapped = parse_tool_result(result)
        if not wrapped["success"]:
            return normalize_tool_result(wrapped)

        data = wrapped.get("data", "")
        warnings: list[str] = []
        truncated = wrapped.get("truncated") is True
        if truncated:
            warnings.append(f"SMP timeline hit the limit of {limit} events; raise limit for the rest.")

        if not isinstance(data, str) or not data.strip():
            return envelope_response(
                data={
                    "timeline": [],
                    "pairing_method": None,
                    "key_material": {},
                    "findings": [],
                    "summary": f"{OK} No BLE pairing (SMP) traffic found in this capture.",
                },
                scope={"pcap_file": pcap_file, "filter": "btsmp"},
                coverage={"status": "complete", "events": 0, "limit": limit},
            )

        lines = data.strip().splitlines()
        start_idx = 1 if "frame.number" in lines[0] else 0

        timeline: list[dict[str, Any]] = []
        pairing_request: dict[str, Any] | None = None
        pairing_response: dict[str, Any] | None = None
        key_material: dict[str, Any] = {}
        failures: list[dict[str, Any]] = []
        for line in lines[start_idx:]:
            parts = line.split("\t")
            if len(parts) < 3:
                continue
            # SMP opcodes share the byte space with ATT but have their own table.
            opcode = _strip(_col(parts, 2))
            try:
                operation = SMP_OPCODE_NAMES.get(int(opcode, 16), f"Unknown ({opcode})")
            except ValueError:
                operation = f"Unknown ({opcode})"
            frame_raw = _strip(_col(parts, 0))
            frame = int(frame_raw) if frame_raw.isdigit() else None
            try:
                time_value: float | None = float(_strip(_col(parts, 1)))
            except ValueError:
                time_value = None
            event: dict[str, Any] = {"frame": frame, "time": time_value, "opcode": opcode, "operation": operation}

            if opcode in ("0x01", "0x02"):  # Pairing Request / Response
                params = {
                    "io_capability": _strip(_col(parts, 3)),
                    "oob": _strip(_col(parts, 4)),
                    "authreq": _strip(_col(parts, 5)),
                    "mitm": _strip(_col(parts, 6)),
                    "sc": _strip(_col(parts, 7)),
                    "bonding": _strip(_col(parts, 8)),
                    "max_key_size": _strip(_col(parts, 9)),
                    "key_distribution": _strip(_col(parts, 10 if opcode == "0x01" else 11)),
                }
                event["parameters"] = params
                if opcode == "0x01":
                    pairing_request = params
                else:
                    pairing_response = params
            elif opcode == "0x05":  # Pairing Failed
                reason = _smp_fail_reason(_col(parts, 12))
                event["reason"] = reason
                failures.append({"frame": frame, "reason": reason})
            elif opcode == "0x06":  # Encryption Information: LTK
                ltk = _strip(_col(parts, 13))
                if ltk:
                    key_material["ltk"] = ltk
            elif opcode == "0x07":  # Master Identification: EDIV (+ rand, not a filterable field set here)
                ediv = _strip(_col(parts, 14))
                if ediv:
                    key_material["ediv"] = ediv
            elif opcode == "0x08":  # Identity Information: IRK
                irk = _strip(_col(parts, 15))
                if irk:
                    key_material["irk"] = irk
            timeline.append(event)

        method, method_note = _infer_pairing_method(pairing_request, pairing_response)

        findings: list[Finding] = []
        if method == "Just Works":
            finding: Finding = {
                "observation": (
                    f"Pairing uses Just Works ({method_note}) — no authenticated MITM protection. "
                    "A passive attacker that captures this exchange and later recovers the LTK can decrypt all traffic."
                ),
                "severity": "low",
                "confidence": "likely",
                "evidence": [
                    FindingEvidence(
                        field="btsmp.io_capability",
                        filter="btsmp.opcode == 0x01 or btsmp.opcode == 0x02",
                        description="Pairing request/response IO capabilities and authreq flags",
                        value=(
                            f"initiator io={pairing_request['io_capability'] if pairing_request else '?'} "
                            f"mitm={pairing_request['mitm'] if pairing_request else '?'}; "
                            f"responder io={pairing_response['io_capability'] if pairing_response else '?'} "
                            f"mitm={pairing_response['mitm'] if pairing_response else '?'}"
                        ),
                        frame=timeline[0]["frame"] if timeline else None,
                    )
                ],
                "next_steps": [
                    "Confirm with the device vendor whether a stronger association model (passkey, OOB, NFC) is possible.",
                ],
            }
            findings.append(finding)
        for failure in failures:
            fail_finding: Finding = {
                "observation": f"Pairing failed: {failure['reason']}.",
                "severity": "info",
                "confidence": "confirmed",
                "evidence": [
                    FindingEvidence(
                        field="btsmp.reason",
                        filter=f"frame.number == {failure['frame']}",
                        description="Pairing Failed reason code",
                        value=failure["reason"],
                        frame=failure["frame"],
                    )
                ],
            }
            findings.append(fail_finding)

        distributed = _key_distribution(pairing_request["key_distribution"]) if pairing_request else []
        summary_lines = [f"BLE pairing: {len(timeline)} SMP message(s)."]
        if pairing_request or pairing_response:
            summary_lines.append(f"Pairing method: {method} ({method_note}).")
        if distributed:
            summary_lines.append(f"Initiator key distribution: {', '.join(distributed)}.")
        if key_material:
            summary_lines.append(
                f"Distributed key material captured: {', '.join(sorted(key_material))} (values in key_material)."
            )
        if failures:
            summary_lines.append(f"{len(failures)} pairing failure(s).")

        return envelope_response(
            data={
                "timeline": timeline,
                "pairing_request": pairing_request,
                "pairing_response": pairing_response,
                "pairing_method": {"method": method, "note": method_note},
                "key_material": key_material,
                "findings": finalize_findings("wireshark_analyze_protocol", pcap_file, findings, "ble_pairing"),
                "summary": "\n".join(summary_lines),
            },
            scope={"pcap_file": pcap_file, "filter": "btsmp"},
            coverage={"status": "partial" if truncated else "complete", "events": len(timeline), "limit": limit},
            truncated=truncated or None,
            warnings=warnings or None,
        )

    return {
        "ble_devices": ble_devices,
        "ble_scan_activity": ble_scan_activity,
        "ble_gatt_timeline": ble_gatt_timeline,
        "ble_connections": ble_connections,
        "ble_pairing": ble_pairing,
    }
