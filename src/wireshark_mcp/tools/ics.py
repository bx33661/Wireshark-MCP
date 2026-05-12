"""ICS/SCADA protocol analysis tools for Wireshark MCP."""

import logging
from typing import Any

from ..tshark.client import TSharkClient
from .envelope import normalize_tool_result, parse_tool_result, success_response
from .formatting import INFO, WARN

logger = logging.getLogger("wireshark_mcp")


def make_contextual_ics_tools(client: TSharkClient) -> list[tuple[str, Any]]:
    """Create contextual ICS/SCADA protocol tools for the stable contextual catalog."""

    async def wireshark_analyze_modbus(pcap_file: str, limit: int = 100) -> str:
        """[ICS] Analyze Modbus TCP traffic (function codes, unit IDs, transactions, write operations)."""
        fields = [
            "ip.src",
            "ip.dst",
            "tcp.srcport",
            "tcp.dstport",
            "mbtcp.trans_id",
            "mbtcp.unit_id",
            "modbus.func_code",
            "modbus.exception_code",
        ]
        result = await client.extract_fields(
            pcap_file,
            fields,
            display_filter="modbus",
            limit=limit,
        )
        wrapped = parse_tool_result(result)
        if not wrapped["success"]:
            return normalize_tool_result(wrapped)

        data = wrapped.get("data", "")
        if not isinstance(data, str) or len(data.strip()) < 20:
            return success_response("No Modbus TCP traffic found in this capture.")

        output_parts = ["Modbus TCP Traffic Summary"]

        # Parse function codes for statistics
        lines = data.strip().splitlines()
        func_codes: dict[str, int] = {}
        exception_count = 0
        unit_ids: set[str] = set()

        for line in lines[1:]:
            parts = line.split("\t")
            if len(parts) >= 8:
                unit_id = parts[5].strip().strip('"')
                func_code = parts[6].strip().strip('"')
                exception_code = parts[7].strip().strip('"')

                if unit_id:
                    unit_ids.add(unit_id)
                if func_code:
                    func_codes[func_code] = func_codes.get(func_code, 0) + 1
                if exception_code and exception_code != "":
                    exception_count += 1

        output_parts.append(f"Total Modbus packets: {len(lines) - 1}")
        output_parts.append(f"Unique unit IDs: {len(unit_ids)}")

        if func_codes:
            output_parts.append("\nFunction code distribution:")
            for code, count in sorted(func_codes.items(), key=lambda x: x[1], reverse=True):
                output_parts.append(f"  FC {code}: {count}")

        if exception_count > 0:
            output_parts.append(f"\n{WARN} Exception responses: {exception_count}")

        output_parts.append("\n" + data)

        # Extract write operations separately
        write_fields = [
            "ip.src",
            "ip.dst",
            "modbus.func_code",
            "modbus.reference_num",
            "modbus.data",
        ]
        write_result = await client.extract_fields(
            pcap_file,
            write_fields,
            display_filter="modbus.func_code in {5 6 15 16}",
            limit=limit,
        )
        write_wrapped = parse_tool_result(write_result)
        if write_wrapped["success"]:
            write_data = write_wrapped.get("data", "")
            if isinstance(write_data, str) and len(write_data.strip()) > 20:
                output_parts.append(f"\n{INFO} Write Operations (FC 5/6/15/16):")
                output_parts.append(write_data)

        return success_response("\n".join(output_parts))

    async def wireshark_analyze_s7comm(pcap_file: str, limit: int = 100) -> str:
        """[ICS] Analyze Siemens S7comm sessions (function codes, data areas, DB access, PLC operations)."""
        fields = [
            "ip.src",
            "ip.dst",
            "s7comm.param.func",
            "s7comm.param.item.area",
            "s7comm.param.item.dbnum",
            "s7comm.resp.data",
        ]
        result = await client.extract_fields(
            pcap_file,
            fields,
            display_filter="s7comm",
            limit=limit,
        )
        wrapped = parse_tool_result(result)
        if not wrapped["success"]:
            return normalize_tool_result(wrapped)

        data = wrapped.get("data", "")
        if not isinstance(data, str) or len(data.strip()) < 20:
            return success_response("No S7comm traffic found in this capture.")

        output_parts = ["S7comm Traffic Summary"]

        lines = data.strip().splitlines()
        func_codes: dict[str, int] = {}
        areas: set[str] = set()
        db_numbers: set[str] = set()

        for line in lines[1:]:
            parts = line.split("\t")
            if len(parts) >= 6:
                func_code = parts[2].strip().strip('"')
                area = parts[3].strip().strip('"')
                dbnum = parts[4].strip().strip('"')

                if func_code:
                    func_codes[func_code] = func_codes.get(func_code, 0) + 1
                if area:
                    areas.add(area)
                if dbnum:
                    db_numbers.add(dbnum)

        output_parts.append(f"Total S7comm packets: {len(lines) - 1}")

        if func_codes:
            output_parts.append("\nFunction code distribution:")
            for code, count in sorted(func_codes.items(), key=lambda x: x[1], reverse=True):
                output_parts.append(f"  FC {code}: {count}")

        if areas:
            output_parts.append(f"\n{INFO} Data areas accessed: {', '.join(sorted(areas))}")

        if db_numbers:
            output_parts.append(f"{INFO} DB numbers accessed: {', '.join(sorted(db_numbers))}")

        output_parts.append("\n" + data)

        return success_response("\n".join(output_parts))

    async def wireshark_analyze_dnp3(pcap_file: str, limit: int = 100) -> str:
        """[ICS] Analyze DNP3 SCADA sessions (function codes, objects, internal indications)."""
        fields = [
            "ip.src",
            "ip.dst",
            "dnp3.al.func",
            "dnp3.al.obj",
            "dnp3.al.iin",
            "dnp3.src",
            "dnp3.dst",
        ]
        result = await client.extract_fields(
            pcap_file,
            fields,
            display_filter="dnp3",
            limit=limit,
        )
        wrapped = parse_tool_result(result)
        if not wrapped["success"]:
            return normalize_tool_result(wrapped)

        data = wrapped.get("data", "")
        if not isinstance(data, str) or len(data.strip()) < 20:
            return success_response("No DNP3 traffic found in this capture.")

        output_parts = ["DNP3 Traffic Summary"]

        lines = data.strip().splitlines()
        func_codes: dict[str, int] = {}
        iin_flags: set[str] = set()
        stations: set[str] = set()

        for line in lines[1:]:
            parts = line.split("\t")
            if len(parts) >= 7:
                func_code = parts[2].strip().strip('"')
                iin = parts[4].strip().strip('"')
                src_addr = parts[5].strip().strip('"')
                dst_addr = parts[6].strip().strip('"')

                if func_code:
                    func_codes[func_code] = func_codes.get(func_code, 0) + 1
                if iin:
                    iin_flags.add(iin)
                if src_addr:
                    stations.add(src_addr)
                if dst_addr:
                    stations.add(dst_addr)

        output_parts.append(f"Total DNP3 packets: {len(lines) - 1}")

        if func_codes:
            output_parts.append("\nFunction code distribution:")
            for code, count in sorted(func_codes.items(), key=lambda x: x[1], reverse=True):
                output_parts.append(f"  FC {code}: {count}")

        if stations:
            output_parts.append(f"\n{INFO} DNP3 stations: {', '.join(sorted(stations))}")

        if iin_flags:
            output_parts.append(f"{INFO} IIN flags observed: {', '.join(sorted(iin_flags))}")

        output_parts.append("\n" + data)

        return success_response("\n".join(output_parts))

    return [
        ("wireshark_analyze_modbus", wireshark_analyze_modbus),
        ("wireshark_analyze_s7comm", wireshark_analyze_s7comm),
        ("wireshark_analyze_dnp3", wireshark_analyze_dnp3),
    ]
