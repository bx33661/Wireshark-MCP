"""IoT protocol analysis tools for Wireshark MCP."""

import logging
from typing import Any

from ..tshark.client import TSharkClient
from .envelope import normalize_tool_result, parse_tool_result, success_response
from .formatting import INFO

logger = logging.getLogger("wireshark_mcp")


def make_contextual_iot_tools(client: TSharkClient) -> list[tuple[str, Any]]:
    """Create contextual IoT protocol tools."""

    async def wireshark_analyze_coap(pcap_file: str, limit: int = 100) -> str:
        """[IoT] Analyze CoAP sessions (methods, URIs, response codes, tokens, observe notifications)."""
        fields = [
            "ip.src",
            "ip.dst",
            "udp.srcport",
            "udp.dstport",
            "coap.type",
            "coap.code",
            "coap.opt.uri_path",
            "coap.token",
        ]
        result = await client.extract_fields(
            pcap_file,
            fields,
            display_filter="coap",
            limit=limit,
        )
        wrapped = parse_tool_result(result)
        if not wrapped["success"]:
            return normalize_tool_result(wrapped)

        data = wrapped.get("data", "")
        if not isinstance(data, str) or len(data.strip()) < 20:
            return success_response("No CoAP traffic found in this capture.")

        output_parts = ["CoAP Traffic Summary"]

        lines = data.strip().splitlines()
        methods: dict[str, int] = {}
        uri_paths: set[str] = set()
        tokens: set[str] = set()

        for line in lines[1:]:
            parts = line.split("\t")
            if len(parts) >= 8:
                code = parts[5].strip().strip('"')
                uri_path = parts[6].strip().strip('"')
                token = parts[7].strip().strip('"')

                if code:
                    methods[code] = methods.get(code, 0) + 1
                if uri_path:
                    uri_paths.add(uri_path)
                if token:
                    tokens.add(token)

        output_parts.append(f"Total CoAP packets: {len(lines) - 1}")
        output_parts.append(f"Unique tokens: {len(tokens)}")

        if methods:
            output_parts.append("\nMethod/response code distribution:")
            for code, count in sorted(methods.items(), key=lambda x: x[1], reverse=True):
                output_parts.append(f"  {code}: {count}")

        if uri_paths:
            output_parts.append(f"\n{INFO} URI paths observed: {', '.join(sorted(uri_paths))}")

        output_parts.append("\n" + data)

        return success_response("\n".join(output_parts))

    async def wireshark_analyze_mqtt_deep(pcap_file: str, limit: int = 100) -> str:
        """[IoT] Deep MQTT 5.0 analysis (topics, QoS, properties, client IDs, auth, session state)."""
        fields = [
            "ip.src",
            "ip.dst",
            "mqtt.msgtype",
            "mqtt.topic",
            "mqtt.clientid",
            "mqtt.ver",
            "mqtt.prop.id",
        ]
        result = await client.extract_fields(
            pcap_file,
            fields,
            display_filter="mqtt",
            limit=limit,
        )
        wrapped = parse_tool_result(result)
        if not wrapped["success"]:
            return normalize_tool_result(wrapped)

        data = wrapped.get("data", "")
        if not isinstance(data, str) or len(data.strip()) < 20:
            return success_response("No MQTT traffic found in this capture.")

        output_parts = ["MQTT Deep Analysis"]

        lines = data.strip().splitlines()
        msg_types: dict[str, int] = {}
        topics: set[str] = set()
        client_ids: set[str] = set()
        versions: set[str] = set()

        for line in lines[1:]:
            parts = line.split("\t")
            if len(parts) >= 7:
                msgtype = parts[2].strip().strip('"')
                topic = parts[3].strip().strip('"')
                clientid = parts[4].strip().strip('"')
                ver = parts[5].strip().strip('"')

                if msgtype:
                    msg_types[msgtype] = msg_types.get(msgtype, 0) + 1
                if topic:
                    topics.add(topic)
                if clientid:
                    client_ids.add(clientid)
                if ver:
                    versions.add(ver)

        output_parts.append(f"Total MQTT packets: {len(lines) - 1}")

        if msg_types:
            output_parts.append("\nMessage type distribution:")
            for mtype, count in sorted(msg_types.items(), key=lambda x: x[1], reverse=True):
                output_parts.append(f"  Type {mtype}: {count}")

        if client_ids:
            output_parts.append(f"\n{INFO} Client IDs: {', '.join(sorted(client_ids))}")

        if topics:
            output_parts.append(f"{INFO} Topics: {', '.join(sorted(topics))}")

        if versions:
            output_parts.append(f"{INFO} Protocol versions: {', '.join(sorted(versions))}")

        output_parts.append("\n" + data)

        # Extract SUBSCRIBE requests separately
        sub_fields = [
            "ip.src",
            "mqtt.topic",
            "mqtt.sub.qos",
        ]
        sub_result = await client.extract_fields(
            pcap_file,
            sub_fields,
            display_filter="mqtt.msgtype == 8",
            limit=limit,
        )
        sub_wrapped = parse_tool_result(sub_result)
        if sub_wrapped["success"]:
            sub_data = sub_wrapped.get("data", "")
            if isinstance(sub_data, str) and len(sub_data.strip()) > 20:
                output_parts.append(f"\n{INFO} SUBSCRIBE Requests (msgtype 8):")
                output_parts.append(sub_data)

        return success_response("\n".join(output_parts))

    async def wireshark_analyze_zigbee(pcap_file: str, limit: int = 100) -> str:
        """[IoT] Analyze Zigbee network traffic (NWK layer, APS profiles, ZCL clusters and commands)."""
        fields = [
            "zbee_nwk.src",
            "zbee_nwk.dst",
            "zbee_nwk.frame_type",
            "zbee_aps.profile",
            "zbee_aps.cluster",
            "zbee_zcl.cmd.id",
        ]
        result = await client.extract_fields(
            pcap_file,
            fields,
            display_filter="zbee_nwk",
            limit=limit,
        )
        wrapped = parse_tool_result(result)
        if not wrapped["success"]:
            return normalize_tool_result(wrapped)

        data = wrapped.get("data", "")
        if not isinstance(data, str) or len(data.strip()) < 20:
            return success_response("No Zigbee traffic found in this capture.")

        output_parts = ["Zigbee Traffic Summary"]

        lines = data.strip().splitlines()
        frame_types: dict[str, int] = {}
        profiles: set[str] = set()
        clusters: set[str] = set()

        for line in lines[1:]:
            parts = line.split("\t")
            if len(parts) >= 6:
                frame_type = parts[2].strip().strip('"')
                profile = parts[3].strip().strip('"')
                cluster = parts[4].strip().strip('"')

                if frame_type:
                    frame_types[frame_type] = frame_types.get(frame_type, 0) + 1
                if profile:
                    profiles.add(profile)
                if cluster:
                    clusters.add(cluster)

        output_parts.append(f"Total Zigbee packets: {len(lines) - 1}")

        if frame_types:
            output_parts.append("\nFrame type distribution:")
            for ftype, count in sorted(frame_types.items(), key=lambda x: x[1], reverse=True):
                output_parts.append(f"  {ftype}: {count}")

        if profiles:
            output_parts.append(f"\n{INFO} APS profiles: {', '.join(sorted(profiles))}")

        if clusters:
            output_parts.append(f"{INFO} ZCL clusters: {', '.join(sorted(clusters))}")

        output_parts.append("\n" + data)

        return success_response("\n".join(output_parts))

    return [
        ("wireshark_analyze_coap", wireshark_analyze_coap),
        ("wireshark_analyze_mqtt_deep", wireshark_analyze_mqtt_deep),
        ("wireshark_analyze_zigbee", wireshark_analyze_zigbee),
    ]
