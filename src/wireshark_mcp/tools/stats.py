from mcp.server.fastmcp import FastMCP

from ..tshark.client import TSharkClient
from .envelope import normalize_tool_result, parse_tool_result, success_response
from .formatting import summarize_tabular


def _maybe_summarize(raw_result: str, max_rows: int = 50) -> str:
    """Apply tabular summarization to successful string results."""
    wrapped = parse_tool_result(raw_result)
    if wrapped["success"] and isinstance(wrapped.get("data"), str):
        return success_response(summarize_tabular(wrapped["data"], max_rows))
    return normalize_tool_result(raw_result)


def register_stats_tools(mcp: FastMCP, client: TSharkClient):

    @mcp.tool()
    async def wireshark_stats_protocol_hierarchy(pcap_file: str) -> str:
        """[PHS] Protocol hierarchy statistics showing distribution of protocols in the capture."""
        return normalize_tool_result(await client.get_protocol_stats(pcap_file))

    @mcp.tool()
    async def wireshark_stats_endpoints(pcap_file: str, type: str = "ip") -> str:
        """[Endpoints] List all endpoints and traffic stats. type: 'eth'|'ip'|'ipv6'|'tcp'|'udp'|'sctp'|'wlan'."""
        return _maybe_summarize(await client.get_endpoints(pcap_file, type))

    @mcp.tool()
    async def wireshark_stats_conversations(pcap_file: str, type: str = "ip") -> str:
        """[Conversations] Communication pairs and stats. type: 'eth'|'ip'|'ipv6'|'tcp'|'udp'|'sctp'|'wlan'."""
        return _maybe_summarize(await client.get_conversations(pcap_file, type))

    @mcp.tool()
    async def wireshark_stats_io_graph(pcap_file: str, interval: int = 1) -> str:
        """[I/O Graph] Traffic volume over time. interval: bucket size in seconds."""
        return _maybe_summarize(await client.get_io_graph(pcap_file, interval))

    @mcp.tool()
    async def wireshark_stats_expert_info(pcap_file: str) -> str:
        """[Expert Info] Automatic anomaly detection: retransmissions, errors, warnings, protocol issues."""
        return _maybe_summarize(await client.get_expert_info(pcap_file), max_rows=80)

    @mcp.tool()
    async def wireshark_stats_service_response_time(pcap_file: str, protocol: str = "http") -> str:
        """[SRT] Service response time statistics. protocol: 'http'|'dns'|'smb' etc."""
        return _maybe_summarize(await client.get_service_response_time(pcap_file, protocol))
