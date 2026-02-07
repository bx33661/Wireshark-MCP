from mcp.server.fastmcp import FastMCP
from ..tshark.client import TSharkClient

def register_stats_tools(mcp: FastMCP, client: TSharkClient):

    @mcp.tool()
    async def wireshark_stats_protocol_hierarchy(pcap_file: str) -> str:
        """
        [PHS] Get Protocol Hierarchy Statistics.
        Shows distribution of protocols in the capture.
        
        Returns:
            Tree-structured protocol statistics or JSON error
            
        Errors:
            FileNotFound: pcap_file does not exist
            
        Example:
            wireshark_stats_protocol_hierarchy("traffic.pcap")
        """
        return await client.get_protocol_stats(pcap_file)

    @mcp.tool()
    async def wireshark_stats_endpoints(pcap_file: str, type: str = "ip") -> str:
        """
        [Endpoints] List all endpoints and their traffic stats.
        
        Args:
            type: Protocol type - 'eth', 'ip', 'ipv6', 'tcp', 'udp', 'sctp', 'wlan'
            
        Returns:
            Endpoint statistics table or JSON error
            
        Errors:
            FileNotFound: pcap_file does not exist
            InvalidParameter: Invalid protocol type
            
        Example:
            wireshark_stats_endpoints("traffic.pcap", type="tcp")
        """
        return await client.get_endpoints(pcap_file, type)

    @mcp.tool()
    async def wireshark_stats_conversations(pcap_file: str, type: str = "ip") -> str:
        """
        [Conversations] Show communication pairs and their stats.
        
        Args:
            type: Protocol type - 'eth', 'ip', 'ipv6', 'tcp', 'udp', 'sctp', 'wlan'
            
        Returns:
            Conversation statistics table or JSON error
            
        Errors:
            FileNotFound: pcap_file does not exist
            InvalidParameter: Invalid protocol type
            
        Example:
            wireshark_stats_conversations("traffic.pcap", type="tcp")
        """
        return await client.get_conversations(pcap_file, type)

    @mcp.tool()
    async def wireshark_stats_io_graph(pcap_file: str, interval: int = 1) -> str:
        """
        [I/O Graph] Traffic volume over time.
        
        Args:
            interval: Time interval in seconds (default: 1)
            
        Returns:
            Time-series traffic statistics or JSON error
            
        Errors:
            FileNotFound: pcap_file does not exist
            
        Example:
            wireshark_stats_io_graph("traffic.pcap", interval=5)
        """
        return await client.get_io_graph(pcap_file, interval)

    @mcp.tool()
    async def wireshark_stats_expert_info(pcap_file: str) -> str:
        """
        [Expert Info] Automatic anomaly detection.
        Detects: retransmissions, errors, warnings, protocol issues.
        
        Returns:
            Expert analysis results or JSON error
            
        Errors:
            FileNotFound: pcap_file does not exist
            
        Example:
            wireshark_stats_expert_info("traffic.pcap")
        """
        return await client.get_expert_info(pcap_file)

    @mcp.tool()
    async def wireshark_stats_service_response_time(pcap_file: str, protocol: str = "http") -> str:
        """
        [SRT] Service Response Time statistics.
        
        Args:
            protocol: Application protocol - 'http', 'dns', 'smb', etc.
            
        Returns:
            Response time statistics or JSON error
            
        Errors:
            FileNotFound: pcap_file does not exist
            
        Example:
            wireshark_stats_service_response_time("web.pcap", protocol="http")
        """
        return await client.get_service_response_time(pcap_file, protocol)
