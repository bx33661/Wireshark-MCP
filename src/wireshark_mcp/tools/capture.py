from mcp.server.fastmcp import FastMCP
from ..tshark.client import TSharkClient
import os

def register_capture_tools(mcp: FastMCP, client: TSharkClient):
    
    @mcp.tool()
    async def wireshark_list_interfaces() -> str:
        """
        List available network interfaces for capture.
        
        Returns:
            List of interfaces with index, name, and status
            
        Example:
            wireshark_list_interfaces()
        """
        return await client.list_interfaces()

    @mcp.tool()
    async def wireshark_capture(interface: str, output_file: str, 
                              duration_seconds: int = 10, packet_count: int = 0,
                              capture_filter: str = "", ring_buffer: str = "") -> str:
        """
        Capture live network traffic.
        
        Args:
            interface: Interface index or name (from list_interfaces)
            output_file: Absolute path for output .pcap file
            duration_seconds: Capture duration (0 = unlimited)
            packet_count: Stop after N packets (0 = unlimited)
            capture_filter: BPF filter (e.g. "host 192.168.1.1 and port 80")
            ring_buffer: Ring buffer config (e.g. "filesize:1024,files:5")
            
        Returns:
            Success message with file path or error JSON
            
        Errors:
            ExecutionError: Capture failed
            
        Example:
            wireshark_capture("eth0", "/tmp/capture.pcap", duration_seconds=30, capture_filter="port 80")
        """
        res = await client.capture_packets(interface, output_file, duration_seconds, 
                                         packet_count, capture_filter, ring_buffer=ring_buffer)
        
        if os.path.exists(output_file):
            return f"Capture saved to {output_file}\n{res}"
        
        return f"Capture completed but file not found:\n{res}"

    @mcp.tool()
    async def wireshark_filter_save(input_file: str, output_file: str, display_filter: str) -> str:
        """
        Filter packets from a pcap and save to a new file.
        
        Args:
            input_file: Source pcap file
            output_file: Destination pcap file
            display_filter: Wireshark display filter (e.g. "http.request.method == POST")
            
        Returns:
            Success message or error JSON
            
        Errors:
            FileNotFound: input_file does not exist
            ExecutionError: Filter failed
            
        Example:
            wireshark_filter_save("big.pcap", "http_only.pcap", "http")
        """
        return await client.filter_and_save(input_file, output_file, display_filter)
