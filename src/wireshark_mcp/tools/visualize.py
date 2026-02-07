from mcp.server.fastmcp import FastMCP
from ..tshark.client import TSharkClient
import re
import math
from typing import List, Tuple, Dict, Any

def _parse_io_graph(output: str) -> List[Tuple[float, int]]:
    """
    Parse output of `tshark -z io,stat,interval`.
    Returns list of (time_start, packet_count).
    """
    data = []
    lines = output.splitlines()
    
    for line in lines:
        line = line.strip()
        # Skip headers/footers
        if "=|" in line or "|---" in line or "Duration" in line or "Interval:" in line:
             continue
        
        # Regex to find float range and int
        # Matches: "000.000-001.000     154" or "|  0.0-  1.0|   20|"
        # Group 1: Start Time, Group 2: Count
        match = re.search(r"([\d\.]+)\s*-\s*[\d\.]+\s+[|]?\s*(\d+)", line)
        if match:
            try:
                t = float(match.group(1))
                count = int(match.group(2))
                data.append((t, count))
            except ValueError:
                continue
    return data

def _render_ascii_bar_chart(data: List[Tuple[float, int]], height: int = 15) -> str:
    if not data:
        return "No traffic data found."
        
    max_val = max(d[1] for d in data) if data else 0
    if max_val == 0:
        return "No packets found in this capture."
        
    # Scaling
    scale = max_val / height if max_val > height else 1
    
    # Build chart rows (top to bottom)
    lines = []
    lines.append(f"[Traffic I/O Graph] Max: {max_val} pkts/interval")
    
    # Y-axis + Bars
    for h in range(height, -1, -1):
        threshold = h * scale
        row = f"{str(int(threshold)).rjust(5)} | "
        for _, count in data:
            if count >= threshold and count > 0: # Only draw if count > 0
                if count >= threshold + (scale * 0.5): 
                     row += "█" # Full block
                else:
                     row += "▄" # Half block
            elif h == 0:
                row += "_" # Baseline
            else:
                row += " "
        lines.append(row)
        
    # X-axis Labels (Start and End time)
    start_time = data[0][0]
    duration = (data[1][0] - data[0][0]) * len(data) if len(data) > 1 else 0
    end_time = start_time + duration
    
    # Footer
    footer = " " * 8
    # Try to align labels
    footer += f"{start_time}s"
    spacer_len = max(0, len(data) - len(str(start_time)) - len(str(end_time)) - 2)
    footer += " " * spacer_len
    footer += f"{end_time}s"
    lines.append(footer)
    
    total_pkts = sum(d[1] for d in data)
    avg_rate = total_pkts / duration if duration > 0 else 0
    lines.append(f"\nStats: Total Packets: {total_pkts} | Avg Rate: {avg_rate:.2f} pkts/s")
    
    return "\n".join(lines)

def _parse_protocol_hierarchy(output: str) -> Dict[str, Any]:
    """Parse tshark -z io,phs output into a nested dict."""
    lines = output.splitlines()
    # Find root indentation logic
    # TShark output usually starts with the protocol name. hierarchy is by indentation.
    # We need a dummy root to hold everything.
    root = {"name": "root", "frames": 0, "bytes": 0, "children": []}
    stack = [(root, -1)] # (node, indent_level)
    
    for line in lines:
        if "frames:bytes" in line or "Filter:" in line or "Statistics" in line or "====" in line:
            continue
        if not line.strip(): continue
        
        # Calculate indent: number of leading spaces
        indent = len(line) - len(line.lstrip())
        
        # Regex: protocol name can contain dots, dashes, underscores
        # "ip                                     100:150000"
        match = re.search(r"([a-zA-Z0-9\-\._]+)\s+(\d+):(\d+)", line)
        if match:
            name = match.group(1)
            frames = int(match.group(2))
            bytes_val = int(match.group(3))
            
            node = {
                "name": name, 
                "frames": frames, 
                "bytes": bytes_val, 
                "children": []
            }
            
            # Find parent: parent indent must be less than current indent
            while stack and stack[-1][1] >= indent:
                stack.pop()
            
            if stack:
                parent = stack[-1][0]
                parent["children"].append(node)
                stack.append((node, indent))
            else:
                 # Should not happen if we have a root, but as fallback
                 root["children"].append(node)
                 stack.append((node, indent))
                 
    return root

def _render_ascii_tree(node: Dict[str, Any], total_frames: int, prefix: str = "", is_last: bool = True) -> List[str]:
    lines = []
    
    if node["name"] != "root":
        percent = (node["frames"] / total_frames * 100) if total_frames > 0 else 0
        connector = "└── " if is_last else "├── "
        
        # Format: └── ip (99.5%) [100 pkts]
        line = f"{prefix}{connector}{node['name']} ({percent:.1f}%) [{node['frames']} pkts]"
        lines.append(line)
        
        prefix += "    " if is_last else "│   "
        
    children = node["children"]
    count = len(children)
    for i, child in enumerate(children):
        lines.extend(_render_ascii_tree(child, total_frames, prefix, i == count - 1))
        
    return lines

def register_visualize_tools(mcp: FastMCP, client: TSharkClient):

    @mcp.tool()
    async def wireshark_plot_traffic(pcap_file: str, interval: int = 1) -> str:
        """
        [Visualization] Generate an ASCII bar chart of traffic volume (I/O Graph).
        Useful for identifying traffic spikes, DDoS start times, or silence patterns.
        
        Args:
            pcap_file: Path to pcap file
            interval: Time interval bucket in seconds (default: 1)
            
        Returns:
            String containing the ASCII chart
        """
        raw_output = await client.get_io_graph_data(pcap_file, interval)
        if raw_output.strip().startswith("{") and "error" in raw_output:
             return raw_output 
             
        data = _parse_io_graph(raw_output)
        return _render_ascii_bar_chart(data)

    @mcp.tool()
    async def wireshark_plot_protocols(pcap_file: str) -> str:
        """
        [Visualization] Generate an ASCII tree of protocol hierarchy.
        Shows the distribution of protocols (e.g., how much is HTTP vs DNS).
        
        Args:
            pcap_file: Path to pcap file
            
        Returns:
            String containing the ASCII tree
        """
        raw_output = await client.get_protocol_stats_data(pcap_file)
        if raw_output.strip().startswith("{") and "error" in raw_output:
             return raw_output
             
        root = _parse_protocol_hierarchy(raw_output)
        
        # Calculate total frames from top-level children
        total_frames = sum(c["frames"] for c in root["children"]) if root["children"] else 0
        if total_frames == 0 and root["children"]:
             # If root sum is 0 (unlikely), try max of children
             total_frames = max(c["frames"] for c in root["children"])
             
        tree_lines = _render_ascii_tree(root, total_frames)
        
        if not tree_lines:
            return "No protocol hierarchy data found."
            
        header = "[Protocol Hierarchy Statistics]\n"
        return header + "\n".join(tree_lines)
