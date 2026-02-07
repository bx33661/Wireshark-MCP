import subprocess
import json
import os
import shutil
import asyncio
from typing import List, Dict, Any, Optional, Union
from pathlib import Path

class TSharkClient:
    """Production-grade TShark wrapper with validation and error handling."""
    
    # Protocol whitelists
    VALID_ENDPOINT_TYPES = {"eth", "ip", "ipv6", "tcp", "udp", "sctp", "wlan"}
    VALID_EXPORT_PROTOCOLS = {"http", "smb", "tftp", "imf", "dicom"}
    VALID_STREAM_PROTOCOLS = {"tcp", "udp", "tls", "http", "http2"}
    
    def __init__(self, tshark_path: str = "tshark"):
        self.tshark_path = shutil.which(tshark_path) or tshark_path
        self.capinfos_path = shutil.which("capinfos")
        self.mergecap_path = shutil.which("mergecap")
        self.editcap_path = shutil.which("editcap")
        self._version = None

    # --- Validation Methods ---
    
    def _validate_file(self, filepath: str) -> Dict[str, Any]:
        """Validate file exists and is readable."""
        if not filepath:
            return {"success": False, "error": {"type": "InvalidParameter", "message": "File path cannot be empty"}}
        
        path = Path(filepath)
        if not path.exists():
            return {"success": False, "error": {"type": "FileNotFound", "message": f"File not found: {filepath}"}}
        
        if not path.is_file():
            return {"success": False, "error": {"type": "InvalidParameter", "message": f"Path is not a file: {filepath}"}}
            
        return {"success": True}
    
    def _validate_protocol(self, protocol: str, valid_set: set) -> Dict[str, Any]:
        """Validate protocol against whitelist."""
        if protocol.lower() not in valid_set:
            return {
                "success": False, 
                "error": {
                    "type": "InvalidParameter",
                    "message": f"Invalid protocol: {protocol}",
                    "details": f"Valid options: {', '.join(sorted(valid_set))}"
                }
            }
        return {"success": True}

    # --- Core Methods ---

    async def check_capabilities(self) -> Dict[str, Any]:
        """Check availability and version of all Wireshark suite tools."""
        async def get_version(tool_path):
            if not tool_path:
                return {"available": False}
            try:
                proc = await asyncio.create_subprocess_exec(
                    tool_path, "-v",
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE
                )
                stdout, _ = await proc.communicate()
                version_line = stdout.decode('utf-8').split('\n')[0]
                # Extract version number (e.g., "TShark 4.0.3" -> "4.0.3")
                version = version_line.split()[-1] if version_line else "unknown"
                return {"available": True, "version": version}
            except:
                return {"available": True, "version": "unknown"}
        
        return {
            "success": True,
            "data": {
                "tshark": await get_version(self.tshark_path),
                "capinfos": await get_version(self.capinfos_path),
                "mergecap": await get_version(self.mergecap_path),
                "editcap": await get_version(self.editcap_path)
            }
        }

    async def list_interfaces(self) -> str:
        """List interfaces (-D)."""
        return await self._run_command([self.tshark_path, "-D"])

    # --- Capture Management ---

    async def capture_packets(self, interface: str, output_file: str, 
                            duration: int = 0, packet_count: int = 0,
                            capture_filter: str = "", ring_buffer: str = "") -> str:
        """Capture packets with validation."""
        cmd = [self.tshark_path, "-i", interface, "-w", output_file]
        
        if capture_filter:
            cmd.extend(["-f", capture_filter])
        
        if ring_buffer:
            for part in ring_buffer.split(","):
                cmd.extend(["-b", part.strip()])
        
        if duration > 0:
            cmd.extend(["-a", f"duration:{duration}"])
        if packet_count > 0:
            cmd.extend(["-c", str(packet_count)])
            
        return await self._run_command(cmd)

    # --- Statistics ---


    async def get_protocol_stats(self, pcap_file: str) -> str:
        """Protocol Hierarchy (-z io,phs)."""
        validation = self._validate_file(pcap_file)
        if not validation["success"]:
            return json.dumps(validation)
            
        return await self._run_command([self.tshark_path, "-r", pcap_file, "-q", "-z", "io,phs"])

    async def get_protocol_stats_data(self, pcap_file: str) -> str:
        """Protocol Hierarchy raw output for parsing."""
        # Use same command, but we need the raw string to parse in the visualizer.
        # The existing get_protocol_stats returns exactly what we need (the raw text output from tshark).
        # We can reuse it, or if we want to parse it into JSON here, we could.
        # For now, let's keep it simple: the visualizer will parse the text output of `tshark -z io,phs`.
        # So we might not need a new method if the existing one returns the raw string.
        # Let's check get_io_graph.
        return await self.get_protocol_stats(pcap_file)


    async def get_endpoints(self, pcap_file: str, type: str = "ip") -> str:
        """Endpoints (-z endpoints,type)."""
        validation = self._validate_file(pcap_file)
        if not validation["success"]:
            return json.dumps(validation)
        
        proto_validation = self._validate_protocol(type, self.VALID_ENDPOINT_TYPES)
        if not proto_validation["success"]:
            return json.dumps(proto_validation)
            
        return await self._run_command([self.tshark_path, "-r", pcap_file, "-q", "-z", f"endpoints,{type}"])

    async def get_conversations(self, pcap_file: str, type: str = "ip") -> str:
        """Conversations (-z conv,type)."""
        validation = self._validate_file(pcap_file)
        if not validation["success"]:
            return json.dumps(validation)
            
        proto_validation = self._validate_protocol(type, self.VALID_ENDPOINT_TYPES)
        if not proto_validation["success"]:
            return json.dumps(proto_validation)
            
        return await self._run_command([self.tshark_path, "-r", pcap_file, "-q", "-z", f"conv,{type}"])


    async def get_io_graph(self, pcap_file: str, interval: int = 1) -> str:
        """I/O Graphs (-z io,stat,interval)."""
        validation = self._validate_file(pcap_file)
        if not validation["success"]:
            return json.dumps(validation)
            
        return await self._run_command([
            self.tshark_path, "-r", pcap_file, "-q", 
            "-z", f"io,stat,{interval}"
        ])

    async def get_io_graph_data(self, pcap_file: str, interval: int = 1) -> str:
        """Raw I/O Graph data for visualization."""
        return await self.get_io_graph(pcap_file, interval)


    async def get_service_response_time(self, pcap_file: str, protocol: str = "http") -> str:
        """Service Response Time (-z proto,tree)."""
        validation = self._validate_file(pcap_file)
        if not validation["success"]:
            return json.dumps(validation)
            
        return await self._run_command([
            self.tshark_path, "-r", pcap_file, "-q", 
            "-z", f"{protocol},tree"
        ])

    async def get_expert_info(self, pcap_file: str) -> str:
        """Expert Information (-z expert)."""
        validation = self._validate_file(pcap_file)
        if not validation["success"]:
            return json.dumps(validation)
            
        return await self._run_command([self.tshark_path, "-r", pcap_file, "-q", "-z", "expert"])

    # --- JSON Packet Reading ---

    async def read_packets_json(self, pcap_file: str, limit: int = 100, 
                               display_filter: str = "", offset: int = 0) -> str:
        """
        Read packets in JSON format (-T json).
        Returns structured packet data for AI parsing.
        """
        validation = self._validate_file(pcap_file)
        if not validation["success"]:
            return json.dumps(validation)
        
        cmd = [self.tshark_path, "-r", pcap_file, "-T", "json"]
        
        if display_filter:
            cmd.extend(["-Y", display_filter])
        
        if limit > 0:
            cmd.extend(["-c", str(limit + offset)])
        
        result = await self._run_command(cmd)
        
        if offset > 0:
            try:
                packets = json.loads(result)
                if isinstance(packets, list):
                    packets = packets[offset:]
                    result = json.dumps(packets)
            except json.JSONDecodeError:
                pass
        
        return result

    async def get_packet_list(self, pcap_file: str, limit: int = 20, offset: int = 0, 
                            display_filter: str = "", custom_columns: List[str] = None) -> str:
        """
        Get summary list of packets (like Wireshark's top pane).
        If custom_columns provided, uses those instead of default [No, Time, Src, Dst, Proto, Len, Info].
        """
        validation = self._validate_file(pcap_file)
        if not validation["success"]:
            return json.dumps(validation)
        
        if custom_columns:
             fields = custom_columns
             # Always ensure frame.number is there if we want to reference it? 
             # Actually, the user might just want specific fields.
             # But for context/linking, frame.number is good. 
             # However, let's respect the user's list.
        else:
            fields = [
                "frame.number",
                "_ws.col.Time",
                "_ws.col.Source",
                "_ws.col.Destination",
                "_ws.col.Protocol",
                "_ws.col.Length",
                "_ws.col.Info"
            ]
        
        cmd = [self.tshark_path, "-r", pcap_file, "-T", "fields"]
        for f in fields:
            cmd.extend(["-e", f])
            
        if display_filter:
            cmd.extend(["-Y", display_filter])
        
        cmd.extend(["-E", "header=y", "-E", "separator=/t", "-E", "quote=d", "-E", "occurrence=f"])
        
        return await self._run_command(cmd, limit_lines=limit, offset_lines=offset)

    async def get_packet_details(self, pcap_file: str, frame_number: int, included_layers: List[str] = None) -> str:
        """
        Get full JSON details for a single packet.
        Optionally filter to specific layers using included_layers (TShark -j).
        """
        validation = self._validate_file(pcap_file)
        if not validation["success"]:
            return json.dumps(validation)
            
        cmd = [
            self.tshark_path, "-r", pcap_file, 
            "-Y", f"frame.number == {frame_number}",
            "-T", "json"
        ]
        
        if included_layers:
            # -j "layer1 layer2"
            filter_str = " ".join(included_layers)
            cmd.extend(["-j", filter_str])
        
        # In tshark read mode (-r), -c limits the *input* packets processed.
        # If the target frame is #100, "-c 1" stops at frame #1 and never finds #100.
        
        return await self._run_command(cmd)

    async def get_packet_bytes(self, pcap_file: str, frame_number: int) -> str:
        """
        Get standard Hex/ASCII dump of a packet (Packet Bytes view).
        """
        validation = self._validate_file(pcap_file)
        if not validation["success"]:
            return json.dumps(validation)
            
        cmd = [
            self.tshark_path, "-r", pcap_file, 
            "-Y", f"frame.number == {frame_number}",
            "-x"  # Hex/ASCII dump
        ]
        
        return await self._run_command(cmd)

    # --- Extraction ---

    async def extract_fields(self, pcap_file: str, fields: List[str], 
                           display_filter: str = "", separator: str = "\t",
                           limit: int = 100, offset: int = 0) -> str:
        """Extract fields (-T fields -e ...)."""
        validation = self._validate_file(pcap_file)
        if not validation["success"]:
            return json.dumps(validation)
        
        cmd = [self.tshark_path, "-r", pcap_file, "-T", "fields"]
        for f in fields:
            cmd.extend(["-e", f])
        if display_filter:
            cmd.extend(["-Y", display_filter])
        
        cmd.extend(["-E", "header=y", "-E", f"separator={separator}", "-E", "quote=d"])
        
        return await self._run_command(cmd, limit_lines=limit, offset_lines=offset)

    async def export_objects(self, pcap_file: str, protocol: str, dest_dir: str) -> str:
        """Export Objects (--export-objects protocol,dest_dir)."""
        validation = self._validate_file(pcap_file)
        if not validation["success"]:
            return json.dumps(validation)
        
        proto_validation = self._validate_protocol(protocol, self.VALID_EXPORT_PROTOCOLS)
        if not proto_validation["success"]:
            return json.dumps(proto_validation)
        
        os.makedirs(dest_dir, exist_ok=True)
        cmd = [
            self.tshark_path, "-r", pcap_file, 
            "--export-objects", f"{protocol},{dest_dir}"
        ]
        return await self._run_command(cmd)

    async def search_packet_contents(self, pcap_file: str, match_pattern: str, search_type: str = "string", 
                                   limit: int = 50, scope: str = "bytes") -> str:
        """
        Search for packets.
        scope="bytes" -> searches raw payload (frame contains)
        scope="details" -> searches decoded text (frame matches)
        """
        validation = self._validate_file(pcap_file)
        if not validation["success"]:
            return json.dumps(validation)
        
        # Construct specific display filter for search
        # TShark filter syntax:
        # contains: searches raw bytes (can be string or hex)
        # matches: searches text representation (regex)
        
        display_filter = ""
        
        if scope == "bytes":
             # "frame contains" works for string or hex
             if search_type == "hex":
                 # 00:11:22
                 display_filter = f'frame contains {match_pattern}'
             else:
                 # Standard string search in bytes
                 # Escape quotes
                 safe_pattern = match_pattern.replace('"', '\\"')
                 display_filter = f'frame contains "{safe_pattern}"'
                 
        elif scope == "details":
             # "frame matches" uses PCRE on the text layer
             # We treat match_pattern as regex if search_type == "regex", else escape it
             if search_type == "regex":
                 display_filter = f'frame matches "{match_pattern}"'
             else:
                 import re
                 safe_pattern = re.escape(match_pattern)
                 display_filter = f'frame matches "{safe_pattern}"'
        
        elif scope == "filter":
             # Raw Wireshark display filter (e.g. "http.response.code == 200")
             display_filter = match_pattern
                 
        else:
             return json.dumps({"success": False, "error": f"Invalid scope: {scope}. Use 'bytes' or 'details'."})

        
        # We want to return the LIST of matching packets
        return await self.get_packet_list(pcap_file, limit=limit, display_filter=display_filter)

    async def follow_stream(self, pcap_file: str, stream_index: int, 
                          protocol: str = "tcp", mode: str = "ascii",
                          limit_lines: int = 500, offset_lines: int = 0,
                          search_content: str = "") -> str:
        """
        Follow Stream (-z follow).
        Supports pagination (limit_lines, offset_lines) and searching (grep).
        """
        validation = self._validate_file(pcap_file)
        if not validation["success"]:
            return json.dumps(validation)
        
        proto_validation = self._validate_protocol(protocol, self.VALID_STREAM_PROTOCOLS)
        if not proto_validation["success"]:
            return json.dumps(proto_validation)
        
        # TShark follows stream and outputs pure text/hex
        output = await self._run_command([
            self.tshark_path, "-r", pcap_file, "-q", 
            "-z", f"follow,{protocol},{mode},{stream_index}"
        ], limit_lines=0, offset_lines=0)
        
        # Ideally we would pipe to grep/head/tail to avoid loading 100MB into memory.
        # But _run_command loads memory anyway.
        # For now, let's just implement the logic in Python on the string result.
        
        lines = output.splitlines()
        
        # Filter if search_content provided
        if search_content:
            lines = [line for line in lines if search_content in line]
            if not lines:
                return f"No occurrences of '{search_content}' found in stream {stream_index}."
        
        total_lines = len(lines)
        
        # Pagination
        if offset_lines > 0:
            lines = lines[offset_lines:]
            
        truncated = False
        if limit_lines > 0 and len(lines) > limit_lines:
            lines = lines[:limit_lines]
            truncated = True
            
        final_output = "\n".join(lines)
        
        if truncated:
             final_output += f"\n\n[Displaying {limit_lines} lines. {total_lines - (offset_lines + limit_lines)} more lines available. Use offset={offset_lines + limit_lines} to see more.]"
             
        return final_output

    async def decrypt_ssl(self, pcap_file: str, keylog_file: str) -> str:
        """Decrypt SSL/TLS using a Keylog file."""
        validation = self._validate_file(pcap_file)
        if not validation["success"]:
            return json.dumps(validation)
        
        keylog_validation = self._validate_file(keylog_file)
        if not keylog_validation["success"]:
            return json.dumps(keylog_validation)
        
        cmd = [
            self.tshark_path, "-r", pcap_file,
            "-o", f"tls.keylog_file:{keylog_file}",
            "-q", "-z", "expert"
        ]
        return await self._run_command(cmd)

    # --- File Utilities ---

    async def get_file_info(self, pcap_file: str) -> str:
        """Capinfos: Get file metadata."""
        validation = self._validate_file(pcap_file)
        if not validation["success"]:
            return json.dumps(validation)
        
        if not self.capinfos_path:
            return json.dumps({
                "success": False,
                "error": {"type": "ToolNotFound", "message": "capinfos tool not found"}
            })
        
        return await self._run_command([self.capinfos_path, pcap_file])

    async def merge_pcap_files(self, output_file: str, input_files: List[str]) -> str:
        """Mergecap: Merge multiple pcaps."""
        if not self.mergecap_path:
            return json.dumps({
                "success": False,
                "error": {"type": "ToolNotFound", "message": "mergecap tool not found"}
            })
        
        # Validate all input files
        for f in input_files:
            validation = self._validate_file(f)
            if not validation["success"]:
                return json.dumps(validation)
        
        cmd = [self.mergecap_path, "-w", output_file] + input_files
        return await self._run_command(cmd)

    async def filter_and_save(self, input_file: str, output_file: str, display_filter: str) -> str:
        """
        Filter packets and save to new file.
        Uses tshark -r input -Y filter -w output.
        """
        validation = self._validate_file(input_file)
        if not validation["success"]:
            return json.dumps(validation)
        
        cmd = [self.tshark_path, "-r", input_file, "-Y", display_filter, "-w", output_file]
        result = await self._run_command(cmd)
        
        if os.path.exists(output_file):
            return f"Filtered packets saved to {output_file}\n{result}"
        return result


    # --- Helper ---

    async def _run_command(self, cmd: List[str], limit_lines: int = 0, offset_lines: int = 0, timeout: int = 30) -> str:
        """Run command with error handling and timeout."""
        # print(f"Executing: {' '.join(cmd)}", file=sys.stderr)
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL  # Prevent hanging if tool expects input
            )
            
            try:
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            except asyncio.TimeoutError:
                try:
                    proc.kill()
                except ProcessLookupError:
                    pass
                return json.dumps({
                    "success": False,
                    "error": {
                        "type": "TimeoutError",
                        "message": f"Command timed out after {timeout} seconds",
                        "details": f"Command: {' '.join(cmd)}"
                    }
                })
            
            output = stdout.decode('utf-8', errors='replace')
            error = stderr.decode('utf-8', errors='replace')
            
            if proc.returncode != 0:
                return json.dumps({
                    "success": False,
                    "error": {
                        "type": "ExecutionError",
                        "message": f"Command failed with exit code {proc.returncode}",
                        "details": error or output
                    }
                })
            
            lines = output.splitlines()
            total_lines = len(lines)
            
            if offset_lines > 0:
                lines = lines[offset_lines:]
            
            truncated = False
            if limit_lines > 0 and len(lines) > limit_lines:
                lines = lines[:limit_lines]
                truncated = True
            
            final_output = "\n".join(lines)
            
            # Add metadata if truncated
            if truncated:
                final_output += f"\n\n[Truncated: showing {limit_lines} of {total_lines} lines]"
            
            if error and not truncated:
                final_output += f"\n[Stderr]: {error}"
            
            return final_output
            
        except Exception as e:
            return json.dumps({
                "success": False,
                "error": {
                    "type": "ExecutionError",
                    "message": "Command execution failed",
                    "details": str(e)
                }
            })
