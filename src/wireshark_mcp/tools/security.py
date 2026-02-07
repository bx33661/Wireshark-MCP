from mcp.server.fastmcp import FastMCP
from ..tshark.client import TSharkClient
import urllib.request
import os
import json

URLHAUS_URL = "https://urlhaus.abuse.ch/downloads/text/"
THREAT_CACHE_FILE = "urlhaus_cache.txt"

def register_security_tools(mcp: FastMCP, client: TSharkClient):

    @mcp.tool()
    async def wireshark_check_threats(pcap_file: str) -> str:
        """
        [Security] Check captured IPs against URLhaus threat intelligence.
        Downloads and caches threat feed from abuse.ch.
        
        Returns:
            Threat analysis summary or JSON error
            
        Errors:
            FileNotFound: pcap_file does not exist
            DependencyError: Failed to extract IPs
            NetworkError: Failed to download threat feed
            
        Example:
            wireshark_check_threats("suspicious.pcap")
        """
        # Extract unique IPs
        ips_str = await client.extract_fields(pcap_file, ["ip.src", "ip.dst"], separator=",", limit=10000)
        
        # Handle upstream errors from extract_fields
        try:
            error_obj = json.loads(ips_str)
            if not error_obj.get("success", True):
                return json.dumps({
                    "success": False,
                    "error": {
                        "type": "DependencyError",
                        "message": "Failed to extract IPs from pcap",
                        "upstream_error": error_obj.get("error")
                    }
                })
        except json.JSONDecodeError:
            pass  # Not JSON, continue processing
        
        unique_ips = set()
        for line in ips_str.splitlines()[1:]:
            parts = line.split(",")
            for p in parts:
                if p.strip() and not p.startswith("["): 
                    unique_ips.add(p.strip().strip('"'))
        
        if not unique_ips:
            return json.dumps({"success": True, "data": {"ips_checked": 0, "threats": []}})

        try:
            if not os.path.exists(THREAT_CACHE_FILE):
                with urllib.request.urlopen(URLHAUS_URL) as response:
                    data = response.read().decode('utf-8')
                    with open(THREAT_CACHE_FILE, 'w', encoding='utf-8') as f:
                        f.write(data)
            
            with open(THREAT_CACHE_FILE, 'r', encoding='utf-8') as f:
                threat_data = f.read()
            
            matches = [ip for ip in unique_ips if ip in threat_data]
            
            return json.dumps({
                "success": True,
                "data": {
                    "ips_checked": len(unique_ips),
                    "threats_found": len(matches),
                    "malicious_ips": matches
                }
            })
            
        except Exception as e:
            return json.dumps({
                "success": False, 
                "error": {
                    "type": "NetworkError", 
                    "message": "Failed to fetch threat feed", 
                    "details": str(e)
                }
            })

    @mcp.tool()
    async def wireshark_extract_credentials(pcap_file: str) -> str:
        """
        [Security] Scan for plaintext credentials in traffic.
        Detects: HTTP Basic Auth, FTP passwords, Telnet login attempts.
        
        Returns:
            Credential findings summary or JSON error
            
        Errors:
            FileNotFound: pcap_file does not exist
            DependencyError: Field extraction failed
            
        Example:
            wireshark_extract_credentials("insecure.pcap")
        """
        findings = []
        
        http_auth = await client.extract_fields(pcap_file, ["http.authbasic"], "http.authbasic", limit=50)
        if not http_auth.startswith('{"success"') and len(http_auth.strip()) > 20:
            findings.append(f"HTTP Basic Auth:\n{http_auth[:500]}")
            
        ftp_pass = await client.extract_fields(pcap_file, ["ftp.request.arg"], "ftp.request.command == PASS", limit=50)
        if not ftp_pass.startswith('{"success"') and len(ftp_pass.strip()) > 20:
            findings.append(f"FTP Passwords:\n{ftp_pass[:500]}")

        telnet_data = await client.search_packet_contents(pcap_file, "login", "string", limit=10)
        if not telnet_data.startswith('{"success"') and ("Login" in telnet_data or "Password" in telnet_data):
             findings.append("Possible Telnet/cleartext authentication detected (use follow_stream to analyze)")

        if not findings:
            return "No obvious plaintext credentials found."
            
        return "\n\n---\n".join(findings)
