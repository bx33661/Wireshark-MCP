import json
from unittest.mock import AsyncMock

import pytest
from conftest import MockTSharkClient

from wireshark_mcp.tools.envelope import envelope_response, error_response, parse_tool_result, success_response
from wireshark_mcp.tools.threat import make_threat_tools


class TestDetectPortScan:
    """Tests for port scan detection queries and candidate signal analysis."""

    @pytest.mark.asyncio
    async def test_syn_scan_query(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.extract_fields(
            "test.pcap",
            ["ip.src", "ip.dst", "tcp.dstport"],
            display_filter="tcp.flags.syn == 1 and tcp.flags.ack == 0",
            limit=10000,
        )
        assert "tcp.flags.syn == 1" in result
        assert "tcp.flags.ack == 0" in result

    @pytest.mark.asyncio
    async def test_synfin_check(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.get_packet_list(
            "test.pcap",
            limit=10,
            display_filter="tcp.flags.syn == 1 and tcp.flags.fin == 1",
        )
        assert "tcp.flags.fin == 1" in result

    @pytest.mark.asyncio
    async def test_null_scan_check(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.get_packet_list(
            "test.pcap",
            limit=10,
            display_filter="tcp.flags == 0",
        )
        assert "tcp.flags == 0" in result

    @pytest.mark.asyncio
    async def test_detect_port_scan_candidate_behavior(self) -> None:
        mock_client = AsyncMock()
        # Simulate SYN packets from 192.168.1.100 to 20 different ports
        syn_rows = ["frame.number\tip.src\tip.dst\ttcp.dstport"]
        for p in range(20):
            syn_rows.append(f"{p + 1}\t192.168.1.100\t10.0.0.1\t{8000 + p}")

        mock_client.extract_fields.side_effect = [
            success_response("\n".join(syn_rows)),  # SYN
            success_response(""),  # SYN-FIN
            success_response(""),  # NULL
        ]

        tools = dict(make_threat_tools(mock_client))
        raw = await tools["wireshark_detect_port_scan"]("test.pcap", threshold=15)
        parsed = parse_tool_result(raw)

        assert parsed["success"] is True
        data = parsed["data"]
        assert len(data["findings"]) == 1
        finding = data["findings"][0]
        assert finding["severity"] == "high"
        assert finding["confidence"] == "candidate"
        assert "192.168.1.100" in finding["evidence"][0]["value"]
        assert "20 ports" in finding["evidence"][0]["value"]


class TestDetectDnsTunnel:
    """Tests for DNS tunnel detection queries and signal calibration."""

    @pytest.mark.asyncio
    async def test_dns_query_extraction(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.extract_fields(
            "test.pcap",
            ["ip.src", "dns.qry.name", "dns.qry.type", "dns.resp.len"],
            display_filter="dns",
            limit=5000,
        )
        assert "-e dns.qry.name" in result
        assert "-e dns.qry.type" in result

    @pytest.mark.asyncio
    async def test_detect_dns_tunnel_candidate_signals(self) -> None:
        mock_client = AsyncMock()
        # Build queries: long query (>50) and >20 subdomains
        dns_rows = ["frame.number\tip.src\tdns.qry.name\tdns.qry.type"]
        for i in range(25):
            sub = f"sub{i:03d}dataexfilpayloadwithlongrandomstring1234567890abcdef"
            dns_rows.append(f"{i + 1}\t192.168.1.50\t{sub}.tunnel.example.com\tTXT")

        mock_client.extract_fields.return_value = success_response("\n".join(dns_rows))

        tools = dict(make_threat_tools(mock_client))
        raw = await tools["wireshark_detect_dns_tunnel"]("test.pcap")
        parsed = parse_tool_result(raw)

        assert parsed["success"] is True
        data = parsed["data"]
        assert len(data["findings"]) == 1
        finding = data["findings"][0]
        assert finding["severity"] == "high"
        # Confidence is CANDIDATE, NOT an uncalibrated "HIGH probability"
        assert finding["confidence"] == "candidate"
        assert finding["constraints"]["scanned"] == 25
        assert finding["constraints"]["limit"] == 5000
        assert "Candidate DNS tunneling" in finding["observation"]

    @pytest.mark.asyncio
    async def test_detect_dns_tunnel_clean_traffic(self) -> None:
        mock_client = AsyncMock()
        dns_rows = [
            "frame.number\tip.src\tdns.qry.name\tdns.qry.type",
            "1\t192.168.1.1\twww.google.com\tA",
            "2\t192.168.1.1\tapi.github.com\tA",
        ]
        mock_client.extract_fields.return_value = success_response("\n".join(dns_rows))

        tools = dict(make_threat_tools(mock_client))
        raw = await tools["wireshark_detect_dns_tunnel"]("test.pcap")
        parsed = parse_tool_result(raw)

        assert parsed["success"] is True
        finding = parsed["data"]["findings"][0]
        assert finding["severity"] == "info"
        assert finding["confidence"] == "confirmed"
        assert "No DNS tunneling candidate indicators" in finding["observation"]


class TestDetectDosAttack:
    """Tests for DoS detection queries and rate windowing."""

    @pytest.mark.asyncio
    async def test_syn_flood_check(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.get_packet_list(
            "test.pcap",
            limit=10000,
            display_filter="tcp.flags.syn == 1 and tcp.flags.ack == 0",
        )
        assert "tcp.flags.syn == 1" in result

    @pytest.mark.asyncio
    async def test_icmp_flood_check(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.get_packet_list(
            "test.pcap",
            limit=10000,
            display_filter="icmp",
        )
        assert "icmp" in result

    @pytest.mark.asyncio
    async def test_dns_amplification_check(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.get_packet_list(
            "test.pcap",
            limit=1000,
            display_filter="dns.flags.response == 1 and udp.length > 512",
        )
        assert "udp.length > 512" in result

    @pytest.mark.asyncio
    async def test_dos_single_sided_capture_warning(self) -> None:
        mock_client = AsyncMock()
        # 100 SYNs within 1 second, but 0 SYN-ACKs!
        syn_rows = ["frame.number\tframe.time_relative\tip.src\tip.dst"]
        for i in range(100):
            syn_rows.append(f"{i + 1}\t{i * 0.01:.2f}\t192.168.1.10\t10.0.0.1")

        mock_client.extract_fields.side_effect = [
            success_response("\n".join(syn_rows)),  # SYN
            success_response(""),  # SYN-ACK (0 responses)
            success_response(""),  # ICMP
            success_response(""),  # UDP
            success_response(""),  # DNS amp
        ]

        tools = dict(make_threat_tools(mock_client))
        raw = await tools["wireshark_detect_dos_attack"]("test.pcap")
        parsed = parse_tool_result(raw)

        assert parsed["success"] is True
        # Must flag single-sided warning!
        assert parsed["warnings"] is not None
        assert any("single-sided" in w.lower() for w in parsed["warnings"])
        finding = parsed["data"]["findings"][0]
        assert finding["constraints"]["single_sided"] is True

    @pytest.mark.asyncio
    async def test_dos_subquery_failure_returns_partial_coverage_and_no_false_confirmed(self) -> None:
        mock_client = AsyncMock()
        # SYN succeeds but no packets; remaining subqueries FAIL
        mock_client.extract_fields.side_effect = [
            success_response(""),  # SYN (empty)
            error_response("Failed to extract SYN-ACK fields"),  # SYN-ACK
            error_response("Failed to extract ICMP fields"),  # ICMP
            error_response("Failed to extract UDP fields"),  # UDP
            error_response("Failed to extract DNS amp fields"),  # DNS amp
        ]

        tools = dict(make_threat_tools(mock_client))
        raw = await tools["wireshark_detect_dos_attack"]("test.pcap")
        parsed = parse_tool_result(raw)

        assert parsed["success"] is True
        # Critical: coverage must be partial, NOT complete!
        assert parsed["coverage"]["status"] == "partial"
        assert "failed_checks" in parsed["coverage"]
        assert len(parsed["coverage"]["failed_checks"]) == 4

        # Critical: confidence must NOT be confirmed!
        finding = parsed["data"]["findings"][0]
        assert finding["confidence"] != "confirmed"
        assert "Partial DoS/DDoS evaluation" in finding["observation"]
        assert "checks failed to execute" in finding["observation"]

    @pytest.mark.asyncio
    async def test_dos_synack_failure_skips_ratio_and_does_not_assert_false_ratio_evidence(self) -> None:
        mock_client = AsyncMock()
        # 100 SYNs across 1.0s window
        syn_rows = "\n".join(f"{i}\t{i * 0.01:.2f}\t10.0.0.1\t10.0.0.2" for i in range(1, 101))
        mock_client.extract_fields.side_effect = [
            success_response(syn_rows),  # 1. 100 SYNs
            error_response("SYN-ACK query crashed"),  # 2. SYN-ACK fails!
            success_response(""),  # 3. ICMP
            success_response(""),  # 4. UDP
            success_response(""),  # 5. DNS amp
        ]

        tools = dict(make_threat_tools(mock_client))
        raw = await tools["wireshark_detect_dos_attack"]("test.pcap")
        parsed = parse_tool_result(raw)

        assert parsed["success"] is True
        assert parsed["coverage"]["status"] == "partial"
        assert "SYN-ACK response analysis" in parsed["coverage"]["failed_checks"]

        # Critical: finding evidence must NOT report 100 SYNs vs 0 SYN-ACKs or Ratio 100.0
        raw_text = json.dumps(parsed)
        assert "Ratio 100.0" not in raw_text
        assert "vs 0 SYN-ACKs" not in raw_text

        # Finding must be candidate/partial
        finding = parsed["data"]["findings"][0]
        assert finding["confidence"] == "candidate"
        assert finding["evidence"] == []

        # Summary line must report elevated SYN rate and note ratio cannot be evaluated
        summary = parsed["data"]["summary"]
        assert "Elevated SYN rate" in summary
        assert "SYN-ACK ratio cannot be evaluated" in summary

    @pytest.mark.asyncio
    async def test_dos_syn_query_truncation_propagated(self) -> None:
        mock_client = AsyncMock()
        mock_client.extract_fields.side_effect = [
            envelope_response("1\t0.00\t10.0.0.1\t10.0.0.2", truncated=True),  # SYN truncated
            success_response(""),  # SYN-ACK
            success_response(""),  # ICMP
            success_response(""),  # UDP
            success_response(""),  # DNS amp
        ]

        tools = dict(make_threat_tools(mock_client))
        raw = await tools["wireshark_detect_dos_attack"]("test.pcap")
        parsed = parse_tool_result(raw)

        assert parsed["success"] is True
        assert parsed["truncated"] is True
        assert parsed["coverage"]["status"] == "partial"
        assert any("SYN search reached ceiling" in w for w in parsed["warnings"])
        finding = parsed["data"]["findings"][0]
        assert finding["constraints"]["truncated"] is True

    @pytest.mark.asyncio
    async def test_port_scan_subquery_failure_returns_partial_coverage(self) -> None:
        mock_client = AsyncMock()
        mock_client.extract_fields.side_effect = [
            success_response(""),  # SYN (0 sources)
            error_response("SYN-FIN query error"),  # SYN-FIN fails
            error_response("NULL query error"),  # NULL fails
        ]

        tools = dict(make_threat_tools(mock_client))
        raw = await tools["wireshark_detect_port_scan"]("test.pcap")
        parsed = parse_tool_result(raw)

        assert parsed["success"] is True
        assert parsed["coverage"]["status"] == "partial"
        assert "failed_checks" in parsed["coverage"]
        assert "SYN-FIN stealth scan" in parsed["coverage"]["failed_checks"]
        assert "NULL stealth scan" in parsed["coverage"]["failed_checks"]

        finding = parsed["data"]["findings"][0]
        assert finding["confidence"] != "confirmed"
        assert "stealth scan checks failed to execute" in finding["observation"]


class TestAnalyzeSuspiciousTraffic:
    """Tests for comprehensive suspicious traffic analysis queries."""

    @pytest.mark.asyncio
    async def test_ftp_cleartext_check(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.get_packet_list(
            "test.pcap",
            limit=5,
            display_filter="ftp",
        )
        assert "-Y ftp" in result

    @pytest.mark.asyncio
    async def test_expert_info_check(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.get_expert_info("test.pcap")
        assert "-z expert" in result
