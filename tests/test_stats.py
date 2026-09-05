"""Tests for stats tools."""

import json

import pytest
from conftest import MockTSharkClient, call_tool_text

from wireshark_mcp.tools.formatting import parse_tsv_rows


class TestProtocolHierarchy:
    """Tests for get_protocol_stats."""

    @pytest.mark.asyncio
    async def test_phs_command(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.get_protocol_stats("test.pcap")
        assert "-z io,phs" in result
        assert "-q" in result


class TestEndpoints:
    """Tests for get_endpoints."""

    @pytest.mark.asyncio
    async def test_default_ip_type(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.get_endpoints("test.pcap")
        assert "-z endpoints,ip" in result

    @pytest.mark.asyncio
    async def test_tcp_type(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.get_endpoints("test.pcap", type="tcp")
        assert "-z endpoints,tcp" in result


class TestConversations:
    """Tests for get_conversations."""

    @pytest.mark.asyncio
    async def test_default_type(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.get_conversations("test.pcap")
        assert "-z conv,ip" in result


class TestIOGraph:
    """Tests for get_io_graph."""

    @pytest.mark.asyncio
    async def test_default_interval(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.get_io_graph("test.pcap")
        assert "-z io,stat,1" in result

    @pytest.mark.asyncio
    async def test_custom_interval(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.get_io_graph("test.pcap", interval=5)
        assert "-z io,stat,5" in result


class TestExpertInfo:
    """Tests for get_expert_info."""

    @pytest.mark.asyncio
    async def test_expert_command(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.get_expert_info("test.pcap")
        assert "-z expert" in result


class TestServiceResponseTime:
    """Tests for get_service_response_time."""

    @pytest.mark.asyncio
    async def test_http_srt(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.get_service_response_time("test.pcap", protocol="http")
        assert "-z http,tree" in result


class AggregateClient(MockTSharkClient):
    """Return deterministic field rows for aggregate-tool tests."""

    def __init__(self, data: str, stream_result: dict | None = None) -> None:
        super().__init__()
        self.data = data
        self.stream_result = stream_result
        self.aggregate_fields: list[str] = []
        self.aggregate_filter = ""
        self.aggregate_limit = 0
        self.aggregate_stream_limit = False

    async def stream_fields(
        self,
        pcap_file: str,
        fields: list[str],
        consumer,
        display_filter: str = "",
        max_rows: int = 1_000_000,
        timeout: int = 30,
    ) -> dict:
        self.aggregate_fields = fields
        self.aggregate_filter = display_filter
        self.aggregate_limit = max_rows
        self.aggregate_stream_limit = True
        if self.stream_result is not None:
            return self.stream_result
        rows = parse_tsv_rows(self.data)
        for row in rows:
            consumer(row)
        return {"success": True, "rows": len(rows), "bytes_read": len(self.data.encode())}

    async def extract_fields(self, *_args, **_kwargs) -> str:
        raise AssertionError("aggregate tool must not materialize complete field output")


async def _call_aggregate(client: AggregateClient, **arguments):
    from mcp.server import MCPServer

    from wireshark_mcp.tools.stats import register_stats_tools

    mcp = MCPServer("test")
    register_stats_tools(mcp, client)
    raw = await call_tool_text(
        mcp,
        "wireshark_aggregate",
        {"pcap_file": "demo.pcap", **arguments},
    )
    return json.loads(raw)


class TestAggregate:
    @pytest.mark.asyncio
    async def test_numeric_aggregates_report_value_quality(self) -> None:
        client = AggregateClient(
            "frame.number\tip.src\tframe.len\n"
            '"1"\t"10.0.0.1"\t"100"\n'
            '"2"\t"10.0.0.1"\t"200"\n'
            '"3"\t"10.0.0.1"\t""\n'
            '"4"\t"10.0.0.1"\t"bad"\n'
            '"5"\t"10.0.0.2"\t"50"'
        )

        result = await _call_aggregate(
            client,
            group_by="ip.src",
            sum_fields="frame.len",
            min_fields="frame.len",
            max_fields="frame.len",
            avg_fields="frame.len",
            sort_by="numeric_desc",
            sort_numeric="frame.len",
        )

        assert result["success"] is True
        assert result["coverage"]["status"] == "partial"
        assert client.aggregate_fields == ["frame.number", "ip.src", "frame.len"]
        assert result["data"]["numeric_operations"] == {"frame.len": ["avg", "max", "min", "sum"]}
        assert result["data"]["groups"][0] == {
            "key": {"ip.src": "10.0.0.1"},
            "count": 4,
            "numeric": {
                "frame.len": {
                    "valid_values": 2,
                    "missing_values": 1,
                    "invalid_values": 1,
                    "sum": 300.0,
                    "min": 100.0,
                    "max": 200.0,
                    "avg": 150.0,
                }
            },
        }
        assert "frame.len" in result["warnings"][0]

    @pytest.mark.asyncio
    async def test_numeric_sort_requires_requested_field(self) -> None:
        client = AggregateClient('frame.number\tframe.len\n"1"\t"100"')
        result = await _call_aggregate(
            client,
            sum_fields="frame.len",
            sort_by="numeric_desc",
            sort_numeric="tcp.len",
        )
        assert result["success"] is False
        assert result["error"]["type"] == "InvalidParameter"

    @pytest.mark.asyncio
    async def test_multi_occurrence_numeric_value_is_not_silently_summed(self) -> None:
        client = AggregateClient('frame.number\ttcp.len\n"1"\t"10,20"')
        result = await _call_aggregate(client, sum_fields="tcp.len")
        metric = result["data"]["groups"][0]["numeric"]["tcp.len"]
        assert metric == {"valid_values": 0, "missing_values": 0, "invalid_values": 1, "sum": None}
        assert result["coverage"]["status"] == "partial"

    @pytest.mark.asyncio
    async def test_groups_counts_and_distinct_values(self) -> None:
        client = AggregateClient(
            "frame.number\tip.src\tdns.qry.name\n"
            '"1"\t"10.0.0.1"\t"a.example"\n'
            '"2"\t"10.0.0.1"\t"b.example"\n'
            '"3"\t"10.0.0.1"\t"a.example"\n'
            '"4"\t"10.0.0.2"\t"c.example"'
        )

        result = await _call_aggregate(
            client,
            display_filter="dns.flags.response == 0",
            group_by="ip.src",
            distinct="dns.qry.name",
        )

        assert result["success"] is True
        assert result["data"]["matched_packets"] == 4
        assert result["data"]["groups"] == [
            {"key": {"ip.src": "10.0.0.1"}, "count": 3, "distinct": {"dns.qry.name": 2}},
            {"key": {"ip.src": "10.0.0.2"}, "count": 1, "distinct": {"dns.qry.name": 1}},
        ]
        assert client.aggregate_fields == ["frame.number", "ip.src", "dns.qry.name"]
        assert client.aggregate_filter == "dns.flags.response == 0"
        assert client.aggregate_stream_limit is True

    @pytest.mark.asyncio
    async def test_multi_value_fields_expand_occurrences_for_distinct(self) -> None:
        client = AggregateClient(
            "frame.number\tip.addr\ttcp.port\n"
            '"1"\t"10.1.1.1,10.2.2.2"\t"443,51234"\n'
            '"2"\t"10.1.1.1,10.3.3.3"\t"443,51235"'
        )

        result = await _call_aggregate(
            client,
            distinct="ip.addr,tcp.port",
        )

        assert result["success"] is True
        assert result["data"]["matched_packets"] == 2
        # Packet 1 has 2 IPs and 2 ports; packet 2 shares 10.1.1.1 and 443 -> 3 distinct IPs, 3 distinct ports
        assert result["data"]["groups"] == [
            {
                "key": {},
                "count": 2,
                "distinct": {
                    "ip.addr": 3,
                    "tcp.port": 3,
                },
            }
        ]

    @pytest.mark.asyncio
    async def test_literal_string_fields_not_split_by_comma(self) -> None:
        client = AggregateClient(
            "frame.number\thttp.user_agent\n"
            '"1"\t"Mozilla/5.0, CustomAgent/1.0, Token/2.0"\n'
            '"2"\t"Mozilla/5.0, CustomAgent/1.0, Token/2.0"\n'
            '"3"\t"DifferentAgent/1.0"'
        )

        result = await _call_aggregate(
            client,
            distinct="http.user_agent",
        )

        assert result["success"] is True
        assert result["data"]["matched_packets"] == 3
        # Mozilla User-Agent contains 2 commas, but is ONE distinct user agent, plus DifferentAgent = 2 distinct!
        assert result["data"]["groups"][0]["distinct"]["http.user_agent"] == 2

    @pytest.mark.asyncio
    async def test_single_line_distinct_strictly_enforces_ceiling(self) -> None:
        # One line with 6,000 distinct values
        vals = ",".join(f"val_{i}" for i in range(6000))
        client = AggregateClient(f"frame.number\tip.src\n1\t{vals}")

        result = await _call_aggregate(client, distinct="ip.src")
        assert result["success"] is True
        # Must be strictly capped to 5000, NOT 6000!
        assert result["data"]["groups"][0]["distinct"]["ip.src"] == 5000
        # Must generate warning
        assert any("distinct cardinality ceiling" in w for w in result["warnings"])

    def test_distinct_cross_group_global_budget(self) -> None:
        from wireshark_mcp.tools.stats import MAX_TOTAL_DISTINCT_ITEMS, _aggregate_rows

        # 15 groups, each with 4000 items -> total 60,000 attempted (> 50,000 budget)
        rows = []
        for g in range(15):
            vals = ",".join(f"g{g}_v{i}" for i in range(4000))
            rows.append([f"group_{g}", vals])

        groups, _, warnings = _aggregate_rows(rows, ["grp", "fld"], ["grp"], ["fld"], 0)
        total_items = sum(g["distinct"]["fld"] for g in groups)
        assert total_items == MAX_TOTAL_DISTINCT_ITEMS
        assert any("global distinct cardinality budget" in w for w in warnings)

    @pytest.mark.asyncio
    async def test_time_buckets_can_be_sorted_chronologically(self) -> None:
        client = AggregateClient(
            "frame.number\tip.src\tframe.time_relative\n"
            '"1"\t"10.0.0.1"\t"61.2"\n'
            '"2"\t"10.0.0.1"\t"1.0"\n'
            '"3"\t"10.0.0.1"\t"59.9"\n'
            '"4"\t"10.0.0.1"\t"121.0"'
        )

        result = await _call_aggregate(
            client,
            group_by="frame.time_relative,ip.src",
            time_bucket_seconds=60,
        )

        assert result["success"] is True
        assert result["data"]["sort_by"] == "key_asc"
        assert result["data"]["group_by"] == ["ip.src"]
        assert result["data"]["normalized_group_by"] == ("frame.time_relative is implicit in time buckets")
        assert result["data"]["groups"] == [
            {
                "key": {"time_bucket_start": 0, "time_bucket_end": 60, "ip.src": "10.0.0.1"},
                "count": 2,
            },
            {
                "key": {"time_bucket_start": 60, "time_bucket_end": 120, "ip.src": "10.0.0.1"},
                "count": 1,
            },
            {
                "key": {"time_bucket_start": 120, "time_bucket_end": 180, "ip.src": "10.0.0.1"},
                "count": 1,
            },
        ]

    @pytest.mark.asyncio
    async def test_time_bucket_seconds_validates_finite_and_sensible_width(self) -> None:
        client = AggregateClient('frame.number\n"1"')

        # Negative
        res_neg = await _call_aggregate(client, time_bucket_seconds=-5)
        assert res_neg["success"] is False
        assert res_neg["error"]["type"] == "InvalidParameter"

        # NaN
        res_nan = await _call_aggregate(client, time_bucket_seconds=float("nan"))
        assert res_nan["success"] is False
        assert res_nan["error"]["type"] == "InvalidParameter"

        # Infinity
        res_inf = await _call_aggregate(client, time_bucket_seconds=float("inf"))
        assert res_inf["success"] is False
        assert res_inf["error"]["type"] == "InvalidParameter"

        # Subnormal positive float triggering division overflow
        res_tiny = await _call_aggregate(client, time_bucket_seconds=5e-324)
        assert res_tiny["success"] is False
        assert res_tiny["error"]["type"] == "InvalidParameter"
        assert "at least" in res_tiny["error"]["message"]

    @pytest.mark.asyncio
    async def test_time_bucketing_handles_overflow_gracefully(self) -> None:
        # Huge relative time that causes float division/floor overflow
        client = AggregateClient('frame.number\tframe.time_relative\n"1"\t"1e308"\n"2"\t"10.0"')
        result = await _call_aggregate(client, time_bucket_seconds=1e-6)
        assert result["success"] is True
        assert result["data"]["matched_packets"] == 2
        # The 1e308 value was skipped due to overflow
        assert result["data"]["skipped_invalid_time"] == 1
        assert len(result["data"]["groups"]) == 1

    @pytest.mark.asyncio
    async def test_without_grouping_returns_total_count(self) -> None:
        client = AggregateClient('frame.number\n"1"\n"2"\n"3"')

        result = await _call_aggregate(client, display_filter="tcp")

        assert result["success"] is True
        assert result["data"]["groups"] == [{"key": {}, "count": 3}]

    @pytest.mark.asyncio
    async def test_field_content_containing_showing_does_not_false_positive_truncate(self) -> None:
        # A legitimate field (e.g. User-Agent) containing "[Showing " must not trigger LimitExceeded
        client = AggregateClient(
            'frame.number\thttp.user_agent\n"1"\t"Mozilla/5.0 [Showing off] Chrome/120"\n"2"\t"curl/8.1"'
        )

        result = await _call_aggregate(
            client,
            group_by="http.user_agent",
        )

        assert result["success"] is True
        assert result["data"]["matched_packets"] == 2
        assert len(result["data"]["groups"]) == 2

    @pytest.mark.asyncio
    async def test_refuses_to_report_a_truncated_input_as_full_capture(self) -> None:
        client = AggregateClient(
            "frame.number\n",
            {
                "success": False,
                "rows": 1_000_000,
                "bytes_read": 42_000_000,
                "error": {
                    "type": "LimitExceeded",
                    "message": "Matching packet rows exceed the 1000000 row limit",
                },
            },
        )

        result = await _call_aggregate(client)

        assert result["success"] is False
        assert result["error"]["type"] == "LimitExceeded"
        assert result["coverage"] == {"status": "partial", "scanned": 1_000_000, "limit": 1_000_000}
        assert client.aggregate_limit == 1_000_000


class TestIoGraphFilterConsolidation:
    """The former wireshark_io_stat_filters folded into wireshark_stats_io_graph as `filters`."""

    @pytest.mark.asyncio
    async def test_filters_route_to_the_multi_filter_command(self, mock_client: MockTSharkClient) -> None:
        import json

        from mcp.server import MCPServer

        from wireshark_mcp.tools.stats import register_stats_tools

        mcp = MCPServer("test")
        register_stats_tools(mcp, mock_client)

        result = json.loads(
            await call_tool_text(
                mcp, "wireshark_stats_io_graph", {"pcap_file": "demo.pcap", "interval": 2, "filters": "tcp;dns"}
            )
        )
        assert result["success"]
        assert '"tcp"' in result["data"]
        assert '"dns"' in result["data"]
        assert "io,stat,2" in result["data"]

    @pytest.mark.asyncio
    async def test_no_filters_uses_the_plain_command(self, mock_client: MockTSharkClient) -> None:
        import json

        from mcp.server import MCPServer

        from wireshark_mcp.tools.stats import register_stats_tools

        mcp = MCPServer("test")
        register_stats_tools(mcp, mock_client)

        result = json.loads(await call_tool_text(mcp, "wireshark_stats_io_graph", {"pcap_file": "demo.pcap"}))
        assert result["success"]
        assert "io,stat,1" in result["data"]
        assert '"' not in result["data"].split("io,stat,1")[1][:20]
