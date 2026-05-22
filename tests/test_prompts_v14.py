"""Tests for v1.4 MCP prompts — hypothesis-driven and alert investigation."""

import asyncio

from mcp.server.fastmcp import FastMCP

from wireshark_mcp.prompts import register_prompts


def _run_async(coro):
    return asyncio.run(coro)


def test_analyze_with_hypothesis_prompt_registered() -> None:
    """Verify the hypothesis analysis prompt is registered."""
    mcp = FastMCP("test")
    register_prompts(mcp)

    names = {prompt.name for prompt in mcp._prompt_manager.list_prompts()}
    assert "analyze_with_hypothesis" in names


def test_analyze_with_hypothesis_without_initial_hypothesis() -> None:
    """Prompt renders correctly when no hypothesis is provided."""
    mcp = FastMCP("test")
    register_prompts(mcp)

    messages = _run_async(mcp._prompt_manager.render_prompt("analyze_with_hypothesis", {"pcap_file": "test.pcap"}))
    text = messages[0].content.text

    assert 'wireshark_open_file("test.pcap")' in text
    assert "No initial hypothesis provided" in text
    assert "Hypothesis-Driven Analysis" in text


def test_analyze_with_hypothesis_with_initial_hypothesis() -> None:
    """Prompt renders correctly when an initial hypothesis is supplied."""
    mcp = FastMCP("test")
    register_prompts(mcp)

    messages = _run_async(
        mcp._prompt_manager.render_prompt(
            "analyze_with_hypothesis",
            {"pcap_file": "test.pcap", "hypothesis": "DNS exfiltration is occurring"},
        )
    )
    text = messages[0].content.text

    assert "DNS exfiltration is occurring" in text
    assert "No initial hypothesis provided" not in text


def test_investigate_alert_prompt_registered() -> None:
    """Verify the alert investigation prompt is registered."""
    mcp = FastMCP("test")
    register_prompts(mcp)

    names = {prompt.name for prompt in mcp._prompt_manager.list_prompts()}
    assert "investigate_alert" in names


def test_investigate_alert_renders_ioc() -> None:
    """Prompt includes the IOC value and instructs to search for it."""
    mcp = FastMCP("test")
    register_prompts(mcp)

    messages = _run_async(
        mcp._prompt_manager.render_prompt(
            "investigate_alert",
            {"pcap_file": "incident.pcap", "ioc": "192.168.1.100"},
        )
    )
    text = messages[0].content.text

    assert "192.168.1.100" in text
    assert 'wireshark_search_packets("incident.pcap"' in text
    assert "Evidence Chain" in text


def test_investigate_alert_with_ioc_type() -> None:
    """Prompt renders the IOC type hint when provided."""
    mcp = FastMCP("test")
    register_prompts(mcp)

    messages = _run_async(
        mcp._prompt_manager.render_prompt(
            "investigate_alert",
            {"pcap_file": "incident.pcap", "ioc": "evil.example.com", "ioc_type": "domain"},
        )
    )
    text = messages[0].content.text

    assert "evil.example.com" in text
    assert "domain" in text
