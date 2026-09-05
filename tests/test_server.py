import json
import os
import socket
import subprocess
import sys
import time
import urllib.request
from importlib import metadata

import pytest
from mcp import Client
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.server import MCPServer
from mcp.types.version import LATEST_PROTOCOL_VERSION

import wireshark_mcp
import wireshark_mcp.server as server


class TestWindowsEventLoop:
    def test_configure_windows_event_loop_is_noop_off_windows(self, monkeypatch):
        applied: list[object] = []

        monkeypatch.setattr(server.sys, "platform", "darwin")
        monkeypatch.setattr(server.asyncio, "set_event_loop_policy", lambda policy: applied.append(policy))

        server._configure_windows_event_loop()

        assert applied == []

    def test_configure_windows_event_loop_sets_proactor_policy(self, monkeypatch):
        class FakePolicy:
            pass

        applied: list[object] = []

        monkeypatch.setattr(server.sys, "platform", "win32")
        monkeypatch.setattr(server.asyncio, "WindowsProactorEventLoopPolicy", FakePolicy, raising=False)
        monkeypatch.setattr(server.asyncio, "get_event_loop_policy", lambda: object())
        monkeypatch.setattr(server.asyncio, "set_event_loop_policy", lambda policy: applied.append(policy))

        server._configure_windows_event_loop()

        assert len(applied) == 1
        assert isinstance(applied[0], FakePolicy)

    def test_configure_windows_event_loop_keeps_existing_proactor_policy(self, monkeypatch):
        class FakePolicy:
            pass

        current_policy = FakePolicy()
        applied: list[object] = []

        monkeypatch.setattr(server.sys, "platform", "win32")
        monkeypatch.setattr(server.asyncio, "WindowsProactorEventLoopPolicy", FakePolicy, raising=False)
        monkeypatch.setattr(server.asyncio, "get_event_loop_policy", lambda: current_policy)
        monkeypatch.setattr(server.asyncio, "set_event_loop_policy", lambda policy: applied.append(policy))

        server._configure_windows_event_loop()

        assert applied == []


def test_package_version_matches_installed_metadata():
    assert wireshark_mcp.__version__ == metadata.version("wireshark-mcp")


@pytest.mark.asyncio
async def test_server_negotiates_the_mcp_v2_protocol() -> None:
    assert metadata.version("mcp").split(".", 1)[0] == "2"

    mcp = server._build_server(host="127.0.0.1", port=8080, log_level="ERROR")
    assert isinstance(mcp, MCPServer)

    async with Client(mcp) as client:
        assert client.protocol_version == LATEST_PROTOCOL_VERSION
        assert client.server_info is not None
        assert client.server_info.version == wireshark_mcp.__version__
        assert len((await client.list_tools()).tools) == 52


@pytest.mark.asyncio
async def test_real_stdio_subprocess_handshake() -> None:
    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"
    server_params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "wireshark_mcp"],
        env=env,
    )
    async with Client(stdio_client(server_params)) as client:
        assert client.protocol_version == LATEST_PROTOCOL_VERSION
        assert client.server_info is not None
        assert client.server_info.version == wireshark_mcp.__version__
        tools = await client.list_tools()
        assert len(tools.tools) == 52


def test_server_advertises_capture_analysis_instructions():
    mcp = server._build_server(host="127.0.0.1", port=8080, log_level="ERROR")

    assert "wireshark_open_file" in mcp.instructions
    assert "wireshark_aggregate" in mcp.instructions
    assert "prefer" in mcp.instructions.lower()


def test_main_routes_install_subcommand(monkeypatch):
    calls: list[dict] = []

    monkeypatch.setattr(
        "wireshark_mcp.installer.run_install",
        lambda **kwargs: calls.append(kwargs),
    )

    server.main(["install", "--client", "codex"])

    assert calls == [
        {
            "install": True,
            "update": False,
            "uninstall": False,
            "config": False,
            "doctor": False,
            "list_clients": False,
            "selected_clients": ["codex"],
            "config_format": "json",
            "output_format": "text",
        }
    ]


def test_main_routes_legacy_doctor_flag(monkeypatch):
    calls: list[dict] = []

    monkeypatch.setattr(
        "wireshark_mcp.installer.run_install",
        lambda **kwargs: calls.append(kwargs),
    )

    server.main(["--doctor", "--client", "cursor"])

    assert calls == [
        {
            "install": False,
            "update": False,
            "uninstall": False,
            "config": False,
            "doctor": True,
            "list_clients": False,
            "selected_clients": ["cursor"],
            "config_format": "json",
            "output_format": "text",
        }
    ]


def test_main_routes_config_subcommand(monkeypatch):
    calls: list[dict] = []

    monkeypatch.setattr(
        "wireshark_mcp.installer.run_install",
        lambda **kwargs: calls.append(kwargs),
    )

    server.main(["config", "--format", "codex-toml"])

    assert calls == [
        {
            "install": False,
            "update": False,
            "uninstall": False,
            "config": True,
            "doctor": False,
            "list_clients": False,
            "selected_clients": None,
            "config_format": "codex-toml",
            "output_format": "text",
        }
    ]


def test_main_routes_doctor_json_subcommand(monkeypatch):
    calls: list[dict] = []

    monkeypatch.setattr(
        "wireshark_mcp.installer.run_install",
        lambda **kwargs: calls.append(kwargs),
    )

    server.main(["doctor", "--client", "codex", "--format", "json"])

    assert calls == [
        {
            "install": False,
            "update": False,
            "uninstall": False,
            "config": False,
            "doctor": True,
            "list_clients": False,
            "selected_clients": ["codex"],
            "config_format": "json",
            "output_format": "json",
        }
    ]


def test_main_routes_clients_json_subcommand(monkeypatch):
    calls: list[dict] = []

    monkeypatch.setattr(
        "wireshark_mcp.installer.run_install",
        lambda **kwargs: calls.append(kwargs),
    )

    server.main(["clients", "--format", "json"])

    assert calls == [
        {
            "install": False,
            "update": False,
            "uninstall": False,
            "config": False,
            "doctor": False,
            "list_clients": True,
            "selected_clients": None,
            "config_format": "json",
            "output_format": "json",
        }
    ]


def test_main_routes_legacy_doctor_flag_with_json(monkeypatch):
    calls: list[dict] = []

    monkeypatch.setattr(
        "wireshark_mcp.installer.run_install",
        lambda **kwargs: calls.append(kwargs),
    )

    server.main(["--doctor", "--client", "cursor", "--format", "json"])

    assert calls == [
        {
            "install": False,
            "update": False,
            "uninstall": False,
            "config": False,
            "doctor": True,
            "list_clients": False,
            "selected_clients": ["cursor"],
            "config_format": "json",
            "output_format": "json",
        }
    ]


def test_main_starts_sse_server_with_explicit_host_port(monkeypatch):
    build_calls: list[dict] = []
    run_calls: list[dict] = []

    class FakeMCP:
        def run(self, **kwargs):
            run_calls.append(kwargs)

    monkeypatch.setattr(
        server,
        "_build_server",
        lambda **kwargs: build_calls.append(kwargs) or FakeMCP(),
    )
    monkeypatch.setattr(server, "_configure_windows_event_loop", lambda: None)
    monkeypatch.setattr(server.logging, "basicConfig", lambda **kwargs: None)

    server.main(
        [
            "serve",
            "--transport",
            "sse",
            "--host",
            "0.0.0.0",
            "--port",
            "9090",
            "--mount-path",
            "/ws",
            "--log-level",
            "INFO",
            "--allow-insecure-http",
        ]
    )

    assert build_calls == [{"host": "0.0.0.0", "port": 9090, "log_level": "INFO", "profile": "full"}]
    assert run_calls == [
        {
            "transport": "sse",
            "host": "0.0.0.0",
            "port": 9090,
            "sse_path": "/ws/sse",
            "message_path": "/ws/messages/",
        }
    ]


def test_main_defaults_to_serve_for_top_level_transport_flags(monkeypatch):
    build_calls: list[dict] = []
    run_calls: list[dict] = []

    class FakeMCP:
        def run(self, **kwargs):
            run_calls.append(kwargs)

    monkeypatch.setattr(
        server,
        "_build_server",
        lambda **kwargs: build_calls.append(kwargs) or FakeMCP(),
    )
    monkeypatch.setattr(server, "_configure_windows_event_loop", lambda: None)
    monkeypatch.setattr(server.logging, "basicConfig", lambda **kwargs: None)

    server.main(
        [
            "--transport",
            "streamable-http",
            "--host",
            "0.0.0.0",
            "--port",
            "9000",
            "--allow-insecure-http",
        ]
    )

    assert build_calls == [{"host": "0.0.0.0", "port": 9000, "log_level": "WARNING", "profile": "full"}]
    assert run_calls == [{"transport": "streamable-http", "host": "0.0.0.0", "port": 9000}]


def test_main_rejects_non_loopback_http_without_explicit_opt_in(monkeypatch):
    monkeypatch.setattr(server.logging, "basicConfig", lambda **kwargs: None)

    with pytest.raises(SystemExit, match="2"):
        server.main(["serve", "--transport", "streamable-http", "--host", "0.0.0.0"])


@pytest.mark.parametrize("host", ["127.0.0.1", "::1", "localhost", "LOCALHOST."])
def test_loopback_host_detection(host):
    assert server._is_loopback_host(host)


def test_real_streamable_http_transport() -> None:
    from mcp.server.streamable_http import TransportSecuritySettings
    from starlette.testclient import TestClient

    mcp = server._build_server(host="127.0.0.1", port=8080, log_level="ERROR")
    sec = TransportSecuritySettings(enable_dns_rebinding_protection=False)
    app = mcp.streamable_http_app(transport_security=sec)

    with TestClient(app, base_url="http://127.0.0.1") as client:
        # 1. Initialize
        res = client.post(
            "/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "pytest-http", "version": "1.0"},
                },
            },
        )
        assert res.status_code == 200
        session_id = res.headers.get("mcp-session-id")
        assert session_id

        # 2. Initialized notification
        client.post(
            "/mcp",
            json={"jsonrpc": "2.0", "method": "notifications/initialized"},
            headers={"mcp-session-id": session_id},
        )

        # 3. List tools
        res_tools = client.post(
            "/mcp",
            json={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
            headers={"mcp-session-id": session_id},
        )
        assert res_tools.status_code == 200
        assert "wireshark_aggregate" in res_tools.text


def test_streamable_http_latest_protocol_discovery_and_tool_execution() -> None:
    from mcp.server.streamable_http import TransportSecuritySettings
    from starlette.testclient import TestClient

    mcp = server._build_server(host="127.0.0.1", port=8080, log_level="ERROR")
    sec = TransportSecuritySettings(enable_dns_rebinding_protection=False)
    app = mcp.streamable_http_app(
        transport_security=sec,
        stateless_http=True,
        json_response=True,
    )

    base_headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "MCP-Protocol-Version": LATEST_PROTOCOL_VERSION,
    }
    request_meta = {
        "io.modelcontextprotocol/protocolVersion": LATEST_PROTOCOL_VERSION,
        "io.modelcontextprotocol/clientInfo": {"name": "pytest-http-latest", "version": "3.0"},
        "io.modelcontextprotocol/clientCapabilities": {},
    }

    with TestClient(app, base_url="http://127.0.0.1") as client:
        # 1. Modern discovery is a self-contained request, not an initialize handshake.
        res = client.post(
            "/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "server/discover",
                "params": {"_meta": request_meta},
            },
            headers={**base_headers, "MCP-Method": "server/discover"},
        )
        assert res.status_code == 200
        assert "mcp-session-id" not in res.headers
        discovery = res.json()
        assert discovery["jsonrpc"] == "2.0"
        assert discovery["id"] == 1
        assert discovery["result"]["supportedVersions"] == [LATEST_PROTOCOL_VERSION]
        assert discovery["result"]["resultType"] == "complete"
        assert discovery["result"]["_meta"]["io.modelcontextprotocol/serverInfo"]["version"] == "3.0.0"

        # 2. List tools without a session.
        res_tools = client.post(
            "/mcp",
            json={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {"_meta": request_meta}},
            headers={**base_headers, "MCP-Method": "tools/list"},
        )
        assert res_tools.status_code == 200
        assert "mcp-session-id" not in res_tools.headers
        listed = res_tools.json()
        assert listed["result"]["resultType"] == "complete"
        tool_names = {tool["name"] for tool in listed["result"]["tools"]}
        assert {"wireshark_get_capabilities", "wireshark_aggregate"} <= tool_names

        # 3. Successful tool call using the modern routing envelope.
        res_call_success = client.post(
            "/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "_meta": request_meta,
                    "name": "wireshark_get_capabilities",
                    "arguments": {},
                },
            },
            headers={
                **base_headers,
                "MCP-Method": "tools/call",
                "MCP-Name": "wireshark_get_capabilities",
            },
        )
        assert res_call_success.status_code == 200
        assert "mcp-session-id" not in res_call_success.headers
        successful = res_call_success.json()["result"]
        assert successful["isError"] is False
        assert successful["resultType"] == "complete"
        assert "tshark" in successful["content"][0]["text"]

        # 4. Failed tool call preserves the protocol-level error marker.
        res_call_fail = client.post(
            "/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {
                    "_meta": request_meta,
                    "name": "wireshark_get_file_info",
                    "arguments": {"pcap_file": "/nonexistent/test.pcap"},
                },
            },
            headers={
                **base_headers,
                "MCP-Method": "tools/call",
                "MCP-Name": "wireshark_get_file_info",
            },
        )
        assert res_call_fail.status_code == 200
        assert "mcp-session-id" not in res_call_fail.headers
        failed = res_call_fail.json()["result"]
        assert failed["isError"] is True
        assert failed["resultType"] == "complete"
        assert "FileNotFound" in failed["content"][0]["text"]


def test_real_streamable_http_listening_subprocess() -> None:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()

    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "wireshark_mcp",
            "serve",
            "--transport",
            "streamable-http",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    try:
        ready = False
        for _ in range(50):
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                    ready = True
                    break
            except OSError:
                time.sleep(0.1)
        assert ready, "Server failed to start listening within 5s"

        base_headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "MCP-Protocol-Version": LATEST_PROTOCOL_VERSION,
        }
        request_meta = {
            "io.modelcontextprotocol/protocolVersion": LATEST_PROTOCOL_VERSION,
            "io.modelcontextprotocol/clientInfo": {"name": "test-http-client", "version": "3.0"},
            "io.modelcontextprotocol/clientCapabilities": {},
        }

        def modern_request(request_id: int, method: str, params: dict, *, name: str | None = None):
            request_headers = {**base_headers, "MCP-Method": method}
            if name is not None:
                request_headers["MCP-Name"] = name
            return urllib.request.Request(
                f"http://127.0.0.1:{port}/mcp",
                data=json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": request_id,
                        "method": method,
                        "params": {"_meta": request_meta, **params},
                    }
                ).encode("utf-8"),
                headers=request_headers,
            )

        # 1. Discover the modern protocol without creating a session.
        discover_req = modern_request(1, "server/discover", {})
        with opener.open(discover_req, timeout=5) as resp:
            assert resp.status == 200
            assert resp.headers.get("mcp-session-id") is None
            discovery = json.loads(resp.read())
            assert discovery["result"]["supportedVersions"] == [LATEST_PROTOCOL_VERSION]
            assert discovery["result"]["resultType"] == "complete"

        # 2. tools/list is another self-contained request.
        list_req = modern_request(2, "tools/list", {})
        with opener.open(list_req, timeout=5) as resp:
            assert resp.status == 200
            assert resp.headers.get("mcp-session-id") is None
            listed = json.loads(resp.read())
            assert listed["result"]["resultType"] == "complete"
            assert "wireshark_get_capabilities" in {tool["name"] for tool in listed["result"]["tools"]}

        # 3. tools/call success.
        call_req = modern_request(
            3,
            "tools/call",
            {"name": "wireshark_get_capabilities", "arguments": {}},
            name="wireshark_get_capabilities",
        )
        with opener.open(call_req, timeout=5) as resp:
            assert resp.status == 200
            assert resp.headers.get("mcp-session-id") is None
            called = json.loads(resp.read())["result"]
            assert called["isError"] is False
            assert called["resultType"] == "complete"

        # 4. tools/call failure.
        fail_req = modern_request(
            4,
            "tools/call",
            {
                "name": "wireshark_get_file_info",
                "arguments": {"pcap_file": "/nonexistent.pcap"},
            },
            name="wireshark_get_file_info",
        )
        with opener.open(fail_req, timeout=5) as resp:
            assert resp.status == 200
            assert resp.headers.get("mcp-session-id") is None
            failed = json.loads(resp.read())["result"]
            assert failed["isError"] is True
            assert failed["resultType"] == "complete"
            assert "FileNotFound" in failed["content"][0]["text"]
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=1)
