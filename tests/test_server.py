"""Tests for server bootstrap behavior."""

from importlib import metadata

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
        ]
    )

    assert build_calls == [{"host": "0.0.0.0", "port": 9090, "log_level": "INFO"}]
    assert run_calls == [{"transport": "sse", "mount_path": "/ws"}]


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

    server.main(["--transport", "streamable-http", "--host", "0.0.0.0", "--port", "9000"])

    assert build_calls == [{"host": "0.0.0.0", "port": 9000, "log_level": "WARNING"}]
    assert run_calls == [{"transport": "streamable-http"}]
