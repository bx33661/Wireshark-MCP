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
