"""Tests for the wireshark-mcp auto-configuration installer."""

import json
import os
from unittest.mock import patch

from wireshark_mcp.installer import (
    SERVER_NAME,
    _collect_python_env,
    _get_client_configs,
    _get_linux_config_home,
    _get_mcp_servers_dict,
    _get_python_executable,
    _read_json_config,
    _render_codex_toml_block,
    _write_json_config,
    generate_mcp_config,
    install_mcp_servers,
)


class TestPythonEnvDetection:
    """Tests for smart Python environment detection."""

    def test_get_python_executable_returns_string(self):
        result = _get_python_executable()
        assert isinstance(result, str)
        assert len(result) > 0

    def test_get_python_executable_in_venv(self, tmp_path, monkeypatch):
        venv_dir = tmp_path / "venv"
        bin_dir = venv_dir / "bin"
        bin_dir.mkdir(parents=True)
        python_path = bin_dir / "python3"
        python_path.write_text("")
        monkeypatch.setenv("VIRTUAL_ENV", str(venv_dir))
        assert _get_python_executable() == str(python_path)

    def test_collect_python_env_empty(self, monkeypatch):
        for var in ("PYTHONHOME", "PYTHONPATH", "VIRTUAL_ENV"):
            monkeypatch.delenv(var, raising=False)
        env = _collect_python_env()
        # Might still have some vars from the test env, just check type
        assert isinstance(env, dict)

    def test_collect_python_env_forwards_virtual_env(self, monkeypatch):
        monkeypatch.setenv("VIRTUAL_ENV", "/some/venv")
        env = _collect_python_env()
        assert env.get("VIRTUAL_ENV") == "/some/venv"


class TestGenerateMcpConfig:
    """Tests for generate_mcp_config."""

    def test_returns_dict_with_command(self):
        config = generate_mcp_config()
        assert "command" in config
        assert isinstance(config.get("args", []), list)

    def test_command_is_valid(self):
        config = generate_mcp_config()
        # Should either be the script path or a python executable
        assert len(config["command"]) > 0

    def test_non_windows_uses_python_module_entrypoint(self, monkeypatch):
        monkeypatch.setattr("wireshark_mcp.installer.sys.platform", "darwin")
        monkeypatch.setattr("wireshark_mcp.installer._get_python_executable", lambda: "/venv/bin/python3")
        monkeypatch.setenv("PATH", "/opt/homebrew/bin:/usr/bin")
        monkeypatch.setattr(
            "wireshark_mcp.installer._detect_wireshark_tool_paths",
            lambda: {
                "WIRESHARK_MCP_TSHARK_PATH": "/Applications/Wireshark.app/Contents/MacOS/tshark",
                "WIRESHARK_MCP_CAPINFOS_PATH": None,
                "WIRESHARK_MCP_MERGECAP_PATH": None,
                "WIRESHARK_MCP_EDITCAP_PATH": None,
                "WIRESHARK_MCP_DUMPCAP_PATH": "/Applications/Wireshark.app/Contents/MacOS/dumpcap",
                "WIRESHARK_MCP_TEXT2PCAP_PATH": None,
            },
        )
        config = generate_mcp_config()
        assert config["command"] == "/venv/bin/python3"
        assert config["args"] == ["-u", "-m", "wireshark_mcp.server"]
        assert config["env"]["PYTHONUNBUFFERED"] == "1"
        assert config["env"]["PYTHONIOENCODING"] == "utf-8"
        assert config["env"]["PATH"] == "/opt/homebrew/bin:/usr/bin"
        assert config["env"]["WIRESHARK_MCP_TSHARK_PATH"] == "/Applications/Wireshark.app/Contents/MacOS/tshark"
        assert config["env"]["WIRESHARK_MCP_DUMPCAP_PATH"] == "/Applications/Wireshark.app/Contents/MacOS/dumpcap"

    def test_windows_stdio_uses_unbuffered_python(self, monkeypatch):
        monkeypatch.setattr("wireshark_mcp.installer.sys.platform", "win32")
        monkeypatch.setattr("wireshark_mcp.installer._get_python_executable", lambda: r"C:\\Python\\python.exe")
        config = generate_mcp_config()
        assert config["command"] == r"C:\\Python\\python.exe"
        assert config["args"] == ["-u", "-m", "wireshark_mcp.server"]
        assert config["env"]["PYTHONUNBUFFERED"] == "1"
        assert config["env"]["PYTHONIOENCODING"] == "utf-8"


class TestReadWriteJsonConfig:
    """Tests for low-level JSON config helpers."""

    def test_read_missing_file(self, tmp_path):
        result = _read_json_config(str(tmp_path / "nonexistent.json"))
        assert result == {}

    def test_read_empty_file(self, tmp_path):
        f = tmp_path / "empty.json"
        f.write_text("")
        assert _read_json_config(str(f)) == {}

    def test_read_valid_json(self, tmp_path):
        f = tmp_path / "valid.json"
        f.write_text('{"foo": "bar"}')
        assert _read_json_config(str(f)) == {"foo": "bar"}

    def test_read_invalid_json(self, tmp_path):
        f = tmp_path / "bad.json"
        f.write_text("{bad json}")
        assert _read_json_config(str(f)) == {}

    def test_write_creates_file(self, tmp_path):
        path = str(tmp_path / "out.json")
        _write_json_config(path, {"hello": "world"})
        assert os.path.exists(path)
        with open(path) as f:
            data = json.load(f)
        assert data == {"hello": "world"}

    def test_write_overwrites_existing(self, tmp_path):
        path = str(tmp_path / "out.json")
        _write_json_config(path, {"a": 1})
        _write_json_config(path, {"b": 2})
        with open(path) as f:
            data = json.load(f)
        assert data == {"b": 2}


class TestGetMcpServersDict:
    """Tests for the JSON nesting helper."""

    def test_standard_client_uses_mcpServers(self):
        config: dict = {}
        servers = _get_mcp_servers_dict(config, "Claude")
        assert "mcpServers" in config
        assert servers is config["mcpServers"]

    def test_vscode_uses_mcp_servers(self):
        config: dict = {}
        servers = _get_mcp_servers_dict(config, "VS Code")
        assert config == {"mcp": {"servers": {}}}
        assert servers is config["mcp"]["servers"]

    def test_vscode_insiders(self):
        config: dict = {}
        _get_mcp_servers_dict(config, "VS Code Insiders")
        assert "mcp" in config
        assert "servers" in config["mcp"]

    def test_preserves_existing_config(self):
        config = {"mcpServers": {"other-mcp": {"command": "other"}}}
        servers = _get_mcp_servers_dict(config, "Cursor")
        assert "other-mcp" in servers


class TestInstallMcpServers:
    """Integration tests for install/uninstall using fake client directories."""

    def _make_fake_clients(self, tmp_path):
        """Create fake client config directories and patch _get_client_configs."""
        claude_dir = tmp_path / "claude"
        claude_dir.mkdir()
        cursor_dir = tmp_path / "cursor"
        cursor_dir.mkdir()
        vscode_dir = tmp_path / "vscode"
        vscode_dir.mkdir()
        missing_dir = tmp_path / "missing"  # intentionally not created

        fake_configs = {
            "Claude": (str(claude_dir), "claude_desktop_config.json"),
            "Cursor": (str(cursor_dir), "mcp.json"),
            "VS Code": (str(vscode_dir), "settings.json"),
            "Missing Client": (str(missing_dir), "config.json"),
        }
        return fake_configs

    def test_install_creates_configs(self, tmp_path):
        fake = self._make_fake_clients(tmp_path)
        with patch("wireshark_mcp.installer._get_client_configs", return_value=fake):
            count = install_mcp_servers(uninstall=False)

        # 3 clients installed (Missing Client skipped)
        assert count == 3

        # Claude — standard mcpServers
        claude_cfg = json.loads((tmp_path / "claude" / "claude_desktop_config.json").read_text())
        assert SERVER_NAME in claude_cfg["mcpServers"]

        # VS Code — nested mcp.servers
        vscode_cfg = json.loads((tmp_path / "vscode" / "settings.json").read_text())
        assert SERVER_NAME in vscode_cfg["mcp"]["servers"]

    def test_install_preserves_existing_settings(self, tmp_path):
        fake = self._make_fake_clients(tmp_path)

        # Pre-populate Cursor config
        cursor_cfg = {"mcpServers": {"existing-mcp": {"command": "existing"}}}
        (tmp_path / "cursor" / "mcp.json").write_text(json.dumps(cursor_cfg))

        with patch("wireshark_mcp.installer._get_client_configs", return_value=fake):
            install_mcp_servers(uninstall=False)

        result = json.loads((tmp_path / "cursor" / "mcp.json").read_text())
        assert "existing-mcp" in result["mcpServers"]
        assert SERVER_NAME in result["mcpServers"]

    def test_uninstall_removes_entry(self, tmp_path):
        fake = self._make_fake_clients(tmp_path)

        # Install first
        with patch("wireshark_mcp.installer._get_client_configs", return_value=fake):
            install_mcp_servers(uninstall=False)
            count = install_mcp_servers(uninstall=True)

        assert count == 3

        claude_cfg = json.loads((tmp_path / "claude" / "claude_desktop_config.json").read_text())
        assert SERVER_NAME not in claude_cfg.get("mcpServers", {})

    def test_uninstall_skips_not_installed(self, tmp_path):
        fake = self._make_fake_clients(tmp_path)

        # Don't install anything, just try to uninstall
        with patch("wireshark_mcp.installer._get_client_configs", return_value=fake):
            count = install_mcp_servers(uninstall=True)

        assert count == 0

    def test_skips_missing_directories(self, tmp_path, capsys):
        fake = {
            "Nonexistent": (str(tmp_path / "does_not_exist"), "config.json"),
        }
        with patch("wireshark_mcp.installer._get_client_configs", return_value=fake):
            count = install_mcp_servers(uninstall=False)

        assert count == 0
        output = capsys.readouterr().out
        assert "not found" in output

    def test_install_updates_codex_toml(self, tmp_path):
        codex_dir = tmp_path / "codex"
        codex_dir.mkdir()
        config_path = codex_dir / "config.toml"
        config_path.write_text('[mcp_servers.other]\ncommand = "other"\n', encoding="utf-8")

        fake = {"Codex": (str(codex_dir), "config.toml")}
        with patch("wireshark_mcp.installer._get_client_configs", return_value=fake):
            count = install_mcp_servers(uninstall=False)

        assert count == 1
        content = config_path.read_text(encoding="utf-8")
        assert "[mcp_servers.other]" in content
        assert f"[mcp_servers.{SERVER_NAME}]" in content

    def test_uninstall_removes_codex_toml_block(self, tmp_path):
        codex_dir = tmp_path / "codex"
        codex_dir.mkdir()
        config_path = codex_dir / "config.toml"
        config_path.write_text(_render_codex_toml_block() + "\n", encoding="utf-8")

        fake = {"Codex": (str(codex_dir), "config.toml")}
        with patch("wireshark_mcp.installer._get_client_configs", return_value=fake):
            count = install_mcp_servers(uninstall=True)

        assert count == 1
        assert f"[mcp_servers.{SERVER_NAME}]" not in config_path.read_text(encoding="utf-8")


class TestPlatformConfigs:
    def test_linux_config_home_uses_xdg(self, monkeypatch):
        monkeypatch.setenv("XDG_CONFIG_HOME", "/tmp/xdg-config")
        assert _get_linux_config_home("/home/tester") == "/tmp/xdg-config"

    def test_linux_client_configs_use_xdg(self, monkeypatch):
        monkeypatch.setattr("wireshark_mcp.installer.sys.platform", "linux")
        monkeypatch.setattr("wireshark_mcp.installer.os.path.expanduser", lambda _: "/home/tester")
        monkeypatch.setenv("XDG_CONFIG_HOME", "/tmp/xdg-config")

        configs = _get_client_configs()

        assert configs["VS Code"] == ("/tmp/xdg-config/Code/User", "settings.json")
        assert configs["Zed"] == ("/tmp/xdg-config/zed", "settings.json")

    def test_windows_client_configs_include_supported_paths(self, monkeypatch):
        monkeypatch.setattr("wireshark_mcp.installer.sys.platform", "win32")
        monkeypatch.setenv("APPDATA", r"C:\Users\tester\AppData\Roaming")
        monkeypatch.setattr("wireshark_mcp.installer.os.path.expanduser", lambda _: r"C:\Users\tester")

        configs = _get_client_configs()

        assert configs["Claude"] == (
            r"C:\Users\tester\AppData\Roaming\Claude",
            "claude_desktop_config.json",
        )
        assert configs["Codex"] == (r"C:\Users\tester\.codex", "config.toml")
        assert configs["VS Code"] == (
            r"C:\Users\tester\AppData\Roaming\Code\User",
            "settings.json",
        )
