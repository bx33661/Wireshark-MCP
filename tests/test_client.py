"""Tests for TSharkClient core functionality."""

import asyncio
import json
import shutil

import pytest

from wireshark_mcp.tshark.client import TSharkClient


class TestValidation:
    """Tests for file and protocol validation."""

    def test_validate_file_not_found(self, real_client: TSharkClient) -> None:
        result = real_client._validate_file("/nonexistent/file.pcap")
        assert not result["success"]
        assert result["error"]["type"] == "FileNotFound"

    def test_validate_file_empty_path(self, real_client: TSharkClient) -> None:
        result = real_client._validate_file("")
        assert not result["success"]
        assert result["error"]["type"] == "InvalidParameter"

    def test_validate_file_exists(self, tmp_pcap: str, real_client: TSharkClient) -> None:
        result = real_client._validate_file(tmp_pcap)
        assert result["success"]

    def test_validate_file_is_directory(self, tmp_dir: str, real_client: TSharkClient) -> None:
        result = real_client._validate_file(tmp_dir)
        assert not result["success"]
        assert result["error"]["type"] == "InvalidParameter"

    def test_validate_protocol_valid(self, real_client: TSharkClient) -> None:
        result = real_client._validate_protocol("tcp", TSharkClient.VALID_ENDPOINT_TYPES)
        assert result["success"]

    def test_validate_protocol_invalid(self, real_client: TSharkClient) -> None:
        result = real_client._validate_protocol("invalid", TSharkClient.VALID_ENDPOINT_TYPES)
        assert not result["success"]
        assert result["error"]["type"] == "InvalidParameter"

    def test_validate_protocol_case_insensitive(self, real_client: TSharkClient) -> None:
        result = real_client._validate_protocol("TCP", TSharkClient.VALID_ENDPOINT_TYPES)
        assert result["success"]

    @pytest.mark.parametrize(
        "path",
        [
            r"C:\captures\NUL.pcap",
            r"C:\captures\NUL .pcap",
            r"C:\captures\con.txt",
            r"C:\captures\capture.pcap:secret",
            r"\\.\PhysicalDrive0",
            r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\cap.pcap",
        ],
    )
    def test_windows_unsafe_input_paths_are_rejected(self, monkeypatch, path: str) -> None:
        client = TSharkClient()
        monkeypatch.setattr("wireshark_mcp.tshark._validation.sys.platform", "win32")

        result = client._validate_file(path)

        assert result["success"] is False
        assert result["error"]["type"] == "InvalidParameter"

    @pytest.mark.parametrize(
        "path",
        [
            r"C:\captures\LPT1.pcapng",
            r"C:\captures\output.pcapng:hidden",
            r"\\?\C:\captures\output.pcapng",
        ],
    )
    def test_windows_unsafe_output_paths_are_rejected(self, monkeypatch, path: str) -> None:
        client = TSharkClient()
        monkeypatch.setattr("wireshark_mcp.tshark._validation.sys.platform", "win32")

        result = client._validate_output_path(path)

        assert result["success"] is False
        assert result["error"]["type"] == "InvalidParameter"

    def test_windows_normal_path_is_not_flagged(self, monkeypatch) -> None:
        monkeypatch.setattr("wireshark_mcp.tshark._validation.sys.platform", "win32")

        assert TSharkClient._is_unsafe_windows_path(r"C:\captures\trace.pcapng") is False


class TestSandbox:
    """Tests for path sandbox enforcement."""

    def test_sandbox_allows_file_in_allowed_dir(self, tmp_dir: str, tmp_pcap: str) -> None:
        client = TSharkClient(allowed_dirs=[tmp_dir])
        result = client._validate_file(tmp_pcap)
        assert result["success"]

    def test_sandbox_blocks_file_outside_allowed_dir(self, tmp_dir: str) -> None:
        client = TSharkClient(allowed_dirs=[tmp_dir])
        result = client._validate_file("/etc/passwd")
        assert not result["success"]
        assert result["error"]["type"] == "PermissionDenied"

    def test_sandbox_blocks_path_traversal(self, tmp_dir: str) -> None:
        client = TSharkClient(allowed_dirs=[tmp_dir])
        malicious_path = f"{tmp_dir}/../../../etc/passwd"
        result = client._validate_file(malicious_path)
        assert not result["success"]
        assert result["error"]["type"] == "PermissionDenied"

    def test_no_sandbox_allows_any_path(self, tmp_pcap: str) -> None:
        client = TSharkClient()
        result = client._validate_file(tmp_pcap)
        assert result["success"]

    def test_no_sandbox_blocks_all_output_paths(self) -> None:
        client = TSharkClient()
        result = client._validate_output_path("/tmp/output.pcap")
        assert not result["success"]
        assert result["error"]["type"] == "PermissionDenied"
        assert "WIRESHARK_MCP_ALLOWED_DIRS" in result["error"]["message"]

    def test_allowed_directory_must_exist(self, tmp_path) -> None:
        with pytest.raises(ValueError, match="must already exist"):
            TSharkClient(allowed_dirs=[str(tmp_path / "missing")])

    def test_temporary_output_requires_allowed_directory(self) -> None:
        result = TSharkClient()._create_temporary_output_dir("test_")
        assert result["success"] is False
        assert result["error"]["type"] == "PermissionDenied"

    def test_temporary_output_is_created_inside_allowed_directory(self, tmp_path) -> None:
        result = TSharkClient(allowed_dirs=[str(tmp_path)])._create_temporary_output_dir("test_")
        assert result["success"] is True
        assert str(result["path"]).startswith(str(tmp_path))

    @pytest.mark.asyncio
    async def test_cve_2026_43901_export_fails_closed_without_allowed_dirs(self, tmp_path) -> None:
        pcap = tmp_path / "input.pcap"
        pcap.write_bytes(b"")
        destination = tmp_path / "exported"

        result = json.loads(await TSharkClient().export_objects(str(pcap), "http", str(destination)))

        assert result["success"] is False
        assert result["error"]["type"] == "PermissionDenied"
        assert not destination.exists()

    def test_sandbox_output_path_validation(self, tmp_dir: str) -> None:
        client = TSharkClient(allowed_dirs=[tmp_dir])
        result = client._validate_output_path(f"{tmp_dir}/output.pcap")
        assert result["success"]

        result = client._validate_output_path("/tmp/evil/output.pcap")
        assert not result["success"]


class TestCapabilities:
    """Tests for check_capabilities."""

    @pytest.mark.asyncio
    async def test_check_capabilities(self, real_client: TSharkClient) -> None:
        result = await real_client.check_capabilities()
        assert result["success"]
        assert "tshark" in result["data"]
        assert "capinfos" in result["data"]
        assert "_meta" in result["data"]

    def test_client_prefers_env_tool_paths(self, monkeypatch) -> None:
        monkeypatch.setenv("WIRESHARK_MCP_TSHARK_PATH", "/opt/wireshark/tshark")
        monkeypatch.setenv("WIRESHARK_MCP_CAPINFOS_PATH", "/opt/wireshark/capinfos")
        monkeypatch.setenv("WIRESHARK_MCP_MERGECAP_PATH", "/opt/wireshark/mergecap")
        monkeypatch.setenv("WIRESHARK_MCP_EDITCAP_PATH", "/opt/wireshark/editcap")
        monkeypatch.setenv("WIRESHARK_MCP_DUMPCAP_PATH", "/opt/wireshark/dumpcap")
        monkeypatch.setenv("WIRESHARK_MCP_TEXT2PCAP_PATH", "/opt/wireshark/text2pcap")

        client = TSharkClient()

        assert client.tshark_path == "/opt/wireshark/tshark"
        assert client.capinfos_path == "/opt/wireshark/capinfos"
        assert client.mergecap_path == "/opt/wireshark/mergecap"
        assert client.editcap_path == "/opt/wireshark/editcap"
        assert client.dumpcap_path == "/opt/wireshark/dumpcap"
        assert client.text2pcap_path == "/opt/wireshark/text2pcap"

    def test_describe_capabilities_reports_capture_backend_fallback(self, mock_client) -> None:
        capabilities = mock_client.describe_capabilities()
        assert capabilities["_meta"]["capture_backend"] == "dumpcap"
        assert capabilities["dumpcap"]["requirement"] == "optional"
        assert "path" not in capabilities["dumpcap"]

        mock_client.dumpcap_path = None
        mock_client._tool_paths["dumpcap"] = None

        fallback_capabilities = mock_client.describe_capabilities()
        assert fallback_capabilities["_meta"]["capture_backend"] == "tshark"

    @pytest.mark.asyncio
    async def test_check_capabilities_detects_real_tshark_when_installed(self) -> None:
        if shutil.which("tshark") is None:
            pytest.skip("tshark not installed on this host")

        result = await TSharkClient().check_capabilities()

        assert result["success"]
        assert result["data"]["tshark"]["available"] is True

    @pytest.mark.asyncio
    async def test_windows_capability_probes_do_not_open_console_windows(self, monkeypatch) -> None:
        captured_kwargs = []
        client = TSharkClient()
        client._tool_paths = {name: name for name in client._tool_paths}

        class FakeProc:
            async def communicate(self):
                return b"TShark 4.6.0", b""

        async def fake_exec(*_args, **kwargs):
            captured_kwargs.append(kwargs)
            return FakeProc()

        monkeypatch.setattr(client, "_tool_is_available", lambda _path: True)
        monkeypatch.setattr("wireshark_mcp.tshark._capability.sys.platform", "win32")
        monkeypatch.setattr("wireshark_mcp.tshark._capability.subprocess.CREATE_NO_WINDOW", 0x08000000, raising=False)
        monkeypatch.setattr("asyncio.create_subprocess_exec", fake_exec)

        result = await client.check_capabilities()

        assert result["success"] is True
        assert captured_kwargs
        assert all(kwargs["creationflags"] == 0x08000000 for kwargs in captured_kwargs)


class TestRunCommand:
    """Tests for _run_command error handling."""

    @pytest.mark.asyncio
    async def test_file_not_found_returns_error(self, real_client: TSharkClient) -> None:
        result_str = await real_client.get_protocol_stats("/nonexistent.pcap")
        result = json.loads(result_str)
        assert not result["success"]
        assert result["error"]["type"] == "FileNotFound"

    @pytest.mark.asyncio
    async def test_binary_whitelist_blocks_unknown(self, real_client: TSharkClient) -> None:
        result_str = await real_client._run_command(["curl", "http://evil.com"])
        result = json.loads(result_str)
        assert not result["success"]
        assert result["error"]["type"] == "SecurityError"

    @pytest.mark.asyncio
    async def test_binary_whitelist_allows_windows_exe_names(self, real_client: TSharkClient) -> None:
        result_str = await real_client._run_command(["C:\\Wireshark\\tshark.exe", "-v"])
        result = json.loads(result_str)
        assert not result["success"]
        assert result["error"]["type"] != "SecurityError"

    @pytest.mark.asyncio
    async def test_binary_whitelist_allows_windows_exe_names_case_insensitive(self, real_client: TSharkClient) -> None:
        result_str = await real_client._run_command(["C:\\Wireshark\\tshark.EXE", "-v"])
        result = json.loads(result_str)
        assert not result["success"]
        assert result["error"]["type"] != "SecurityError"

    @pytest.mark.asyncio
    async def test_windows_subprocesses_are_started_without_a_console_window(self, monkeypatch) -> None:
        captured_kwargs = {}
        client = TSharkClient()

        class FakeProc:
            returncode = 0
            stdout = None
            stderr = None

            async def communicate(self):
                return b"TShark 4.6.0", b""

        async def fake_exec(*_args, **kwargs):
            captured_kwargs.update(kwargs)
            return FakeProc()

        monkeypatch.setattr("wireshark_mcp.tshark.client.sys.platform", "win32")
        monkeypatch.setattr("wireshark_mcp.tshark.client.subprocess.CREATE_NO_WINDOW", 0x08000000, raising=False)
        monkeypatch.setattr("asyncio.create_subprocess_exec", fake_exec)

        result = json.loads(await client._run_command(["tshark", "-v"]))

        assert result["success"] is True
        assert captured_kwargs["creationflags"] == 0x08000000

    def test_sensitive_command_arguments_are_redacted(self) -> None:
        rendered = TSharkClient._redact_command(
            [
                "tshark",
                "-o",
                'uat:80211_keys:"wpa-pwd:super-secret:CorpWifi",1',
                "-o",
                "tls.keylog_file:/secret/keys.log",
            ]
        )
        assert "super-secret" not in rendered
        assert "/secret/keys.log" not in rendered
        assert rendered.count("<redacted>") == 2

    @pytest.mark.asyncio
    async def test_subprocess_output_is_bounded(self, monkeypatch) -> None:
        killed = {"value": False}

        class FakeStream:
            def __init__(self, payload: bytes) -> None:
                self.payload = payload

            async def read(self, maximum: int) -> bytes:
                chunk, self.payload = self.payload[:maximum], self.payload[maximum:]
                return chunk

        class FakeProc:
            returncode = 0
            stdout = FakeStream(b"x" * 33)
            stderr = FakeStream(b"")

            def kill(self) -> None:
                killed["value"] = True

            async def wait(self) -> int:
                return 0

        async def fake_exec(*_args, **_kwargs):
            return FakeProc()

        monkeypatch.setattr("asyncio.create_subprocess_exec", fake_exec)
        client = TSharkClient()
        client.MAX_STDOUT_BYTES = 32
        result = json.loads(await client._run_command([client.tshark_path, "-v"]))
        assert result["success"] is False
        assert result["error"]["type"] == "LimitExceeded"
        assert killed["value"] is True

    @pytest.mark.asyncio
    async def test_timeout_kills_and_reaps_subprocess(self, monkeypatch) -> None:
        state = {"killed": False, "waited": False}

        class FakeProc:
            returncode = None
            stdout = None
            stderr = None

            async def communicate(self):
                await asyncio.sleep(1)
                return b"", b""

            def kill(self) -> None:
                state["killed"] = True

            async def wait(self) -> int:
                state["waited"] = True
                return 0

        async def fake_exec(*_args, **_kwargs):
            return FakeProc()

        monkeypatch.setattr("asyncio.create_subprocess_exec", fake_exec)
        result = json.loads(await TSharkClient()._run_command(["tshark", "-v"], timeout=0.01))
        assert result["error"]["type"] == "TimeoutError"
        assert state == {"killed": True, "waited": True}

    @pytest.mark.asyncio
    async def test_cancellation_kills_and_waits_proc(self, monkeypatch) -> None:
        state = {"killed": False, "waited": False}

        class FakeProc:
            returncode = 0
            stdout = None
            stderr = None

            async def communicate(self) -> tuple[bytes, bytes]:
                await asyncio.sleep(10)
                return b"", b""

            def kill(self) -> None:
                state["killed"] = True

            async def wait(self) -> int:
                state["waited"] = True
                return 0

        async def fake_exec(*_args, **_kwargs):
            return FakeProc()

        monkeypatch.setattr("asyncio.create_subprocess_exec", fake_exec)
        client = TSharkClient()
        task = asyncio.create_task(client._run_command(["tshark", "-v"]))
        await asyncio.sleep(0.01)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert state == {"killed": True, "waited": True}


class TestEnvelopeContract:
    """The client must always return an envelope, so `data` is never re-parsed."""

    def test_ok_wraps_data_as_string(self) -> None:
        wrapped = json.loads(TSharkClient._ok("hello"))
        assert wrapped == {"success": True, "data": "hello"}

    def test_stderr_kept_out_of_data(self) -> None:
        # Diagnostic stderr must not corrupt structured data (e.g. -T json).
        wrapped = json.loads(TSharkClient._ok('[{"frame":1}]', stderr="tshark: warning"))
        assert wrapped["data"] == '[{"frame":1}]'
        assert json.loads(wrapped["data"]) == [{"frame": 1}]  # data stays parseable
        assert wrapped["stderr"] == "tshark: warning"

    def test_unwrap_success_returns_data(self) -> None:
        ok, text = TSharkClient._unwrap(TSharkClient._ok("payload"))
        assert ok is True
        assert text == "payload"

    def test_unwrap_error_propagates_envelope(self) -> None:
        err = json.dumps({"success": False, "error": {"type": "X", "message": "boom"}})
        ok, text = TSharkClient._unwrap(err)
        assert ok is False
        assert text == err

    def test_unwrap_tolerates_bare_text(self) -> None:
        ok, text = TSharkClient._unwrap("just raw text")
        assert ok is True
        assert text == "just raw text"


class TestFieldRowStreaming:
    @pytest.mark.asyncio
    async def test_stream_fields_consumes_rows_incrementally(self, monkeypatch, tmp_pcap: str) -> None:
        captured_command: tuple[str, ...] = ()

        class FakeStream:
            def __init__(self, chunks: list[bytes]) -> None:
                self.chunks = chunks

            async def readline(self) -> bytes:
                return self.chunks.pop(0) if self.chunks else b""

            async def read(self, _maximum: int) -> bytes:
                return self.chunks.pop(0) if self.chunks else b""

        class FakeProc:
            returncode = 0
            stdout = FakeStream(
                [
                    b"frame.number\tip.src\n",
                    b'"1"\t"10.0.0.1"\n',
                    b'"2"\t"10.0.0.2"\n',
                ]
            )
            stderr = FakeStream([b"diagnostic\n"])

            def kill(self) -> None:  # pragma: no cover - successful completion
                raise AssertionError("completed stream must not be killed")

            async def wait(self) -> int:
                return 0

        async def fake_exec(*args, **_kwargs):
            nonlocal captured_command
            captured_command = args
            return FakeProc()

        monkeypatch.setattr("asyncio.create_subprocess_exec", fake_exec)
        consumed: list[list[str]] = []

        result = await TSharkClient().stream_fields(
            tmp_pcap,
            ["frame.number", "ip.src"],
            consumed.append,
            display_filter="ip",
            max_rows=10,
        )

        assert result["success"] is True
        assert result["rows"] == 2
        assert consumed == [["1", "10.0.0.1"], ["2", "10.0.0.2"]]
        assert result["stderr"] == "diagnostic\n"
        assert "-n" in captured_command
        assert captured_command[captured_command.index("-Y") + 1] == "ip"
        assert "separator=/t" in captured_command

    @pytest.mark.asyncio
    async def test_stream_row_limit_kills_and_reaps_subprocess(self, monkeypatch) -> None:
        state = {"killed": False, "waited": False}

        class FakeStream:
            def __init__(self) -> None:
                self.lines = iter([b"header\n", b"1\n", b"2\n", b"3\n"])

            async def readline(self) -> bytes:
                return next(self.lines, b"")

        class FakeProc:
            returncode = 0
            stdout = FakeStream()
            stderr = None

            def kill(self) -> None:
                state["killed"] = True

            async def wait(self) -> int:
                state["waited"] = True
                return 0

        async def fake_exec(*_args, **_kwargs):
            return FakeProc()

        monkeypatch.setattr("asyncio.create_subprocess_exec", fake_exec)
        consumed: list[list[str]] = []
        client = TSharkClient()

        result = await client._stream_field_rows([client.tshark_path], consumed.append, max_rows=2)

        assert result["success"] is False
        assert result["error"]["type"] == "LimitExceeded"
        assert result["rows"] == 2
        assert consumed == [["1"], ["2"]]
        assert state == {"killed": True, "waited": True}

    @pytest.mark.asyncio
    async def test_stream_byte_limit_kills_before_consuming_oversized_row(self, monkeypatch) -> None:
        state = {"killed": False, "waited": False}

        class FakeStream:
            def __init__(self) -> None:
                self.lines = iter([b"header\n", b"1\n"])

            async def readline(self) -> bytes:
                return next(self.lines, b"")

        class FakeProc:
            returncode = 0
            stdout = FakeStream()
            stderr = None

            def kill(self) -> None:
                state["killed"] = True

            async def wait(self) -> int:
                state["waited"] = True
                return 0

        async def fake_exec(*_args, **_kwargs):
            return FakeProc()

        monkeypatch.setattr("asyncio.create_subprocess_exec", fake_exec)
        consumed: list[list[str]] = []
        client = TSharkClient()
        client.MAX_STREAM_STDOUT_BYTES = 8

        result = await client._stream_field_rows([client.tshark_path], consumed.append, max_rows=10)

        assert result["success"] is False
        assert result["error"]["type"] == "LimitExceeded"
        assert result["rows"] == 0
        assert consumed == []
        assert state == {"killed": True, "waited": True}

    @pytest.mark.asyncio
    async def test_stream_cancellation_kills_and_reaps_subprocess(self, monkeypatch) -> None:
        state = {"killed": False, "waited": False}

        class WaitingStream:
            async def readline(self) -> bytes:
                await asyncio.sleep(10)
                return b""

        class FakeProc:
            returncode = None
            stdout = WaitingStream()
            stderr = None

            def kill(self) -> None:
                state["killed"] = True

            async def wait(self) -> int:
                state["waited"] = True
                return 0

        async def fake_exec(*_args, **_kwargs):
            return FakeProc()

        monkeypatch.setattr("asyncio.create_subprocess_exec", fake_exec)
        client = TSharkClient()
        task = asyncio.create_task(client._stream_field_rows([client.tshark_path], lambda _row: None, max_rows=2))
        await asyncio.sleep(0.01)
        task.cancel()

        with pytest.raises(asyncio.CancelledError):
            await task
        assert state == {"killed": True, "waited": True}


class TestEnvelopeDataClassification:
    @pytest.mark.asyncio
    async def test_packet_data_mimicking_error_is_not_misclassified(self, monkeypatch, tmp_path) -> None:
        """Regression: field data that looks like {"success": false} must stay data."""
        from wireshark_mcp.tools.envelope import parse_tool_result

        pcap = tmp_path / "cap.pcap"
        pcap.write_bytes(b"\x00" * 64)
        evil = '{"success": false, "error": "this is packet DATA not an error"}'

        class FakeProc:
            returncode = 0

            async def communicate(self):
                return evil.encode(), b""

            def kill(self) -> None:  # pragma: no cover
                pass

        async def fake_exec(*_args, **_kwargs):
            return FakeProc()

        monkeypatch.setattr("asyncio.create_subprocess_exec", fake_exec)

        client = TSharkClient()
        raw = await client._run_command([client.tshark_path, "-r", str(pcap), "-T", "fields"])
        wrapped = parse_tool_result(raw)

        assert wrapped["success"] is True
        assert wrapped["data"] == evil


class TestPagination:
    """Tests for offset/limit windowing and cache/pagination independence."""

    def test_paginate_windows_and_marks_truncation(self) -> None:
        output = "\n".join(str(i) for i in range(10))
        text, truncated = TSharkClient._paginate(output, limit_lines=3, offset_lines=0)
        assert text.startswith("0\n1\n2")
        assert truncated is True
        assert "Next: offset=3" in text

    def test_paginate_offset_slices_from_start(self) -> None:
        output = "\n".join(str(i) for i in range(10))
        text, truncated = TSharkClient._paginate(output, limit_lines=0, offset_lines=5)
        assert text == "5\n6\n7\n8\n9"
        assert truncated is False

    def test_paginate_no_limit_returns_all(self) -> None:
        output = "a\nb\nc"
        text, truncated = TSharkClient._paginate(output, limit_lines=0, offset_lines=0)
        assert text == "a\nb\nc"
        assert truncated is False

    def test_output_paths_detects_write_target(self) -> None:
        assert TSharkClient._output_paths(["mergecap", "-w", "out.pcap", "a.pcap"]) == ["out.pcap"]
        assert TSharkClient._output_paths(["tshark", "-r", "in.pcap"]) == []

    @pytest.mark.asyncio
    async def test_different_offsets_do_not_pollute_cache(self, monkeypatch, tmp_path) -> None:
        """Regression: paginated reads must not overwrite each other in the cache."""
        pcap = tmp_path / "cap.pcap"
        pcap.write_bytes(b"\x00" * 64)
        full = "\n".join(f"row{i}" for i in range(6))

        client = TSharkClient()
        calls = {"n": 0}

        class FakeProc:
            returncode = 0

            async def communicate(self):
                calls["n"] += 1
                return full.encode(), b""

            def kill(self) -> None:  # pragma: no cover - not reached
                pass

        async def fake_exec(*_args, **_kwargs):
            return FakeProc()

        monkeypatch.setattr("asyncio.create_subprocess_exec", fake_exec)

        cmd = [client.tshark_path, "-r", str(pcap), "-T", "fields"]

        _, first = client._unwrap(await client._run_command(cmd, limit_lines=2, offset_lines=0))
        assert first.startswith("row0\nrow1")
        assert "Next: offset=2" in first

        # Second call: same command, different window — served from cache, correct slice.
        _, second = client._unwrap(await client._run_command(cmd, limit_lines=0, offset_lines=4))
        assert second == "row4\nrow5"
        assert calls["n"] == 1  # subprocess ran only once; window applied post-cache

    @pytest.mark.asyncio
    async def test_stream_limit_terminates_early_when_limit_exceeded(self, monkeypatch, tmp_path) -> None:
        pcap = tmp_path / "cap.pcap"
        pcap.write_bytes(b"\x00" * 64)

        killed = {"called": False}
        read_lines_count = {"n": 0}
        total_available = 10

        class FakeStream:
            async def readline(self) -> bytes:
                if read_lines_count["n"] < total_available:
                    line = f"packet_{read_lines_count['n']}\n".encode()
                    read_lines_count["n"] += 1
                    return line
                return b""

        class FakeProc:
            returncode = 0
            stdout = FakeStream()
            stderr = None

            def kill(self) -> None:
                killed["called"] = True

            async def wait(self) -> int:
                return 0

        async def fake_exec(*_args, **_kwargs):
            return FakeProc()

        monkeypatch.setattr("asyncio.create_subprocess_exec", fake_exec)

        client = TSharkClient()
        cmd = [client.tshark_path, "-r", str(pcap), "-T", "fields"]
        raw = await client._run_command(cmd, limit_lines=3, stream_limit=True)
        wrapped = json.loads(raw)

        assert wrapped["success"] is True
        assert wrapped["truncated"] is True
        assert killed["called"] is True
        # Read exactly limit + 1 (4 lines) before terminating
        assert read_lines_count["n"] == 4
        assert "packet_0\npacket_1\npacket_2" in wrapped["data"]
        assert "[Showing 3/4 lines. Next: offset=3]" in wrapped["data"]
        # Incomplete output must never pollute the cache
        assert client._cache.get(str(pcap), cmd) is None

    @pytest.mark.asyncio
    async def test_stream_limit_caches_when_within_limit(self, monkeypatch, tmp_path) -> None:
        pcap = tmp_path / "cap.pcap"
        pcap.write_bytes(b"\x00" * 64)

        killed = {"called": False}
        read_lines_count = {"n": 0}
        items = ["line0\n", "line1\n"]

        class FakeStream:
            async def readline(self) -> bytes:
                if read_lines_count["n"] < len(items):
                    line = items[read_lines_count["n"]].encode()
                    read_lines_count["n"] += 1
                    return line
                return b""

        class FakeProc:
            returncode = 0
            stdout = FakeStream()
            stderr = None

            def kill(self) -> None:
                killed["called"] = True

            async def wait(self) -> int:
                return 0

        async def fake_exec(*_args, **_kwargs):
            return FakeProc()

        monkeypatch.setattr("asyncio.create_subprocess_exec", fake_exec)

        client = TSharkClient()
        cmd = [client.tshark_path, "-r", str(pcap), "-T", "fields"]
        raw = await client._run_command(cmd, limit_lines=5, stream_limit=True)
        wrapped = json.loads(raw)

        assert wrapped["success"] is True
        assert "truncated" not in wrapped
        assert killed["called"] is False
        assert wrapped["data"] == "line0\nline1"
        # Naturally completed output IS cached
        assert client._cache.get(str(pcap), cmd) == "line0\nline1"


class TestSuiteBehavior:
    @pytest.mark.asyncio
    async def test_list_interfaces_prefers_dumpcap_when_available(self, mock_client) -> None:
        result = await mock_client.list_interfaces()
        assert "dumpcap" in result
        assert mock_client._last_cmd[0] == "dumpcap"

    @pytest.mark.asyncio
    async def test_list_interfaces_falls_back_to_tshark(self, mock_client) -> None:
        mock_client.dumpcap_path = None
        mock_client._tool_paths["dumpcap"] = None

        result = await mock_client.list_interfaces()
        assert "tshark" in result
        assert mock_client._last_cmd[0] == "tshark"

    @pytest.mark.asyncio
    async def test_capture_prefers_dumpcap_when_available(self, mock_client) -> None:
        result = await mock_client.capture_packets("en0", "/tmp/out.pcapng", duration=10)
        assert "dumpcap" in result
        assert mock_client._last_cmd[0] == "dumpcap"

    @pytest.mark.asyncio
    async def test_capture_falls_back_to_tshark(self, mock_client) -> None:
        mock_client.dumpcap_path = None
        mock_client._tool_paths["dumpcap"] = None

        result = await mock_client.capture_packets("en0", "/tmp/out.pcapng", duration=10)
        assert "tshark" in result
        assert mock_client._last_cmd[0] == "tshark"
