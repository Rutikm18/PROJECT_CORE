"""
agent/os/macos/collectors/volatile.py — High-frequency collectors (10 s interval).

  metrics     — CPU %, RAM, swap, disk I/O, network I/O, load average
  connections — Established TCP/UDP connections with process owner + private/public flag
  processes   — Top 80 processes by CPU with signing status
"""
from __future__ import annotations

import ipaddress
import logging
import os
import threading
import time

from .base import BaseCollector, CollectorResult, _run, codesign_trust

log = logging.getLogger("agent.collectors.volatile")

# Shared lock so psutil/lsof calls don't race on the same socket table
_NET_LOCK = threading.Lock()

# psutil.cpu_freq() is known to return implausible values on Apple Silicon
# (no public sysctl exposes per-cluster clock speed the way it does on
# Intel) — values seen in practice are off by orders of magnitude (e.g. a
# literal 4.0, presumably GHz mislabelled as MHz). No real Mac CPU in the
# last two decades runs outside this MHz range; anything else is discarded
# rather than shipped as a confidently-wrong number.
_CPU_FREQ_MIN_MHZ = 100
_CPU_FREQ_MAX_MHZ = 10_000
_warned_bad_cpu_freq = False

# psutil is optional but strongly recommended (ARM64 native wheel available)
try:
    import psutil as _psutil
    _HAS_PSUTIL = True
except ImportError:
    _psutil = None       # type: ignore[assignment]
    _HAS_PSUTIL = False


def _is_private_ip(addr: str) -> bool:
    try:
        return ipaddress.ip_address(addr).is_private
    except ValueError:
        return False


class MetricsCollector(BaseCollector):
    name = "metrics"

    # Disk/network counters from previous tick for delta calculation
    _prev_disk: object = None
    _prev_net:  object = None
    _prev_ts:   float  = 0.0

    def collect(self) -> dict:
        # Never let one bad psutil call (e.g. cpu_freq() raising on macOS) kill
        # the whole section — fall back to the CLI path, which can't raise.
        if _HAS_PSUTIL:
            try:
                return self._collect_psutil()
            except Exception:
                pass
        return self._collect_cli()

    def _collect_psutil(self) -> dict:
        now  = time.time()
        mem  = _psutil.virtual_memory()
        swap = _psutil.swap_memory()
        boot = _psutil.boot_time()

        # getloadavg() can be unavailable in some sandboxed contexts — guard it.
        try:
            load = _psutil.getloadavg()
        except Exception:
            load = (0.0, 0.0, 0.0)

        # Single sampling window for BOTH the aggregate and per-core CPU
        # percent. Calling cpu_percent(interval=1) and cpu_percent(percpu=True)
        # separately measures two DIFFERENT windows — the first forces a fresh
        # 1s sample, the second compares against whenever cpu_percent() was
        # last called (here, the previous collection cycle, ~one interval
        # ago). On a real device this consistently read the aggregate 2-4x
        # higher than the per-core average, every single sample — not noise,
        # a structural mismatch. One call, one window, so cpu_percent is
        # always exactly consistent with cpu_per_core by construction.
        try:
            cpu_per_core = _psutil.cpu_percent(interval=1, percpu=True)
        except Exception:
            cpu_per_core = []
        cpu = (sum(cpu_per_core) / len(cpu_per_core)) if cpu_per_core \
            else _psutil.cpu_percent(interval=1)

        # CPU frequency — psutil.cpu_freq() RAISES NotImplementedError on macOS
        # in many builds, and on Apple Silicon often returns an implausible
        # value instead of raising (no public per-cluster clock-speed sysctl).
        # Must be guarded or it takes the whole metrics section down
        # (circuit-breaker → no data); the range check below additionally
        # refuses to ship a confidently-wrong number when it doesn't raise.
        cpu_freq_mhz = None
        try:
            freq = _psutil.cpu_freq()
            if freq and freq.current and _CPU_FREQ_MIN_MHZ <= freq.current <= _CPU_FREQ_MAX_MHZ:
                cpu_freq_mhz = round(freq.current, 0)
            elif freq and freq.current:
                global _warned_bad_cpu_freq
                if not _warned_bad_cpu_freq:
                    log.warning(
                        "cpu_freq() returned implausible value %.1f (expected "
                        "%d-%d MHz) — reporting null instead of a wrong number; "
                        "known psutil/Apple Silicon limitation",
                        freq.current, _CPU_FREQ_MIN_MHZ, _CPU_FREQ_MAX_MHZ,
                    )
                    _warned_bad_cpu_freq = True
        except Exception:
            cpu_freq_mhz = None

        def _cores(logical):
            try:
                return _psutil.cpu_count(logical=logical)
            except Exception:
                return None

        # Disk I/O delta
        disk_read_mb_s = disk_write_mb_s = None
        try:
            disk_now = _psutil.disk_io_counters()
            if disk_now and MetricsCollector._prev_disk and MetricsCollector._prev_ts > 0:
                dt = now - MetricsCollector._prev_ts
                if dt > 0:
                    disk_read_mb_s  = round((disk_now.read_bytes  - MetricsCollector._prev_disk.read_bytes)  / dt / (1024*1024), 3)
                    disk_write_mb_s = round((disk_now.write_bytes - MetricsCollector._prev_disk.write_bytes) / dt / (1024*1024), 3)
            MetricsCollector._prev_disk = disk_now
        except Exception:
            pass

        # Network I/O delta
        net_sent_mb_s = net_recv_mb_s = None
        try:
            net_now = _psutil.net_io_counters()
            if net_now and MetricsCollector._prev_net and MetricsCollector._prev_ts > 0:
                dt = now - MetricsCollector._prev_ts
                if dt > 0:
                    net_sent_mb_s = round((net_now.bytes_sent - MetricsCollector._prev_net.bytes_sent) / dt / (1024*1024), 3)
                    net_recv_mb_s = round((net_now.bytes_recv - MetricsCollector._prev_net.bytes_recv) / dt / (1024*1024), 3)
            MetricsCollector._prev_net = net_now
        except Exception:
            pass

        MetricsCollector._prev_ts = now

        return {
            # Dashboard-expected field names (cpu_percent, mem_percent)
            "cpu_percent":      round(cpu, 1),
            "mem_percent":      round(mem.percent, 1),
            # Extended metrics
            "cpu_per_core":     [round(c, 1) for c in cpu_per_core],
            "cpu_cores":        _cores(True),
            "cpu_cores_physical": _cores(False),
            "cpu_freq_mhz":     cpu_freq_mhz,
            "mem_used_mb":      mem.used    // (1024 * 1024),
            "mem_total_mb":     mem.total   // (1024 * 1024),
            "mem_available_mb": mem.available // (1024 * 1024),
            "swap_percent":     round(swap.percent, 1),
            "swap_used_mb":     swap.used   // (1024 * 1024),
            "swap_total_mb":    swap.total  // (1024 * 1024),
            "load_1m":          round(load[0], 2),
            "load_5m":          round(load[1], 2),
            "load_15m":         round(load[2], 2),
            "disk_read_mb_s":   disk_read_mb_s,
            "disk_write_mb_s":  disk_write_mb_s,
            "net_sent_mb_s":    net_sent_mb_s,
            "net_recv_mb_s":    net_recv_mb_s,
            "uptime_sec":       int(now - boot),
        }

    def _collect_cli(self) -> dict:
        # Two-pass top for accurate CPU
        cpu_lines = _run(["top", "-l", "2", "-n", "0"]).split("\n")
        cpu_line  = next((l for l in reversed(cpu_lines) if "CPU usage" in l), "")
        return {
            "cpu_percent":  None,
            "mem_percent":  None,
            "cpu_raw":      cpu_line.strip(),
            "load_raw":     _run(["sysctl", "-n", "vm.loadavg"]).strip(),
            "vmstat_raw":   _run(["vm_stat"]).strip(),
            "swap_raw":     _run(["sysctl", "-n", "vm.swapusage"]).strip(),
        }


class ConnectionsCollector(BaseCollector):
    name = "connections"

    # Well-known service port → name mapping for enrichment
    _SERVICES: dict[int, str] = {
        20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
        53: "dns", 80: "http", 110: "pop3", 143: "imap", 443: "https",
        445: "smb", 465: "smtps", 587: "smtp-sub", 993: "imaps", 995: "pop3s",
        1080: "socks5", 1194: "openvpn", 1433: "mssql", 3306: "mysql",
        3389: "rdp", 4444: "meterpreter", 5432: "postgres", 5900: "vnc",
        6379: "redis", 6881: "bittorrent", 8080: "http-alt", 8443: "https-alt",
        9200: "elasticsearch", 27017: "mongodb",
    }

    def collect(self) -> list:
        with _NET_LOCK:
            if _HAS_PSUTIL:
                return self._collect_psutil()
            return self._collect_lsof()

    def _collect_psutil(self) -> list:
        pid_map: dict[int, dict] = {}
        try:
            for p in _psutil.process_iter(["pid", "name", "username"]):
                pid_map[p.info["pid"]] = {
                    "name": p.info["name"] or "",
                    "user": p.info["username"] or "",
                }
        except Exception:
            pass

        try:
            conns = _psutil.net_connections(kind="inet")
        except Exception:
            return self._collect_lsof()

        rows = []
        for c in conns:
            try:
                if c.status not in ("ESTABLISHED", "LISTEN", "CLOSE_WAIT", "TIME_WAIT"):
                    continue
                if not c.laddr:
                    continue
                remote_ip   = c.raddr.ip   if c.raddr else None
                remote_port = c.raddr.port if c.raddr else None
                proto = "tcp" if (c.type and c.type.name == "SOCK_STREAM") else "udp"
                proc  = pid_map.get(c.pid or -1, {})
                rows.append({
                    "proto":         proto,
                    "local_addr":    c.laddr.ip,
                    "local_port":    c.laddr.port,
                    "remote_addr":   remote_ip,
                    "remote_port":   remote_port,
                    "remote_service": self._SERVICES.get(remote_port or 0),
                    "state":         c.status,
                    "pid":           c.pid,
                    "process":       proc.get("name", ""),
                    "user":          proc.get("user", ""),
                    "is_private":    _is_private_ip(remote_ip) if remote_ip else True,
                    "direction":     "inbound" if c.status == "LISTEN" else "outbound",
                })
            except Exception:
                continue
        return rows

    def _collect_lsof(self) -> list:
        out  = _run(["lsof", "-nP", "-iTCP", "-sTCP:ESTABLISHED"])
        rows = []
        for line in out.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 9:
                continue
            addr_str = parts[8].split(" ")[0]
            # Parse local->remote
            if "->" in addr_str:
                local, remote = addr_str.split("->", 1)
            else:
                local, remote = addr_str, ""
            def _split(s: str):
                if ":" in s:
                    h, _, p = s.rpartition(":")
                    try:
                        return h, int(p)
                    except ValueError:
                        pass
                return s, 0
            local_ip, local_port   = _split(local)
            remote_ip, remote_port = _split(remote)
            rows.append({
                "proto":         "tcp",
                "local_addr":    local_ip,
                "local_port":    local_port,
                "remote_addr":   remote_ip or None,
                "remote_port":   remote_port or None,
                "remote_service": self._SERVICES.get(remote_port) if remote_port else None,
                "state":         "ESTABLISHED",
                "pid":           parts[1],
                "process":       parts[0],
                "user":          parts[2],
                "is_private":    _is_private_ip(remote_ip) if remote_ip else True,
                "direction":     "outbound",
            })
        return rows


class ProcessesCollector(BaseCollector):
    name = "processes"

    # Code-signing verdict cache, keyed by (exe_path, mtime). A binary's
    # signature can't change without its mtime changing, so this is safe to
    # keep across cycles — turning an ~80-call codesign sweep on a cold start
    # into near-zero work every 60 s thereafter. Bounded to avoid unbounded
    # growth on hosts that churn through many short-lived executables.
    _sign_cache: dict[tuple, "bool | None"] = {}
    _SIGN_CACHE_MAX = 4096

    def collect(self) -> list:
        if _HAS_PSUTIL:
            return self._collect_psutil()
        return self._collect_ps()

    def _signing_status(self, exe: str) -> "bool | None":
        """Cached, security-grade signing verdict for a process's executable.

        Fills the `signed` field the section has always advertised but never
        populated (it was hard-coded None) — an unsigned/ad-hoc process is one
        of the highest-value signals a process collector can surface.
        """
        if not exe:
            return None
        try:
            mtime = int(os.path.getmtime(exe))
        except OSError:
            return None
        key = (exe, mtime)
        cache = ProcessesCollector._sign_cache
        if key in cache:
            return cache[key]
        verdict = codesign_trust(exe)
        if len(cache) >= self._SIGN_CACHE_MAX:
            cache.clear()   # cheap bound; the hot set re-warms within a cycle
        cache[key] = verdict
        return verdict

    def _collect_psutil(self) -> list:
        attrs = ["pid", "ppid", "name", "username", "cpu_percent",
                 "memory_percent", "memory_info", "status", "create_time",
                 "cmdline", "exe"]
        procs = []
        try:
            _psutil.cpu_percent(interval=None)
            for p in _psutil.process_iter(attrs):
                try:
                    i = p.info
                    mem_info = i.get("memory_info")
                    rss = getattr(mem_info, "rss", 0) or 0
                    vms = getattr(mem_info, "vms", 0) or 0
                    cmd = " ".join(i.get("cmdline") or []) or i.get("name") or ""
                    exe = i.get("exe") or ""
                    procs.append({
                        "pid":          i["pid"],
                        "ppid":         i.get("ppid"),
                        "name":         i.get("name") or "",
                        "user":         i.get("username") or "",
                        "cpu_percent":  round(p.cpu_percent(interval=None), 2),
                        "mem_percent":  round(i.get("memory_percent") or 0.0, 3),
                        "mem_rss_mb":   rss // (1024 * 1024),
                        "mem_vms_mb":   vms // (1024 * 1024),
                        "status":       i.get("status") or "",
                        "started_at":   int(i.get("create_time") or 0),
                        "cmdline":      cmd[:512],
                        "exe":          exe,
                        "signed":       None,
                    })
                except (_psutil.NoSuchProcess, _psutil.AccessDenied):
                    pass
                except Exception:
                    pass
        except Exception:
            return self._collect_ps()
        # Enrich ONLY the top-80 we actually ship — bounds codesign work to ≤80
        # lookups on a cold cache (near-zero once warm), never the full table.
        top = sorted(procs, key=lambda x: x["cpu_percent"], reverse=True)[:80]
        for row in top:
            row["signed"] = self._signing_status(row.get("exe", ""))
        return top

    def _collect_ps(self) -> list:
        out  = _run(["ps", "-axo", "pid=,ppid=,user=,pcpu=,pmem=,rss=,stat=,comm="])
        rows = []
        for line in out.splitlines():
            parts = line.split(None, 7)
            if len(parts) == 8:
                rows.append({
                    "pid":         parts[0], "ppid":       parts[1],
                    "user":        parts[2], "cpu_percent": parts[3],
                    "mem_percent": parts[4], "mem_rss_mb":  str(int(parts[5]) // 1024),
                    "status":      parts[6], "name":        parts[7],
                    "exe": "", "signed": None,
                })
        return sorted(
            rows,
            key=lambda r: float(r["cpu_percent"]) if str(r["cpu_percent"]).replace(".", "").isdigit() else 0,
            reverse=True,
        )[:80]
