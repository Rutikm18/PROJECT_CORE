"""
agent/os/macos/diagnostics.py — self-diagnostic / log decoder for the macOS agent.

Turns the manual troubleshooting we keep doing by hand into runnable code:

  1. MESSAGE_CATALOG — every known agent log line decoded into
     {level, meaning, why, fix}. `explain(line)` maps a raw log line to it.
  2. scan_log()      — reads agent.log and classifies recent activity:
                       collector timeouts (per section), open circuit breakers,
                       restarts, and the "Replaying N" backlog trend that proves
                       a spool storm.
  3. probe_manager() — the blocker the log itself can't show: is the configured
                       manager URL actually the manager, or a rogue/wrong server
                       (e.g. a stray `python -m http.server`) returning 404 HTML?
                       Also flags plain-HTTP and unreachable.
  4. check_spool()   — current offline backlog size.
  5. diagnose()      — runs all of the above into one structured report;
                       format_report() renders it; `python3 -m
                       agent.os.macos.diagnostics` (or run directly) prints it.

Every probe is wrapped so the diagnostic NEVER raises — a broken diagnostic
that crashes is worse than no diagnostic. Read-only: opens log/config/spool and
does a single GET to the manager's /health. No agent state is modified.
"""
from __future__ import annotations

import json
import os
import re
import socket
import subprocess
import sys
import urllib.error
import urllib.request

try:
    import tomllib
except ImportError:  # pragma: no cover - 3.9/3.10 backport
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ImportError:
        tomllib = None  # type: ignore[assignment]

# ── Canonical macOS paths (match agent/core.py) ───────────────────────────────
LOG_FILE    = "/Library/AttackLens/logs/agent.log"
STDERR_LOG  = "/Library/AttackLens/logs/agent-stderr.log"
CONFIG_FILE = "/Library/AttackLens/agent.toml"
SPOOL_FILE  = "/Library/AttackLens/spool/unsent.ndjson"
STATUS_FILE = "/Library/AttackLens/health.json"


# ── 1. Known-message catalog ──────────────────────────────────────────────────
# Ordered most-specific → most-general; explain() returns the first match.
# `pattern` is a regex tested against the message portion of a log line.

MESSAGE_CATALOG: list[dict] = [
    {
        "id": "collector_timeout",
        "pattern": r"Collector .* timed out \(limit=\d+s\)",
        "level": "ERROR",
        "meaning": "A collector didn't finish in its time budget; the engine abandoned it.",
        "why": "The collector-timeout safety net — converts a hang into a recoverable "
               "failure instead of freezing the section forever.",
        "fix": "Usually transient under load. If ONE section repeats every cycle, that "
               "collector's underlying tool is slow/stuck (see the matching "
               "'Timed out after Ns:' line). Persistent storms are almost always the "
               "spool backlog starving CPU — clear the spool / restore the manager.",
    },
    {
        "id": "subprocess_timeout",
        "pattern": r"Timed out after \d+s: (?P<cmd>.+)",
        "level": "WARNING",
        "meaning": "The OS tool a collector shells out to was killed at its own deadline.",
        "why": "These tools are genuinely slow — docker ps (Docker Desktop), "
               "system_profiler (hardware enumeration), pip3 list (package indexing), "
               "plutil (plist parsing) — especially when the box is under load.",
        "fix": "Benign if occasional. If docker ps times out constantly, Docker Desktop "
               "is down/slow. If system_profiler does, the machine is busy — often the "
               "spool storm; fix that first.",
    },
    {
        "id": "circuit_open",
        "pattern": r"circuit OPEN after \d+ failures",
        "level": "WARNING",
        "meaning": "A section failed 3× in a row, so it's paused for the cooldown (60s).",
        "why": "Stops a broken collector from retrying every cycle and wasting CPU.",
        "fix": "Self-recovers — it will be probed again after the cooldown. Only act if a "
               "section stays OPEN for many minutes (its tool is persistently failing).",
    },
    {
        "id": "circuit_closed",
        "pattern": r"circuit CLOSED after recovery",
        "level": "INFO",
        "meaning": "A paused section was probed, worked, and resumed.",
        "why": "Normal self-healing — the good half of the circuit breaker.",
        "fix": "None — informational.",
    },
    {
        "id": "shutdown",
        "pattern": r"Shutting down \(signal \d+\)",
        "level": "INFO",
        "meaning": "Clean SIGTERM stop.",
        "why": "Each attacklens-service stop/restart, or launchd unloading the daemon.",
        "fix": "None if you initiated it. Frequent unexplained shutdowns → check the "
               "watchdog log and launchd (a crash-loop restart pattern).",
    },
    {
        "id": "replay_spool",
        "pattern": r"Replaying (?P<n>\d+) spooled envelopes",
        "level": "INFO",
        "meaning": "On startup, buffered offline data is re-queued for delivery.",
        "why": "The manager was unreachable while the agent ran, so telemetry piled up "
               "on disk and is now being replayed.",
        "fix": "Normal after an outage — it drains automatically once the manager is "
               "reachable. A backlog that GROWS across restarts means the manager is "
               "still unreachable (see probe_manager).",
    },
    {
        "id": "queue_full",
        "pattern": r"Send queue full \(max=\d+\)",
        "level": "WARNING",
        "meaning": "In-memory queue overflowed; the oldest item was spilled back to the "
                   "disk spool (NOT dropped).",
        "why": "Backpressure — the sender can't drain because the manager isn't "
               "accepting data fast enough (usually unreachable).",
        "fix": "Restore manager connectivity. Raising [manager] max_queue_size only "
               "delays the spill; it doesn't fix the root cause.",
    },
    {
        "id": "cpu_freq_implausible",
        "pattern": r"cpu_freq\(\) returned implausible value",
        "level": "WARNING",
        "meaning": "psutil reported a bogus CPU frequency; the agent discarded it (null).",
        "why": "Known psutil/Apple-Silicon limitation — the accuracy guard working as "
               "designed (better a null than a confidently-wrong number).",
        "fix": "None — cosmetic. cpu_freq_mhz is simply reported as null on this hardware.",
    },
    {
        "id": "plain_http",
        "pattern": r"Manager URL is plain HTTP",
        "level": "WARNING",
        "meaning": "Telemetry is sent unencrypted.",
        "why": "The [manager] url is http:// (no TLS). Fine for localhost; unsafe over a "
               "real network.",
        "fix": "For anything beyond localhost, use https:// with a valid cert and set "
               "tls_verify=true.",
    },
    {
        "id": "http_401",
        "pattern": r"HTTP 401",
        "level": "WARNING",
        "meaning": "The manager rejected the agent's API key.",
        "why": "Key invalidated/rotated, or the agent was pointed at a different manager "
               "that doesn't know it.",
        "fix": "Auto re-enrolls after 3 consecutive 401s. If it persists: "
               "sudo attacklens-service enroll.",
    },
    {
        "id": "enroll_fail",
        "pattern": r"Enrollment failed",
        "level": "WARNING",
        "meaning": "First-run registration with the manager could not complete.",
        "why": "Manager unreachable at boot, or an enrollment token is required/wrong.",
        "fix": "Start the manager first, then restart the agent. Token mode: set "
               "[enrollment] token in agent.toml.",
    },
]

_CATALOG_RE = [(re.compile(e["pattern"]), e) for e in MESSAGE_CATALOG]

# Pull the message out of a standard log line:
#   "2026-06-22 09:43:08,040 agent.circuit_breaker WARNING [ports] circuit OPEN ..."
_LINE_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} [\d:,]+)\s+(?P<logger>\S+)\s+"
    r"(?P<level>DEBUG|INFO|WARNING|ERROR|CRITICAL)\s+(?P<msg>.*)$"
)


def explain(line: str) -> dict | None:
    """Decode a single raw log line → its catalog entry (with the original line
    and parsed fields attached), or None if unrecognised."""
    if not line:
        return None
    m = _LINE_RE.match(line.strip())
    msg = m.group("msg") if m else line.strip()
    for rx, entry in _CATALOG_RE:
        hit = rx.search(msg)
        if hit:
            out = dict(entry)
            out["line"] = line.strip()
            out["captures"] = hit.groupdict()
            if m:
                out["timestamp"] = m.group("ts")
                out["logger"] = m.group("logger")
            return out
    return None


# ── 2. Log scan ───────────────────────────────────────────────────────────────

def _read_tail(path: str, max_lines: int = 4000) -> tuple[list[str], str | None]:
    """Return (lines, error). Never raises — a permission/FS error becomes a
    human string so the report can explain it (logs are root-owned: run sudo)."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
        return lines[-max_lines:], None
    except FileNotFoundError:
        return [], f"log not found at {path} (agent may never have started)"
    except PermissionError:
        return [], f"permission denied reading {path} (run with sudo)"
    except Exception as exc:  # noqa: BLE001 - diagnostic must not crash
        return [], f"could not read {path}: {exc}"


def scan_log(path: str = LOG_FILE, max_lines: int = 4000) -> dict:
    """Classify recent log activity into an actionable summary."""
    lines, err = _read_tail(path, max_lines)
    summary: dict = {
        "path": path,
        "error": err,
        "counts": {},                  # message id → occurrences
        "timeouts_by_section": {},     # section → count
        "open_circuits": [],           # sections seen going OPEN
        "replay_values": [],           # successive "Replaying N" counts
        "restarts": 0,
        "recent_examples": [],         # one decoded example per message id
    }
    if err:
        return summary

    seen_ids: set[str] = set()
    for line in lines:
        if "agent starting" in line:
            summary["restarts"] += 1
        decoded = explain(line)
        if not decoded:
            continue
        mid = decoded["id"]
        summary["counts"][mid] = summary["counts"].get(mid, 0) + 1
        if mid not in seen_ids:
            seen_ids.add(mid)
            summary["recent_examples"].append({
                "id": mid, "level": decoded["level"],
                "meaning": decoded["meaning"], "why": decoded["why"],
                "fix": decoded["fix"], "example": decoded["line"],
            })
        if mid == "collector_timeout":
            sm = re.search(r"Collector (\S+) timed out", line)
            if sm:
                s = sm.group(1)
                summary["timeouts_by_section"][s] = \
                    summary["timeouts_by_section"].get(s, 0) + 1
        elif mid == "circuit_open":
            cm = re.search(r"\[(\w+)\] circuit OPEN", line)
            if cm and cm.group(1) not in summary["open_circuits"]:
                summary["open_circuits"].append(cm.group(1))
        elif mid == "replay_spool":
            try:
                summary["replay_values"].append(int(decoded["captures"]["n"]))
            except (KeyError, ValueError, TypeError):
                pass

    # Interpret the backlog trend: growing across restarts == manager still down.
    rv = summary["replay_values"]
    if len(rv) >= 2 and rv[-1] > rv[0]:
        summary["backlog_trend"] = (
            f"GROWING ({rv[0]} → {rv[-1]}) — the spool is not draining; the manager "
            f"has stayed unreachable across restarts."
        )
    elif rv:
        summary["backlog_trend"] = f"last replay backlog: {rv[-1]} envelopes"
    else:
        summary["backlog_trend"] = "no spool replay seen (clean) "
    return summary


# ── 3. Manager probe (the blocker the log can't show) ─────────────────────────

def _port_from_url(url: str) -> int | None:
    """Extract the TCP port from a manager URL (defaults: http=80, https=443)."""
    try:
        m = re.match(r"(?P<scheme>https?)://(?P<host>[^/:]+)(?::(?P<port>\d+))?", url)
        if not m:
            return None
        if m.group("port"):
            return int(m.group("port"))
        return 443 if m.group("scheme") == "https" else 80
    except Exception:  # noqa: BLE001
        return None


def port_listeners(port: int) -> list[dict]:
    """Best-effort: who is LISTENing on `port`. Returns [{pid, command, addr}].

    Used to NAME the exact process squatting the manager port — so the fix can
    say `kill <pid>` instead of a generic 'find and kill it'. The classic case:
    a `python -m http.server` bound to IPv4 127.0.0.1:8080 shadows Docker's
    `*:8080` manager forward, so every agent POST hits the static server and
    404s. Never raises; returns [] if lsof is unavailable or denied.
    """
    listeners: list[dict] = []
    try:
        r = subprocess.run(
            ["lsof", "-nP", f"-iTCP:{port}", "-sTCP:LISTEN"],
            capture_output=True, text=True, timeout=8,
        )
        for line in r.stdout.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 9:
                continue
            # lsof NAME column (parts[8]) is the bind address, e.g.
            # "127.0.0.1:8080"; parts[-1] is the "(LISTEN)" state.
            listeners.append({"command": parts[0], "pid": parts[1],
                              "addr": parts[8]})
    except Exception:  # noqa: BLE001
        pass
    return listeners


def _rogue_pid_hint(port: int) -> str:
    """Build a precise kill instruction naming the non-Docker squatter, plus the
    IPv4-loopback-shadow explanation when a Docker listener is also present."""
    lst = port_listeners(port)
    if not lst:
        return (f"Find and kill the rogue listener:\n"
                f"      lsof -nP -iTCP:{port} -sTCP:LISTEN\n"
                f"      pkill -f 'http.server'")
    docker = [x for x in lst if x["command"].lower().startswith(("com.docke", "docker"))]
    rogue = [x for x in lst if x not in docker]
    lines = ["Listeners on this port:"]
    for x in lst:
        lines.append(f"        {x['command']} PID {x['pid']} {x['addr']}")
    if rogue:
        pids = " ".join(x["pid"] for x in rogue)
        lines.append(f"      Kill the non-manager listener:  kill {pids}")
        if docker:
            lines.append("      (It is bound to IPv4 loopback and SHADOWS Docker's "
                         f"*:{port} manager forward — killing it restores the manager.)")
    else:
        lines.append("      pkill -f 'http.server'")
    return "\n".join(lines)


def _manager_url(config_file: str = CONFIG_FILE) -> str | None:
    if tomllib is None:
        return None
    try:
        with open(config_file, "rb") as f:
            cfg = tomllib.load(f)
        url = (cfg.get("manager") or {}).get("url")
        return url.rstrip("/") if isinstance(url, str) and url else None
    except FileNotFoundError:
        return None
    except Exception:  # noqa: BLE001
        return None


def probe_manager(url: str | None = None, timeout: float = 6.0) -> dict:
    """Classify what's actually answering at the configured manager URL.

    verdict ∈ {ok, rogue_server, wrong_endpoint, unreachable, plain_http_warn,
    no_url, error}. The 'rogue_server' verdict is the exact failure where a stray
    `python -m http.server` (or any non-manager) squats the port and 404s every
    POST, so telemetry is silently dropped and the dashboard stays empty.
    """
    result: dict = {"url": url, "verdict": "error", "detail": "", "fix": ""}
    if url is None:
        url = _manager_url()
        result["url"] = url
    if not url:
        result.update(verdict="no_url",
                      detail="No [manager] url in agent.toml (or config unreadable).",
                      fix="Set [manager] url, e.g. sudo attacklens-service set-manager <IP>.")
        return result

    if url.startswith("http://"):
        result["plain_http"] = True

    health = url + "/health"
    try:
        req = urllib.request.Request(health, method="GET",
                                     headers={"User-Agent": "attacklens-diagnostics"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status = resp.status
            server = resp.headers.get("Server", "")
            body = resp.read(4096).decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        status = exc.code
        server = (exc.headers or {}).get("Server", "")
        try:
            body = exc.read(4096).decode("utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            body = ""
    except (urllib.error.URLError, socket.timeout, TimeoutError, OSError) as exc:
        result.update(
            verdict="unreachable",
            detail=f"{health} is not reachable ({exc}).",
            fix="Start the manager (e.g. docker compose up -d) and confirm the host/port "
                "in [manager] url is correct.",
        )
        return result
    except Exception as exc:  # noqa: BLE001
        result.update(verdict="error", detail=f"probe failed: {exc}")
        return result

    result["http_status"] = status
    result["server_header"] = server

    # Real manager: 200 + JSON body with manager-ish keys.
    looks_static = ("SimpleHTTP" in server) or body.lstrip()[:9].lower() == "<!doctype" \
        or body.lstrip()[:5].lower() == "<html"
    parsed = None
    try:
        parsed = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        parsed = None

    if status == 200 and isinstance(parsed, dict) and (
        "status" in parsed or "db" in parsed or "store" in parsed
    ):
        result.update(verdict="ok",
                      detail="Manager /health responded with valid JSON.",
                      fix="")
    elif looks_static or (parsed is None and status in (200, 404)):
        port = _port_from_url(url)
        kill_hint = _rogue_pid_hint(port) if port else \
            "      lsof -nP -iTCP:<port> -sTCP:LISTEN ; pkill -f 'http.server'"
        result["listeners"] = port_listeners(port) if port else []
        result.update(
            verdict="rogue_server",
            detail=(f"Port is answered by a NON-manager server "
                    f"(Server={server or 'unknown'!r}, HTTP {status}, non-JSON body). "
                    f"A stray static server (e.g. `python -m http.server`) is squatting "
                    f"the manager's port — every telemetry POST 404s and is dropped."),
            fix=(f"{kill_hint}\n"
                 f"      curl -s {health}   # should return manager JSON, not HTML\n"
                 f"      Don't run `python -m http.server` on the manager port; use "
                 f"another port (e.g. 8000) to share files."),
        )
    elif status == 401:
        result.update(verdict="wrong_endpoint",
                      detail="Manager returned 401 to /health (auth/endpoint mismatch).",
                      fix="Verify the URL points at the manager root; check enrollment.")
    else:
        result.update(
            verdict="wrong_endpoint",
            detail=f"Unexpected /health response (HTTP {status}, not manager JSON).",
            fix="Confirm [manager] url points at the AttackLens manager, not another service.",
        )
    return result


# ── 4. Spool check ────────────────────────────────────────────────────────────

def check_spool(path: str = SPOOL_FILE) -> dict:
    try:
        size = os.path.getsize(path)
    except FileNotFoundError:
        return {"path": path, "exists": False, "bytes": 0,
                "note": "no spool file — nothing buffered (good, or never written)"}
    except PermissionError:
        return {"path": path, "exists": True, "bytes": None,
                "note": "permission denied (run with sudo) — cannot size the spool"}
    except Exception as exc:  # noqa: BLE001
        return {"path": path, "exists": True, "bytes": None, "note": f"error: {exc}"}
    note = "empty — no offline backlog" if size == 0 else \
           f"{size/1_048_576:.1f} MB buffered offline (manager was/is unreachable)"
    return {"path": path, "exists": True, "bytes": size, "note": note}


# ── 5. Orchestration + rendering ──────────────────────────────────────────────

def diagnose(*, log_file: str = LOG_FILE, config_file: str = CONFIG_FILE,
             spool_file: str = SPOOL_FILE) -> dict:
    """Full read-only diagnosis. Never raises."""
    report: dict = {}
    try:
        report["log"] = scan_log(log_file)
    except Exception as exc:  # noqa: BLE001
        report["log"] = {"error": f"scan_log crashed: {exc}"}
    try:
        report["manager"] = probe_manager(_manager_url(config_file))
    except Exception as exc:  # noqa: BLE001
        report["manager"] = {"verdict": "error", "detail": f"probe crashed: {exc}"}
    try:
        report["spool"] = check_spool(spool_file)
    except Exception as exc:  # noqa: BLE001
        report["spool"] = {"note": f"check crashed: {exc}"}
    report["top_blocker"] = _top_blocker(report)
    return report


def _top_blocker(report: dict) -> str:
    """Single most important next action, derived from the worst finding."""
    mgr = report.get("manager", {})
    verdict = mgr.get("verdict")
    if verdict == "rogue_server":
        return ("A non-manager server is squatting the manager port — telemetry is being "
                "dropped. " + mgr.get("fix", ""))
    if verdict == "unreachable":
        return "The manager is unreachable — start it; the agent will auto-drain its spool."
    if verdict in ("wrong_endpoint", "no_url"):
        return mgr.get("fix") or "Fix the [manager] url so it points at the manager."
    log = report.get("log", {})
    if isinstance(log.get("backlog_trend"), str) and "GROWING" in log["backlog_trend"]:
        return "Spool backlog is growing — the manager isn't accepting data. Fix connectivity."
    if verdict == "ok":
        spool = report.get("spool", {})
        if spool.get("bytes"):
            return ("Manager reachable; a spool backlog is still draining — give it time, "
                    "watch it shrink.")
        return "No blocker detected — manager reachable and no backlog. Data should be flowing."
    return "Run with sudo for full log access, then re-check."


def format_report(report: dict) -> str:
    L = []
    L.append("")
    L.append("  AttackLens macOS Agent — Self Diagnosis")
    L.append("  " + "=" * 54)

    blk = report.get("top_blocker", "")
    L.append("")
    L.append("  ► TOP BLOCKER")
    for line in _wrap(blk, 70):
        L.append("    " + line)

    mgr = report.get("manager", {})
    L.append("")
    L.append("  [Manager link]")
    L.append(f"    url      : {mgr.get('url')}")
    L.append(f"    verdict  : {mgr.get('verdict')}"
             + (f"   (HTTP {mgr.get('http_status')}, "
                f"Server={mgr.get('server_header')!r})"
                if mgr.get("http_status") else ""))
    for line in _wrap(mgr.get("detail", ""), 70):
        L.append("    " + line)
    if mgr.get("plain_http"):
        L.append("    note     : plain HTTP — unencrypted (fine for localhost only)")
    if mgr.get("fix"):
        L.append("    fix:")
        for line in mgr["fix"].splitlines():
            L.append("      " + line)

    spool = report.get("spool", {})
    L.append("")
    L.append("  [Spool / offline backlog]")
    L.append(f"    {spool.get('note', '')}")

    log = report.get("log", {})
    L.append("")
    L.append("  [Log scan]")
    if log.get("error"):
        L.append(f"    {log['error']}")
    else:
        L.append(f"    restarts seen        : {log.get('restarts', 0)}")
        L.append(f"    backlog trend        : {log.get('backlog_trend', '')}")
        if log.get("open_circuits"):
            L.append(f"    sections tripped open: {', '.join(log['open_circuits'])}")
        tbs = log.get("timeouts_by_section") or {}
        if tbs:
            top = sorted(tbs.items(), key=lambda x: -x[1])[:6]
            L.append("    collector timeouts   : "
                     + ", ".join(f"{s}×{n}" for s, n in top))

    ex = (report.get("log", {}) or {}).get("recent_examples") or []
    if ex:
        L.append("")
        L.append("  [Message decode — what was seen in this log]")
        for e in ex:
            L.append(f"    • [{e['level']}] {e['id']}")
            for line in _wrap(e["meaning"], 66):
                L.append("        " + line)
            for line in _wrap("fix: " + e["fix"], 66):
                L.append("        " + line)
    L.append("")
    return "\n".join(L)


def _wrap(text: str, width: int) -> list[str]:
    if not text:
        return []
    words, cur, out = text.split(), "", []
    for w in words:
        if len(cur) + len(w) + 1 > width:
            out.append(cur)
            cur = w
        else:
            cur = f"{cur} {w}".strip()
    if cur:
        out.append(cur)
    return out


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    as_json = "--json" in argv
    report = diagnose()
    if as_json:
        print(json.dumps(report, indent=2, default=str))
    else:
        print(format_report(report))
    # Exit non-zero when there's a hard blocker, so it's scriptable.
    verdict = (report.get("manager") or {}).get("verdict")
    return 0 if verdict == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
