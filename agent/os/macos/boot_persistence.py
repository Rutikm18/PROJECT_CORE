"""
agent/os/macos/boot_persistence.py — guarantee the agent auto-launches after a
shutdown/reboot, survive tampering, and record boot transitions.

Base auto-start is already provided by the LaunchDaemon plist installed in
/Library/LaunchDaemons with `RunAtLoad=true` + `KeepAlive=true`: when the Mac is
shut down and later powered back on, launchd re-loads the plist at boot and
starts the agent on its own. This module hardens the gaps that RunAtLoad alone
CANNOT cover — and which silently defeat boot-persistence in the field:

  1. Persistence self-repair — on every agent startup, AND periodically while the
     agent runs (an in-process guard thread, see _start_persistence_guard_thread),
     verify the LaunchDaemon plist is present, well-formed (RunAtLoad + KeepAlive
     + the right binary path + label), owned root:wheel with 0644 perms, ENABLED
     in launchctl, and loaded. Repair any drift: rewrite a deleted/edited plist,
     fix ownership/perms, `launchctl enable` a disabled label, and (re)bootstrap
     an unloaded job. This defeats an attacker — or a botched uninstall — that
     deletes or `launchctl disable`s the plist to stop the agent from surviving
     the NEXT reboot (RunAtLoad never fires for a disabled/absent job, so
     KeepAlive can't save it either). The startup pass alone cannot catch tamper
     that happens WHILE the agent is up — a disabled/deleted plist would then only
     bite at the next power-off — so the periodic guard closes that window.

  2. Reboot detection — persist a small boot marker (kernel boot time + last
     heartbeat + a clean-stop flag). On startup, compare the stored kernel boot
     time with the live one: a change means the machine rebooted since the agent
     last ran. Emit a `system_boot` telemetry event with the estimated downtime
     and a clean/unexpected verdict (unexpected = the agent did NOT receive a
     graceful SIGTERM before the box went down — a power loss, panic, or kill).

Everything here is best-effort and MUST NEVER raise into the caller: persistence
repair and boot reporting run on the agent's critical startup path and must not
be able to crash it. Every public function returns a structured dict instead.
"""
from __future__ import annotations

import json
import logging
import os
import re
import subprocess
import sys
import threading
import time

log = logging.getLogger("agent.os.macos.boot_persistence")

# Marker file lives in the root-owned install dir alongside self_heal state.
_STATE_FILE = "/Library/AttackLens/boot_state.json"

# How far the wall clock must jump between marker updates before we still trust
# the previous "clean_stop" flag. (Unused directly; kept for symmetry/clarity.)
_HEARTBEAT_INTERVAL_SEC = 60

# A monotonic reference so repeated repairs don't thrash launchctl on a tight
# self_heal cadence (the plist rarely changes; re-bootstrapping every 5 min is
# wasteful and noisy). Only the *repair* actions are throttled — verification
# always runs.
_last_bootstrap_attempt = 0.0
_BOOTSTRAP_MIN_GAP_SEC = 60


# ── State marker I/O (atomic, never raises) ────────────────────────────────────

def _load_state() -> dict:
    try:
        with open(_STATE_FILE, encoding="utf-8") as f:
            obj = json.load(f)
        return obj if isinstance(obj, dict) else {}
    except FileNotFoundError:
        return {}
    except Exception as exc:  # noqa: BLE001 - marker I/O must never crash startup
        log.debug("boot_state read failed: %s", exc)
        return {}


def _save_state(state: dict) -> None:
    try:
        os.makedirs(os.path.dirname(_STATE_FILE), exist_ok=True)
        tmp = _STATE_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(state, f)
        os.replace(tmp, _STATE_FILE)
    except Exception as exc:  # noqa: BLE001
        log.debug("boot_state write failed: %s", exc)


# ── Kernel boot time ───────────────────────────────────────────────────────────

def _current_boot_time() -> int | None:
    """Kernel boot time as an epoch int, or None if it can't be determined.

    Prefers psutil (native ARM64 wheel present); falls back to
    `sysctl -n kern.boottime`, which every macOS ships, so a psutil import
    failure never blinds reboot detection.
    """
    try:
        import psutil  # local import: optional dep, avoid import cost at load
        return int(psutil.boot_time())
    except Exception:
        pass
    try:
        out = subprocess.check_output(
            ["sysctl", "-n", "kern.boottime"], text=True, timeout=5,
        )
        # Format: "{ sec = 1700000000, usec = 0 } Wed Nov 15 ..."
        m = re.search(r"sec\s*=\s*(\d+)", out)
        if m:
            return int(m.group(1))
    except Exception as exc:  # noqa: BLE001
        log.debug("kern.boottime probe failed: %s", exc)
    return None


# ── Reboot detection ───────────────────────────────────────────────────────────

def detect_boot_transition() -> dict:
    """Compare the stored kernel boot time against the live one and persist the
    updated marker. Returns a structured verdict; NEVER raises.

    Keys:
      rebooted       — bool: the machine booted since the agent last ran.
      first_run      — bool: no prior marker (fresh install / cleared state).
      current_boot   — int|None: live kernel boot epoch.
      previous_boot  — int|None: boot epoch recorded on the last run.
      downtime_sec   — int|None: estimated seconds the box was OFF (from the
                       agent's last heartbeat to the new boot). None if unknown.
      clean_shutdown — bool|None: True if the agent got a graceful SIGTERM before
                       going down (orderly reboot); False if it did not (power
                       loss / panic / SIGKILL); None when not applicable.
    """
    current = _current_boot_time()
    state = _load_state()

    prev_boot = state.get("boot_time")
    last_seen = state.get("last_seen")          # wall clock of last marker update
    prev_clean = state.get("clean_stop")

    first_run = prev_boot is None
    rebooted = (
        not first_run
        and current is not None
        and isinstance(prev_boot, (int, float))
        and int(current) != int(prev_boot)
    )

    downtime_sec: int | None = None
    clean_shutdown: bool | None = None
    if rebooted:
        if isinstance(last_seen, (int, float)) and current is not None:
            # Time from the agent's last sign of life to the new kernel boot.
            downtime_sec = max(0, int(current) - int(last_seen))
        clean_shutdown = bool(prev_clean) if prev_clean is not None else False

    # Record the new running state: current boot, fresh heartbeat, clean_stop
    # reset to False. It only flips True again when mark_clean_stop() runs on a
    # graceful SIGTERM — so a hard power loss leaves it False for the next boot.
    _save_state({
        "boot_time":  int(current) if current is not None else prev_boot,
        "last_seen":  int(time.time()),
        "clean_stop": False,
    })

    return {
        "rebooted":       rebooted,
        "first_run":      first_run,
        "current_boot":   int(current) if current is not None else None,
        "previous_boot":  int(prev_boot) if isinstance(prev_boot, (int, float)) else None,
        "downtime_sec":   downtime_sec,
        "clean_shutdown": clean_shutdown,
    }


def touch_heartbeat() -> None:
    """Update last_seen without disturbing the clean_stop flag, so downtime is
    measured from the agent's most recent sign of life (not process start).
    Best-effort; never raises."""
    state = _load_state()
    state["last_seen"] = int(time.time())
    _save_state(state)


def mark_clean_stop() -> None:
    """Record that the agent is stopping gracefully (SIGTERM). The next boot then
    classifies the shutdown as clean. Best-effort; never raises."""
    state = _load_state()
    state["clean_stop"] = True
    state["last_seen"] = int(time.time())
    _save_state(state)


# ── Plist analysis (pure, unit-testable) ───────────────────────────────────────

def _analyze_plist(text: str, agent_bin: str, label: str) -> list[str]:
    """Return a list of drift issue codes for a LaunchDaemon plist body.

    Pure string analysis so it is trivially unit-testable without a real plist on
    disk or a running launchd. An empty list means the plist is structurally
    sound for boot-persistence.
    """
    issues: list[str] = []
    if not re.search(rf"<key>\s*Label\s*</key>\s*<string>\s*{re.escape(label)}\s*</string>", text):
        issues.append("wrong_label")
    # RunAtLoad must be explicitly true, else the job won't start at boot.
    if not re.search(r"<key>\s*RunAtLoad\s*</key>\s*<true\s*/>", text):
        issues.append("no_run_at_load")
    # KeepAlive may be <true/> or a <dict>…</dict> policy — either keeps it up.
    if not re.search(r"<key>\s*KeepAlive\s*</key>\s*(<true\s*/>|<dict>)", text):
        issues.append("no_keep_alive")
    if agent_bin not in text:
        issues.append("wrong_binary")
    return issues


def _parse_disabled(text: str, label: str) -> bool:
    """Given `launchctl print-disabled system` output, return True if `label` is
    marked disabled. launchctl has shipped two formats over the years:
        "com.attacklens.agent" => true        (true == disabled)
        "com.attacklens.agent" => disabled
    Absent from the list == enabled.
    """
    for line in text.splitlines():
        if f'"{label}"' in line:
            low = line.lower()
            if "=> true" in low or "disabled" in low:
                return True
            return False
    return False


# ── Persistence verification + repair ──────────────────────────────────────────

def verify_persistence(
    agent_plist: str | None = None,
    agent_bin: str | None = None,
    label: str | None = None,
) -> dict:
    """Inspect the agent LaunchDaemon and report its boot-persistence health.
    NEVER raises. Read-only (no root required) — repair is a separate step.

    Returns a dict with individual booleans plus an `issues` list of codes:
      plist_missing, <analysis codes>, bad_owner, bad_perms, disabled, not_loaded
    An empty `issues` list means the agent WILL auto-start on the next boot.
    """
    from .launchd import _AGENT_PLIST, _AGENT_BIN, _AGENT_LABEL

    agent_plist = agent_plist or _AGENT_PLIST
    agent_bin = agent_bin or _AGENT_BIN
    label = label or _AGENT_LABEL

    report: dict = {
        "plist_path":   agent_plist,
        "plist_exists": False,
        "owner_ok":     None,
        "perms_ok":     None,
        "enabled":      None,
        "loaded":       None,
        "issues":       [],
    }

    # 1. Plist file present + structurally correct.
    try:
        with open(agent_plist, encoding="utf-8") as f:
            body = f.read()
        report["plist_exists"] = True
        report["issues"].extend(_analyze_plist(body, agent_bin, label))
    except FileNotFoundError:
        report["issues"].append("plist_missing")
    except Exception as exc:  # noqa: BLE001
        log.debug("plist read failed: %s", exc)
        report["issues"].append("plist_unreadable")

    # 2. Ownership + permissions (root:wheel, 0644). A world-writable or
    #    non-root plist is both a tamper vector and something launchd may refuse.
    if report["plist_exists"]:
        try:
            st = os.stat(agent_plist)
            owner_ok = (st.st_uid == 0 and st.st_gid == 0)
            perms_ok = (st.st_mode & 0o777) == 0o644
            report["owner_ok"] = owner_ok
            report["perms_ok"] = perms_ok
            if not owner_ok:
                report["issues"].append("bad_owner")
            if not perms_ok:
                report["issues"].append("bad_perms")
        except Exception as exc:  # noqa: BLE001
            log.debug("plist stat failed: %s", exc)

    # 3. launchctl enable state + loaded/running state.
    try:
        from .launchd import is_enabled, is_running
        enabled = is_enabled(label)
        report["enabled"] = enabled
        if not enabled:
            report["issues"].append("disabled")
        loaded = is_running(label)
        report["loaded"] = loaded
        if not loaded:
            report["issues"].append("not_loaded")
    except Exception as exc:  # noqa: BLE001
        log.debug("launchctl state probe failed: %s", exc)

    return report


def ensure_boot_persistence(
    config_path: str | None = None,
    agent_bin: str | None = None,
    log_dir: str | None = None,
) -> dict:
    """Verify boot-persistence and repair any drift so the agent is GUARANTEED to
    auto-launch after the next shutdown/reboot. Idempotent. NEVER raises.

    Repair requires root (writing /Library/LaunchDaemons + launchctl in the
    system domain); when not root we return a verify-only report with a warning
    rather than failing.
    """
    global _last_bootstrap_attempt

    if sys.platform != "darwin":
        return {"skipped": "not-macos"}

    from .launchd import (
        _AGENT_PLIST, _AGENT_BIN, _AGENT_LABEL, _CONFIG_DEFAULT, _LOG_DIR,
    )
    agent_bin = agent_bin or _AGENT_BIN
    config_path = config_path or _CONFIG_DEFAULT
    log_dir = log_dir or _LOG_DIR

    report = verify_persistence(agent_bin=agent_bin, label=_AGENT_LABEL)
    issues = report.get("issues", [])
    if not issues:
        return {"healthy": True, "actions": [], "report": report}

    is_root = (hasattr(os, "geteuid") and os.geteuid() == 0)
    if not is_root:
        log.warning("boot-persistence drift detected but not root — cannot repair: %s",
                    issues)
        return {"healthy": False, "actions": [], "report": report,
                "note": "repair requires root"}

    actions: list[str] = []

    # 1. Rewrite the plist if it is missing or structurally wrong.
    structural = {"plist_missing", "plist_unreadable", "wrong_label",
                  "no_run_at_load", "no_keep_alive", "wrong_binary"}
    if structural.intersection(issues):
        try:
            from .launchd import _agent_plist_xml, _write_plist
            xml = _agent_plist_xml(config_path, agent_bin, log_dir)
            _write_plist(_AGENT_PLIST, xml)
            actions.append("rewrote_plist")
            log.warning("boot-persistence: rewrote agent plist (was %s)", sorted(issues))
        except Exception as exc:  # noqa: BLE001
            log.error("boot-persistence: plist rewrite failed: %s", exc)

    # 2. Fix ownership/permissions if the file exists but drifted.
    if "bad_owner" in issues or "bad_perms" in issues:
        try:
            os.chown(_AGENT_PLIST, 0, 0)
            os.chmod(_AGENT_PLIST, 0o644)
            actions.append("fixed_ownership")
            log.warning("boot-persistence: reset plist to root:wheel 0644")
        except Exception as exc:  # noqa: BLE001
            log.error("boot-persistence: ownership fix failed: %s", exc)

    # 3. Re-enable a disabled label so RunAtLoad can fire at the next boot.
    if "disabled" in issues:
        try:
            from .launchd import enable
            if enable(_AGENT_LABEL):
                actions.append("enabled")
                log.warning("boot-persistence: re-enabled disabled label %s", _AGENT_LABEL)
        except Exception as exc:  # noqa: BLE001
            log.error("boot-persistence: enable failed: %s", exc)

    # 4. (Re)bootstrap an unloaded job — but throttle so a tight self_heal
    #    cadence can't thrash launchctl. Also runs after a rewrite so the fresh
    #    plist is actually loaded.
    if "not_loaded" in issues or "rewrote_plist" in actions:
        now = time.monotonic()
        if now - _last_bootstrap_attempt >= _BOOTSTRAP_MIN_GAP_SEC:
            _last_bootstrap_attempt = now
            try:
                from .launchd import start
                if start(_AGENT_LABEL):
                    actions.append("bootstrapped")
                    log.warning("boot-persistence: (re)bootstrapped %s", _AGENT_LABEL)
            except Exception as exc:  # noqa: BLE001
                log.error("boot-persistence: bootstrap failed: %s", exc)
        else:
            log.debug("boot-persistence: bootstrap throttled (last %.0fs ago)",
                      now - _last_bootstrap_attempt)

    return {"healthy": len(actions) > 0, "actions": actions, "report": report}


# ── Periodic persistence guard (runtime tamper repair) ─────────────────────────
# RunAtLoad only fires at boot for a plist that is still present + enabled, and
# on_agent_startup repairs drift only ONCE when the agent launches. If the plist
# is disabled or deleted WHILE the agent runs (tampering, or a botched admin
# action), nothing fixes it before the next reboot — and a disabled/absent job
# never auto-starts, permanently defeating boot-persistence. This guard re-runs
# ensure_boot_persistence on a slow cadence so runtime drift is repaired long
# before the machine is powered off. (ensure_boot_persistence itself throttles
# re-bootstrap, so a tight interval can't thrash launchctl.)
_PERSISTENCE_GUARD_DEFAULT_SEC = 900   # 15 min
_persistence_guard_started = False


def _guard_interval_sec() -> int:
    """Guard cadence, overridable via ATTACKLENS_PERSISTENCE_GUARD_SEC. Floored so
    a misconfiguration can't turn the guard into a launchctl hot-loop."""
    try:
        return max(30, int(os.environ.get(
            "ATTACKLENS_PERSISTENCE_GUARD_SEC", _PERSISTENCE_GUARD_DEFAULT_SEC)))
    except (TypeError, ValueError):
        return _PERSISTENCE_GUARD_DEFAULT_SEC


def _persistence_guard_tick(config_path: str | None = None) -> dict:
    """One guard iteration: re-verify + repair boot persistence. NEVER raises —
    returns the repair report (or an {"error": ...} dict) so the loop and tests
    can inspect it without risk to the agent."""
    try:
        res = ensure_boot_persistence(config_path=config_path)
        if res.get("actions"):
            log.warning("boot-persistence guard repaired runtime drift: %s", res["actions"])
        return res
    except Exception as exc:  # noqa: BLE001 - guard must never crash the agent
        log.debug("persistence guard cycle failed: %s", exc)
        return {"error": type(exc).__name__}


def _start_persistence_guard_thread(config_path: str | None = None) -> None:
    """Start the background guard that periodically repairs boot persistence so
    tampering done while the agent is running is fixed before the next shutdown.
    Idempotent; macOS-only path (callers already gate on darwin)."""
    global _persistence_guard_started
    if _persistence_guard_started:
        return
    _persistence_guard_started = True
    interval = _guard_interval_sec()

    def _run() -> None:
        while True:
            time.sleep(interval)
            _persistence_guard_tick(config_path)

    threading.Thread(target=_run, daemon=True, name="boot-persistence-guard").start()
    log.info("boot-persistence guard active — re-verifying every %ss", interval)


# ── Startup integration ────────────────────────────────────────────────────────

_heartbeat_started = False


def _start_heartbeat_thread() -> None:
    """Background daemon that refreshes the boot marker's last_seen every 60 s so
    downtime is measured from the agent's most recent heartbeat. Idempotent."""
    global _heartbeat_started
    if _heartbeat_started:
        return
    _heartbeat_started = True

    def _run():
        while True:
            time.sleep(_HEARTBEAT_INTERVAL_SEC)
            try:
                touch_heartbeat()
            except Exception as exc:  # noqa: BLE001
                log.debug("heartbeat marker update failed: %s", exc)

    threading.Thread(target=_run, daemon=True, name="boot-marker-heartbeat").start()


def on_agent_startup(orch, config_path: str | None = None) -> None:
    """Called ONCE from the agent's main() on macOS, after the orchestrator and
    sender are up. Best-effort; NEVER raises into the caller.

      1. Self-repair boot persistence (so the NEXT reboot still auto-starts).
      2. Detect a reboot since the last run and, if found, emit a `system_boot`
         telemetry event through the orchestrator.
      3. Start the heartbeat thread that keeps the downtime estimate accurate.
    """
    # 1. Guarantee we survive the next reboot.
    try:
        res = ensure_boot_persistence(config_path=config_path)
        if res.get("actions"):
            log.warning("boot-persistence repaired at startup: %s", res["actions"])
        else:
            log.info("boot-persistence verified — agent will auto-start on next boot")
    except Exception as exc:  # noqa: BLE001
        log.debug("ensure_boot_persistence at startup failed: %s", exc)

    # 2. Detect + report a reboot.
    try:
        t = detect_boot_transition()
        if t.get("rebooted") and orch is not None:
            payload = {
                "event":          "system_boot",
                "boot_time":      t.get("current_boot"),
                "previous_boot":  t.get("previous_boot"),
                "downtime_sec":   t.get("downtime_sec"),
                "clean_shutdown": t.get("clean_shutdown"),
                "detected_at":    int(time.time()),
            }
            try:
                orch.emit_event("system_boot", payload)
            except Exception as exc:  # noqa: BLE001
                log.debug("system_boot emit failed: %s", exc)
            log.info("system reboot detected — downtime=%ss clean_shutdown=%s",
                     t.get("downtime_sec"), t.get("clean_shutdown"))
        elif t.get("first_run"):
            log.info("boot marker initialized (first run) — reboot tracking active")
    except Exception as exc:  # noqa: BLE001
        log.debug("reboot detection failed: %s", exc)

    # 3. Keep the marker warm.
    _start_heartbeat_thread()

    # 4. Keep boot-persistence healthy against tampering done while the agent is
    #    running — so the NEXT power-off still auto-starts even if someone
    #    disabled/deleted the plist mid-run.
    _start_persistence_guard_thread(config_path)


# ── One-shot CLI (ops / periodic daemon) ───────────────────────────────────────

def main(argv: list[str] | None = None) -> int:
    """`python -m agent.os.macos.boot_persistence [--verify|--repair]`.

    --verify : print the persistence report and exit non-zero on any drift.
    --repair : verify AND repair (default). Also usable as a periodic
               LaunchDaemon (StartInterval) for standalone tamper-repair.
    """
    import argparse
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    parser = argparse.ArgumentParser(description="AttackLens macOS boot-persistence guard")
    parser.add_argument("--verify", action="store_true",
                        help="report only; do not repair")
    parser.add_argument("--repair", action="store_true",
                        help="verify and repair drift (default)")
    args = parser.parse_args(argv)

    if args.verify and not args.repair:
        report = verify_persistence()
        print(json.dumps(report, indent=2))
        return 0 if not report.get("issues") else 1

    result = ensure_boot_persistence()
    print(json.dumps(result, indent=2, default=str))
    issues = result.get("report", {}).get("issues", [])
    # Success = no issues, or issues we actually repaired.
    return 0 if (not issues or result.get("actions")) else 1


if __name__ == "__main__":
    raise SystemExit(main())
