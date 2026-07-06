"""
agent/os/macos/self_heal.py — macOS self-healing supervisor.

Closes the recovery gaps that launchd's KeepAlive cannot, and that the user hit
in practice:

  1. Boot / load recovery — make sure the agent LaunchDaemon is actually loaded
     and running. After a reboot, a crash-loop back-off, or launchd dropping the
     job, this re-bootstraps it so the agent comes back ON ITS OWN.

  2. Silent non-delivery — the agent process can be ALIVE and launchd-happy while
     delivering ZERO telemetry: manager unreachable, a rogue server squatting the
     manager port (404s every POST), a wrong URL, or a persistent 401. KeepAlive
     never fires because nothing crashes. This detects that via the connectivity
     probe and recovers safely or escalates with an exact, human-actionable fix.

Designed to run as a periodic one-shot (a LaunchDaemon with StartInterval): each
invocation checks once and exits. A small JSON state file tracks consecutive
failures so recovery escalates only after SUSTAINED failure, never on a single
transient blip.

Safety rule that matters: when the manager is simply DOWN (`unreachable`), we do
NOT restart the agent — a restart would replay the whole disk spool and cause
the exact CPU-starvation storm we just eliminated. The sender already reconnects
and drains on its own. We only take heavier action for states a restart can
actually fix (a wedged agent, or a config the operator just corrected).
"""
from __future__ import annotations

import json
import logging
import os
import time

log = logging.getLogger("agent.os.macos.self_heal")

# State + diagnosis output (root-owned install dir).
_STATE_FILE     = "/Library/AttackLens/self_heal_state.json"
_DIAGNOSIS_FILE = "/Library/AttackLens/health_diagnosis.json"

# Escalation thresholds (consecutive failed checks). With a 5-min StartInterval:
#   3 → ~15 min: re-read config (cheap; picks up an operator's corrected URL)
#   6 → ~30 min: kickstart the agent daemon (fresh process + sender)
_RELOAD_AFTER  = 3
_RESTART_AFTER = 6


# ── State ─────────────────────────────────────────────────────────────────────

def _load_state() -> dict:
    try:
        with open(_STATE_FILE, encoding="utf-8") as f:
            obj = json.load(f)
        return obj if isinstance(obj, dict) else {}
    except FileNotFoundError:
        return {}
    except Exception as exc:  # noqa: BLE001 - never let state I/O crash the healer
        log.debug("self_heal state read failed: %s", exc)
        return {}


def _save_state(state: dict) -> None:
    try:
        tmp = _STATE_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(state, f)
        os.replace(tmp, _STATE_FILE)
    except Exception as exc:  # noqa: BLE001
        log.debug("self_heal state write failed: %s", exc)


def _write_diagnosis(report: dict) -> None:
    try:
        tmp = _DIAGNOSIS_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({"updated_at": int(time.time()), **report}, f, default=str)
        os.replace(tmp, _DIAGNOSIS_FILE)
    except Exception as exc:  # noqa: BLE001
        log.debug("self_heal diagnosis write failed: %s", exc)


# ── Recovery primitives (reuse the launchd wrappers) ──────────────────────────

def ensure_daemon_loaded() -> bool:
    """Boot/load recovery: if the agent isn't running under launchd, (re)start it.

    Returns True if it was already running OR we successfully started it. This is
    the 'automatically get up' mechanism — independent of, and a backstop to,
    the plist's RunAtLoad/KeepAlive.
    """
    try:
        from .launchd import is_running, start, _AGENT_LABEL
    except Exception as exc:  # noqa: BLE001
        log.warning("self_heal: launchd helpers unavailable: %s", exc)
        return False

    try:
        if is_running(_AGENT_LABEL):
            return True
        log.warning("self_heal: agent daemon not running — attempting (re)bootstrap")
        ok = start(_AGENT_LABEL)
        log.info("self_heal: agent daemon start %s", "succeeded" if ok else "FAILED")
        return ok
    except Exception as exc:  # noqa: BLE001
        log.warning("self_heal: ensure_daemon_loaded error: %s", exc)
        return False


def _reload_config() -> None:
    """SIGHUP the agent so it re-reads agent.toml WITHOUT a restart — the safe way
    to make an operator's corrected manager URL take effect (no spool replay)."""
    try:
        from .launchd import reload_config
        if reload_config():
            log.info("self_heal: sent config reload (SIGHUP) to agent")
    except Exception as exc:  # noqa: BLE001
        log.debug("self_heal: reload_config failed: %s", exc)


def _restart_agent() -> None:
    """Heavier recovery: kickstart the agent daemon (fresh process + sender).
    Only used for a wedged agent — NEVER when the manager is merely unreachable
    (that would trigger a spool-replay storm)."""
    try:
        from .launchd import restart, _AGENT_LABEL
        if restart(_AGENT_LABEL):
            log.warning("self_heal: restarted agent daemon (sustained failure)")
    except Exception as exc:  # noqa: BLE001
        log.debug("self_heal: restart failed: %s", exc)


# ── Core check + heal ─────────────────────────────────────────────────────────

def check_and_heal() -> dict:
    """One self-heal cycle. Returns a result dict (also persisted to the
    diagnosis file). Never raises."""
    # 1. Make sure the agent is even up (boot/crash/launchd-drop recovery).
    loaded = ensure_daemon_loaded()

    # 2. Probe whether the agent can actually reach the manager.
    try:
        from .diagnostics import probe_manager, _manager_url
        probe = probe_manager(_manager_url())
    except Exception as exc:  # noqa: BLE001
        probe = {"verdict": "error", "detail": f"probe unavailable: {exc}"}

    verdict = probe.get("verdict")
    state = _load_state()
    fails = int(state.get("consecutive_failures", 0))

    action = "none"
    if verdict == "ok":
        fails = 0
        action = "healthy"
    else:
        fails += 1
        # Pick recovery by WHAT is wrong — not all failures want the same action.
        if verdict == "unreachable":
            # Manager down. Sender handles reconnect+spool. Do NOT restart
            # (avoids spool-replay storm). Just escalate visibility.
            action = "wait_for_manager"
        elif verdict in ("rogue_server", "wrong_endpoint", "no_url"):
            # Misconfiguration a restart can't fix. Re-read config in case the
            # operator just corrected agent.toml; otherwise escalate to human.
            if fails == _RELOAD_AFTER:
                _reload_config()
                action = "config_reloaded"
            else:
                action = "needs_operator"
            log.error("self_heal: agent cannot deliver — %s. %s",
                      probe.get("detail", verdict), probe.get("fix", ""))
        else:  # error / unknown
            action = "unknown"

        # Last-resort: a sustained failure that survived a config reload AND is
        # not a 'manager simply down' case → the agent may be wedged; restart it.
        if fails >= _RESTART_AFTER and verdict not in ("unreachable",):
            _restart_agent()
            action = "agent_restarted"
            fails = 0  # give the fresh process a clean slate to re-evaluate

    state["consecutive_failures"] = fails
    state["last_verdict"] = verdict
    state["last_check"] = int(time.time())
    _save_state(state)

    result = {
        "verdict": verdict,
        "daemon_loaded": loaded,
        "consecutive_failures": fails,
        "action": action,
        "manager": probe,
    }
    _write_diagnosis(result)
    return result


def main(argv: list[str] | None = None) -> int:
    """One-shot entry point for the periodic LaunchDaemon (StartInterval)."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    try:
        result = check_and_heal()
    except Exception as exc:  # noqa: BLE001 - the healer must never crash-loop
        log.error("self_heal cycle crashed: %s", exc)
        return 1
    verdict = result.get("verdict")
    log.info("self_heal: verdict=%s action=%s fails=%s",
             verdict, result.get("action"), result.get("consecutive_failures"))
    return 0 if verdict == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
