"""
manager/manager/attacklens/engine.py — AttackLens Detection Engine: correlates raw telemetry into verified findings.

Processing pipeline per payload:
  1. Route section → appropriate analyzer(s)
  2. Each analyzer emits a list of raw finding dicts
  3. Findings are upserted into intel.db (dedup by agent_id+category+item_key)
  4. Change timeline entry created for new/modified items
  5. Behavioral baseline updated

Analyzers:
  ports       — malicious port detection, unusual binding
  processes   — suspicious cmdline / path / SUID patterns
  connections — threat-feed IP lookup, unknown destinations
  services    — suspicious LaunchDaemon labels / paths
  apps        — unsigned / quarantined apps
  packages    — CVE lookup, risky tool detection
  network     — new/changed interfaces
  users       — new admin accounts, locked-out users
  tasks       — suspicious cron / launchd tasks
  security    — SIP/GK/FV posture changes
  configs     — suspicious content in monitored files
  binaries    — SUID/SGID binaries, world-writable
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import re
import time
from typing import Any, Optional

from .rules import (
    MALICIOUS_PORTS, PROCESS_RULES, SUSPICIOUS_PATHS, CONFIG_RULES,
    RISKY_PACKAGES, SUSPICIOUS_SERVICE_PATTERNS, PARENT_CHILD_RULES,
    OBFUSCATION_RULES, STANDALONE_RULES, get_tactic, severity_to_score,
)
from .allowlist import (
    is_trusted_ip, is_apple_system_process, get_dual_use_info,
    is_suspicious_spawn, has_benign_parent, adjust_finding_for_allowlist,
    cap_severity, APPLE_SYSTEM_PROCS,
)
from .behavioral  import BehavioralAnalyzer
from .feeds       import FeedManager
from .nvd         import CVELookup
from .correlator  import CorrelationEngine
from .fleet_correlator import FleetCorrelator
from .signals     import Signal, layer_for
from .detections  import (
    analyze_port_listener, analyze_user_account,
    analyze_sysctl_monitor, analyze_arp_spoofing,
    analyze_container_security, analyze_sbom_posture,
)
from .clustering  import cluster_signals
from .confidence  import score_confidence
from .validation  import validate_cluster
from .config      import ENGINE_CONFIG
from .ai_validator import (
    validate_with_ai,
    ai_validation_enabled,
    resolve_threshold,
    use_ai_verdict_for,
    PrecisionResult,
)
from ..threat.scoring import score_matrix

log = logging.getLogger("manager.attacklens.engine")

# Minimum gap between fleet-wide correlation sweeps. Per-agent correlation runs
# frequently (every few payloads per host); the fleet sweep reads findings across
# ALL hosts, so it's throttled to avoid redundant full-fleet scans under load.
_FLEET_MIN_INTERVAL_SEC = 120

# ── Bounded detection executor (throughput control for large data volumes) ────
# Ingest hands each payload to a bounded queue drained by a fixed worker pool,
# instead of spawning an unbounded asyncio.create_task per payload. Two reasons:
#   1. Backpressure / memory: under a burst (many agents × many sections), an
#      unbounded create_task fan-out piles thousands of in-flight process()
#      coroutines into memory at once.
#   2. Write-lock fairness: every process() ultimately serializes on IntelDB's
#      single write connection. Capping concurrency to DETECTION_WORKERS keeps a
#      stable, shallow queue at that lock instead of a thundering herd that makes
#      every writer slower. Fewer, steadier writers drain FASTER overall.
# Ingest itself never blocks on detection — enqueue() is a non-blocking put, so
# ingest latency stays flat regardless of detection backlog.
_DETECTION_WORKERS   = int(os.getenv("ATTACKLENS_DETECTION_WORKERS", "4"))
_DETECTION_QUEUE_MAX = int(os.getenv("ATTACKLENS_DETECTION_QUEUE_MAX", "2000"))

# Sections that report the agent's CURRENT live inventory every cycle. For these,
# absence of an entity in a fresh, valid snapshot means it's genuinely gone, so
# its incident should auto-resolve. Event/streaming or ambiguous-state sections
# (posture, config, sysctl, network, sbom, …) are intentionally excluded — we
# never auto-resolve on those.
_RECONCILE_SECTIONS: dict[str, tuple[str, ...]] = {
    # Vector / Citadels — live runtime inventories
    "ports":       ("port",),
    "services":    ("service",),
    "processes":   ("process",),
    "connections": ("connection",),
    "users":       ("user",),
    "tasks":       ("task",),
    "network":     ("network",),
    "containers":  ("container",),
    # Origin — supply-chain / config inventories (clears removed packages,
    # uninstalled apps, fixed sysctl, dropped SBOM components, removed configs/binaries)
    "packages":    ("package",),
    "apps":        ("app",),
    "sbom":        ("sbom",),
    "sysctl":      ("sysctl",),
    "configs":     ("config",),
    "binaries":    ("binary",),
}


# Sections routed to the rich detections/ modules (verified against real agent
# data shapes AND locked by the accuracy harness). Unrouted sections keep the
# engine's inline analyzer. GROW this map one module at a time — only after the
# module is confirmed to fire on live telemetry (many modules guard on section
# names that differ from what the agent sends, so a blind add emits nothing).
_DETECTION_MODULE_ROUTES: dict[str, list] = {
    "ports": [analyze_port_listener],
    "users": [analyze_user_account],
    # Confirmed against agent/os/macos/collectors/__init__.py's COLLECTORS
    # registry — each of these sections has NO inline analyzer today (not in
    # AttackLensEngine._dispatch()'s `fn` map), so routing them here is purely
    # additive. Module-internal section guards verified to match exactly:
    #   sysctl_monitor.SYSCTL_SECTIONS    ⊇ {"sysctl"}
    #   arp_spoofing.analyze()            guards on section == "arp"
    #   container_security.analyze()      guards on section in {"containers", ...}
    #   sbom_posture.SBOM_SECTIONS        ⊇ {"sbom"}
    "sysctl":     [analyze_sysctl_monitor],
    "arp":        [analyze_arp_spoofing],
    "containers": [analyze_container_security],
    "sbom":       [analyze_sbom_posture],
}

# Map an agent section → the engine's finding `category` (keeps terrain mapping
# and dedup consistent with the inline analyzers).
_SECTION_CATEGORY: dict[str, str] = {
    "ports": "port", "processes": "process", "connections": "connection",
    "services": "service", "apps": "app", "packages": "package",
    "network": "network", "users": "user", "tasks": "task",
    "security": "security", "configs": "config", "binaries": "binary",
    "metrics": "behavioral",
    "sysctl": "sysctl", "sbom": "sbom", "arp": "arp", "containers": "container",
}

# Evidence keys that change every snapshot — excluded from the item_key hash so
# dedup recognises the same entity across cycles.
_VOLATILE_EVIDENCE_KEYS = frozenset({
    "pid", "ppid", "timestamp", "timestamp_utc", "alert_id", "created_at", "detected_at",
})
_ITEM_KEY_FIELDS = ("item_key", "username", "cve_id", "package", "name",
                    "port", "path", "binary", "process", "ip", "mac")


def _derive_item_key(rule_id: str, evidence: dict) -> str:
    """Stable dedup key for a module finding (modules don't emit item_key).
    Prefer a natural identifier in the evidence; else hash the stable evidence
    fields (excluding volatile ones like pid/timestamps that would break dedup)."""
    for k in _ITEM_KEY_FIELDS:
        v = evidence.get(k)
        if v not in (None, "", [], {}):
            return f"{rule_id}:{v}"
    stable = {k: v for k, v in evidence.items() if k not in _VOLATILE_EVIDENCE_KEYS}
    digest = hashlib.sha256(
        json.dumps(stable, sort_keys=True, default=str).encode()
    ).hexdigest()[:16]
    return f"{rule_id}:{digest}"


_SEV_PRECISION: dict[str, float] = {
    "critical": 0.70, "high": 0.62, "medium": 0.50, "low": 0.35, "info": 0.20,
}


def _adapt_module_finding(f: dict, section: str) -> dict:
    """Map a detections/ module's alert dict → the engine finding format that
    upsert_finding / _dispatch_to_signals require (category, item_key, source,
    score). Non-destructive — anything the module already set is preserved."""
    ev   = f.get("evidence") or {}
    rule = f.get("rule_id") or f.get("detection_module") or "detection"
    f.setdefault("category", _SECTION_CATEGORY.get(section, f.get("detection_module") or section))
    f.setdefault("item_key", _derive_item_key(rule, ev))
    f.setdefault("source", rule)
    f.setdefault("rule_id", rule)
    if "score" not in f:
        f["score"] = severity_to_score(f.get("severity", "info"))
    f["evidence"] = ev
    # Seed a deterministic precision_score from the rule's own confidence so
    # module findings are not permanently stuck at 0.0.  The AI validation
    # pipeline overwrites this with a higher-fidelity value when it runs; for
    # the common case (AI off, or finding not yet correlated) this gives the
    # Validated Findings page a meaningful score floor to filter on.
    if not f.get("precision_score"):
        conf = f.get("confidence")
        if conf is not None:
            f["precision_score"] = round(float(conf), 3)
        else:
            f["precision_score"] = _SEV_PRECISION.get(
                (f.get("severity") or "medium").lower(), 0.50
            )
    return f


def _is_live_snapshot(data) -> bool:
    """True only for a real, non-empty snapshot — NOT an empty result and NOT a
    collector error ({"error": ...}). This is the guard that stops "data missed"
    (empty/errored section) from being mistaken for "evidence gone" and
    mass-resolving real incidents."""
    if not data:
        return False
    if isinstance(data, dict):
        return len(data) > 0 and set(data.keys()) != {"error"}
    if isinstance(data, (list, tuple)):
        return len(data) > 0
    return False


# Private IP ranges — never flag as threat-feed hits
_PRIVATE_RE = re.compile(
    r"^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|::1|fe80:)"
)

# Ports that are genuinely safe to listen on (reduce FP)
_SAFE_LISTEN: set[int] = {22, 25, 53, 80, 443, 587, 993, 995,
                           3389, 5985, 5986, 27017, 5432, 3306,
                           6379, 5672, 8080, 8443, 8000, 8001, 2375}


class AttackLensEngine:
    """
    AttackLens — AI-powered correlation engine. Created once at server startup.
    Receives raw telemetry from the ingest pipeline, correlates against threat
    intelligence sources, applies behavioral baselines, and writes verified
    findings into the IntelDB (verified findings store).
    """

    def __init__(self, db, intel_db, ai_analyst=None) -> None:
        self._db      = db           # main manager DB (agents, keys)
        self._idb     = intel_db     # IntelDB (findings, timeline, baseline)
        self._feeds   = FeedManager(intel_db)
        self._nvd     = CVELookup(intel_db)
        self._behav   = BehavioralAnalyzer(intel_db)
        self._corr    = CorrelationEngine(intel_db)
        self._fleet   = FleetCorrelator(intel_db, db)   # cross-host / global-threat layer
        # Optional AI analyst — used by the precision validator if set.
        # Server wiring assigns this after both objects are constructed.
        self._ai_analyst = ai_analyst
        self._ready   = False
        self._nvd_queue: asyncio.Queue = asyncio.Queue(maxsize=200)
        # Real-time correlation coalescing (replaces the old "every 3rd payload"
        # sampling, which let 2 of every 3 payloads — and any attack chain that
        # landed in the gap — go uncorrelated). Every payload now requests a
        # correlation pass, but we never run more than ONE per agent at a time:
        # if a pass is already in flight for an agent, the new request just sets
        # a "dirty" flag and the in-flight pass loops once more when it finishes.
        # → correlate-on-every-event latency, with bounded (1 per agent) work.
        self._correlate_inflight: set[str] = set()
        self._correlate_dirty:    set[str] = set()
        # Per-agent metrics state — tracks consecutive high-resource readings so
        # transient spikes (single payload) don't fire; sustained anomalies do.
        # Structure: agent_id → {"cpu_high": int, "mem_high": int, "net_high": int}
        self._metrics_state: dict[str, dict] = {}

        # Bounded detection executor (see module constants). The queue is created
        # lazily in start() on the running loop; workers drain it concurrently up
        # to _DETECTION_WORKERS. Counters give operators a live throughput view.
        self._detect_queue: Optional[asyncio.Queue] = None
        self._detect_workers: list[asyncio.Task] = []
        self._detect_stats = {
            "enqueued": 0, "processed": 0, "dropped_queue_full": 0, "errors": 0,
        }
        # Auto-resolve stale period cache — read from org_settings on first use
        # per cycle, refreshed each process() call (every ~payload; cheap warm read).
        self._auto_resolve_sec_cache: float = 0.0
        self._auto_resolve_sec_ts:    float = 0.0

    async def _auto_resolve_stale_sec(self) -> float:
        """Read the live Settings → Data Retention → auto_resolve_stale_days value
        from org_settings with a 60 s in-process cache. Falls back to the env var
        default (2 days) if unreadable — auto-resolve must never crash a payload."""
        now = time.time()
        if self._auto_resolve_sec_cache and (now - self._auto_resolve_sec_ts) < 60:
            return self._auto_resolve_sec_cache
        try:
            row = await self._idb._fetchone(
                "SELECT value FROM org_settings WHERE key='auto_resolve_stale_days'", ()
            )
            days = int(row["value"]) if row else 2
            self._auto_resolve_sec_cache = float(max(1, min(14, days))) * 86400.0
        except Exception:
            self._auto_resolve_sec_cache = float(
                ENGINE_CONFIG.get("auto_resolve_stale_sec", 2 * 86400)
            )
        self._auto_resolve_sec_ts = now
        return self._auto_resolve_sec_cache

    def attach_ai_analyst(self, ai_analyst) -> None:
        """Late binding for the AI analyst (server constructs both lazily)."""
        self._ai_analyst = ai_analyst

    @property
    def feeds(self) -> "FeedManager":
        """Shared FeedManager instance (used by ThreatIntelWorker)."""
        return self._feeds

    @property
    def nvd(self) -> "CVELookup":
        """Shared CVELookup instance (used by ThreatIntelWorker)."""
        return self._nvd

    async def start(self) -> None:
        """Call once at startup. Feed scheduling is owned by ThreatIntelWorker."""
        await self._feeds.refresh()   # initial load from DB cache only (no network)
        asyncio.create_task(self._nvd_worker())
        asyncio.create_task(self._fleet_worker())
        # Bounded detection executor: create the queue on the running loop and
        # spawn the fixed worker pool that drains it.
        self._detect_queue = asyncio.Queue(maxsize=_DETECTION_QUEUE_MAX)
        self._detect_workers = [
            asyncio.create_task(self._detection_worker(i))
            for i in range(_DETECTION_WORKERS)
        ]
        self._ready = True
        log.info("AttackLens engine started (detection workers=%d, queue_max=%d)",
                 _DETECTION_WORKERS, _DETECTION_QUEUE_MAX)

    def enqueue(self, agent_id: str, section: str, data: Any,
                collected_at: float | None = None) -> bool:
        """Hand a payload to the bounded detection executor. Non-blocking.

        Returns True if accepted, False if dropped (queue saturated). Ingest
        calls this instead of asyncio.create_task(process(...)) so that:
          - ingest latency stays flat (a near-instant put_nowait), and
          - concurrent process() work is capped at _DETECTION_WORKERS.

        On saturation we DROP and count rather than block ingest or spawn an
        unbounded task — the raw telemetry is already persisted by ingest, so a
        dropped detection is recoverable (reprocessable) and never silent (the
        dropped_queue_full counter + a warning surface it). Falls back to a
        one-off task only if the executor isn't running yet (e.g. a direct
        caller before start()), preserving old behavior for tests."""
        if self._detect_queue is None:
            # Executor not started (unit tests, pre-start) — preserve legacy
            # fire-and-forget so nothing depends on start() ordering.
            try:
                asyncio.create_task(
                    self.process(agent_id, section, data, collected_at=collected_at)
                )
            except RuntimeError:
                pass  # no running loop (sync test context) — caller awaits process directly
            return True
        try:
            self._detect_queue.put_nowait((agent_id, section, data, collected_at))
            self._detect_stats["enqueued"] += 1
            return True
        except asyncio.QueueFull:
            self._detect_stats["dropped_queue_full"] += 1
            # Log sparsely — once per 100 drops — to avoid log floods under load.
            if self._detect_stats["dropped_queue_full"] % 100 == 1:
                log.warning(
                    "Detection queue full (cap=%d) — dropped %d payload(s) so far; "
                    "raw telemetry is still stored and reprocessable. Consider raising "
                    "ATTACKLENS_DETECTION_WORKERS/QUEUE_MAX or enabling queue mode.",
                    _DETECTION_QUEUE_MAX, self._detect_stats["dropped_queue_full"],
                )
            return False

    async def _detection_worker(self, idx: int) -> None:
        """Drains the detection queue, running process() one payload at a time.
        N of these run concurrently, capping total in-flight detection at N."""
        assert self._detect_queue is not None
        while True:
            try:
                agent_id, section, data, collected_at = await self._detect_queue.get()
            except asyncio.CancelledError:
                raise
            try:
                await self.process(agent_id, section, data, collected_at=collected_at)
                self._detect_stats["processed"] += 1
            except Exception as exc:
                self._detect_stats["errors"] += 1
                log.warning("detection worker %d error agent=%s section=%s: %s",
                            idx, agent_id, section, exc)
            finally:
                self._detect_queue.task_done()

    def detection_stats(self) -> dict:
        """Live executor throughput + backlog, for the health/diagnostics page.
        depth = payloads waiting; a depth pinned near queue_max means detection
        is the bottleneck (raise workers, or switch to queue mode)."""
        depth = self._detect_queue.qsize() if self._detect_queue is not None else 0
        return {
            **self._detect_stats,
            "queue_depth":  depth,
            "queue_max":    _DETECTION_QUEUE_MAX,
            "workers":      _DETECTION_WORKERS,
            "running":      bool(self._detect_workers),
        }

    async def _fleet_worker(self) -> None:
        """Periodic cross-host / global-threat sweep. Fully decoupled from the
        per-payload ingest path — a fleet campaign is inherently periodic, and
        coupling it to per-agent correlation would add DB I/O to the hot path."""
        while True:
            try:
                await asyncio.sleep(_FLEET_MIN_INTERVAL_SEC)
                await self._run_fleet_correlations()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                log.warning("Fleet worker error: %s", exc)

    @staticmethod
    def _stamp_provenance(evidence: Any, agent_id: str, section: str,
                          collected_at: float | None) -> None:
        """Record where a finding's evidence came from in the RAW telemetry, so
        every incident is verifiable against Deep Analysis (`/api/v1/raw/query?
        agent_id=…&section=…`). Stamped onto the evidence dict (no schema change)
        before the signal/finding is persisted; never overwrites an existing
        stamp (the primary signal of a multi-section cluster keeps its own)."""
        if isinstance(evidence, dict) and "_source" not in evidence:
            evidence["_source"] = {
                "agent_id":     agent_id,
                "section":      section,
                "collected_at": int(collected_at) if collected_at else None,
            }

    async def process(
        self,
        agent_id: str,
        section: str,
        data: Any,
        skip_correlation: bool = False,
        collected_at: float | None = None,
    ) -> None:
        """
        Entry point for every payload (or chunk).

        skip_correlation=True when the caller is processing a chunk that is
        part of a larger chunk set — the ChunkTracker will fire correlation
        once when the final chunk completes, rather than once per chunk.
        """
        if not self._ready:
            return
        # Captured BEFORE dispatch: present entities will be re-stamped with a
        # last_detected_at > t0 during this call; entities absent from this fresh
        # snapshot keep their older timestamp and get auto-resolved below.
        t0 = time.time()
        try:
            prov_ts = collected_at if collected_at else t0
            # ── Stage 1: rule matching → signals ──────────────────────────────
            # Dispatch ONCE per payload and reuse — the detections/ modules keep
            # internal dedup state, so a second dispatch in the same payload
            # would be suppressed (and the shadow-emit path would get nothing).
            disp_findings = await self._dispatch(agent_id, section, data)
            signals = await self._dispatch_to_signals(
                agent_id, section, data, findings=disp_findings,
            )
            beh_signals = await self._behav.analyze_as_signals(agent_id, section, data)
            signals.extend(beh_signals)

            # Stamp raw-payload provenance onto every signal BEFORE persisting,
            # so the finding it later produces is traceable to a Deep-Analysis row.
            for sig in signals:
                self._stamp_provenance(sig.evidence, agent_id, section, prov_ts)

            # Persist all signals (raw, before any filtering)
            for sig in signals:
                try:
                    sig_id = await self._idb.upsert_signal(sig)
                    sig.id = sig_id
                except Exception as exc:
                    log.debug("upsert_signal failed: %s", exc)

            # ── Stage 2: shadow mode — emit findings the old way ───────────────
            if not ENGINE_CONFIG["validation_pipeline_enabled"]:
                # Legacy emission path. We still compute a deterministic
                # precision score for each finding (without the LLM step) so
                # the UI's AI Precision Validator panel has something honest
                # to show instead of a misleading "0% / NO LLM VERDICT".
                findings = list(disp_findings)   # reuse the single dispatch above
                beh_old  = await self._behav.analyze(agent_id, section, data)
                findings.extend(beh_old)
                ts = time.time()
                for f in findings:
                    f["agent_id"] = agent_id
                    # Provenance → verifiable against the raw payload in Deep Analysis.
                    f["evidence"] = f.get("evidence") or {}
                    self._stamp_provenance(f["evidence"], agent_id, section, prov_ts)
                    try:
                        await self._attach_legacy_precision(f)
                    except Exception as exc:
                        log.debug("legacy precision attach failed: %s", exc)
                    await self._idb.upsert_finding(f, ts)
            else:
                # ── Stage 3: cluster → confidence → validate → emit ────────────
                await self._run_validation_pipeline(agent_id, signals)

            # ── Auto-resolve incidents whose evidence is no longer present ─────
            # For a live-inventory section delivered as a whole, valid snapshot,
            # any active finding in its categories that this snapshot did NOT
            # re-confirm (last_detected_at < t0) is resolved — closed ports,
            # removed packages and exited processes stop showing as active
            # incidents. Skipped for chunks (partial snapshot) and for
            # empty/errored data ("missed", not "gone") so we never mass-resolve.
            if not skip_correlation and ENGINE_CONFIG.get("auto_resolve_enabled"):
                recon_cats = _RECONCILE_SECTIONS.get(section)
                if recon_cats and _is_live_snapshot(data):
                    # Stale cutoff must exceed the longest alert-dedup window, or
                    # a still-present-but-dedup'd finding (last_detected_at not
                    # refreshed during its dedup window) would be wrongly resolved.
                    # Reads the live Settings → Data Retention value (org_settings)
                    # with a short cache, falling back to the env var default.
                    stale_sec = await self._auto_resolve_stale_sec()
                    try:
                        n = await self._idb.auto_resolve_absent(
                            agent_id, list(recon_cats), t0 - stale_sec, "evidence_stale",
                        )
                        if n:
                            log.info("auto-resolved %d stale %s incident(s) agent=%s "
                                     "(not re-confirmed in %.0fh)",
                                     n, section, agent_id, stale_sec / 3600.0)
                    except Exception as exc:
                        log.debug("auto_resolve_absent failed agent=%s section=%s: %s",
                                  agent_id, section, exc)

            if not skip_correlation:
                self._request_correlation(agent_id)

            # Mark the payload's detection complete in the ledger (the reconciler
            # replays anything that never reaches this point). Keyed on the same
            # (agent, section, collected_at) the telemetry worker recorded as
            # 'received'. Best-effort: a ledger write must never fail detection.
            try:
                if self._db is not None:
                    await self._db.ledger_processed(
                        agent_id, section, prov_ts, signal_count=len(signals),
                    )
            except Exception as exc:
                log.debug("ledger_processed failed agent=%s section=%s: %s",
                          agent_id, section, exc)
        except Exception as exc:
            log.warning("AttackLens.process error agent=%s section=%s: %s",
                        agent_id, section, exc)

    async def _dispatch_to_signals(self, agent_id: str, section: str, data: Any,
                                   findings: list[dict] | None = None) -> list[Signal]:
        """Run rules and convert matches to Signal objects (does not emit findings).

        `findings` may be passed in to avoid re-running `_dispatch` — important
        now that detection runs through the detections/ modules, which keep
        INTERNAL dedup state: dispatching twice in one payload would suppress the
        second call. process() dispatches once and shares the result here.
        """
        if findings is None:
            findings = await self._dispatch(agent_id, section, data)
        signals: list[Signal] = []
        for f in findings:
            # rule_id first: several detections/*.py build_alert() helpers
            # (arp_spoofing, container_security, ...) default "source" to a
            # generic module-level constant (e.g. "rule:arp_spoofing") even
            # when "rule_id" carries the specific, correctly-set identifier
            # (e.g. "arp:duplicate_ip_mapping") — `source or rule_id` would
            # always pick the less-specific generic one. rule_id is reliably
            # specific across every module; source is not.
            source = f.get("rule_id") or f.get("source") or "unknown"
            rule   = _lookup_rule_by_source(source)
            layer  = rule.get("layer") if rule else layer_for(section)
            if rule and "weight" in rule:
                weight = float(rule["weight"])
            elif "weight" in f:
                weight = float(f["weight"])
            else:
                weight = 0.65

            # strength = how strong is the EVIDENCE itself, independent of severity.
            # Prefer the rule's own confidence; fall back to the finding's confidence
            # if the rule didn't declare one; only fall back to score/10 as last resort.
            if rule and "confidence" in rule:
                strength = float(rule["confidence"])
            elif "confidence" in f:
                strength = float(f["confidence"])
            else:
                # Score is severity-derived (10 = critical); use a damped mapping so
                # a critical-severity rule with only weak evidence doesn't get 0.95.
                strength = min(0.85, float(f.get("score", 5.0)) / 10.0 * 0.85)

            # Authoritative external intel hits boost strength regardless of rule
            ev = f.get("evidence") or {}
            if ev.get("kev") or f.get("kev"):
                strength = max(strength, 0.95)
            if ev.get("malware_hash_hit") or ev.get("threat_hash_match"):
                strength = max(strength, 0.95)

            strength = max(0.0, min(1.0, strength))

            # Carry the original finding's title/description into evidence
            # under reserved keys so _emit_finding_from_cluster can recover them
            # instead of synthesizing a generic "[rule_id] severity detection"
            # placeholder — the specific title (e.g. detector-generated, naming
            # the actual host/process/account) is otherwise discarded the moment
            # a finding becomes a Signal for clustering.
            if f.get("title") and "_title" not in ev:
                ev["_title"] = f["title"]
            if f.get("description") and "_description" not in ev:
                ev["_description"] = f["description"]

            signals.append(Signal(
                rule_id=source,
                layer=layer,
                data_point=section,
                entity_key=f.get("item_key", f"{section}:{agent_id}"),
                agent_id=agent_id,
                severity_hint=f.get("severity", "medium"),
                evidence=ev,
                weight=weight,
                strength=strength,
            ))
        return signals

    async def _run_validation_pipeline(self, agent_id: str, new_signals: list[Signal]) -> None:
        """Cluster → enrich → score → validate → emit findings from validated clusters."""
        if not new_signals:
            return
        window = ENGINE_CONFIG["correlation_window_sec"]
        try:
            recent_rows = await self._idb.get_recent_signals(agent_id, since=time.time() - window)
        except Exception:
            recent_rows = []

        recent: list[Signal] = []
        for r in recent_rows:
            try:
                import json as _json
                recent.append(Signal(
                    rule_id=r["rule_id"],
                    layer=r["layer"],
                    data_point=r["data_point"],
                    entity_key=r["entity_key"],
                    agent_id=r["agent_id"],
                    severity_hint=r.get("severity_hint", "medium"),
                    evidence=_json.loads(r["evidence"] or "{}"),
                    weight=float(r["weight"] or 0.5),
                    strength=float(r["strength"] or 0.5),
                    detected_at=float(r["detected_at"]),
                    id=r["id"],
                    cluster_id=r.get("cluster_id"),
                ))
            except Exception:
                continue

        clusters = cluster_signals(new_signals + recent, window)

        # Only evaluate clusters that include at least one brand-new signal
        new_sig_ids = {id(s) for s in new_signals}
        clusters = [c for c in clusters if any(id(s) in new_sig_ids for s in c.signals)]

        ts = time.time()
        for cluster in clusters:
            try:
                enriched = await self._enrich_cluster(cluster)
                cluster_id = await self._idb.persist_cluster(cluster)

                cluster.confidence = await score_confidence(cluster, enriched, self._idb, agent_id)
                log.debug("cluster=%d agent=%s confidence=%.3f layers=%s",
                          cluster_id, agent_id, cluster.confidence, cluster.layers_covered)

                if cluster.confidence < ENGINE_CONFIG["confidence_threshold"]:
                    await self._idb.record_cluster_rejection(cluster, "low_confidence")
                    continue

                verdict = await validate_cluster(cluster, enriched, self._idb, self._feeds, self._db)
                if not verdict.passed:
                    await self._idb.record_cluster_rejection(cluster, verdict.failed_gate or "unknown")
                    continue

                # ── AI precision layer ───────────────────────────────────
                # Aggregates LLM verdict + multi-source TI + cross-layer +
                # baseline drift + asset tier + FP history into a single
                # precision score; requires ≥ threshold to promote.
                #
                # Threshold is resolved per cluster via the settings layer:
                #   per-agent > per-terrain > global > ENGINE_CONFIG default
                # The Settings → Validation page writes these knobs.
                precision: PrecisionResult | None = None
                if ai_validation_enabled():
                    # Resolve threshold for THIS cluster's primary category.
                    primary_cat = (cluster.signals[0].data_point
                                   if cluster.signals else "")
                    try:
                        threshold = await resolve_threshold(
                            self._idb, cluster.agent_id, primary_cat,
                        )
                    except Exception:
                        threshold = float(
                            ENGINE_CONFIG.get("ai_precision_threshold", 0.90)
                        )

                    # Settings can also gate whether the LLM step runs at all.
                    try:
                        ai_on = await use_ai_verdict_for(self._idb)
                    except Exception:
                        ai_on = True
                    ai_for_call = self._ai_analyst if ai_on else None

                    try:
                        precision = await validate_with_ai(
                            cluster, enriched, self._idb, self._feeds,
                            ai_for_call,
                            threshold=threshold,
                        )
                    except Exception as exc:
                        log.warning(
                            "ai_validator error agent=%s cluster=%s: %s",
                            agent_id, cluster_id, exc,
                        )
                    if precision is not None and not precision.promoted:
                        await self._idb.record_cluster_rejection(
                            cluster,
                            f"ai_precision:{precision.rejection_reason or 'low_score'}",
                        )
                        log.info(
                            "cluster=%s rejected by AI precision "
                            "(score=%.3f threshold=%.2f reason=%s)",
                            cluster_id, precision.score, threshold,
                            (precision.rejection_reason or "")[:120],
                        )
                        continue

                await self._emit_finding_from_cluster(
                    cluster, enriched, ts, precision=precision,
                )
            except Exception as exc:
                # Persist the error so the Validation Settings status page
                # can surface what broke instead of just logging silently.
                log.warning(
                    "validation_pipeline cluster error agent=%s cluster_id=%s: %s",
                    agent_id, getattr(cluster, "id", None), exc,
                )
                try:
                    if cluster is not None:
                        await self._idb.record_cluster_rejection(
                            cluster, f"engine_error:{type(exc).__name__}:{str(exc)[:120]}",
                        )
                except Exception:
                    pass

    async def _attach_legacy_precision(self, f: dict) -> None:
        """
        For findings emitted via the legacy path (validation pipeline OFF) we
        still compute a deterministic precision score so the UI panel reflects
        REAL evidence quality instead of showing a misleading 0%.

        The score uses the same deterministic factors as the AI validator:
        TI corroboration + asset criticality + FP-history damping + KEV/EPSS,
        but skips the LLM verdict entirely.  Findings get a clear status
        marker (`ai_validation_used = 0`) so the UI can render the right
        "validator not run" state.
        """
        from .ai_validator import (
            _ti_corroboration_score, _asset_criticality_score,
            _fp_damping_score, PRECISION_WEIGHTS,
        )

        ev = f.get("evidence") or {}
        if isinstance(ev, str):
            try:
                import json as _json
                ev = _json.loads(ev) or {}
            except Exception:
                ev = {}

        # Pull KEV / EPSS / IOC context out of the finding itself (cheap, no DB)
        kev = bool(f.get("kev") or ev.get("kev") or (isinstance(ev.get("cve"), dict) and ev["cve"].get("kev")))
        # Also cross-reference with the live FeedManager KEV set — covers
        # findings whose CVE was learned after emission
        if not kev:
            for cve_id in (f.get("cve_ids") or []) + (
                [ev["cve"]["cve_id"]] if isinstance(ev.get("cve"), dict) and ev["cve"].get("cve_id") else []
            ):
                try:
                    if cve_id and self._feeds.is_kev_cve(str(cve_id)):
                        kev = True
                        break
                except Exception:
                    pass

        epss_val = float(f.get("epss_score") or ev.get("epss_score") or 0.0)
        agent_id = f.get("agent_id", "")

        # Cross-finding enrichment so terrain criteria can resolve flags they
        # otherwise can't see from a single finding's evidence.  Each lookup is
        # cheap (indexed agent_id+category) and runs once per emit.
        package_running = False
        port_open       = False
        paired_persist  = False
        controls_off    = 0
        asset_tier      = f.get("asset_tier") or ""
        try:
            if agent_id:
                # Sibling categories on the same agent
                sibs = await self._idb._fetchall(
                    "SELECT category, item_key, evidence FROM findings "
                    "WHERE agent_id=? AND is_active=1 LIMIT 200",
                    (agent_id,),
                )
                pkg_name = str(ev.get("name") or "").lower()
                for row in sibs:
                    cat = row["category"]
                    if cat == "process" and pkg_name:
                        try:
                            sib_ev = json.loads(row["evidence"] or "{}")
                        except Exception:
                            sib_ev = {}
                        proc = str(sib_ev.get("process") or sib_ev.get("name") or "").lower()
                        path = str(sib_ev.get("path") or "").lower()
                        if pkg_name and (pkg_name in proc or pkg_name in path):
                            package_running = True
                    if cat == "port":
                        port_open = True
                    if cat in ("service", "task"):
                        paired_persist = True
                    if cat == "security":
                        controls_off += 1

                # Asset tier from registry — if not set on the finding itself
                if not asset_tier:
                    try:
                        asset_tier = await self._idb.get_asset_tier(agent_id)
                    except Exception:
                        asset_tier = "endpoint"
        except Exception as exc:
            log.debug("legacy cross-finding enrichment error: %s", exc)

        enriched = {
            "kev_hit":              kev,
            "malicious_ip_hit":     bool(str(f.get("source", "")).startswith("feed:") or f.get("source") == "abuseipdb"),
            "malicious_hash_hit":   bool(ev.get("malware_hash_hit") or ev.get("threat_hash_match")),
            "epss_scores":          [epss_val] if epss_val > 0 else [],
            "asset_tier":           asset_tier or "endpoint",
            "host_class":           f.get("host_class") or asset_tier or "unknown",
            "compensating_controls": [],
            # Cross-finding flags consumed by terrain_validators.py
            "package_running":      package_running,
            "port_open":            port_open,
            "paired_with_persistence": paired_persist,
            "cross_layer_match":    paired_persist,
            "controls_disabled_count": controls_off,
            "threat_intel_source_count": (1 if str(f.get("source","")).startswith("feed:") or f.get("source") == "abuseipdb" else 0) + (1 if kev else 0),
        }
        ti_score    = _ti_corroboration_score(enriched)
        asset_score = _asset_criticality_score(enriched)

        # FP damping needs a cluster-like object; fake the minimum interface.
        class _SyntheticCluster:
            agent_id = f.get("agent_id", "")
            signals  = []
            layers_covered: set = set()
        try:
            fp_damping = await _fp_damping_score(_SyntheticCluster(), enriched, self._idb)
        except Exception:
            fp_damping = 1.0

        # Use the rule's confidence (if known) as a stand-in for AI verdict
        # so the score stays calibrated against the real validator output.
        rule = _lookup_rule_by_source(f.get("source") or f.get("rule_id") or "")
        if rule and "confidence" in rule:
            ai_proxy = float(rule["confidence"])
        else:
            ai_proxy = min(0.85, float(f.get("score", 5.0)) / 10.0 * 0.85)
        # Strong external intel hits boost the proxy
        if kev: ai_proxy = max(ai_proxy, 0.92)
        if epss_val >= 0.7: ai_proxy = max(ai_proxy, 0.85)

        factors = {
            "ai_verdict":         ai_proxy,
            "ti_corroboration":   ti_score,
            "cross_layer":        0.40,            # single-source/legacy assumed surface
            "baseline_anomaly":   0.85,            # legacy can't easily check baselines
            "asset_criticality":  asset_score,
            "fp_history_damping": fp_damping,
        }
        score = sum(PRECISION_WEIGHTS.get(k, 0) * v for k, v in factors.items())
        score = max(0.0, min(1.0, score))

        # ── Terrain validation — same criteria the validated findings page
        # filters on, computed here even in legacy mode so findings get a
        # real, terrain-appropriate percentage instead of a generic factor mix.
        try:
            from .terrain_validators import evaluate_finding
            tv = evaluate_finding(f, enriched, ai_verdict=None)
            f["terrain_validation"] = tv
            # Replace the factor-only score with the terrain percentage so
            # the threshold filter (Settings → Validation) gates on the same
            # number the analyst sees in the UI checklist.
            score = tv["score"]
        except Exception as exc:
            log.debug("terrain_validation legacy error: %s", exc)

        f["precision_score"]    = round(score, 3)
        f["precision_factors"]  = factors
        # No LLM call ran in legacy mode — clear ai_verdict and signal that
        # validation_used == 0 so the UI renders "Validator not active".
        f["ai_verdict"]         = {}
        f["ai_validation_used"] = 0

    async def _enrich_cluster(self, cluster) -> dict:
        """Gather threat-intel context using existing FeedManager + CVELookup."""
        cve_ids: set[str] = set()
        ips:     set[str] = set()
        hashes:  set[str] = set()
        exploit_available = False   # public exploit (ExploitDB/Metasploit/PoC)

        for s in cluster.signals:
            ev = s.evidence or {}
            # Public-exploit availability — nvd.py derives `exploit_available`
            # from a CVE's references (ExploitDB/Metasploit/PoC); rules may also
            # attach it directly. Surfaced here so the precision score can credit
            # "weaponised, code is public" as an authoritative corroborating source.
            if ev.get("exploit_available"):
                exploit_available = True
            if isinstance(ev.get("cve"), dict) and ev["cve"].get("exploit_available"):
                exploit_available = True
            for _c in ev.get("cves") or []:
                if isinstance(_c, dict) and _c.get("exploit_available"):
                    exploit_available = True
            # CVE extraction — tolerate every shape rules emit
            if cve := ev.get("cve_id"):
                cve_ids.add(str(cve).upper())
            if isinstance(ev.get("cve"), dict) and (cid := ev["cve"].get("cve_id")):
                cve_ids.add(str(cid).upper())
            elif isinstance(ev.get("cve"), str) and ev["cve"]:
                cve_ids.add(ev["cve"].upper())
            for cid in ev.get("cve_ids") or []:
                if cid:
                    cve_ids.add(str(cid).upper())
            for c in ev.get("cves") or []:
                if isinstance(c, dict) and c.get("cve_id"):
                    cve_ids.add(str(c["cve_id"]).upper())
                elif isinstance(c, str):
                    cve_ids.add(c.upper())

            # IP extraction
            remote = (
                ev.get("dst_ip")
                or ev.get("remote_ip")
                or ev.get("remote_addr", "").rsplit(":", 1)[0].strip("[]")
            )
            if remote and remote not in ("", "-", "0.0.0.0"):
                ips.add(remote)

            # Hash extraction — accept many shapes
            for k in ("sha256", "binary_hash", "image_disk_sha256", "image_mem_sha256", "file_hash"):
                if h := ev.get(k):
                    hashes.add(str(h).lower())

        # KEV check — sync method on FeedManager is is_kev_cve()
        kev_hit = False
        if cve_ids:
            try:
                kev_hit = any(self._feeds.is_kev_cve(c) for c in cve_ids)
            except Exception as exc:
                log.debug("KEV lookup error: %s", exc)

        # EPSS scores — bulk cache lookup first, then per-CVE live fetch only for misses.
        epss_scores: list[float] = []
        if cve_ids:
            try:
                bulk = await self._feeds.bulk_epss(sorted(cve_ids))
            except Exception as exc:
                log.debug("EPSS bulk lookup error: %s", exc)
                bulk = {}
            missing = [c for c in cve_ids if c not in bulk]
            for c, score in bulk.items():
                try:
                    if score is not None:
                        epss_scores.append(float(score))
                except (TypeError, ValueError):
                    pass
            # Cap live fetches at 3 per cluster to bound NVD/EPSS rate-limit pressure
            for c in list(missing)[:3]:
                try:
                    rec = await self._feeds.get_epss(c)
                    if rec and rec.get("epss") is not None:
                        epss_scores.append(float(rec["epss"]))
                except Exception as exc:
                    log.debug("EPSS lookup error for %s: %s", c, exc)

        # Malicious IP / hash IOC checks
        mal_ip = False
        if ips:
            try:
                mal_ip = any(self._feeds.is_malicious_ip(ip) for ip in ips)
            except Exception as exc:
                log.debug("malicious IP lookup error: %s", exc)

        mal_hash = False
        for h in hashes:
            try:
                if await self._idb.is_malicious_hash(h):
                    mal_hash = True
                    break
            except Exception as exc:
                log.debug("malicious hash lookup error for %s: %s", h, exc)

        # Threat-intel source count: each independent corroborating source
        ti_count = (
            (1 if kev_hit else 0)
            + (1 if mal_ip else 0)
            + (1 if mal_hash else 0)
            + (1 if epss_scores else 0)
            + (1 if exploit_available else 0)
        )

        asset_tier = await self._idb.get_asset_tier(cluster.agent_id)
        host_class = await self._idb.get_host_class(cluster.agent_id) or asset_tier
        controls   = await self._idb.get_compensating_controls(cluster.agent_id)

        return {
            "kev_hit":                   kev_hit,
            "epss_scores":               epss_scores,
            "malicious_ip_hit":          mal_ip,
            "malicious_hash_hit":        mal_hash,
            "exploit_available":         exploit_available,
            "threat_intel_source_count": ti_count,
            "asset_tier":                asset_tier,
            "host_class":                host_class,
            "compensating_controls":     controls,
            "cve_ids":                   sorted(cve_ids),
            "malicious_ips":             sorted(ips) if mal_ip else [],
            "malicious_hashes":          sorted(hashes) if mal_hash else [],
        }

    async def _emit_finding_from_cluster(
        self,
        cluster,
        enriched: dict,
        ts: float,
        precision: PrecisionResult | None = None,
    ) -> None:
        """Build a finding dict from the highest-severity signal in the cluster and upsert it."""
        primary = max(cluster.signals, key=lambda s: (s.weight, s.strength))
        sev     = primary.severity_hint
        layers  = sorted(cluster.layers_covered)
        # Reserved keys carried via _dispatch_to_signals — recover then strip
        # so they don't leak into the persisted evidence shown to analysts.
        title       = primary.evidence.pop("_title", None)
        description = primary.evidence.pop("_description", None)
        f: dict[str, Any] = {
            "agent_id":              cluster.agent_id,
            # Map the raw section name (data_point, e.g. "ports") through the
            # same _SECTION_CATEGORY taxonomy the legacy path and every
            # dashboard /api/v1/detection/* endpoint filters on (e.g. "port",
            # singular) — using data_point directly silently orphaned every
            # validation-promoted finding from category-scoped queries.
            "category":              _SECTION_CATEGORY.get(primary.data_point, primary.data_point),
            "item_key":              cluster.entity_key,
            "severity":              sev,
            "score":                 severity_to_score(sev),
            "title":                 title or f"[{primary.rule_id}] {sev} detection",
            "description":           description or primary.evidence.get("desc", ""),
            "evidence":              primary.evidence,
            "source":                primary.rule_id,
            "rule_id":               primary.rule_id,
            "mitre_technique":       primary.evidence.get("mitre_technique", ""),
            "mitre_tactic":          primary.evidence.get("mitre_tactic", ""),
            "tags":                  [primary.data_point, primary.rule_id],
            "confidence":            round(cluster.confidence or 0.0, 3),
            "signal_cluster_id":     cluster.id,
            "validation_gates_passed": "[]",
            "layers_involved":       f'[{",".join(repr(l) for l in layers)}]',
            "host_class":            enriched.get("host_class", ""),
            "kev":                   enriched.get("kev_hit", False),
            "epss_score":            max(enriched.get("epss_scores") or [0]),
        }

        # Stamp the AI precision verdict and per-factor breakdown so analysts
        # and the dashboard can audit *why* this finding was promoted.
        if precision is not None:
            f["precision_score"]   = precision.score
            f["precision_factors"] = precision.factors
            if precision.ai is not None:
                f["ai_verdict"] = {
                    "label":        precision.ai.label,
                    "confidence":   precision.ai.confidence,
                    "reasoning":    precision.ai.reasoning,
                    "key_evidence": precision.ai.key_evidence,
                    "risk_factors": precision.ai.risk_factors,
                    "tokens_used":  precision.ai.tokens_used,
                }
                # Add a structured tag so the UI can filter for AI-validated findings.
                f["tags"] = list(f["tags"]) + [f"ai:{precision.ai.label}"]
            # Surface precision in the analyst-visible evidence too.
            ev = dict(f.get("evidence") or {})
            ev["precision_score"]   = precision.score
            ev["precision_factors"] = precision.factors
            f["evidence"] = ev

        # ── Terrain validation — the analyst-facing per-criterion checklist.
        # This is what the Validated Findings page filters on (precision_score
        # is set equal to the terrain percentage, normalised to 0..1).
        try:
            from .terrain_validators import evaluate_finding
            ai_dict = f.get("ai_verdict") if isinstance(f.get("ai_verdict"), dict) else None
            tv = evaluate_finding(f, enriched, ai_dict)
            f["terrain_validation"] = tv
            # Make terrain score the canonical precision number so the
            # Validated Findings threshold filter "just works".
            f["precision_score"] = tv["score"]
        except Exception as exc:
            log.warning("terrain_validation error agent=%s: %s", cluster.agent_id, exc)

        composite = score_matrix.compute(f, agent_id=cluster.agent_id, collected_ts=ts)
        f["composite_score"] = composite
        result = await self._idb.upsert_finding(f, ts)
        if result == "new":
            row = await self._idb._fetchone(
                "SELECT id FROM findings WHERE agent_id=? AND category=? AND item_key=?",
                (cluster.agent_id, f["category"], f["item_key"]),
            )
            if row and cluster.id:
                await self._idb.mark_cluster_promoted(cluster.id, row["id"])

    async def run_correlations(self, agent_id: str) -> None:
        """
        Public trigger for cross-section correlation.
        Called by ChunkTracker when the last chunk of a chunk set completes.
        """
        self._request_correlation(agent_id)

    def _request_correlation(self, agent_id: str) -> None:
        """Request a correlation pass for an agent, coalescing concurrent
        requests. At most one pass runs per agent at a time; requests that
        arrive while a pass is in flight set a dirty flag so exactly one more
        pass runs after it — every event gets correlated promptly without
        spawning a pass per payload (which at volume would hammer the DB)."""
        if agent_id in self._correlate_inflight:
            self._correlate_dirty.add(agent_id)
            return
        self._correlate_inflight.add(agent_id)
        try:
            asyncio.create_task(self._correlation_loop(agent_id))
        except RuntimeError:
            # No running loop (sync/test context) — drop the inflight marker so
            # a later call in a real loop can schedule.
            self._correlate_inflight.discard(agent_id)

    async def _correlation_loop(self, agent_id: str) -> None:
        """Run correlation for an agent, then re-run once if more data arrived
        while it was running (coalesced burst). Always clears its inflight
        marker on exit so the agent can be scheduled again."""
        try:
            while True:
                await self._run_correlations(agent_id)
                if agent_id in self._correlate_dirty:
                    self._correlate_dirty.discard(agent_id)
                    continue   # data arrived mid-pass — fold it into one more run
                break
        finally:
            self._correlate_inflight.discard(agent_id)

    async def _run_correlations(self, agent_id: str) -> None:
        """Evaluate cross-section correlation rules and store results."""
        try:
            correlations = await self._corr.correlate(agent_id)
            ts = time.time()
            for c in correlations:
                await self._idb.upsert_correlation(c, ts)
        except Exception as exc:
            log.warning("Correlation error agent=%s: %s", agent_id, exc)

    async def run_fleet_correlations(self) -> None:
        """Public trigger for the cross-host sweep (e.g. a periodic scheduler)."""
        asyncio.create_task(self._run_fleet_correlations())

    async def _run_fleet_correlations(self) -> None:
        """Evaluate fleet-wide / global-threat campaigns across all hosts and
        persist them under the reserved __fleet__ pseudo-agent."""
        try:
            campaigns = await self._fleet.correlate()
            ts = time.time()
            for c in campaigns:
                await self._idb.upsert_correlation(c, ts)
            if campaigns:
                log.info("Fleet correlation: %d cross-host campaign(s) active",
                         len(campaigns))
        except Exception as exc:
            log.warning("Fleet correlation error: %s", exc)

    async def get_correlations(self, agent_id: str) -> list[dict]:
        """Return current correlations for an agent (called by API)."""
        try:
            return await self._idb.get_correlations(agent_id)
        except Exception:
            return []

    async def get_fleet_correlations(self) -> list[dict]:
        """Return current fleet-wide / global-threat campaigns (called by API)."""
        try:
            from ..indexer import FLEET_AGENT_ID
            return await self._idb.get_correlations(FLEET_AGENT_ID)
        except Exception:
            return []

    # ── Dispatcher ────────────────────────────────────────────────────────────

    async def _dispatch(self, agent_id: str, section: str, data: Any) -> list[dict]:
        # Route verified sections through the rich detections/ modules (which
        # carry baselines, allowlists, MITRE mapping + the FP fixes); fall back
        # to the inline analyzer for everything else. Each module's findings are
        # adapted to the engine finding format. Opt out via use_detection_modules.
        if ENGINE_CONFIG.get("use_detection_modules", True):
            routes = _DETECTION_MODULE_ROUTES.get(section)
            if routes:
                # The engine is the single dedup authority: upsert_finding dedups
                # by fingerprint and WANTS every observation to re-upsert (so
                # scan_count + last_detected_at refresh, which auto-resolve relies
                # on). The modules' INTERNAL in-memory alert-dedup would suppress
                # that re-emission, so reset it per dispatch. (First-run seeding is
                # DB-backed entity-state, not this cache, so the FP fix is intact.)
                import sys as _sys
                for analyze in routes:
                    _m = _sys.modules.get(getattr(analyze, "__module__", ""))
                    for _attr in ("_dedup_cache", "_rate_counter"):
                        _c = getattr(_m, _attr, None)
                        if isinstance(_c, dict):
                            _c.clear()
                mod_findings: list[dict] = []
                for analyze in routes:
                    try:
                        res = await analyze(agent_id, section, data, self._idb, "")
                    except Exception as exc:
                        log.warning(
                            "detection module %s failed agent=%s section=%s: %s",
                            getattr(analyze, "__module__", "?"), agent_id, section, exc,
                        )
                        continue
                    for f in (res or []):
                        mod_findings.append(_adapt_module_finding(f, section))
                return mod_findings

        fn = {
            "ports":       self._ports,
            "processes":   self._processes,
            "connections": self._connections,
            "services":    self._services,
            "apps":        self._apps,
            "packages":    self._packages,
            "network":     self._network,
            "users":       self._users,
            "tasks":       self._tasks,
            "security":    self._security,
            "configs":     self._configs,
            "binaries":    self._binaries,
            "metrics":     self._metrics,
        }.get(section)
        if fn is None:
            return []
        return await fn(agent_id, data)

    # ── Section analyzers ─────────────────────────────────────────────────────

    # ── Resource-anomaly detection (metrics section) ──────────────────────────

    # Thresholds — conservative to avoid alerting on temporary spikes.
    _CPU_HIGH_PCT   = 90.0   # % total CPU
    _MEM_HIGH_PCT   = 92.0   # % RAM used
    _NET_HIGH_MB_S  = 50.0   # MB/s outbound (exfil signal)
    _DISK_HIGH_MB_S = 150.0  # MB/s write (ransomware encryption signal)
    _LOAD_RATIO     = 2.0    # load_1m / logical_cores — system under sustained load
    _CONSEC_NEEDED  = 2      # consecutive high readings before alerting

    async def _metrics(self, agent_id: str, data) -> list[dict]:
        """Detect resource anomalies that signal cryptomining, ransomware, or exfil.

        Requires _CONSEC_NEEDED consecutive high readings to fire — avoids
        alerting on transient spikes (JIT compilation, Time Machine backup, etc.).
        Auto-resolves when readings return to normal via the standard mechanism
        (findings are NOT re-upserted once the anomaly clears).
        """
        findings = []
        # The metrics section is a single dict per collection cycle.
        m: dict = data if isinstance(data, dict) else (data[0] if data else {})
        if not isinstance(m, dict):
            return findings

        cpu_pct    = float(m.get("cpu_percent") or 0.0)
        mem_pct    = float(m.get("mem_percent") or 0.0)
        net_out    = float(m.get("net_sent_mb_s") or 0.0)
        disk_write = float(m.get("disk_write_mb_s") or 0.0)
        load_1m    = float(m.get("load_1m") or 0.0)
        cores      = int(m.get("cpu_cores") or 1) or 1

        state = self._metrics_state.setdefault(agent_id, {
            "cpu_high": 0, "mem_high": 0, "net_high": 0, "disk_high": 0,
        })

        # ── CPU spike ────────────────────────────────────────────────────────
        load_ratio = load_1m / cores
        cpu_anomaly = cpu_pct >= self._CPU_HIGH_PCT or load_ratio >= self._LOAD_RATIO
        if cpu_anomaly:
            state["cpu_high"] += 1
        else:
            state["cpu_high"] = 0

        if state["cpu_high"] >= self._CONSEC_NEEDED:
            findings.append(self._finding(
                category="behavioral",
                item_key=f"metrics:cpu_spike:{agent_id}",
                severity="high",
                score=7.5,
                title="Sustained CPU spike — possible cryptominer",
                desc=(
                    f"System CPU has been at {cpu_pct:.1f}% for "
                    f"{state['cpu_high']} consecutive readings "
                    f"(load average: {load_1m:.2f} / {cores} cores = {load_ratio:.1f}x). "
                    "Sustained high CPU on a desktop endpoint is a strong indicator "
                    "of cryptocurrency mining (T1496) or a runaway malicious process."
                ),
                evidence=m,
                source="rule:metrics_cpu_spike",
                mitre="T1496",
                tags=["metrics", "cryptominer", "resource_abuse"],
                confidence=0.75,
                weight=0.80,
            ))

        # ── Memory exhaustion ────────────────────────────────────────────────
        if mem_pct >= self._MEM_HIGH_PCT:
            state["mem_high"] += 1
        else:
            state["mem_high"] = 0

        if state["mem_high"] >= self._CONSEC_NEEDED:
            mem_used  = m.get("mem_used_mb", 0)
            mem_total = m.get("mem_total_mb", 0)
            findings.append(self._finding(
                category="behavioral",
                item_key=f"metrics:mem_pressure:{agent_id}",
                severity="medium",
                score=5.5,
                title=f"Sustained memory pressure ({mem_pct:.1f}% used)",
                desc=(
                    f"RAM usage has been at {mem_pct:.1f}% "
                    f"({mem_used} MB / {mem_total} MB) for "
                    f"{state['mem_high']} consecutive readings. "
                    "Excessive memory pressure can indicate process injection, "
                    "memory-resident malware, or a DoS condition (T1499)."
                ),
                evidence=m,
                source="rule:metrics_mem_pressure",
                mitre="T1499",
                tags=["metrics", "memory", "resource_abuse"],
                confidence=0.60,
                weight=0.65,
            ))

        # ── High outbound network (exfiltration signal) ───────────────────
        if net_out >= self._NET_HIGH_MB_S:
            state["net_high"] += 1
        else:
            state["net_high"] = 0

        if state["net_high"] >= self._CONSEC_NEEDED:
            findings.append(self._finding(
                category="behavioral",
                item_key=f"metrics:net_exfil:{agent_id}",
                severity="high",
                score=7.0,
                title=f"High outbound network ({net_out:.1f} MB/s) — possible exfiltration",
                desc=(
                    f"Outbound network throughput has been {net_out:.1f} MB/s for "
                    f"{state['net_high']} consecutive readings. "
                    "Sustained high egress from an endpoint is a key indicator of "
                    "data exfiltration (T1048). Correlate with connection and process data."
                ),
                evidence=m,
                source="rule:metrics_net_exfil",
                mitre="T1048",
                tags=["metrics", "exfiltration", "network"],
                confidence=0.70,
                weight=0.75,
            ))

        # ── High disk write (ransomware encryption signal) ───────────────
        if disk_write >= self._DISK_HIGH_MB_S:
            state["disk_high"] += 1
        else:
            state["disk_high"] = 0

        if state["disk_high"] >= self._CONSEC_NEEDED:
            findings.append(self._finding(
                category="behavioral",
                item_key=f"metrics:disk_ransomware:{agent_id}",
                severity="critical",
                score=9.0,
                title=f"High sustained disk write ({disk_write:.1f} MB/s) — possible ransomware",
                desc=(
                    f"Disk write throughput has been {disk_write:.1f} MB/s for "
                    f"{state['disk_high']} consecutive readings — well above the "
                    "threshold for normal user workloads. Sustained bulk writes at "
                    "this rate on an endpoint are a hallmark of ransomware encrypting "
                    "files in place (T1486). Isolate immediately and investigate."
                ),
                evidence=m,
                source="rule:metrics_disk_ransomware",
                mitre="T1486",
                tags=["metrics", "ransomware", "disk"],
                confidence=0.78,
                weight=0.85,
            ))

        return findings

    async def _ports(self, agent_id: str, data: list) -> list[dict]:
        findings = []
        if not isinstance(data, list):
            return findings
        seen_ports: set[int] = set()
        for item in data:
            if not isinstance(item, dict):
                continue
            port   = int(item.get("port", 0) or 0)
            proto  = item.get("proto", "tcp")
            proc   = item.get("process", "") or item.get("name", "")
            path   = item.get("path", "") or item.get("exe", "")
            bind   = item.get("bind_addr", item.get("addr", ""))
            key    = f"{proto}:{port}"

            if port in seen_ports:
                continue
            seen_ports.add(port)

            # Known malicious port
            if port in MALICIOUS_PORTS and port not in _SAFE_LISTEN:
                rule = MALICIOUS_PORTS[port]
                findings.append(self._finding(
                    category="port", item_key=key,
                    severity=rule["severity"],
                    score=severity_to_score(rule["severity"]),
                    title=f"Malicious port listening: {proto.upper()}/{port}",
                    desc=f"{rule['desc']}. Bound by process: {proc or 'unknown'}.",
                    evidence=item, source="rule:malicious_port",
                    mitre=rule["mitre"],
                    tags=["port", "c2", proto],
                ))

            # Process running from suspicious path
            if path:
                for sp in SUSPICIOUS_PATHS:
                    if sp["pattern"].match(path):
                        findings.append(self._finding(
                            category="port", item_key=f"{key}:susppath",
                            severity=sp["severity"],
                            score=severity_to_score(sp["severity"]),
                            title=f"Listening process in suspicious path: {path}",
                            desc=f"{sp['desc']} — {proc} listening on {proto}/{port}.",
                            evidence=item, source="rule:suspicious_path",
                            mitre="T1036", tags=["port", "suspicious_path"],
                        ))
                        break

            # Binding to 0.0.0.0 on unusual port
            if bind in ("0.0.0.0", "::") and port not in _SAFE_LISTEN and port > 1024:
                findings.append(self._finding(
                    category="port", item_key=f"{key}:wildcard",
                    severity="low", score=2.5,
                    title=f"Port {port} bound to all interfaces",
                    desc=f"Process '{proc}' is listening on 0.0.0.0:{port} (world-accessible).",
                    evidence=item, source="rule:wildcard_bind",
                    mitre="T1049", tags=["port", "exposure"],
                ))
        return findings

    async def _processes(self, agent_id: str, data: list) -> list[dict]:
        findings = []
        if not isinstance(data, list):
            return findings

        # Build a pid → name/exe lookup for parent-child analysis
        pid_map: dict[int, dict] = {}
        for item in data:
            if isinstance(item, dict):
                try:
                    pid_map[int(item.get("pid", 0) or 0)] = item
                except (ValueError, TypeError):
                    pass

        for item in data:
            if not isinstance(item, dict):
                continue
            name    = str(item.get("name", "") or "")
            cmd     = str(item.get("cmdline", "") or item.get("cmd", "") or "")
            exe     = str(item.get("exe", "") or item.get("path", "") or "")
            pid     = item.get("pid", "?")
            ppid    = item.get("ppid") or item.get("parent_pid")
            full    = f"{exe} {cmd}".strip()

            # Derive exe from cmdline first token when the field is absent.
            # Some agents (macOS ps-based collector) omit exe but embed the full
            # path as argv[0] in cmdline — without this, /System/Library/ and
            # /usr/libexec/ processes pass is_apple_system_process unchecked.
            if not exe and cmd:
                exe = cmd.split()[0]

            # Skip Apple system processes entirely
            if is_apple_system_process(name, exe):
                continue

            # Resolve parent name for lineage checks
            parent_name = ""
            if ppid:
                try:
                    parent_item = pid_map.get(int(ppid), {})
                    parent_name = str(parent_item.get("name", "") or "")
                except (ValueError, TypeError):
                    pass

            # Benign parent check — suppress if spawned from known-good IDE/shell
            if parent_name and has_benign_parent(parent_name, name):
                continue

            # Parent-child lineage rules (Office/browser → shell is critical)
            for lrule in PARENT_CHILD_RULES:
                if parent_name and lrule["parent_re"].search(parent_name):
                    if lrule["child_re"].search(name) or lrule["child_re"].search(cmd):
                        f = self._finding(
                            category="process",
                            item_key=f"lineage:{parent_name}:{name}:{pid}",
                            severity=lrule["severity"],
                            score=severity_to_score(lrule["severity"]),
                            title=f"Suspicious spawn: {parent_name} → {name}",
                            desc=(f"{lrule['desc']} — "
                                  f"'{parent_name}' (PID {ppid}) spawned '{name}' (PID {pid}): {cmd[:100]}"),
                            evidence={**item, "parent_name": parent_name, "ppid": ppid},
                            source="rule:process_lineage", mitre=lrule["mitre"],
                            tags=["process", "lineage", "high_confidence"],
                            confidence=lrule.get("confidence"),
                            # PARENT_CHILD_RULES has no explicit weight field — these
                            # are individually diagnostic (office/browser spawning a
                            # shell has no benign explanation), hence the high default.
                            weight=0.90,
                        )
                        findings.append(f)
                        break

            # Standard process pattern rules
            for rule in PROCESS_RULES:
                if rule["compiled"].search(full) or rule["compiled"].search(name):
                    f = self._finding(
                        category="process",
                        item_key=f"proc:{name}:{_fp(exe or cmd)}",
                        severity=rule["severity"],
                        score=severity_to_score(rule["severity"]) * rule.get("confidence", 0.8),
                        title=f"Suspicious process: {name}",
                        desc=f"{rule['desc']} — PID {pid}: {cmd[:120]}",
                        evidence=item, source="rule:process_pattern",
                        mitre=rule["mitre"], tags=["process", "suspicious"],
                        confidence=rule.get("confidence"),
                        weight=rule.get("weight"),
                    )
                    # Apply dual-use allowlist adjustment
                    f = adjust_finding_for_allowlist(f, name=name, path=exe, cmd=cmd,
                                                     parent_name=parent_name)
                    if f:
                        findings.append(f)
                    break

            # Obfuscation pattern check against cmdline.
            # Electron/Chromium helpers embed --field-trial-handle=1,i,<base64>
            # which matches the generic long-base64 pattern — skip them.
            # Double-check system processes too (belt-and-suspenders: the
            # is_apple_system_process guard at the loop top may have been
            # bypassed if exe was empty before the derivation above).
            _obf_skip = (
                (" helper" in name.lower() and exe.startswith("/Applications/"))
                or is_apple_system_process(name, exe)
            )
            if not _obf_skip:
                for orule in OBFUSCATION_RULES:
                    if orule["compiled"].search(cmd):
                        f = self._finding(
                            category="process",
                            item_key=f"obfusc:{name}:{_fp(cmd)}",
                            severity=orule["severity"],
                            score=severity_to_score(orule["severity"]) * orule.get("confidence", 0.8),
                            title=f"Obfuscated command in process: {name}",
                            desc=f"{orule['desc']} — PID {pid}: {cmd[:150]}",
                            evidence=item, source="rule:obfuscation",
                            mitre=orule["mitre"], tags=["process", "obfuscation"],
                            confidence=orule.get("confidence"),
                            # OBFUSCATION_RULES has no weight field — obfuscated/encoded
                            # execution is itself the diagnostic signal, default high.
                            weight=0.85,
                        )
                        findings.append(f)
                        break

            # SUID / SGID check
            if item.get("suid") or item.get("is_suid"):
                findings.append(self._finding(
                    category="process", item_key=f"proc_suid:{_fp(exe or name)}",
                    severity="medium", score=4.5,
                    title=f"SUID process running: {name}",
                    desc=f"Process {name} (PID {pid}) is running with SUID bit set.",
                    evidence=item, source="rule:suid_process",
                    mitre="T1548.001", tags=["process", "privilege_escalation"],
                ))

        return findings

    async def _connections(self, agent_id: str, data: list) -> list[dict]:
        findings = []
        if not isinstance(data, list):
            return findings
        for item in data:
            if not isinstance(item, dict):
                continue
            raddr = str(item.get("remote_addr", "") or item.get("raddr", "") or "")
            if not raddr or raddr in ("-", "0.0.0.0:0", "*:*"):
                continue
            ip = raddr.rsplit(":", 1)[0].strip("[]")
            if not ip or _PRIVATE_RE.match(ip):
                continue
            # Skip trusted CDN/cloud IPs to reduce FP
            if is_trusted_ip(ip):
                continue

            # Threat feed check
            if self._feeds.is_malicious_ip(ip):
                meta = self._feeds.get_details(ip) or {}
                findings.append(self._finding(
                    category="connection",
                    item_key=f"conn:{ip}",
                    severity=meta.get("severity", "high"),
                    score=severity_to_score(meta.get("severity", "high")),
                    title=f"Connection to threat-feed IP: {ip}",
                    desc=(f"Active connection to {raddr} — "
                          f"{meta.get('description','Known malicious IP')} "
                          f"(source: {meta.get('source','')}, confidence: {meta.get('confidence',0)}%)"),
                    evidence={**item, "threat_meta": meta},
                    source=f"feed:{meta.get('source','unknown')}",
                    mitre="T1071", tags=["connection", "c2", "threat_feed"],
                ))
            else:
                # Queue for live AbuseIPDB check (non-blocking)
                try:
                    self._nvd_queue.put_nowait(("abuseipdb", agent_id, ip, item))
                except asyncio.QueueFull:
                    pass
        return findings

    async def _services(self, agent_id: str, data: list) -> list[dict]:
        findings = []
        if not isinstance(data, list):
            return findings
        for item in data:
            if not isinstance(item, dict):
                continue
            label = str(item.get("label", "") or item.get("name", "") or "")
            prog  = str(item.get("program", "") or item.get("path", "") or "")
            # Apple first-party LaunchDaemons/Agents use reverse-DNS com.apple. prefixes.
            # They are always legitimate; pattern-matching their names generates FPs
            # like com.apple.CryptoTokenKit matching "crypto".
            if label.lower().startswith("com.apple.") or prog.startswith("/System/Library/"):
                continue
            for rule in SUSPICIOUS_SERVICE_PATTERNS:
                if rule["pattern"].search(label) or (prog and rule["pattern"].search(prog)):
                    findings.append(self._finding(
                        category="service", item_key=f"svc:{label}",
                        severity=rule["severity"],
                        score=severity_to_score(rule["severity"]),
                        title=f"Suspicious service: {label}",
                        desc=f"{rule['desc']}.",
                        evidence=item, source="rule:suspicious_service",
                        mitre="T1543.004",
                        tags=["service", "persistence"],
                    ))
                    break
        return findings

    async def _apps(self, agent_id: str, data: list) -> list[dict]:
        findings = []
        if not isinstance(data, list):
            return findings
        for item in data:
            if not isinstance(item, dict):
                continue
            name   = str(item.get("name", "") or "")
            signed = item.get("signed", True)
            notarized = item.get("notarized", True)
            quarantine = item.get("quarantined", False)
            path   = str(item.get("path", "") or "")

            # Apple system apps (/System/Applications/, /System/Library/CoreServices/)
            # are signed directly by Apple and are not subject to the third-party
            # notarization requirement. Flagging them as "non-notarized" is always
            # a false positive — skip all signing/notarization checks for them.
            if path and any(path.startswith(p) for p in APPLE_SYSTEM_PATH_PREFIXES):
                continue

            if not signed:
                findings.append(self._finding(
                    category="app", item_key=f"app:{path or name}:unsigned",
                    severity="medium", score=5.0,
                    title=f"Unsigned application: {name}",
                    desc=f"'{name}' at {path} is not code-signed by Apple.",
                    evidence=item, source="rule:unsigned_app",
                    mitre="T1553.001", tags=["app", "unsigned"],
                ))
            elif not notarized:
                findings.append(self._finding(
                    category="app", item_key=f"app:{path or name}:notarized",
                    severity="low", score=2.0,
                    title=f"Non-notarized application: {name}",
                    desc=f"'{name}' is signed but not notarized by Apple.",
                    evidence=item, source="rule:not_notarized",
                    mitre="T1553.001", tags=["app", "notarization"],
                ))
            if quarantine:
                findings.append(self._finding(
                    category="app", item_key=f"app:{path or name}:quarantine",
                    severity="medium", score=4.0,
                    title=f"Quarantined application running: {name}",
                    desc=f"'{name}' has a quarantine flag — was downloaded from internet.",
                    evidence=item, source="rule:quarantine",
                    mitre="T1204.002", tags=["app", "quarantine"],
                ))
        return findings

    async def _packages(self, agent_id: str, data: list) -> list[dict]:
        findings = []
        if not isinstance(data, list):
            return findings
        for item in data:
            if not isinstance(item, dict):
                continue
            name    = str(item.get("name", "") or "").lower()
            version = str(item.get("version", "") or "")
            manager = str(item.get("manager", "brew") or "")

            # Risky package rule check
            for pkg_name, rule in RISKY_PACKAGES.items():
                if pkg_name in name:
                    f = self._finding(
                        category="package",
                        item_key=f"pkg:{manager}:{name}",
                        severity=rule["severity"],
                        score=severity_to_score(rule["severity"]),
                        title=f"Risky package installed: {name}",
                        desc=f"{rule['desc']} — installed via {manager} v{version}.",
                        evidence=item, source="rule:risky_package",
                        mitre=rule["mitre"],
                        tags=["package", "tool", manager],
                        # RISKY_PACKAGES has no per-entry confidence field (unlike
                        # PROCESS_RULES) — only the critical-severity entries are
                        # genuinely zero-legitimate-use (metasploit, mimikatz,
                        # cobalt-strike, lazagne, empire, xmrig, ...); dual-use
                        # tools (nmap, tcpdump, ngrok) stay at the generic default.
                        confidence=0.95 if rule["severity"] == "critical" else None,
                        weight=0.90 if rule["severity"] == "critical" else None,
                    )
                    # Apply dual-use downgrade for legitimate pentest/admin tools
                    f = adjust_finding_for_allowlist(f, name=name)
                    if f:
                        findings.append(f)
                    break

            # Queue for NVD CVE lookup (async, non-blocking)
            try:
                self._nvd_queue.put_nowait(("nvd", agent_id, name, version, item))
            except asyncio.QueueFull:
                pass
        return findings

    async def _network(self, agent_id: str, data: dict) -> list[dict]:
        # Handled by behavioral analyzer
        return []

    async def _users(self, agent_id: str, data: list) -> list[dict]:
        findings = []
        if not isinstance(data, list):
            return findings
        for item in data:
            if not isinstance(item, dict):
                continue
            name  = str(item.get("name", "") or item.get("username", "") or "")
            admin = item.get("is_admin", False) or item.get("admin", False)
            uid   = item.get("uid", -1)
            shell = str(item.get("shell", "") or "")

            # UID 0 (root) with non-root name
            if uid == 0 and name not in ("root",):
                findings.append(self._finding(
                    category="user", item_key=f"user:{name}:uid0",
                    severity="critical", score=9.0,
                    title=f"Non-root account with UID 0: {name}",
                    desc=f"Account '{name}' has UID 0 (root-equivalent) — possible privilege escalation.",
                    evidence=item, source="rule:uid0",
                    mitre="T1078.003", tags=["user", "privilege_escalation"],
                ))

            # Interactive shell for service accounts
            if uid and 0 < int(uid) < 500 and shell not in ("/bin/false", "/usr/bin/false", "/sbin/nologin", ""):
                findings.append(self._finding(
                    category="user", item_key=f"user:{name}:svc_shell",
                    severity="medium", score=4.0,
                    title=f"Service account with interactive shell: {name}",
                    desc=f"System account '{name}' (UID {uid}) has shell {shell}.",
                    evidence=item, source="rule:svc_interactive_shell",
                    mitre="T1078", tags=["user", "lateral_movement"],
                ))
        return findings

    async def _tasks(self, agent_id: str, data: list) -> list[dict]:
        findings = []
        if not isinstance(data, list):
            return findings
        for item in data:
            if not isinstance(item, dict):
                continue
            cmd  = str(item.get("command", "") or item.get("cmd", "") or "")
            name = str(item.get("name", "") or item.get("label", "") or "")
            for rule in CONFIG_RULES:
                if rule["compiled"].search(cmd):
                    findings.append(self._finding(
                        category="task", item_key=f"task:{name}:{_fp(cmd)}",
                        severity=rule["severity"],
                        score=severity_to_score(rule["severity"]),
                        title=f"Suspicious scheduled task: {name or cmd[:60]}",
                        desc=f"{rule['desc']} — found in scheduled task.",
                        evidence=item, source="rule:task_pattern",
                        mitre=rule["mitre"], tags=["task", "persistence"],
                    ))
                    break
        return findings

    async def _security(self, agent_id: str, data: dict) -> list[dict]:
        # Field names + bad-value sets verified against the actual collector and
        # normalizer output (agent/os/macos/collectors/posture.py and
        # os/windows/collectors/posture.py via agent/os/macos/normalizer.py
        # _norm_security — every field below is wrapped in _s_opt(), i.e. a
        # STRING or None, never a bool):
        #   sip/gatekeeper        -> "enabled" | "disabled" | None
        #   filevault/firewall    -> "on"      | "off"      | None
        # The previous version checked a key that doesn't exist ("sip_enabled" —
        # the real key is "sip") and compared all four against the Python literal
        # False. A str is never == a bool in Python, so is_bad was unconditionally
        # False for every agent, on every platform, since this analyzer existed —
        # the entire SIP/Gatekeeper/FileVault/Firewall posture check never fired.
        findings = []
        if not isinstance(data, dict):
            return findings
        checks = [
            ("sip",        {"disabled"}, "critical", "SIP disabled",
             "System Integrity Protection is disabled — attacker can modify protected files.",
             "T1562.001"),
            ("gatekeeper", {"disabled"}, "high", "Gatekeeper disabled",
             "Gatekeeper is off — unsigned apps can run without warning.",
             "T1553.001"),
            ("filevault",  {"off"}, "high", "FileVault disabled",
             "Full-disk encryption is not enabled — data at risk if device lost.",
             "T1486"),
            ("firewall",   {"off"}, "medium", "Firewall disabled",
             "Application firewall is disabled.",
             "T1562.004"),
        ]
        for key, bad_values, severity, title, desc, mitre in checks:
            val = data.get(key)
            if val is None:
                continue
            if str(val).strip().lower() not in bad_values:
                continue
            findings.append(self._finding(
                category="security", item_key=f"sec:{key}",
                severity=severity, score=severity_to_score(severity),
                title=title, desc=desc,
                evidence={key: val},
                source="rule:security_posture",
                mitre=mitre,
                tags=["security", "posture"],
                # SIP/Gatekeeper/FileVault/Firewall disabled are direct
                # observations of a violated control, not a speculative
                # pattern match — same standalone-floor treatment as
                # uid_zero_clone/sysctl_critical (see cross_matrix.py).
                confidence=0.95, weight=0.90,
            ))

        # lockdown_mode is a genuine bool (macOS posture collector's
        # _lockdown_mode()) — informational only, never raised as "bad".
        lockdown = data.get("lockdown_mode")
        if lockdown is True:
            findings.append(self._finding(
                category="security", item_key="sec:lockdown_mode",
                severity="info", score=0.5,
                title="Lockdown Mode active",
                desc="Device is in Lockdown Mode (highest security posture).",
                evidence={"lockdown_mode": lockdown},
                source="rule:security_posture",
                mitre="",
                tags=["security", "posture"],
            ))
        return findings

    async def _configs(self, agent_id: str, data: Any) -> list[dict]:
        findings = []
        items = data if isinstance(data, list) else (
            [{"path": k, "content": v} for k, v in data.items()]
            if isinstance(data, dict) else []
        )
        for item in items:
            if not isinstance(item, dict):
                continue
            path    = str(item.get("path", "") or "")
            content = str(item.get("content", "") or "")
            if not content:
                continue
            for rule in CONFIG_RULES:
                if rule["compiled"].search(content):
                    findings.append(self._finding(
                        category="config",
                        item_key=f"cfg:{path}:{rule['compiled'].pattern[:20]}",
                        severity=rule["severity"],
                        score=severity_to_score(rule["severity"]),
                        title=f"Suspicious pattern in config: {path}",
                        desc=f"{rule['desc']} — found in {path}.",
                        evidence={"path": path, "match_preview": content[:200]},
                        source="rule:config_pattern",
                        mitre=rule["mitre"],
                        tags=["config", "persistence"],
                    ))
        return findings

    async def _binaries(self, agent_id: str, data: list) -> list[dict]:
        findings = []
        if not isinstance(data, list):
            return findings
        for item in data:
            if not isinstance(item, dict):
                continue
            path  = str(item.get("path", "") or "")
            suid  = item.get("suid", False) or item.get("is_suid", False)
            sgid  = item.get("sgid", False) or item.get("is_sgid", False)
            ww    = item.get("world_writable", False)
            if suid:
                findings.append(self._finding(
                    category="binary", item_key=f"bin_suid:{path}",
                    severity="high", score=7.0,
                    title=f"SUID binary: {path}",
                    desc=f"SUID bit set on {path} — can be used for privilege escalation.",
                    evidence=item, source="rule:suid_binary",
                    mitre="T1548.001", tags=["binary", "suid", "privesc"],
                ))
            if sgid:
                findings.append(self._finding(
                    category="binary", item_key=f"bin_sgid:{path}",
                    severity="medium", score=4.5,
                    title=f"SGID binary: {path}",
                    desc=f"SGID bit set on {path}.",
                    evidence=item, source="rule:sgid_binary",
                    mitre="T1548.001", tags=["binary", "sgid"],
                ))
            if ww:
                findings.append(self._finding(
                    category="binary", item_key=f"bin_ww:{path}",
                    severity="medium", score=5.0,
                    title=f"World-writable binary: {path}",
                    desc=f"{path} is world-writable — could be tampered.",
                    evidence=item, source="rule:world_writable",
                    mitre="T1222", tags=["binary", "world_writable"],
                ))
        return findings

    # ── Background workers ─────────────────────────────────────────────────────

    async def _nvd_worker(self) -> None:
        """Drain the NVD / AbuseIPDB queue at a controlled rate."""
        while True:
            item = await self._nvd_queue.get()
            try:
                if item[0] == "nvd":
                    _, agent_id, name, version, raw = item
                    cves = await self._nvd.lookup(name, version)
                    for cve in cves:
                        score = cve.get("cvss_score") or 0
                        cve_id = cve.get("cve_id", "")
                        # Cross-reference with CISA KEV — KEV-listed CVEs always
                        # surface even if CVSS is below the medium floor.
                        is_kev = False
                        try:
                            is_kev = bool(self._feeds.is_kev_cve(cve_id))
                        except Exception:
                            pass
                        if score < 4.0 and not is_kev:
                            continue
                        sev = cve.get("severity", "medium")
                        if is_kev and sev in ("info", "low", "medium"):
                            sev = "high"  # KEV-listed → minimum high

                        # Pull EPSS to enrich (cache-first; non-blocking on miss)
                        epss_val = 0.0
                        try:
                            rec = await self._feeds.get_epss(cve_id)
                            if rec and rec.get("epss") is not None:
                                epss_val = float(rec["epss"])
                        except Exception:
                            pass

                        cve_enriched = {**cve,
                                        "kev": is_kev,
                                        "cisa_kev": is_kev,
                                        "epss_score": epss_val}
                        f = self._finding(
                            category="package",
                            item_key=f"cve:{name}:{cve_id}",
                            severity=sev, score=max(score, 7.0 if is_kev else score),
                            title=f"CVE in {name}: {cve_id} (CVSS {score}{', KEV' if is_kev else ''})",
                            desc=cve.get("description", "")[:300],
                            evidence={**raw, "cve": cve_enriched},
                            source="nvd",
                            mitre="",
                            tags=["cve", "package", name] + (["kev"] if is_kev else []),
                        )
                        f["agent_id"] = agent_id
                        f["cve_ids"]  = [cve_id]
                        f["cvss_score"]   = score
                        f["cvss_vector"]  = cve.get("cvss_vector", "")
                        f["kev"]          = is_kev
                        f["epss_score"]   = epss_val
                        # Vulnerability recency: parse the CVE publication date so
                        # the exploitability scorer (computed in upsert_finding)
                        # weights newer CVEs higher.
                        f["cve_published_ts"] = _cve_published_ts(cve)
                        f.update(_intel_fields_from_cve(cve_enriched, raw))
                        f["composite_score"] = score_matrix.compute(
                            f, agent_id=agent_id, collected_ts=time.time(),
                        )
                        f["priority_reason"] = _priority_reason(f)
                        f["action_plan"] = _action_plan_for(f)
                        # Stamp deterministic precision + terrain validation
                        # so the analyst sees a real score for KEV findings.
                        try:
                            await self._attach_legacy_precision(f)
                        except Exception as exc:
                            log.debug("nvd-worker legacy precision: %s", exc)
                        await self._idb.upsert_finding(f, time.time())

                elif item[0] == "abuseipdb":
                    _, agent_id, ip, raw_item = item
                    result = await self._feeds.check_ip_live(ip)
                    if result:
                        f = self._finding(
                            category="connection",
                            item_key=f"abuseipdb:{ip}",
                            severity=result["severity"],
                            score=severity_to_score(result["severity"]),
                            title=f"AbuseIPDB: Malicious IP {ip}",
                            desc=result.get("description", ""),
                            evidence={**raw_item, "abuseipdb": result},
                            source="abuseipdb", mitre="T1071",
                            tags=["connection", "abuseipdb"],
                        )
                        f["agent_id"] = agent_id
                        f["asset_tier"] = _asset_tier_from_evidence(raw_item)
                        f["asset_importance"] = _asset_importance(f["asset_tier"])
                        f["composite_score"] = max(
                            f["score"],
                            score_matrix.compute(f, agent_id=agent_id, collected_ts=time.time()),
                        )
                        f["priority_reason"] = _priority_reason(f)
                        f["action_plan"] = _action_plan_for(f)
                        try:
                            await self._attach_legacy_precision(f)
                        except Exception as exc:
                            log.debug("nvd-worker legacy precision: %s", exc)
                        await self._idb.upsert_finding(f, time.time())

            except Exception as exc:
                log.debug("NVD worker error: %s", exc)
            finally:
                self._nvd_queue.task_done()
                await asyncio.sleep(2)   # gentle rate limiting

    # ── Finding factory ───────────────────────────────────────────────────────

    @staticmethod
    def _finding(*, category: str, item_key: str, severity: str,
                 score: float, title: str, desc: str, evidence: dict,
                 source: str, mitre: str = "", tags: list | None = None,
                 cve_ids: list | None = None, cvss_score: float | None = None,
                 cvss_vector: str = "", confidence: float | None = None,
                 weight: float | None = None) -> dict:
        f = {
            "category":        category,
            "item_key":        item_key,
            "severity":        severity,
            "score":           round(score, 2),
            "title":           title,
            "description":     desc,
            "evidence":        evidence,
            "source":          source,
            "rule_id":         source,
            "mitre_technique": mitre,
            "mitre_tactic":    get_tactic(mitre),
            "cve_ids":         cve_ids or [],
            "cvss_score":      cvss_score,
            "cvss_vector":     cvss_vector,
            "tags":            tags or [category, source],
        }
        # Propagate the catalog rule's own per-entry confidence (rules.py sets
        # this per pattern, e.g. X-PROC-CRYPTOMINER=0.97 vs X-PROC-MASSCAN=0.65)
        # so _dispatch_to_signals doesn't fall back to the generic weight=0.65
        # default — every PROCESS_RULES/OBFUSCATION_RULES/PARENT_CHILD_RULES
        # match collapsed to the same generic "rule:process_pattern"-style
        # source string, discarding the specific pattern's own confidence.
        if confidence is not None:
            f["confidence"] = confidence
        if weight is not None:
            f["weight"] = weight
        return f


def _fp(s: str) -> str:
    """Short fingerprint for use in item_key."""
    return hashlib.sha256(s.encode()).hexdigest()[:12]


# Build a flat lookup: source_id → rule dict (populated once at module load)
_RULE_BY_SOURCE: dict[str, dict] = {}

def _build_rule_index() -> None:
    for r in PROCESS_RULES + STANDALONE_RULES:
        key = r.get("id") or r.get("source", "")
        if key:
            _RULE_BY_SOURCE[key] = r

_build_rule_index()


def _lookup_rule_by_source(source: str) -> dict | None:
    return _RULE_BY_SOURCE.get(source)


def _cve_published_ts(cve: dict) -> float:
    """
    Parse a CVE publication date (ISO-8601 from NVD, e.g. '2024-03-14T00:00:00')
    into an epoch timestamp. Returns 0.0 when absent/unparseable so the
    exploitability scorer falls back to neutral recency.
    """
    raw = cve.get("published_at") or cve.get("published") or ""
    if not raw:
        return 0.0
    s = str(raw).strip().replace("Z", "+00:00")
    from datetime import datetime
    for fmt in (None, "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d", "%Y-%m-%dT%H:%M:%S.%f"):
        try:
            if fmt is None:
                return datetime.fromisoformat(s).timestamp()
            return datetime.strptime(s.split("+")[0], fmt).timestamp()
        except (ValueError, TypeError):
            continue
    return 0.0


def _intel_fields_from_cve(cve: dict, evidence: dict) -> dict:
    refs = cve.get("references") or cve.get("reference_urls") or []
    ref_text = " ".join(map(str, refs)).lower()
    desc = str(cve.get("description", "")).lower()
    kev = bool(cve.get("kev") or cve.get("cisa_kev") or cve.get("known_exploited"))
    exploit_sources: list[str] = []
    if cve.get("exploit_db_id"):
        exploit_sources.append(f"ExploitDB:{cve.get('exploit_db_id')}")
    if "exploit-db" in ref_text or "exploitdb" in ref_text:
        exploit_sources.append("ExploitDB reference")
    if "metasploit" in ref_text or "metasploit" in desc:
        exploit_sources.append("Metasploit reference")
    if "proof-of-concept" in desc or "poc" in ref_text:
        exploit_sources.append("public PoC reference")
    epss = float(cve.get("epss_score") or cve.get("epss") or 0)
    tier = _asset_tier_from_evidence(evidence)
    return {
        "kev": kev,
        "epss_score": epss,
        "exploit_available": bool(exploit_sources or cve.get("exploit_available")),
        "exploit_sources": sorted(set(exploit_sources)),
        "asset_tier": tier,
        "asset_importance": _asset_importance(tier),
    }


def _asset_tier_from_evidence(evidence: dict) -> str:
    text = json.dumps(evidence or {}, default=str).lower()
    if any(x in text for x in ("server", "runner", "build", "prod", "database", "k8s", "container")):
        return "server"
    if any(x in text for x in ("executive", "finance", "admin", "ciso", "ceo")):
        return "crown_jewel"
    if any(x in text for x in ("laptop", "macbook", "workstation", "desktop")):
        return "workstation"
    return "endpoint"


def _asset_importance(tier: str) -> float:
    return {
        "crown_jewel": 1.0,
        "server": 0.9,
        "workstation": 0.55,
        "endpoint": 0.4,
    }.get(tier, 0.3)


def _priority_reason(f: dict) -> str:
    bits = []
    if f.get("kev"):
        bits.append("CISA KEV")
    if f.get("exploit_available"):
        bits.append("public exploit")
    if f.get("epss_score"):
        bits.append(f"EPSS {float(f['epss_score']) * 100:.0f}%")
    if f.get("cvss_score"):
        bits.append(f"CVSS {float(f['cvss_score']):.1f}")
    if f.get("asset_tier"):
        bits.append(f"{f['asset_tier']} asset")
    return ", ".join(bits) or "telemetry/rule correlation"


def _action_plan_for(f: dict) -> list[dict]:
    """
    Compact action plan written onto every finding at emit time. Delegates to the
    deterministic remediation KB so the list is always accurate for the finding
    category + evidence shape.
    """
    try:
        from .remediation_kb import action_plan_for as _kb_action_plan
        return _kb_action_plan(f)
    except Exception:
        return [
            {"type": "investigate", "title": "Validate evidence and owner",
             "detail": "Confirm the finding, affected asset, business owner, and immediate blast radius."},
            {"type": "remediate", "title": "Apply recommended mitigation",
             "detail": "Track status, assignee, and closure notes in the finding activity log."},
        ]
