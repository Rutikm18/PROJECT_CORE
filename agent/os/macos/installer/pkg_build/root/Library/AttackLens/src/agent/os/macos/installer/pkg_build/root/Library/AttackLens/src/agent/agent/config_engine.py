"""
agent/agent/config_engine.py — trusted config substrate (ConfigEngine).

Produces ONE immutable `RuntimeConfig` from three layers:

    baseline (agent.toml)  ◅  verified manager policies  ◅  tighten-only overrides

Policies are signature-verified, audience-bound, expiry-checked and
monotonic-versioned by `agent/policy.py`. This module owns the merge, the
fail-closed response gate, the high-water store, and the fetch/cache/reload
machinery. It builds NO detection/response *logic* — only the substrate later
phases consume.

Design rules honoured here:
  • Cache-first, never blocks on the network at startup (`load()`).
  • `refresh()` is non-fatal on transport errors — last good config is kept.
  • Snapshots swap atomically under a lock — readers never see a torn config.
  • `response_enabled` is True ONLY with a fully-valid `response` policy. No
    baseline value and no env override can ever set it True.
  • Durations use `time.monotonic()`; expiry uses wall clock. A backward wall
    jump beyond MAX_SKEW_SEC forces `response_enabled=False` (clock_skew).
"""
from __future__ import annotations

import json
import logging
import os
import stat
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Iterable, Mapping, Optional

from .policy import (
    MAX_SKEW_SEC,
    VALID_TYPES,
    PolicyError,
    SignedPolicy,
    TrustStore,
    load_verified,
)

try:
    import tomllib  # Python 3.11+
except ImportError:  # pragma: no cover - backport path
    import tomli as tomllib  # type: ignore[no-redef]

log = logging.getLogger("agent.config_engine")

# TODO(paths): replace with the canonical PathProvider when it lands; until then
# this single module-level constant is the ONLY hardcoded path in the module.
_FALLBACK_BASE = "/Library/AttackLens"

# Env overrides are tighten-only. This is the explicit allow-list; anything else
# under ATTACKLENS_* that tries to touch policy state is rejected + logged.
_ENV_RESPONSE_ENABLED = "ATTACKLENS_RESPONSE_ENABLED"
_ENV_RESPONSE_ACTIONS = "ATTACKLENS_RESPONSE_ALLOWED_ACTIONS"

_EMPTY = MappingProxyType({})


# ── Paths ──────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class PathProvider:
    """Minimal stand-in for the not-yet-existing canonical PathProvider.

    All paths derive from a single base so there are no scattered literals.
    """
    base: str = _FALLBACK_BASE

    @property
    def config_file(self) -> str:
        return os.path.join(self.base, "agent.toml")

    @property
    def policies_dir(self) -> str:
        return os.path.join(self.base, "policies")

    @property
    def keystore_dir(self) -> str:
        return os.path.join(self.base, "security")


# ── Clock ────────────────────────────────────────────────────────────────────

class SystemClock:
    """Wall clock for expiry; monotonic clock for durations."""

    def wall(self) -> float:
        return time.time()

    def monotonic(self) -> float:
        return time.monotonic()


# ── Immutable runtime config ────────────────────────────────────────────────

@dataclass(frozen=True)
class RuntimeConfig:
    sections: Mapping[str, Mapping[str, Any]]
    policy_versions: Mapping[str, int]
    response_enabled: bool

    def section(self, name: str) -> Mapping[str, Any]:
        return self.sections.get(name, _EMPTY)


@dataclass
class RefreshResult:
    """Per-type outcome of a refresh: accepted | rejected:<reason> | unreachable | unchanged."""
    outcomes: dict[str, str] = field(default_factory=dict)

    def __getitem__(self, key: str) -> str:
        return self.outcomes[key]

    @property
    def accepted(self) -> list[str]:
        return [t for t, o in self.outcomes.items() if o == "accepted"]


# ── Helpers: freeze + deep-merge ────────────────────────────────────────────

def _freeze(value: Any) -> Any:
    """Recursively wrap dicts in MappingProxyType (lists become tuples)."""
    if isinstance(value, Mapping):
        return MappingProxyType({k: _freeze(v) for k, v in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(v) for v in value)
    return value


def _deep_merge(base: Mapping[str, Any], over: Mapping[str, Any]) -> dict:
    """Deep-merge `over` onto `base`; `over` wins on key conflict."""
    out: dict[str, Any] = {k: (dict(v) if isinstance(v, Mapping) else v)
                           for k, v in base.items()}
    for k, v in over.items():
        if isinstance(v, Mapping) and isinstance(out.get(k), Mapping):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


# ── ConfigEngine ────────────────────────────────────────────────────────────

class ConfigEngine:
    POLICY_TYPES = VALID_TYPES  # ("security","response","telemetry","compliance")

    def __init__(
        self,
        *,
        paths: PathProvider,
        trust: TrustStore,
        transport: Any,
        agent_id: str,
        group_ids: Iterable[str],
        clock: Optional[SystemClock] = None,
        refresh_interval_sec: int = 21600,
    ):
        self._paths = paths
        self._trust = trust
        self._transport = transport
        self._agent_id = agent_id
        self._group_ids = list(group_ids or [])
        self._clock = clock or SystemClock()
        self._refresh_interval = refresh_interval_sec

        self._lock = threading.Lock()
        self._current: Optional[RuntimeConfig] = None

        # Accepted policy + the exact wire object behind it, per type.
        self._accepted: dict[str, SignedPolicy] = {}
        self._cached_wire: dict[str, dict] = {}

        # Monotonic-version high-water (persisted), loaded once.
        self._versions: dict[str, int] = {}

        # Boot reference for clock-skew detection.
        self._boot_wall = self._clock.wall()
        self._boot_monotonic = self._clock.monotonic()

        # Background refresh control.
        self._stop = threading.Event()
        self._bg_thread: Optional[threading.Thread] = None

        self._ensure_dirs()
        self._versions = self._load_high_water()

    # ── Public API ──────────────────────────────────────────────────────────

    def load(self) -> RuntimeConfig:
        """Cache-first, NEVER blocks on the network. Builds the first snapshot."""
        baseline = self._read_baseline()
        self._accepted = {}
        self._cached_wire = {}
        for typ in self.POLICY_TYPES:
            wire = self._read_cache_file(typ)
            if wire is None:
                continue
            pol = self._verify_cached(typ, wire)
            if pol is not None:
                self._accepted[typ] = pol
                self._cached_wire[typ] = wire
        snap = self._build_snapshot(baseline)
        with self._lock:
            self._current = snap
        return snap

    def refresh(self) -> RefreshResult:
        """Fetch each policy type, verify, accept-or-keep-last-good, rebuild.

        Transport/network errors are non-fatal: the last good policy is kept and
        the outcome is recorded as `unreachable`.
        """
        baseline = self._read_baseline()
        result = RefreshResult()
        now = self._clock.wall()

        for typ in self.POLICY_TYPES:
            try:
                wire = self._transport.fetch(typ)
            except TransportUnreachable:
                result.outcomes[typ] = "unreachable"
                continue
            except Exception as exc:  # defensive: never let transport crash refresh
                log.warning("policy fetch %s failed: %s", typ, exc)
                result.outcomes[typ] = "unreachable"
                continue

            if wire is None:
                result.outcomes[typ] = "unchanged"
                continue

            # Byte-identical to what we already verified+cached → unchanged.
            cached = self._cached_wire.get(typ)
            if cached and cached.get("payload_b64") == wire.get("payload_b64") \
                    and cached.get("signature_b64") == wire.get("signature_b64"):
                result.outcomes[typ] = "unchanged"
                continue

            try:
                pol = load_verified(
                    wire,
                    agent_id=self._agent_id,
                    group_ids=self._group_ids,
                    trust=self._trust,
                    now_wall=now,
                    high_water=self._versions,
                )
            except PolicyError as exc:
                log.warning("policy %s rejected: %s", typ, exc.reason)
                result.outcomes[typ] = f"rejected:{exc.reason}"
                continue

            # Accept: persist raw bytes + advance high-water, then keep in memory.
            self._accepted[typ] = pol
            self._cached_wire[typ] = wire
            self._versions[typ] = pol.version
            self._write_cache_file(typ, wire)
            self._persist_high_water()
            result.outcomes[typ] = "accepted"
            log.info("policy %s accepted v%d", typ, pol.version)

        snap = self._build_snapshot(baseline)
        with self._lock:
            self._current = snap
        return result

    def current(self) -> RuntimeConfig:
        """Atomic snapshot. Lazily loads on first call."""
        with self._lock:
            if self._current is not None:
                return self._current
        # First access before load() — build cache-first now.
        return self.load()

    # ── Background refresh ────────────────────────────────────────────────────

    def start_background(self) -> threading.Thread:
        """Kick a daemon thread that refreshes on a monotonic cadence.

        Polls more frequently while the transport is unreachable so config is
        re-fetched promptly on reconnect, then settles to refresh_interval_sec.
        """
        self._stop.clear()
        t = threading.Thread(target=self._bg_loop, daemon=True,
                             name="config-refresh")
        t.start()
        self._bg_thread = t
        return t

    def stop(self) -> None:
        self._stop.set()

    def _bg_loop(self) -> None:
        reconnect_poll = min(30, self._refresh_interval)
        next_at = self._clock.monotonic()  # refresh immediately on start
        while not self._stop.is_set():
            if self._clock.monotonic() >= next_at:
                try:
                    result = self.refresh()
                except Exception as exc:  # never let the loop die
                    log.error("background refresh error: %s", exc)
                    result = RefreshResult()
                interval = self._refresh_interval_effective()
                if any(o == "unreachable" for o in result.outcomes.values()):
                    interval = reconnect_poll  # retry soon after reconnect
                next_at = self._clock.monotonic() + interval
            self._stop.wait(timeout=1.0)

    def on_reconnect(self) -> None:
        """Hook for the sender's reachability signal — refresh now."""
        try:
            self.refresh()
        except Exception as exc:
            log.error("on_reconnect refresh error: %s", exc)

    def _refresh_interval_effective(self) -> int:
        # A telemetry policy may override the refresh cadence.
        tel = self._accepted.get("telemetry")
        if tel is not None:
            val = tel.content.get("refresh_interval_sec")
            if isinstance(val, int) and val > 0:
                return val
        return self._refresh_interval

    # ── Snapshot construction (merge + fail-closed + tighten-only) ────────────

    def _build_snapshot(self, baseline: Mapping[str, Any]) -> RuntimeConfig:
        skew = self._clock_skew()

        # Start from a copy of the whole baseline so non-policy tables survive,
        # then overlay each accepted policy's content onto its same-named section.
        merged: dict[str, Any] = {
            k: (dict(v) if isinstance(v, Mapping) else v)
            for k, v in baseline.items()
        }
        for typ in self.POLICY_TYPES:
            base_section = merged.get(typ, {})
            if not isinstance(base_section, Mapping):
                base_section = {}
            pol = self._accepted.get(typ)
            if pol is not None:
                merged[typ] = _deep_merge(base_section, pol.content)
            else:
                merged[typ] = dict(base_section)

        # ── Fail-closed response gate ────────────────────────────────────────
        # True ONLY with a fully-valid response policy AND no clock skew. Never
        # derived from baseline.
        response_enabled = ("response" in self._accepted) and not skew
        if skew:
            log.warning("clock_skew detected — forcing response_enabled=False")

        # ── Tighten-only env overrides (applied last) ─────────────────────────
        response_enabled, merged = self._apply_env_overrides(response_enabled, merged)

        policy_versions = {t: p.version for t, p in self._accepted.items()}

        return RuntimeConfig(
            sections=_freeze(merged),
            policy_versions=MappingProxyType(dict(policy_versions)),
            response_enabled=response_enabled,
        )

    def _apply_env_overrides(self, response_enabled: bool,
                             merged: dict) -> tuple[bool, dict]:
        """Tighten-only: may DISABLE response or SHRINK allowed_actions. Never loosen.

        Anything else under ATTACKLENS_* touching policy is rejected + logged.
        """
        env = os.environ

        # response_enabled: only "false"/"0"/"no" honoured (force off). "true"
        # is a loosening attempt → ignored + logged.
        raw = env.get(_ENV_RESPONSE_ENABLED)
        if raw is not None:
            val = raw.strip().lower()
            if val in ("false", "0", "no", "off"):
                if response_enabled:
                    log.info("env override %s=%s → response disabled (tighten)",
                             _ENV_RESPONSE_ENABLED, raw)
                response_enabled = False
            elif val in ("true", "1", "yes", "on"):
                log.warning(
                    "env override %s=%s tries to ENABLE response — ignored "
                    "(tighten-only)", _ENV_RESPONSE_ENABLED, raw,
                )
            else:
                log.warning("env override %s=%r not understood — ignored",
                            _ENV_RESPONSE_ENABLED, raw)

        # allowed_actions: env may only intersect (shrink) the policy set.
        raw_actions = env.get(_ENV_RESPONSE_ACTIONS)
        if raw_actions is not None:
            requested = {a.strip() for a in raw_actions.split(",") if a.strip()}
            resp = merged.get("response")
            if isinstance(resp, dict) and isinstance(resp.get("allowed_actions"),
                                                     (list, tuple)):
                current = list(resp["allowed_actions"])
                shrunk = [a for a in current if a in requested]
                added = requested - set(current)
                if added:
                    log.warning(
                        "env override %s tries to ADD actions %s — ignored "
                        "(tighten-only)", _ENV_RESPONSE_ACTIONS, sorted(added),
                    )
                if shrunk != current:
                    log.info("env override %s shrank allowed_actions %s → %s",
                             _ENV_RESPONSE_ACTIONS, current, shrunk)
                resp = dict(resp)
                resp["allowed_actions"] = shrunk
                merged["response"] = resp

        return response_enabled, merged

    def _clock_skew(self) -> bool:
        """True if the wall clock jumped backward beyond MAX_SKEW_SEC vs monotonic."""
        elapsed_mono = self._clock.monotonic() - self._boot_monotonic
        expected_wall = self._boot_wall + elapsed_mono
        actual_wall = self._clock.wall()
        return actual_wall < (expected_wall - MAX_SKEW_SEC)

    # ── Baseline ──────────────────────────────────────────────────────────────

    def _read_baseline(self) -> dict:
        path = self._paths.config_file
        try:
            with open(path, "rb") as f:
                return tomllib.load(f)
        except FileNotFoundError:
            return {}
        except Exception as exc:
            log.warning("baseline config unreadable (%s) — using empty baseline", exc)
            return {}

    # ── Cache load with relaxed high-water ────────────────────────────────────

    def _verify_cached(self, typ: str, wire: dict) -> Optional[SignedPolicy]:
        """Re-verify a cached policy. The cache IS our high-water, so the stored
        version must pass — we relax the monotonic check by one to allow the
        equal (already-accepted) version while still rejecting strictly-older
        cache tampering."""
        hw = dict(self._versions)
        if typ in hw:
            hw[typ] = max(0, hw[typ] - 1)
        try:
            return load_verified(
                wire,
                agent_id=self._agent_id,
                group_ids=self._group_ids,
                trust=self._trust,
                now_wall=self._clock.wall(),
                high_water=hw,
            )
        except PolicyError as exc:
            # Corrupt / expired / tampered cache → treat as absent, never crash.
            log.warning("cached policy %s rejected on load: %s", typ, exc.reason)
            return None

    # ── Filesystem: cache + high-water ────────────────────────────────────────

    def _ensure_dirs(self) -> None:
        d = self._paths.policies_dir
        try:
            os.makedirs(d, exist_ok=True)
            os.chmod(d, stat.S_IRWXU)  # 0700
        except Exception as exc:
            log.debug("could not tighten policies_dir %s: %s", d, exc)
        self._warn_permissive(d, 0o077, "policies_dir")

    @staticmethod
    def _warn_permissive(path: str, bad_bits: int, label: str) -> None:
        try:
            mode = os.stat(path).st_mode & 0o777
            if mode & bad_bits:
                log.warning("SECURITY: %s %s has permissive mode %o", label, path, mode)
        except FileNotFoundError:
            pass

    def _cache_path(self, typ: str) -> str:
        return os.path.join(self._paths.policies_dir, f"{typ}.policy")

    def _prev_path(self, typ: str) -> str:
        return os.path.join(self._paths.policies_dir, f"{typ}.prev")

    def _versions_path(self) -> str:
        return os.path.join(self._paths.policies_dir, ".versions.json")

    def _read_cache_file(self, typ: str) -> Optional[dict]:
        path = self._cache_path(typ)
        try:
            with open(path, "rb") as f:
                obj = json.loads(f.read())
            return obj if isinstance(obj, dict) else None
        except FileNotFoundError:
            return None
        except Exception as exc:  # corrupt cache → absent
            log.warning("cache file %s corrupt: %s", path, exc)
            return None

    def _write_cache_file(self, typ: str, wire: dict) -> None:
        path = self._cache_path(typ)
        # Roll current → .prev before overwriting (previous good).
        try:
            if os.path.exists(path):
                os.replace(path, self._prev_path(typ))
        except Exception as exc:
            log.debug("could not roll %s to .prev: %s", path, exc)
        self._atomic_write(path, json.dumps(wire, separators=(",", ":")).encode())

    def _load_high_water(self) -> dict[str, int]:
        path = self._versions_path()
        try:
            with open(path, "rb") as f:
                obj = json.loads(f.read())
            if isinstance(obj, dict):
                return {k: int(v) for k, v in obj.items() if isinstance(v, int)}
        except FileNotFoundError:
            pass
        except Exception as exc:
            log.warning("high-water file %s corrupt: %s — resetting", path, exc)
        return {}

    def _persist_high_water(self) -> None:
        self._atomic_write(
            self._versions_path(),
            json.dumps(self._versions, separators=(",", ":")).encode(),
        )

    @staticmethod
    def _atomic_write(path: str, data: bytes) -> None:
        tmp = path + ".tmp"
        with open(tmp, "wb") as f:
            f.write(data)
        os.chmod(tmp, stat.S_IRUSR | stat.S_IWUSR)  # 0600
        os.replace(tmp, path)


# ── Transport ──────────────────────────────────────────────────────────────

class TransportUnreachable(Exception):
    """Raised by a transport when the manager cannot be reached (non-fatal)."""


class HttpPolicyTransport:
    """Fetches `GET /api/v1/policies/<type>`.

    Mirrors the TLS posture of `agent/sender.py` (TLS 1.3 minimum, optional
    verify) — the asymmetric-verify of policies happens in `policy.py`, this only
    moves bytes. 404 → None (no policy of that type). Network errors →
    TransportUnreachable so `refresh()` keeps the last good config.
    """

    def __init__(self, manager_url: str, *, agent_id: str,
                 tls_verify: bool = True, timeout_sec: int = 10):
        from .tls import build_client_ssl_context

        base = manager_url.rstrip("/")
        self._base = base + "/api/v1/policies/"
        self._agent_id = agent_id
        self._timeout = timeout_sec
        self._ctx = build_client_ssl_context(base, tls_verify)

    def fetch(self, policy_type: str) -> Optional[dict]:
        url = self._base + policy_type
        req = urllib.request.Request(
            url,
            method="GET",
            headers={"X-Agent-ID": self._agent_id,
                     "User-Agent": "attacklens-agent/2.0"},
        )
        kwargs: dict[str, Any] = {"timeout": self._timeout}
        if self._ctx is not None:
            kwargs["context"] = self._ctx
        try:
            with urllib.request.urlopen(req, **kwargs) as resp:
                if resp.status == 200:
                    return json.loads(resp.read())
                if resp.status == 404:
                    return None
                raise TransportUnreachable(f"HTTP {resp.status}")
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return None
            raise TransportUnreachable(f"HTTP {exc.code}") from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise TransportUnreachable(str(exc)) from exc
        except json.JSONDecodeError as exc:
            # Reachable but garbage body — treat as no usable policy this round.
            raise TransportUnreachable(f"bad body: {exc}") from exc
