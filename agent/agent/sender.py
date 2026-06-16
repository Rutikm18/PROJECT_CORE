"""
agent/sender.py — Encrypted HTTPS sender with resilient delivery.

Features:
  - Exponential backoff with jitter on transient failures
  - Disk spool: failed payloads written to disk, replayed on reconnect
  - Connectivity probe: fast manager reachability check before send
  - Auto-drain: spool flushed when manager comes back online
  - TLS 1.3 minimum
"""

import json
import logging
import os
import queue
import random
import ssl
import threading
import time
import urllib.request
import urllib.error

log = logging.getLogger("agent.sender")

# How many bytes the spool file may grow to before we drop oldest lines (~50 MB)
_SPOOL_MAX_BYTES = 50 * 1024 * 1024
# Offline reprobe backoff: probe quickly right after a drop (the manager is
# often back within a second or two), then back off to the ceiling so a long
# outage doesn't hammer the network. Was a flat 30 s, which added up to 30 s of
# recovery latency on every transient blip.
_SPOOL_RETRY_MIN = 2
_SPOOL_RETRY_MAX = 30
# Connectivity probe timeout (seconds)
_PROBE_TIMEOUT = 5
# Consecutive 401s from an "online" manager before triggering re-enrollment
_AUTH_FAIL_THRESHOLD = 3


class DiskSpool:
    """
    Append-only NDJSON spool file.  Thread-safe (one writer thread at a time).
    """

    def __init__(self, path: str):
        self.path = path
        self._lock = threading.Lock()
        os.makedirs(os.path.dirname(path), exist_ok=True)

    def write(self, envelope: dict) -> None:
        """Append one envelope to the spool."""
        line = json.dumps(envelope, separators=(",", ":")) + "\n"
        with self._lock:
            # Trim spool if too large (drop first ~10 % of lines = oldest)
            try:
                if os.path.getsize(self.path) > _SPOOL_MAX_BYTES:
                    self._trim()
            except FileNotFoundError:
                pass
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(line)

    def drain(self) -> list[dict]:
        """Read and clear all spooled envelopes.  Returns list of dicts."""
        with self._lock:
            try:
                with open(self.path, encoding="utf-8") as f:
                    lines = f.readlines()
                os.remove(self.path)
            except FileNotFoundError:
                return []
        out = []
        for l in lines:
            l = l.strip()
            if not l:
                continue
            try:
                out.append(json.loads(l))
            except json.JSONDecodeError:
                pass
        return out

    def size(self) -> int:
        try:
            return os.path.getsize(self.path)
        except FileNotFoundError:
            return 0

    def _trim(self) -> None:
        """Drop the first 10 % of lines to make room (holding lock)."""
        try:
            with open(self.path, encoding="utf-8") as f:
                lines = f.readlines()
            drop = max(1, len(lines) // 10)
            with open(self.path, "w", encoding="utf-8") as f:
                f.writelines(lines[drop:])
            log.warning("Spool trimmed: dropped %d oldest entries (was %d lines)",
                        drop, len(lines))
        except Exception as exc:
            log.error("Spool trim failed: %s", exc)


class Sender:
    def __init__(self, config: dict, send_queue: queue.Queue):
        self.mgr        = config["manager"]
        self.url        = self.mgr["url"].rstrip("/") + "/api/v1/ingest"
        self.probe_url  = self.mgr["url"].rstrip("/") + "/health"
        self.timeout    = self.mgr.get("timeout_sec", 30)
        self.max_retry  = self.mgr.get("retry_attempts", 3)
        self.retry_del  = self.mgr.get("retry_delay_sec", 5)
        self.tls_verify = self.mgr.get("tls_verify", True)
        self.queue      = send_queue
        self._stop      = threading.Event()
        self._ctx       = self._build_ssl_ctx()
        self._online    = False   # tracks last known manager state
        self._last_contact_ts = 0.0   # epoch of last confirmed manager contact

        # Disk spool — persists payloads when manager is unreachable.
        # NOTE: never derive this from __file__; PyInstaller bundles the module
        # inside a temp directory whose path changes between runs.
        import sys as _sys
        if _sys.platform == "darwin":
            _default_spool = "/Library/AttackLens/spool"
        elif _sys.platform == "win32":
            _default_spool = r"C:\Program Files (x86)\AttackLens\spool"
        else:
            _default_spool = "/var/lib/attacklens/spool"
        spool_dir = config.get("paths", {}).get("spool_dir", _default_spool)
        self._spool = DiskSpool(os.path.join(spool_dir, "unsent.ndjson"))

        # Auth-failure tracking: counts consecutive 401s to detect key invalidation
        self._auth_fail_count = 0
        # Optional callback — called when persistent auth failure detected.
        # Signature: on_auth_error() -> None.  Set by caller after construction.
        self.on_auth_error: "threading.Callable | None" = None

    # ── SSL ───────────────────────────────────────────────────────────────────

    def _build_ssl_ctx(self):
        if self.mgr["url"].startswith("http://"):
            log.warning("Manager URL is plain HTTP — no TLS encryption")
            return None   # urllib handles plain HTTP without a context
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        if not self.tls_verify:
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            log.warning("TLS verification disabled — dev/self-signed cert mode")
        else:
            ctx.verify_mode = ssl.CERT_REQUIRED
            ctx.load_default_certs()
        return ctx

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def start(self) -> threading.Thread:
        self._stop.clear()
        # Drain any spool from previous run immediately
        spooled = self._spool.drain()
        if spooled:
            log.info("Replaying %d spooled envelopes from previous run", len(spooled))
            for env in spooled:
                self.queue.put_nowait(env)

        t = threading.Thread(target=self._drain_loop, daemon=True, name="sender")
        t.start()
        return t

    def stop(self):
        self._stop.set()

    def spool_envelope(self, envelope: dict) -> None:
        """Persist one envelope straight to the disk spool.

        Wired to the Orchestrator as its overflow sink: when the in-memory queue
        is full, the evicted envelope lands here instead of being dropped, and is
        replayed once the backlog drains. Thread-safe via DiskSpool's lock.
        """
        self._spool.write(envelope)

    def link_state(self) -> dict:
        """Snapshot of manager connectivity, for the agent_health heartbeat.

        Lets the dashboard show per-agent link health: whether the agent last
        reached the manager, how much telemetry is buffered to disk while
        offline, and whether the key is being rejected. `last_contact_ts` is 0
        until the first successful contact; `seconds_since_contact` is None then.
        """
        last = self._last_contact_ts
        return {
            "manager_online":        self._online,
            "spool_bytes":           self._spool.size(),
            "auth_failures":         self._auth_fail_count,
            "last_contact_ts":       int(last) if last else 0,
            "seconds_since_contact": int(time.time() - last) if last else None,
        }

    # ── Connectivity probe ────────────────────────────────────────────────────

    def _probe(self) -> bool:
        """Quick HEAD/GET to /health to check manager reachability."""
        try:
            req = urllib.request.Request(self.probe_url, method="GET")
            kwargs = {"timeout": _PROBE_TIMEOUT}
            if self._ctx is not None:
                kwargs["context"] = self._ctx
            with urllib.request.urlopen(req, **kwargs):
                return True
        except Exception:
            return False

    # ── Main loop ─────────────────────────────────────────────────────────────

    def _drain_loop(self):
        spool_check = 0.0
        probe_delay = _SPOOL_RETRY_MIN
        while not self._stop.is_set():
            # Reprobe when offline, with fast-first backoff (2s → 30s) so a
            # transient blip recovers in ~2s instead of waiting a flat 30s.
            now = time.time()
            if not self._online and (now - spool_check) >= probe_delay:
                spool_check = now
                if self._probe():
                    probe_delay = _SPOOL_RETRY_MIN          # reset for next outage
                    self._online = True
                    self._last_contact_ts = time.time()
                    if self._auth_fail_count >= _AUTH_FAIL_THRESHOLD:
                        log.warning(
                            "Manager back online after %d auth failures — "
                            "clearing spool and triggering re-enrollment",
                            self._auth_fail_count,
                        )
                        self._auth_fail_count = 0
                        self._spool.drain()   # stale encrypted data, discard
                        if self.on_auth_error:
                            threading.Thread(
                                target=self.on_auth_error,
                                daemon=True,
                                name="re-enroll",
                            ).start()
                    else:
                        log.info("Manager back online — draining spool")
                        spooled = self._spool.drain()
                        for env in spooled:
                            self.queue.put_nowait(env)
                else:
                    probe_delay = min(probe_delay * 2, _SPOOL_RETRY_MAX)
                    log.debug("Manager still unreachable — spool has %d bytes, "
                              "next probe in %ds", self._spool.size(), probe_delay)

            try:
                envelope = self.queue.get(timeout=1)
            except queue.Empty:
                continue

            # When manager is known unreachable, spool directly — skip the
            # full retry cycle (3 × backoff) that wastes time and queue capacity.
            if not self._online:
                self._spool.write(envelope)
                continue

            success = self._send_with_retry(envelope)
            if not success:
                log.warning("Spooling %s to disk", envelope.get("section"))
                self._spool.write(envelope)
                self._online = False
                # Just went offline — reprobe quickly (fast-first backoff).
                probe_delay = _SPOOL_RETRY_MIN
                spool_check = 0.0
                # If auth failures crossed the threshold and manager is reachable,
                # the key is invalid — trigger re-enrollment and clear bad spool.
                if self._auth_fail_count >= _AUTH_FAIL_THRESHOLD:
                    if self._probe():
                        log.warning(
                            "Persistent 401 after %d attempts — manager online but key rejected; "
                            "clearing spool and triggering re-enrollment",
                            self._auth_fail_count,
                        )
                        self._auth_fail_count = 0
                        self._spool.drain()   # old encrypted data can't be re-keyed
                        if self.on_auth_error:
                            threading.Thread(
                                target=self.on_auth_error,
                                daemon=True,
                                name="re-enroll",
                            ).start()

    # ── Send with retry ───────────────────────────────────────────────────────

    @staticmethod
    def _read_error_body(exc: urllib.error.HTTPError, limit: int = 512) -> str:
        """Read and truncate the response body from an HTTPError for logging."""
        try:
            raw = exc.read(limit)
            text = raw.decode("utf-8", errors="replace").strip()
            return text[:limit]
        except Exception:
            return ""

    def _send_with_retry(self, envelope: dict) -> bool:
        """
        Try to POST envelope to manager.
        Returns True on success, False if all attempts failed.
        4xx client errors are dropped (not retried, not spooled).
        503 (storage unavailable on manager) is retried and spooled — it means
        the data was not persisted and the agent must hold onto it.
        """
        body    = json.dumps(envelope).encode()
        delay   = self.retry_del
        section = envelope.get("section", "unknown")
        agent   = envelope.get("agent_id", "unknown")

        for attempt in range(1, self.max_retry + 1):
            try:
                req = urllib.request.Request(
                    self.url,
                    data=body,
                    headers={
                        "Content-Type": "application/json",
                        "X-Agent-ID":   agent,
                        "X-Section":    section,
                        "User-Agent":   "attacklens-agent/2.0",
                    },
                    method="POST",
                )
                kwargs = {"timeout": self.timeout}
                if self._ctx is not None:
                    kwargs["context"] = self._ctx
                with urllib.request.urlopen(req, **kwargs) as resp:
                    if resp.status == 200:
                        if not self._online:
                            log.info("Manager connection restored")
                        self._online = True
                        self._last_contact_ts = time.time()
                        self._auth_fail_count = 0
                        log.debug("Sent %s → 200", section)
                        return True
                    elif resp.status == 401:
                        self._auth_fail_count += 1
                        log.warning(
                            "HTTP 401 (count=%d) agent=%s section=%s — "
                            "key rejected, spooling for re-auth",
                            self._auth_fail_count, agent, section,
                        )
                        return False
                    elif resp.status == 429:
                        retry_after = resp.headers.get("Retry-After", "?")
                        log.warning(
                            "HTTP 429 rate-limited agent=%s section=%s "
                            "retry-after=%ss (attempt %d/%d)",
                            agent, section, retry_after, attempt, self.max_retry,
                        )
                        # treat as transient — fall through to backoff
                    elif resp.status == 503:
                        log.warning(
                            "HTTP 503 storage unavailable agent=%s section=%s "
                            "(attempt %d/%d) — will spool",
                            agent, section, attempt, self.max_retry,
                        )
                        # 503 = manager accepted but couldn't persist; must spool
                    elif 400 <= resp.status < 500:
                        self._auth_fail_count = 0
                        log.error(
                            "Manager rejected HTTP %d agent=%s section=%s — "
                            "dropping (unrecoverable client error)",
                            resp.status, agent, section,
                        )
                        return True   # "handled" — don't spool a bad payload
                    else:
                        log.warning(
                            "Manager HTTP %d agent=%s section=%s (attempt %d/%d)",
                            resp.status, agent, section, attempt, self.max_retry,
                        )

            except urllib.error.HTTPError as exc:
                body_text = self._read_error_body(exc)
                if exc.code == 401:
                    self._auth_fail_count += 1
                    log.warning(
                        "HTTP 401 (count=%d) agent=%s section=%s — "
                        "manager says: %r — spooling for re-auth",
                        self._auth_fail_count, agent, section, body_text,
                    )
                    return False
                if exc.code == 429:
                    retry_after = exc.headers.get("Retry-After", "?")
                    log.warning(
                        "HTTP 429 rate-limited agent=%s section=%s "
                        "retry-after=%ss (attempt %d/%d): %r",
                        agent, section, retry_after, attempt, self.max_retry, body_text,
                    )
                elif exc.code == 503:
                    log.warning(
                        "HTTP 503 storage unavailable agent=%s section=%s "
                        "(attempt %d/%d): %r — will spool",
                        agent, section, attempt, self.max_retry, body_text,
                    )
                elif 400 <= exc.code < 500:
                    self._auth_fail_count = 0
                    log.error(
                        "Manager rejected HTTP %d agent=%s section=%s — "
                        "dropping: %r",
                        exc.code, agent, section, body_text,
                    )
                    return True
                else:
                    log.warning(
                        "HTTP error %d agent=%s section=%s (attempt %d/%d): %r",
                        exc.code, agent, section, attempt, self.max_retry, body_text,
                    )
            except ssl.SSLError as exc:
                log.error(
                    "TLS error agent=%s section=%s (attempt %d/%d): %s — "
                    "check tls_verify setting and manager certificate",
                    agent, section, attempt, self.max_retry, exc,
                )
            except TimeoutError as exc:
                log.warning(
                    "Send timeout agent=%s section=%s (attempt %d/%d) "
                    "timeout=%ss: %s",
                    agent, section, attempt, self.max_retry, self.timeout, exc,
                )
            except OSError as exc:
                log.warning(
                    "Network error agent=%s section=%s (attempt %d/%d): %s",
                    agent, section, attempt, self.max_retry, exc,
                )
            except Exception as exc:
                log.warning(
                    "Send failed agent=%s section=%s (attempt %d/%d): %s",
                    agent, section, attempt, self.max_retry, exc,
                )

            if attempt < self.max_retry:
                jitter = random.uniform(0, delay * 0.3)
                time.sleep(min(delay + jitter, 60))
                delay *= 2

        log.warning(
            "All %d send attempts exhausted agent=%s section=%s — spooling to disk",
            self.max_retry, agent, section,
        )
        return False   # caller will spool to disk
