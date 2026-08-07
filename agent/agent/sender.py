"""
agent/sender.py — Encrypted HTTPS sender with resilient delivery.

Features:
  - Exponential backoff with jitter on transient failures
  - Disk spool: failed payloads written to disk, replayed on reconnect
  - Connectivity probe: fast manager reachability check before send
  - Auto-drain: spool flushed when manager comes back online
  - TLS 1.3 minimum
"""

import errno
import hashlib
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
# Re-enrollment backoff bounds. A mass key-invalidation (e.g. the manager DB was
# reset) makes every one of the ~24 section senders cross the 401 threshold at
# once. Without coordination each incident spawned its own re-enroll thread,
# rotating the key repeatedly — and every rotation invalidated the requests still
# in flight under the previous key, a self-sustaining spiral. Single-flight (one
# re-enroll at a time) plus a growing gap between attempts lets the freshly
# issued key settle before anything else can rotate it again.
_REENROLL_BACKOFF_MIN = 5.0     # seconds — minimum gap between re-enrollments
_REENROLL_BACKOFF_MAX = 300.0   # cap the growth so recovery latency stays bounded
# Upper bound on how long we'll honor a server-supplied Retry-After (matrix R12):
# respect the manager's rate-limit hint, but a pathological value must not park a
# send for hours — cap it and let normal backoff + spooling take over.
_RETRY_AFTER_MAX_SEC = 120


def _parse_retry_after(value: str | None) -> float | None:
    """Parse a Retry-After header (delta-seconds or HTTP-date) → seconds from now,
    or None if absent/unparseable. Negative/zero clamps to 0."""
    if not value:
        return None
    value = value.strip()
    if value.isdigit():
        return float(value)
    try:
        from email.utils import parsedate_to_datetime
        import datetime as _dt
        dt = parsedate_to_datetime(value)
        if dt is None:
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=_dt.timezone.utc)
        return max(0.0, (dt - _dt.datetime.now(_dt.timezone.utc)).total_seconds())
    except Exception:
        return None


# Wake-from-sleep detection: the drain loop cycles ~once per second, so if the
# monotonic clock jumps far beyond that between iterations the process was
# suspended (the machine slept/hibernated). On resume, cached sockets are dead
# and the network may have changed, so we re-verify the manager immediately
# instead of waiting out the offline backoff (up to _SPOOL_RETRY_MAX seconds).
_WAKE_GAP_SEC = 30


class DiskSpool:
    """
    Append-only NDJSON spool file.  Thread-safe (one writer thread at a time).
    """

    def __init__(self, path: str):
        self.path = path
        self._replay_path = path + ".replay"
        self._offset_path = path + ".offset"
        self._lock = threading.Lock()
        # Cumulative, process-lifetime counts of envelopes that never made it
        # to the manager because they were discarded on-disk (size trim) or
        # found unreadable on replay (corrupt line) — visibility into data
        # loss that was previously silent past a log line.
        self._dropped_trim = 0
        self._dropped_corrupt = 0
        self._dropped_auth = 0
        os.makedirs(os.path.dirname(path), exist_ok=True)

    def write(self, envelope: dict) -> None:
        """Append one envelope to the spool. Best-effort — NEVER raises.

        The spool is the delivery path's last resort and write() is called on the
        sender thread AND from the orchestrator's overflow sink. A full disk
        (ENOSPC), a read-only filesystem, or a permission error must not crash
        either — an unhandled OSError here would kill the sender thread and stop
        ALL delivery silently. On a full disk we trim aggressively to free room
        for later writes; the current datum is counted as dropped, not lost
        silently.
        """
        try:
            line = json.dumps(envelope, separators=(",", ":")) + "\n"
        except (TypeError, ValueError) as exc:
            # A non-serialisable envelope should never reach here, but if it does
            # it must not take the whole spool write down.
            log.error("Spool write: envelope not JSON-serialisable (%s) — dropped", exc)
            return
        with self._lock:
            # Trim spool if too large (drop first ~10 % of lines = oldest)
            try:
                if self.size() > _SPOOL_MAX_BYTES:
                    self._trim()
            except FileNotFoundError:
                pass
            except OSError as exc:
                log.debug("Spool size check failed: %s", exc)
            try:
                with open(self.path, "a", encoding="utf-8") as f:
                    f.write(line)
            except OSError as exc:
                self._dropped_trim += 1
                log.error("Spool write failed (%s) — datum dropped (cumulative=%d)",
                          exc, self._dropped_trim)
                # On a full disk / quota, make room so subsequent writes can land.
                if getattr(exc, "errno", None) in (errno.ENOSPC, errno.EDQUOT):
                    try:
                        self._trim()
                    except Exception:  # noqa: BLE001
                        pass

    def drain(self) -> list[dict]:
        """Read and clear all spooled envelopes. Returns list of dicts.

        Normal delivery uses peek()/ack(), which keeps records durable until the
        manager acknowledges them. drain() is retained for explicit administrative
        discard and tests; it may load the bounded (50 MiB) spool into memory.
        """
        with self._lock:
            lines: list[str] = []
            offset = self._read_offset_locked()
            try:
                with open(self._replay_path, encoding="utf-8") as f:
                    f.seek(offset)
                    lines.extend(f.readlines())
            except FileNotFoundError:
                pass
            try:
                with open(self.path, encoding="utf-8") as f:
                    lines.extend(f.readlines())
            except FileNotFoundError:
                pass
            for target in (self.path, self._replay_path, self._offset_path):
                try:
                    os.remove(target)
                except FileNotFoundError:
                    pass
            if not lines:
                return []
        out = []
        corrupt = 0
        for l in lines:
            l = l.strip()
            if not l:
                continue
            try:
                out.append(json.loads(l))
            except json.JSONDecodeError:
                corrupt += 1
        if corrupt:
            with self._lock:
                self._dropped_corrupt += corrupt
            log.warning("Spool drain: dropped %d corrupt line(s) (cumulative=%d)",
                        corrupt, self._dropped_corrupt)
        return out

    def peek(self) -> tuple[dict, tuple[int, int, int, int, str]] | None:
        """Lease the oldest envelope without removing it from durable storage.

        The returned token must be passed to ack() only after the manager has
        accepted the envelope. A process crash before ack causes an idempotent
        resend, never data loss. New writes continue into the main spool while a
        stable replay file is consumed by byte offset.
        """
        with self._lock:
            for _ in range(2):
                if not self._ensure_replay_locked():
                    return None
                offset = self._read_offset_locked()
                try:
                    st = os.stat(self._replay_path)
                    with open(self._replay_path, "rb") as f:
                        f.seek(offset)
                        while True:
                            start = f.tell()
                            raw = f.readline()
                            end = f.tell()
                            if not raw:
                                self._finish_replay_locked()
                                break
                            stripped = raw.strip()
                            if not stripped:
                                self._write_offset_locked(end)
                                offset = end
                                continue
                            try:
                                envelope = json.loads(stripped)
                            except (json.JSONDecodeError, UnicodeDecodeError):
                                self._dropped_corrupt += 1
                                self._write_offset_locked(end)
                                offset = end
                                log.warning(
                                    "Spool replay: dropped corrupt line "
                                    "(cumulative=%d)", self._dropped_corrupt,
                                )
                                continue
                            digest = hashlib.sha256(raw).hexdigest()
                            return envelope, (st.st_dev, st.st_ino, start, end, digest)
                except FileNotFoundError:
                    self._finish_replay_locked()
            return None

    def ack(self, token: tuple[int, int, int, int, str]) -> bool:
        """Advance the durable replay cursor if token is still the leased head."""
        dev, ino, start, end, digest = token
        with self._lock:
            try:
                st = os.stat(self._replay_path)
                if (st.st_dev, st.st_ino) != (dev, ino):
                    return False
                if self._read_offset_locked() != start:
                    return False
                with open(self._replay_path, "rb") as f:
                    f.seek(start)
                    raw = f.readline()
                if hashlib.sha256(raw).hexdigest() != digest:
                    return False
                self._write_offset_locked(end)
                return True
            except FileNotFoundError:
                return False

    def discard_for_auth_rotation(self) -> int:
        """Discard ciphertext that cannot be re-keyed and count the loss."""
        envelopes = self.drain()
        with self._lock:
            self._dropped_auth += len(envelopes)
        if envelopes:
            log.warning(
                "Spool auth rotation: discarded %d unrecoverable envelope(s) "
                "(cumulative=%d)", len(envelopes), self._dropped_auth,
            )
        return len(envelopes)

    def size(self) -> int:
        total = 0
        for target in (self.path, self._replay_path):
            try:
                total += os.path.getsize(target)
            except OSError:
                pass
        return total

    def stats(self) -> dict:
        """Cumulative (process-lifetime) counts of envelopes dropped on disk."""
        with self._lock:
            return {
                "dropped_trim":    self._dropped_trim,
                "dropped_corrupt": self._dropped_corrupt,
                "dropped_auth":    self._dropped_auth,
            }

    def _ensure_replay_locked(self) -> bool:
        if os.path.exists(self._replay_path):
            return True
        try:
            os.replace(self.path, self._replay_path)
        except FileNotFoundError:
            return False
        try:
            os.remove(self._offset_path)
        except FileNotFoundError:
            pass
        return True

    def _finish_replay_locked(self) -> None:
        for target in (self._replay_path, self._offset_path):
            try:
                os.remove(target)
            except FileNotFoundError:
                pass

    def _read_offset_locked(self) -> int:
        try:
            st = os.stat(self._replay_path)
            with open(self._offset_path, encoding="ascii") as f:
                raw = f.read().strip()
            dev, ino, offset = raw.split(":", 2)
            if (int(dev), int(ino)) != (st.st_dev, st.st_ino):
                return 0
            return max(0, int(offset))
        except (FileNotFoundError, OSError, ValueError):
            return 0

    def _write_offset_locked(self, offset: int) -> None:
        tmp = self._offset_path + ".tmp"
        st = os.stat(self._replay_path)
        with open(tmp, "w", encoding="ascii") as f:
            # Bind the cursor to this replay file's inode. If the process dies
            # between rotating a new replay file and clearing an old cursor, the
            # stale cursor is ignored instead of skipping records in the new file.
            f.write(f"{st.st_dev}:{st.st_ino}:{offset}")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self._offset_path)

    def _trim(self) -> None:
        """Drop the first 10 % of lines to make room (holding lock)."""
        try:
            with open(self.path, encoding="utf-8") as f:
                lines = f.readlines()
            drop = max(1, len(lines) // 10)
            with open(self.path, "w", encoding="utf-8") as f:
                f.writelines(lines[drop:])
            self._dropped_trim += drop
            log.warning("Spool trimmed: dropped %d oldest entries (was %d lines, "
                        "cumulative dropped=%d)", drop, len(lines), self._dropped_trim)
        except Exception as exc:
            log.error("Spool trim failed: %s", exc)


class Sender:
    def __init__(self, config: dict, send_queue: queue.Queue, mac_key: bytes | None = None,
                 heartbeat=None):
        # mac_key lets the sender RE-STAMP each envelope's transport timestamp +
        # HMAC at actual send time, so data spooled during an outage is still
        # within the manager's replay window on reconnect (no store-and-forward
        # data loss). None → legacy behaviour (send the sealed envelope as-is).
        self._mac_key   = mac_key
        # Optional callable(success: bool=False) — liveness heartbeat for the
        # Supervisor (matrix R6): pulsed each drain-loop iteration (alive) and on
        # a delivered payload (success), so a wedged sender is detectable.
        self.heartbeat  = heartbeat
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

        # Send pacing: cap outbound rate just below the manager's per-agent rate
        # limit (10 req/s) so draining a large spool after an outage doesn't burst
        # into 429s. At low volume the gap is already exceeded → no added latency.
        _rate = float(self.mgr.get("max_send_rate", 8.0))
        self._min_send_interval = 1.0 / _rate if _rate > 0 else 0.0
        self._last_send_ts = 0.0

        # Auth-failure tracking: counts consecutive 401s to detect key invalidation
        self._auth_fail_count = 0
        self._delivery_stats = {
            "accepted_2xx": 0,
            "rejected_4xx": 0,
            "replay_acked": 0,
        }
        # Optional callback — called when persistent auth failure detected.
        # Signature: on_auth_error() -> None.  Set by caller after construction.
        self.on_auth_error: "threading.Callable | None" = None

        # Single-flight re-enrollment state (see _trigger_reenroll). The lock
        # guards all three fields; the backoff grows per incident and resets to
        # _REENROLL_BACKOFF_MIN on the next accepted 2xx (a re-enroll that stuck).
        self._reenroll_lock = threading.Lock()
        self._reenroll_in_flight = False
        self._last_reenroll_ts = 0.0
        self._reenroll_backoff = _REENROLL_BACKOFF_MIN

    # ── SSL ───────────────────────────────────────────────────────────────────

    def _build_ssl_ctx(self):
        if self.mgr["url"].startswith("http://"):
            log.warning("Manager URL is plain HTTP — no TLS encryption")
            return None   # urllib handles plain HTTP without a context
        from .tls import build_client_ssl_context
        return build_client_ssl_context(self.mgr["url"], self.tls_verify)

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def start(self) -> threading.Thread:
        self._stop.clear()
        # The sender loop replays directly from disk with peek()/ack(). Keeping
        # the record on disk until a manager ACK avoids both unbounded startup
        # memory and the crash-loss window created by drain-then-enqueue.
        t = threading.Thread(target=self._drain_loop, daemon=True, name="sender")
        t.start()
        return t

    def stop(self):
        self._stop.set()

    def set_mac_key(self, mac_key: bytes) -> None:
        """Update the HMAC key after re-enrollment so re-stamping stays valid."""
        self._mac_key = mac_key

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
        spool_stats = self._spool.stats()
        return {
            "manager_online":        self._online,
            "spool_bytes":           self._spool.size(),
            "spool_dropped_trim":    spool_stats["dropped_trim"],
            "spool_dropped_corrupt": spool_stats["dropped_corrupt"],
            "spool_dropped_auth":    spool_stats["dropped_auth"],
            "delivery_accepted_2xx": self._delivery_stats["accepted_2xx"],
            "delivery_rejected_4xx": self._delivery_stats["rejected_4xx"],
            "delivery_replay_acked": self._delivery_stats["replay_acked"],
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
        last_tick = time.monotonic()
        while not self._stop.is_set():
            # Liveness heartbeat (R6): prove the drain loop is ticking even while
            # the manager is offline (no successful sends to pulse on).
            if self.heartbeat is not None:
                try:
                    self.heartbeat()
                except Exception:
                    pass

            # ── Wake-from-sleep resume ────────────────────────────────────────
            # A monotonic jump far past our ~1s cadence means the process was
            # suspended (system slept). Force an immediate manager reprobe so a
            # spool built up while offline drains right after wake, rather than
            # sitting for up to _SPOOL_RETRY_MAX seconds. Marking offline is
            # cheap: if the link is actually fine the reprobe restores it in ~2s.
            mono = time.monotonic()
            if mono - last_tick > _WAKE_GAP_SEC:
                log.info("Resume-from-sleep detected (%.0fs gap) — forcing manager "
                         "reprobe + spool drain", mono - last_tick)
                self._online = False
                probe_delay = _SPOOL_RETRY_MIN
                spool_check = 0.0
            last_tick = mono

            # Reprobe when offline, with fast-first backoff (2s → 30s) so a
            # transient blip recovers in ~2s instead of waiting a flat 30s.
            # Guarded: a probe/drain/spool error must never kill the sender
            # thread (that would stop all delivery silently).
            try:
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
                                "re-enrolling", self._auth_fail_count,
                            )
                            self._trigger_reenroll()
                        else:
                            log.info("Manager back online — durable spool replay enabled")
                    else:
                        probe_delay = min(probe_delay * 2, _SPOOL_RETRY_MAX)
                        log.debug("Manager still unreachable — spool has %d bytes, "
                                  "next probe in %ds", self._spool.size(), probe_delay)
            except Exception as exc:
                log.error("sender reprobe/drain error (continuing): %s", exc)

            replay_token = None
            try:
                replay = self._spool.peek() if self._online else None
            except Exception as exc:
                # A damaged/unwritable cursor must not kill the only delivery
                # thread. Live in-memory telemetry can still be sent, while the
                # durable backlog remains untouched for a later retry/repair.
                log.error("Spool replay read failed (continuing with live queue): %s", exc)
                replay = None
            if replay is not None:
                envelope, replay_token = replay
            else:
                try:
                    envelope = self.queue.get(timeout=1)
                except queue.Empty:
                    continue

            # The whole send path is guarded: an unexpected error (a malformed
            # envelope, an SSL/urllib edge case _send_with_retry didn't catch)
            # must NOT kill the sender thread — that would silently stop ALL
            # delivery. On any surprise we spool the datum and carry on.
            try:
                # When manager is known unreachable, spool directly — skip the
                # full retry cycle (3 × backoff) that wastes time and queue capacity.
                if not self._online:
                    self._spool.write(envelope)
                    continue

                success = self._send_with_retry(envelope)
                if success:
                    if replay_token is not None and not self._spool.ack(replay_token):
                        log.warning("Spool replay ACK cursor changed; envelope may be resent idempotently")
                    elif replay_token is not None:
                        self._delivery_stats["replay_acked"] += 1
                    # Delivered (or cleanly handled) → sender is making progress (R6).
                    if self.heartbeat is not None:
                        try:
                            self.heartbeat(success=True)
                        except Exception:
                            pass
                if not success:
                    if replay_token is None:
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
                            # Single-flight + backoff: coalesces the ~24 sections
                            # that fail together into one re-enroll and stops the
                            # rotate → invalidate-in-flight → 401 spiral.
                            self._trigger_reenroll()
            except Exception as exc:
                log.error("sender send-loop error (continuing): %s", exc)
                if replay_token is None:
                    try:
                        self._spool.write(envelope)   # don't lose the datum
                    except Exception:
                        pass

    # ── Re-enrollment (single-flight + backoff) ────────────────────────────────

    def _trigger_reenroll(self) -> None:
        """Coalesce all concurrent 401 incidents into one backed-off re-enroll.

        Called from both the reconnect path and the send-failure path. It:
          - runs at most ONE re-enrollment at a time (single-flight), so 24
            sections failing together can't rotate the key 24 times; and
          - refuses to start another until a growing backoff has elapsed, so a
            freshly issued key gets a chance to take effect before the next try.

        Only when it actually starts a re-enroll does it reset the 401 counter
        and drop the spool sealed under the dead key — if it's suppressed, the
        counter stays high and the loop retries once the backoff window opens.
        """
        if not self.on_auth_error:
            return
        now = time.monotonic()
        with self._reenroll_lock:
            if self._reenroll_in_flight:
                log.debug("Re-enrollment already in flight — coalescing this 401")
                return
            remaining = self._reenroll_backoff - (now - self._last_reenroll_ts)
            if self._last_reenroll_ts and remaining > 0:
                log.debug("Re-enrollment suppressed by backoff (%.0fs remaining)", remaining)
                return
            self._reenroll_in_flight = True
            self._last_reenroll_ts = now
            backoff = self._reenroll_backoff
            # Grow for the NEXT incident; a successful 2xx resets it to the floor.
            self._reenroll_backoff = min(self._reenroll_backoff * 2, _REENROLL_BACKOFF_MAX)

        log.warning("Persistent 401 — re-enrolling (single-flight; next attempt "
                    "no sooner than %.0fs)", backoff)
        self._auth_fail_count = 0
        try:
            self._spool.discard_for_auth_rotation()
        except Exception as exc:
            log.error("spool discard during re-enroll failed (continuing): %s", exc)

        def _runner():
            try:
                self.on_auth_error()
            except Exception as exc:
                log.error("re-enrollment callback failed: %s", exc)
            finally:
                with self._reenroll_lock:
                    self._reenroll_in_flight = False

        threading.Thread(target=_runner, daemon=True, name="re-enroll").start()

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
        # Pace outbound sends under the manager's rate limit (avoids 429 storms
        # when draining a large spool on reconnect). Interruptible by shutdown.
        if self._min_send_interval > 0:
            gap = time.time() - self._last_send_ts
            if 0 < gap < self._min_send_interval:
                self._stop.wait(self._min_send_interval - gap)
        self._last_send_ts = time.time()

        # Re-stamp transport freshness at SEND time so a spooled/buffered
        # envelope (possibly hours old) lands inside the manager's replay window
        # instead of being rejected as stale. Event time (collected_at) inside
        # the ciphertext is unchanged.
        if self._mac_key is not None:
            try:
                from .crypto import restamp_envelope
                section_hint = envelope.get("section")
                envelope = restamp_envelope(envelope, self._mac_key)
                if section_hint is not None:
                    envelope["section"] = section_hint   # preserve plaintext routing hint
            except Exception as exc:
                log.debug("restamp failed (sending as-is): %s", exc)

        body    = json.dumps(envelope).encode()
        delay   = self.retry_del
        section = envelope.get("section", "unknown")
        agent   = envelope.get("agent_id", "unknown")

        for attempt in range(1, self.max_retry + 1):
            retry_after_sec: float | None = None    # server-supplied backoff hint (R12)
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
                    if 200 <= resp.status < 300:
                        # Any 2xx is delivered: ingest.py's queue-mode path is
                        # documented as "publish → return 202" even though it
                        # currently replies 200 — checking the whole 2xx range
                        # (not == 200) means a future fix to match that doc, or
                        # any 201/204 from a proxy in front of the manager,
                        # can't fall through to the generic "unexpected status"
                        # branch below and get spooled/retried as if it failed.
                        if not self._online:
                            log.info("Manager connection restored")
                        self._online = True
                        self._last_contact_ts = time.time()
                        self._auth_fail_count = 0
                        self._delivery_stats["accepted_2xx"] += 1
                        # A delivery under the current key proves re-enrollment
                        # stuck — reset the backoff so the next unrelated incident
                        # recovers quickly instead of inheriting a long delay.
                        if self._reenroll_backoff != _REENROLL_BACKOFF_MIN:
                            with self._reenroll_lock:
                                self._reenroll_backoff = _REENROLL_BACKOFF_MIN
                        log.debug("Sent %s → %d", section, resp.status)
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
                        retry_after_sec = _parse_retry_after(resp.headers.get("Retry-After"))
                        log.warning(
                            "HTTP 429 rate-limited agent=%s section=%s "
                            "retry-after=%ss (attempt %d/%d)",
                            agent, section, retry_after, attempt, self.max_retry,
                        )
                        # treat as transient — honor Retry-After, then backoff
                    elif resp.status == 503:
                        retry_after_sec = _parse_retry_after(resp.headers.get("Retry-After"))
                        log.warning(
                            "HTTP 503 storage unavailable agent=%s section=%s "
                            "(attempt %d/%d) — will spool",
                            agent, section, attempt, self.max_retry,
                        )
                        # 503 = manager accepted but couldn't persist; must spool
                    elif 400 <= resp.status < 500:
                        self._auth_fail_count = 0
                        self._delivery_stats["rejected_4xx"] += 1
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
                    # Distinguish a replay/duplicate rejection from a real auth
                    # failure. Replay-class 401s (stale timestamp, duplicate
                    # nonce) do NOT mean the key is bad — counting them toward
                    # re-enrollment would wrongly rotate the key and wipe the
                    # spool. The manager now idempotently 200s true duplicates;
                    # this is defense-in-depth for older managers.
                    low = body_text.lower()
                    if any(k in low for k in ("replay", "duplicate", "out of window")):
                        self._delivery_stats["rejected_4xx"] += 1
                        log.info(
                            "HTTP 401 replay/duplicate agent=%s section=%s — "
                            "manager already has it; dropping (not an auth failure): %r",
                            agent, section, body_text,
                        )
                        return True   # handled — do not spool, do not count as auth fail
                    self._auth_fail_count += 1
                    log.warning(
                        "HTTP 401 (count=%d) agent=%s section=%s — "
                        "manager says: %r — spooling for re-auth",
                        self._auth_fail_count, agent, section, body_text,
                    )
                    return False
                if exc.code == 429:
                    retry_after = exc.headers.get("Retry-After", "?")
                    retry_after_sec = _parse_retry_after(exc.headers.get("Retry-After"))
                    log.warning(
                        "HTTP 429 rate-limited agent=%s section=%s "
                        "retry-after=%ss (attempt %d/%d): %r",
                        agent, section, retry_after, attempt, self.max_retry, body_text,
                    )
                elif exc.code == 503:
                    retry_after_sec = _parse_retry_after(exc.headers.get("Retry-After"))
                    log.warning(
                        "HTTP 503 storage unavailable agent=%s section=%s "
                        "(attempt %d/%d): %r — will spool",
                        agent, section, attempt, self.max_retry, body_text,
                    )
                elif 400 <= exc.code < 500:
                    self._auth_fail_count = 0
                    self._delivery_stats["rejected_4xx"] += 1
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
                wait = min(delay + jitter, 60)
                # Honor a server-supplied Retry-After (429/503) — respect it over
                # our own backoff, capped so a pathological value can't park us.
                if retry_after_sec is not None:
                    wait = min(max(wait, retry_after_sec), _RETRY_AFTER_MAX_SEC)
                # Interruptible so shutdown doesn't block on a long Retry-After.
                self._stop.wait(wait)
                delay *= 2

        log.warning(
            "All %d send attempts exhausted agent=%s section=%s — spooling to disk",
            self.max_retry, agent, section,
        )
        return False   # caller will spool to disk
