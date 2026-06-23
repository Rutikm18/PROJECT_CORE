"""
agent/tests/integration/test_offline_online_replay.py
— Proves the offline→online cycle replays the spool with ZERO LOSS.

This is task #2's acceptance check, exercised against the *real* Sender over a
*real* loopback socket (not mocks), so the connectivity probe, the spool, and
the HTTP POST path all run exactly as they do in production.

Scenario (mirrors a laptop losing/regaining network):
  1. Manager is OFFLINE. Agent emits N envelopes → every one lands on disk.
  2. Manager comes back ONLINE.
  3. Sender's periodic probe sees it, drains the spool, and delivers everything.

Assertions:
  - every envelope the agent emitted is received by the manager  (no loss)
  - none is received twice                                        (no dup)
  - delivery order matches emission order                         (FIFO)
  - the on-disk spool ends empty                                  (fully drained)
"""
from __future__ import annotations

import json
import queue
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from agent.agent.sender import Sender


# ── A controllable fake manager ───────────────────────────────────────────────


class FakeManager:
    """Loopback HTTP server that can be flipped offline/online at runtime."""

    def __init__(self):
        self.online = False
        self._lock = threading.Lock()
        self.received: list[dict] = []  # envelopes accepted at /api/v1/ingest

        manager = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):  # silence per-request stderr logging
                pass

            def _send(self, code: int):
                self.send_response(code)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def do_GET(self):
                # /health — the sender's connectivity probe
                with manager._lock:
                    self._send(200 if manager.online else 503)

            def do_POST(self):
                length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(length) if length else b""
                with manager._lock:
                    if not manager.online:
                        self._send(503)
                        return
                    try:
                        manager.received.append(json.loads(body))
                    except json.JSONDecodeError:
                        self._send(400)
                        return
                    self._send(200)

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def start(self):
        self._thread.start()

    def stop(self):
        self._server.shutdown()
        self._server.server_close()

    def set_online(self, value: bool):
        with self._lock:
            self.online = value

    def received_seqs(self) -> list[int]:
        with self._lock:
            return [e["seq"] for e in self.received if "seq" in e]


# ── Fixtures ───────────────────────────────────────────────────────────────────


@pytest.fixture
def fake_manager():
    mgr = FakeManager()
    mgr.start()
    try:
        yield mgr
    finally:
        mgr.stop()


@pytest.fixture
def fast_sender_timing(monkeypatch):
    """Collapse production-scale waits so the test runs in well under a second."""
    import agent.agent.sender as sender_mod
    # Adaptive reprobe backoff (replaces the old flat _SPOOL_RETRY_INTERVAL):
    # collapse both ends so the offline→online transition fires near-instantly.
    monkeypatch.setattr(sender_mod, "_SPOOL_RETRY_MIN", 0.1)
    monkeypatch.setattr(sender_mod, "_SPOOL_RETRY_MAX", 0.1)
    monkeypatch.setattr(sender_mod, "_PROBE_TIMEOUT", 1)


def _make_sender(manager: FakeManager, spool_dir: str) -> tuple[Sender, queue.Queue]:
    send_queue: "queue.Queue" = queue.Queue()
    config = {
        "manager": {
            "url": f"http://127.0.0.1:{manager.port}",
            "tls_verify": False,
            "timeout_sec": 2,
            "retry_attempts": 1,   # fail fast when offline — straight to spool
            "retry_delay_sec": 0,
            "max_send_rate": 100000,  # disable send pacing for this timing test
        },
        "paths": {"spool_dir": spool_dir},
    }
    return Sender(config, send_queue), send_queue


def _wait_until(predicate, timeout=5.0, interval=0.02):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return predicate()


# ── The acceptance test ────────────────────────────────────────────────────────


def test_offline_then_online_replays_spool_with_zero_loss(
    fake_manager, fast_sender_timing, tmp_path
):
    N = 200
    sender, send_queue = _make_sender(fake_manager, str(tmp_path))

    # ── Phase 1: manager OFFLINE — everything the agent emits must spool ──
    fake_manager.set_online(False)
    sender.start()

    emitted = [{"section": "metrics", "agent_id": "agent-test", "seq": i} for i in range(N)]
    for env in emitted:
        send_queue.put_nowait(env)

    # Drained from the in-memory queue and parked on disk; nothing delivered yet.
    assert _wait_until(lambda: send_queue.empty() and sender._spool.size() > 0), (
        "while offline, emitted envelopes should accumulate in the disk spool"
    )
    assert fake_manager.received == [], "nothing should reach an offline manager"

    # ── Phase 2: manager ONLINE — probe should drain the spool and deliver all ──
    fake_manager.set_online(True)

    assert _wait_until(lambda: len(fake_manager.received_seqs()) == N, timeout=10.0), (
        f"expected all {N} envelopes delivered after reconnect, "
        f"got {len(fake_manager.received_seqs())}"
    )

    sender.stop()

    received = fake_manager.received_seqs()

    # Zero loss: every emitted seq arrived.
    assert set(received) == set(range(N)), "every emitted envelope must be delivered"
    # No duplicates: nothing delivered twice.
    assert len(received) == N, f"no duplicate deliveries (got {len(received)} for {N})"
    # Order preserved: spool is append-only + FIFO queue ⇒ monotonic delivery.
    assert received == list(range(N)), "replay must preserve emission order"
    # Spool fully drained.
    assert sender._spool.size() == 0, "spool must be empty after successful replay"


def test_restart_replays_spool_left_by_previous_run(
    fake_manager, fast_sender_timing, tmp_path
):
    """A crash/restart must not lose data already parked on disk: start() drains
    whatever a previous run left in the spool."""
    # Simulate a previous run that spooled 10 envelopes then died.
    from agent.agent.sender import DiskSpool
    import os

    spool = DiskSpool(os.path.join(str(tmp_path), "unsent.ndjson"))
    leftover = [{"section": "metrics", "agent_id": "agent-test", "seq": i} for i in range(10)]
    for env in leftover:
        spool.write(env)

    # Fresh sender (new process) against an online manager.
    fake_manager.set_online(True)
    sender, _ = _make_sender(fake_manager, str(tmp_path))
    sender.start()

    assert _wait_until(lambda: len(fake_manager.received_seqs()) == 10, timeout=10.0), (
        "startup must replay envelopes left in the spool by the previous run"
    )
    sender.stop()

    assert fake_manager.received_seqs() == list(range(10))
    assert sender._spool.size() == 0
