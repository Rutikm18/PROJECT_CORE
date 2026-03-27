"""
agent/sender.py — Encrypted HTTPS sender

Drains the send queue, posts each envelope to the manager.
Implements exponential backoff with jitter on transient failures.
Uses TLS 1.3 minimum.
"""

import logging
import queue
import random
import ssl
import threading
import time
import urllib.request
import json

log = logging.getLogger("agent.sender")


class Sender:
    def __init__(self, config: dict, send_queue: queue.Queue):
        self.mgr       = config["manager"]
        self.url       = self.mgr["url"].rstrip("/") + "/api/v1/ingest"
        self.timeout   = self.mgr.get("timeout_sec", 30)
        self.max_retry = self.mgr.get("retry_attempts", 3)
        self.retry_del = self.mgr.get("retry_delay_sec", 5)
        self.tls_verify = self.mgr.get("tls_verify", True)
        self.queue     = send_queue
        self._stop     = threading.Event()
        self._ctx      = self._build_ssl_ctx()

    def _build_ssl_ctx(self) -> ssl.SSLContext:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        if not self.tls_verify:
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            log.warning("TLS verification disabled — dev/self-signed cert mode")
        else:
            ctx.verify_mode    = ssl.CERT_REQUIRED
            ctx.load_default_certs()
        return ctx

    def start(self) -> threading.Thread:
        self._stop.clear()
        t = threading.Thread(target=self._drain_loop, daemon=True,
                             name="sender")
        t.start()
        return t

    def stop(self):
        self._stop.set()

    def _drain_loop(self):
        while not self._stop.is_set():
            try:
                envelope = self.queue.get(timeout=1)
            except queue.Empty:
                continue
            self._send_with_retry(envelope)

    def _send_with_retry(self, envelope: dict):
        body    = json.dumps(envelope).encode()
        delay   = self.retry_del
        for attempt in range(1, self.max_retry + 1):
            try:
                req = urllib.request.Request(
                    self.url,
                    data=body,
                    headers={
                        "Content-Type": "application/json",
                        "X-Agent-ID":   envelope.get("agent_id", ""),
                        "X-Section":    envelope.get("section", ""),
                        "User-Agent":   "mac_intel-agent/1.0",
                    },
                    method="POST",
                )
                with urllib.request.urlopen(req, context=self._ctx,
                                            timeout=self.timeout) as resp:
                    status = resp.status
                    if status == 200:
                        log.debug("Sent %s → %d", envelope.get("section"), status)
                        return
                    elif 400 <= status < 500:
                        log.error("Manager rejected payload (HTTP %d) — dropping "
                                  "section=%s", status, envelope.get("section"))
                        return  # not retryable
                    else:
                        log.warning("Manager HTTP %d (attempt %d/%d)",
                                    status, attempt, self.max_retry)

            except Exception as exc:
                log.warning("Send failed (attempt %d/%d): %s",
                            attempt, self.max_retry, exc)

            if attempt < self.max_retry:
                jitter = random.uniform(0, delay * 0.3)
                time.sleep(min(delay + jitter, 60))
                delay *= 2

        log.error("Dropped payload for section=%s after %d attempts",
                  envelope.get("section"), self.max_retry)
