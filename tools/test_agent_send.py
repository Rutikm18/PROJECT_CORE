#!/usr/bin/env python3
"""
tools/test_agent_send.py — End-to-end network send test for the Jarvis agent.

Tests
─────
1. Manager reachability (GET /health)
2. Enrollment (POST /api/v1/enroll)  — full first-run flow
3. Single ingest send (POST /api/v1/ingest)  — metrics envelope
4. Spool → drain cycle (simulate offline → online)
5. TLS certificate validation

Usage
─────
  # Start manager first (in another terminal):
  make run-manager

  # Run with a pre-generated key (skips enrollment):
  python3 tools/test_agent_send.py \\
      --manager-url https://127.0.0.1:8443 \\
      --agent-id    test-agent-001 \\
      --api-key     $(python3 -c "import secrets; print(secrets.token_hex(32))")

  # Run enrollment flow (manager must have ENROLLMENT_TOKENS set):
  python3 tools/test_agent_send.py \\
      --manager-url   https://127.0.0.1:8443 \\
      --agent-id      test-agent-001 \\
      --enroll-token  <token-from-manager>

  # Run against external server:
  python3 tools/test_agent_send.py \\
      --manager-url https://your-server.example.com:8443 \\
      --agent-id    test-agent-001 \\
      --api-key     <your-key> \\
      --tls-verify

All tests print PASS / FAIL with details.  Exit code 0 = all passed.
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import socket
import ssl
import sys
import tempfile
import time
import urllib.error
import urllib.request

# ── project root on path so we can import agent modules ──────────────────────
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)

from agent.agent.crypto import derive_keys, encrypt


# ══════════════════════════════════════════════════════════════════════════════
# Helpers
# ══════════════════════════════════════════════════════════════════════════════

_PASS = "\033[32mPASS\033[0m"
_FAIL = "\033[31mFAIL\033[0m"
_SKIP = "\033[33mSKIP\033[0m"

_results: list[tuple[str, bool, str]] = []


def _record(name: str, ok: bool, detail: str = "") -> None:
    _results.append((name, ok, detail))
    status = _PASS if ok else _FAIL
    print(f"  [{status}] {name}" + (f": {detail}" if detail else ""))


def _ssl_ctx(tls_verify: bool) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    if not tls_verify:
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
    else:
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.load_default_certs()
    return ctx


def _get(url: str, ctx: ssl.SSLContext, timeout: int = 10) -> tuple[int, bytes]:
    req = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def _post(url: str, body: dict, headers: dict,
          ctx: ssl.SSLContext, timeout: int = 30) -> tuple[int, bytes]:
    data = json.dumps(body).encode()
    req  = urllib.request.Request(
        url, data=data,
        headers={"Content-Type": "application/json", **headers},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


# ══════════════════════════════════════════════════════════════════════════════
# Test 1: Manager reachability
# ══════════════════════════════════════════════════════════════════════════════

def test_health(base_url: str, ctx: ssl.SSLContext) -> bool:
    print("\n[1] Manager Health Check")
    url = base_url.rstrip("/") + "/health"
    try:
        status, body = _get(url, ctx)
        ok = status == 200
        _record("GET /health → 200", ok, f"HTTP {status}: {body[:120].decode(errors='replace')}")
        return ok
    except Exception as exc:
        _record("GET /health → 200", False, str(exc))
        return False


# ══════════════════════════════════════════════════════════════════════════════
# Test 2: Enrollment
# ══════════════════════════════════════════════════════════════════════════════

def test_enrollment(base_url: str, agent_id: str, enroll_token: str,
                    ctx: ssl.SSLContext) -> str | None:
    print("\n[2] Enrollment Flow")
    api_key = secrets.token_hex(32)
    payload = {
        "agent_id":   agent_id,
        "agent_name": "test-agent",
        "api_key":    api_key,
        "hostname":   socket.gethostname(),
        "os":         "macos",
        "arch":       "arm64",
        "timestamp":  int(time.time()),
    }
    url = base_url.rstrip("/") + "/api/v1/enroll"
    try:
        status, body = _post(url, payload,
                             {"X-Enrollment-Token": enroll_token,
                              "User-Agent": "jarvis-agent/test"},
                             ctx)
        ok = status == 200
        _record("POST /api/v1/enroll → 200", ok,
                f"HTTP {status}: {body[:120].decode(errors='replace')}")
        return api_key if ok else None
    except Exception as exc:
        _record("POST /api/v1/enroll → 200", False, str(exc))
        return None


# ══════════════════════════════════════════════════════════════════════════════
# Test 3: Single ingest send
# ══════════════════════════════════════════════════════════════════════════════

def test_ingest(base_url: str, agent_id: str, api_key: str,
                ctx: ssl.SSLContext) -> bool:
    print("\n[3] Ingest — single encrypted envelope")
    enc_key, mac_key = derive_keys(api_key)

    # Build a minimal metrics payload
    payload = {
        "section":      "metrics",
        "agent_id":     agent_id,
        "agent_name":   "test-agent",
        "os":           "macos",
        "os_version":   "14.0",
        "arch":         "arm64",
        "hostname":     socket.gethostname(),
        "collected_at": int(time.time()),
        "data": {
            "cpu_pct": 12.5,
            "mem_pct": 45.2,
            "mem_used_mb": 8192,
            "mem_total_mb": 16384,
            "load_1m": 1.2,
            "load_5m": 0.9,
            "load_15m": 0.7,
            "uptime_sec": 3600,
        },
    }

    try:
        envelope = encrypt(payload, enc_key, mac_key, agent_id, int(time.time()))
        envelope["section"] = "metrics"
    except Exception as exc:
        _record("Encrypt envelope", False, str(exc))
        return False

    _record("Encrypt envelope", True, f"nonce={envelope.get('nonce', '')[:8]}...")

    url = base_url.rstrip("/") + "/api/v1/ingest"
    try:
        status, body = _post(url, envelope,
                             {"X-Agent-ID": agent_id,
                              "X-Section": "metrics",
                              "User-Agent": "jarvis-agent/test"},
                             ctx)
        ok = status == 200
        _record("POST /api/v1/ingest metrics → 200", ok,
                f"HTTP {status}: {body[:120].decode(errors='replace')}")
        return ok
    except Exception as exc:
        _record("POST /api/v1/ingest metrics → 200", False, str(exc))
        return False


def test_ingest_all_sections(base_url: str, agent_id: str, api_key: str,
                              ctx: ssl.SSLContext) -> None:
    """Send one envelope per section to exercise the full pipeline."""
    print("\n[3b] Ingest — smoke-test every section")
    enc_key, mac_key = derive_keys(api_key)
    url = base_url.rstrip("/") + "/api/v1/ingest"

    sections = {
        "metrics":     {"cpu_pct": 5.0, "mem_pct": 30.0, "mem_used_mb": 4096,
                        "mem_total_mb": 16384},
        "connections": [{"proto": "tcp", "local_addr": "127.0.0.1",
                         "local_port": 52000, "remote_addr": "1.1.1.1",
                         "remote_port": 443, "state": "ESTABLISHED",
                         "pid": 1234, "process": "curl"}],
        "processes":   [{"pid": 1, "name": "launchd", "cpu_pct": 0.0,
                         "mem_pct": 0.1, "status": "running"}],
        "ports":       [{"proto": "tcp", "port": 22, "bind_addr": "0.0.0.0",
                         "state": "LISTEN", "pid": 100, "process": "sshd"}],
        "network":     {"interfaces": [], "dns_servers": ["8.8.8.8"],
                        "default_gw": "192.168.1.1", "hostname": "test",
                        "domain": None, "wifi_ssid": None, "wifi_rssi": None},
    }

    passed = failed = 0
    for section, data in sections.items():
        payload = {
            "section": section, "agent_id": agent_id,
            "agent_name": "test-agent", "os": "macos",
            "os_version": "14.0", "arch": "arm64",
            "hostname": socket.gethostname(),
            "collected_at": int(time.time()), "data": data,
        }
        try:
            envelope = encrypt(payload, enc_key, mac_key, agent_id, int(time.time()))
            envelope["section"] = section
            status, body = _post(url, envelope,
                                 {"X-Agent-ID": agent_id, "X-Section": section,
                                  "User-Agent": "jarvis-agent/test"},
                                 ctx)
            ok = status == 200
            if ok:
                passed += 1
            else:
                failed += 1
                print(f"     section={section} HTTP {status}: "
                      f"{body[:80].decode(errors='replace')}")
        except Exception as exc:
            failed += 1
            print(f"     section={section} ERROR: {exc}")

    _record(f"Ingest {passed+failed} sections",
            failed == 0,
            f"{passed} OK, {failed} failed")


# ══════════════════════════════════════════════════════════════════════════════
# Test 4: Spool → drain cycle
# ══════════════════════════════════════════════════════════════════════════════

def test_spool_cycle(api_key: str) -> bool:
    print("\n[4] Disk Spool — write + drain cycle")
    from agent.agent.sender import DiskSpool
    enc_key, mac_key = derive_keys(api_key)

    with tempfile.TemporaryDirectory() as td:
        spool_path = os.path.join(td, "unsent.ndjson")
        spool = DiskSpool(spool_path)

        # Write 3 envelopes
        try:
            for i in range(3):
                p = {"section": "metrics", "agent_id": "spool-test",
                     "agent_name": "t", "os": "macos", "os_version": "14",
                     "arch": "arm64", "hostname": "h",
                     "collected_at": int(time.time()), "data": {"cpu_pct": float(i)}}
                env = encrypt(p, enc_key, mac_key, "spool-test", int(time.time()))
                env["section"] = "metrics"
                spool.write(env)
            wrote_ok = True
        except Exception as exc:
            wrote_ok = False
            _record("Spool write 3 envelopes", False, str(exc))
            return False

        size = spool.size()
        _record("Spool write 3 envelopes", wrote_ok,
                f"spool size = {size} bytes")

        # Drain
        drained = spool.drain()
        _record("Spool drain returns 3 items", len(drained) == 3,
                f"got {len(drained)} items")

        # File gone after drain
        gone = not os.path.exists(spool_path)
        _record("Spool file removed after drain", gone)

        return wrote_ok and len(drained) == 3 and gone


# ══════════════════════════════════════════════════════════════════════════════
# Test 5: TLS certificate validation
# ══════════════════════════════════════════════════════════════════════════════

def test_tls_enforcement(base_url: str) -> None:
    print("\n[5] TLS Enforcement")

    # Strict ctx — should FAIL against self-signed cert
    strict_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    strict_ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    strict_ctx.verify_mode = ssl.CERT_REQUIRED

    url = base_url.rstrip("/") + "/health"
    try:
        urllib.request.urlopen(
            urllib.request.Request(url), context=strict_ctx, timeout=5
        )
        # If the server has a valid CA-signed cert this will succeed — that's fine
        _record("TLS: strict ctx accepted cert", True,
                "(server uses a valid CA-signed cert)")
    except ssl.SSLCertVerificationError:
        _record("TLS: strict ctx rejects self-signed cert", True,
                "(expected — self-signed cert correctly rejected)")
    except Exception as exc:
        _record("TLS: connection attempt", False, str(exc))

    # Lenient ctx — should succeed
    lenient_ctx = _ssl_ctx(tls_verify=False)
    try:
        status, _ = _get(url, lenient_ctx, timeout=5)
        _record("TLS: lenient ctx can reach manager", status in (200, 401, 404),
                f"HTTP {status}")
    except Exception as exc:
        _record("TLS: lenient ctx can reach manager", False, str(exc))


# ══════════════════════════════════════════════════════════════════════════════
# Test 6: Reject invalid HMAC
# ══════════════════════════════════════════════════════════════════════════════

def test_bad_hmac_rejected(base_url: str, agent_id: str, ctx: ssl.SSLContext) -> None:
    print("\n[6] Security — tampered envelope rejected by manager")
    # Send an envelope with a garbage HMAC — manager should return 401
    bad_envelope = {
        "agent_id": agent_id,
        "section":  "metrics",
        "nonce":    "00" * 12,
        "ct":       "deadbeef" * 8,
        "mac":      "00" * 32,     # wrong HMAC
        "ts":       int(time.time()),
    }
    url = base_url.rstrip("/") + "/api/v1/ingest"
    try:
        status, body = _post(url, bad_envelope,
                             {"X-Agent-ID": agent_id, "X-Section": "metrics",
                              "User-Agent": "jarvis-agent/test"},
                             ctx)
        ok = status in (401, 403, 400)
        _record("Tampered envelope rejected (401/403/400)", ok,
                f"HTTP {status}: {body[:80].decode(errors='replace')}")
    except Exception as exc:
        _record("Tampered envelope rejected", False, str(exc))


# ══════════════════════════════════════════════════════════════════════════════
# Main
# ══════════════════════════════════════════════════════════════════════════════

def main() -> int:
    parser = argparse.ArgumentParser(
        description="End-to-end send test for the Jarvis agent"
    )
    parser.add_argument("--manager-url",  default="https://127.0.0.1:8443")
    parser.add_argument("--agent-id",     default="test-agent-001")
    parser.add_argument("--api-key",      default="",
                        help="64-hex API key (skips enrollment)")
    parser.add_argument("--enroll-token", default="",
                        help="Enrollment token (runs enrollment flow instead)")
    parser.add_argument("--tls-verify",   action="store_true",
                        help="Enable TLS certificate verification (default: off)")
    args = parser.parse_args()

    print(f"\nJarvis Agent — Network Send Test")
    print(f"  Manager : {args.manager_url}")
    print(f"  Agent ID: {args.agent_id}")
    print(f"  TLS     : {'strict' if args.tls_verify else 'lenient (self-signed ok)'}")
    print("=" * 60)

    ctx     = _ssl_ctx(tls_verify=args.tls_verify)
    api_key = args.api_key.strip()

    # ── 1. Health ────────────────────────────────────────────────────────────
    reachable = test_health(args.manager_url, ctx)
    if not reachable:
        print("\n  Manager unreachable — is `make run-manager` running?")
        print("  Remaining tests require manager connectivity.")
        # Still run offline tests
        test_spool_cycle(api_key or secrets.token_hex(32))
        _print_summary()
        return 1

    # ── 2. Enrollment (optional) ─────────────────────────────────────────────
    if args.enroll_token and not api_key:
        enrolled_key = test_enrollment(
            args.manager_url, args.agent_id, args.enroll_token, ctx
        )
        if enrolled_key:
            api_key = enrolled_key
        else:
            print("  Enrollment failed — cannot continue ingest tests.")
    elif not api_key:
        print("\n[2] Enrollment")
        print(f"  [{_SKIP}] No --api-key or --enroll-token provided — skipping")

    # ── 3. Ingest ────────────────────────────────────────────────────────────
    if api_key:
        test_ingest(args.manager_url, args.agent_id, api_key, ctx)
        test_ingest_all_sections(args.manager_url, args.agent_id, api_key, ctx)
    else:
        print("\n[3] Ingest")
        print(f"  [{_SKIP}] No API key available — skipping")

    # ── 4. Spool ─────────────────────────────────────────────────────────────
    test_spool_cycle(api_key or secrets.token_hex(32))

    # ── 5. TLS ───────────────────────────────────────────────────────────────
    test_tls_enforcement(args.manager_url)

    # ── 6. Bad HMAC ──────────────────────────────────────────────────────────
    test_bad_hmac_rejected(args.manager_url, args.agent_id, ctx)

    return _print_summary()


def _print_summary() -> int:
    total = len(_results)
    passed = sum(1 for _, ok, _ in _results if ok)
    failed = total - passed
    print("\n" + "=" * 60)
    print(f"Results: {passed}/{total} passed", end="")
    if failed:
        print(f"  ({failed} failed)")
        for name, ok, detail in _results:
            if not ok:
                print(f"    FAIL: {name}" + (f" — {detail}" if detail else ""))
    else:
        print(" — all passed")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
