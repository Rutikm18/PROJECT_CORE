#!/usr/bin/env python3
"""
scripts/perf/loadtest.py — Large-scale performance / load test harness.

Measures latency (p50/p90/p95/p99/max), throughput (req/s), error rate, and
data-processing efficiency (bytes & rows/sec) against a running AttackLens
deployment — local dev or the AWS deployment.

It drives concurrent async workers against one or more read endpoints, and can
optionally exercise the ingest path to measure end-to-end processing throughput.

USAGE
  # Read-path latency/throughput on the AWS deployment
  python3 scripts/perf/loadtest.py \
      --url https://<aws-host>:8443 \
      --endpoint /api/v1/detection/all \
      --concurrency 50 --requests 5000 --insecure

  # Compare several endpoints in one run
  python3 scripts/perf/loadtest.py --url https://localhost:8443 --insecure \
      --endpoint /api/v1/detection/all \
      --endpoint /api/v1/integrations/health \
      --concurrency 20 --duration 30

  # Dry self-test of the metrics math (no server needed)
  python3 scripts/perf/loadtest.py --selftest

Exit code is non-zero if the measured error rate exceeds --max-error-rate or
p95 latency exceeds --slo-p95-ms, so it can gate a CI/CD performance stage.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import math
import ssl
import statistics
import sys
import time
from dataclasses import dataclass, field
from typing import Optional


# ── Latency statistics ─────────────────────────────────────────────────────────

def percentile(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    if len(s) == 1:
        return s[0]
    rank = (p / 100.0) * (len(s) - 1)
    lo = math.floor(rank)
    hi = math.ceil(rank)
    if lo == hi:
        return s[int(rank)]
    return s[lo] + (s[hi] - s[lo]) * (rank - lo)


@dataclass
class EndpointStats:
    endpoint:     str
    latencies_ms: list[float] = field(default_factory=list)
    errors:       int = 0
    bytes_total:  int = 0
    status_counts: dict = field(default_factory=dict)

    def record(self, latency_ms: float, status: int, nbytes: int) -> None:
        self.status_counts[status] = self.status_counts.get(status, 0) + 1
        if 200 <= status < 400:
            self.latencies_ms.append(latency_ms)
            self.bytes_total += nbytes
        else:
            self.errors += 1

    def report(self, wall_s: float) -> dict:
        n_ok = len(self.latencies_ms)
        total = n_ok + self.errors
        return {
            "endpoint":       self.endpoint,
            "requests":       total,
            "ok":             n_ok,
            "errors":         self.errors,
            "error_rate":     round(self.errors / total, 4) if total else 0.0,
            "throughput_rps": round(total / wall_s, 1) if wall_s > 0 else 0.0,
            "latency_ms": {
                "min":  round(min(self.latencies_ms), 1) if self.latencies_ms else None,
                "p50":  round(percentile(self.latencies_ms, 50), 1),
                "p90":  round(percentile(self.latencies_ms, 90), 1),
                "p95":  round(percentile(self.latencies_ms, 95), 1),
                "p99":  round(percentile(self.latencies_ms, 99), 1),
                "max":  round(max(self.latencies_ms), 1) if self.latencies_ms else None,
                "mean": round(statistics.mean(self.latencies_ms), 1) if self.latencies_ms else None,
            },
            "data_efficiency": {
                "bytes_total":     self.bytes_total,
                "mb_per_sec":      round(self.bytes_total / 1e6 / wall_s, 2) if wall_s > 0 else 0.0,
                "avg_payload_kb":  round(self.bytes_total / 1024 / n_ok, 1) if n_ok else 0.0,
            },
            "status_counts":  self.status_counts,
        }


# ── Load driver ────────────────────────────────────────────────────────────────

async def _worker(session, base_url, endpoints, stats, budget, insecure_ssl):
    """Each worker loops pulling work from the shared budget until exhausted."""
    idx = 0
    while True:
        seq = budget.take()
        if seq is None:
            return
        ep = endpoints[idx % len(endpoints)]
        idx += 1
        url = base_url.rstrip("/") + ep
        t0 = time.monotonic()
        try:
            async with session.get(url, ssl=False if insecure_ssl else None) as resp:
                body = await resp.read()
                lat = (time.monotonic() - t0) * 1000
                stats[ep].record(lat, resp.status, len(body))
        except Exception:
            lat = (time.monotonic() - t0) * 1000
            stats[ep].record(lat, 0, 0)


class _Budget:
    """Thread-safe-ish request budget: fixed count or time-bounded."""
    def __init__(self, total: Optional[int], deadline: Optional[float]):
        self._remaining = total
        self._deadline = deadline
        self._n = 0

    def take(self) -> Optional[int]:
        if self._deadline is not None and time.monotonic() >= self._deadline:
            return None
        if self._remaining is not None:
            if self._remaining <= 0:
                return None
            self._remaining -= 1
        self._n += 1
        return self._n


async def run_load(args) -> dict:
    import aiohttp
    endpoints = args.endpoint or ["/api/v1/integrations/health"]
    stats = {ep: EndpointStats(ep) for ep in endpoints}

    deadline = (time.monotonic() + args.duration) if args.duration else None
    total = None if args.duration else args.requests
    budget = _Budget(total, deadline)

    timeout = aiohttp.ClientTimeout(total=args.timeout)
    connector = aiohttp.TCPConnector(limit=args.concurrency, ssl=False if args.insecure else None)

    print(f"→ Load test: {args.url}  endpoints={endpoints}")
    print(f"  concurrency={args.concurrency}  "
          f"{'duration=' + str(args.duration) + 's' if args.duration else 'requests=' + str(args.requests)}")

    t0 = time.monotonic()
    async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
        workers = [
            asyncio.create_task(_worker(session, args.url, endpoints, stats, budget, args.insecure))
            for _ in range(args.concurrency)
        ]
        await asyncio.gather(*workers)
    wall_s = time.monotonic() - t0

    reports = [stats[ep].report(wall_s) for ep in endpoints]
    return {"wall_seconds": round(wall_s, 2), "endpoints": reports}


# ── SLO gating + output ────────────────────────────────────────────────────────

def evaluate_slo(result: dict, args) -> tuple[bool, list[str]]:
    violations = []
    for ep in result["endpoints"]:
        if ep["error_rate"] > args.max_error_rate:
            violations.append(
                f"{ep['endpoint']}: error_rate {ep['error_rate']} > {args.max_error_rate}")
        p95 = ep["latency_ms"]["p95"]
        if args.slo_p95_ms and p95 and p95 > args.slo_p95_ms:
            violations.append(
                f"{ep['endpoint']}: p95 {p95}ms > SLO {args.slo_p95_ms}ms")
    return (not violations), violations


def print_report(result: dict) -> None:
    print("\n" + "=" * 78)
    print(f"PERFORMANCE REPORT   wall={result['wall_seconds']}s")
    print("=" * 78)
    for ep in result["endpoints"]:
        lat = ep["latency_ms"]
        de = ep["data_efficiency"]
        print(f"\n▸ {ep['endpoint']}")
        print(f"    requests={ep['requests']}  ok={ep['ok']}  errors={ep['errors']}  "
              f"error_rate={ep['error_rate']}")
        print(f"    throughput={ep['throughput_rps']} req/s")
        print(f"    latency(ms): p50={lat['p50']} p90={lat['p90']} p95={lat['p95']} "
              f"p99={lat['p99']} max={lat['max']}")
        print(f"    data: {de['mb_per_sec']} MB/s  avg_payload={de['avg_payload_kb']} KB  "
              f"total={round(de['bytes_total']/1e6, 2)} MB")
        print(f"    status: {ep['status_counts']}")


# ── Self-test (no server) ──────────────────────────────────────────────────────

def selftest() -> int:
    print("Self-test: percentile math + stats aggregation")
    xs = list(range(1, 101))  # 1..100
    assert abs(percentile(xs, 50) - 50.5) < 0.6, percentile(xs, 50)
    assert abs(percentile(xs, 95) - 95.05) < 1.0, percentile(xs, 95)
    assert percentile(xs, 100) == 100
    assert percentile([], 95) == 0.0
    assert percentile([42], 95) == 42

    st = EndpointStats("/x")
    for i in range(100):
        st.record(float(i + 1), 200, 1024)
    st.record(5.0, 500, 0)   # one error
    rep = st.report(wall_s=2.0)
    assert rep["ok"] == 100 and rep["errors"] == 1
    assert rep["error_rate"] == round(1 / 101, 4)
    assert rep["throughput_rps"] == round(101 / 2.0, 1)
    assert rep["latency_ms"]["p50"] and rep["latency_ms"]["p99"]
    assert rep["data_efficiency"]["bytes_total"] == 100 * 1024
    print("  percentiles:", {k: rep["latency_ms"][k] for k in ("p50", "p95", "p99")})
    print("  throughput:", rep["throughput_rps"], "req/s   mb/s:", rep["data_efficiency"]["mb_per_sec"])

    # SLO gating logic
    class A: max_error_rate = 0.001; slo_p95_ms = 50
    ok, viol = evaluate_slo({"endpoints": [rep]}, A)
    assert not ok and len(viol) == 2, viol  # error_rate + p95 both exceed
    print("  SLO gating flagged violations:", len(viol))
    print("SELF-TEST PASS")
    return 0


# ── CLI ────────────────────────────────────────────────────────────────────────

def main() -> int:
    ap = argparse.ArgumentParser(description="AttackLens load / performance test")
    ap.add_argument("--url", default="https://localhost:8443", help="Base URL of the deployment")
    ap.add_argument("--endpoint", action="append", help="Endpoint path (repeatable)")
    ap.add_argument("--concurrency", type=int, default=20)
    ap.add_argument("--requests", type=int, default=2000, help="Total requests (ignored if --duration)")
    ap.add_argument("--duration", type=int, default=0, help="Run for N seconds instead of fixed count")
    ap.add_argument("--timeout", type=float, default=30.0)
    ap.add_argument("--insecure", action="store_true", help="Skip TLS verification (self-signed dev/AWS)")
    ap.add_argument("--max-error-rate", type=float, default=0.01)
    ap.add_argument("--slo-p95-ms", type=float, default=0, help="Fail if p95 exceeds this (0=disabled)")
    ap.add_argument("--json", action="store_true", help="Emit JSON report to stdout")
    ap.add_argument("--selftest", action="store_true", help="Validate the harness math, no server")
    args = ap.parse_args()

    if args.selftest:
        return selftest()

    try:
        import aiohttp  # noqa: F401
    except ImportError:
        print("ERROR: aiohttp required. pip install aiohttp", file=sys.stderr)
        return 2

    result = asyncio.run(run_load(args))
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print_report(result)

    ok, violations = evaluate_slo(result, args)
    if not ok:
        print("\nSLO VIOLATIONS:")
        for v in violations:
            print("  ✗", v)
        return 1
    print("\nSLO: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
