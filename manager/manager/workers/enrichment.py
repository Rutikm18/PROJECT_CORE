"""manager/manager/workers/enrichment.py — External threat-intel enrichment."""
from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from typing import TYPE_CHECKING, Any

import aiohttp

if TYPE_CHECKING:
    from ..indexer import IntelDB

log = logging.getLogger("manager.workers.enrichment")

# Cadences (seconds)
_MISP_INTERVAL    = 30 * 60        # 30 min
_VT_INTERVAL      = 10 * 60        # batch run every 10 min (rate-limited internally)
_SHODAN_INTERVAL  = 6 * 3600       # 6h re-scan of connection findings

# HTTP
_HTTP_TIMEOUT  = aiohttp.ClientTimeout(total=15)
_USER_AGENT    = "AttackLens-Manager/1.0 (+enrichment)"

# Rate limits
_VT_PER_MINUTE     = 4              # free tier
_SHODAN_PER_MINUTE = 60             # InternetDB courtesy cap

# How many findings per loop pass
_BATCH_SIZE = 100


class _RateLimiter:
    """Simple per-minute token bucket."""

    def __init__(self, per_minute: int) -> None:
        self._capacity = max(1, per_minute)
        self._tokens   = float(self._capacity)
        self._last     = time.monotonic()
        self._lock     = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            while True:
                now = time.monotonic()
                elapsed = now - self._last
                self._last = now
                self._tokens = min(
                    self._capacity,
                    self._tokens + elapsed * (self._capacity / 60.0),
                )
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return
                # Need to wait until at least one token is available
                deficit = 1.0 - self._tokens
                wait = deficit / (self._capacity / 60.0)
                await asyncio.sleep(min(wait, 5.0))


class EnrichmentWorker:
    """Enriches IntelDB findings with MISP / VirusTotal / Shodan InternetDB data."""

    def __init__(self, intel_db: "IntelDB", rabbitmq_url: str | None = None) -> None:
        self._idb     = intel_db
        self._url     = rabbitmq_url or ""
        self._running = False
        self._tasks: list[asyncio.Task] = []
        self._session: aiohttp.ClientSession | None = None

        # Config from env
        self._misp_url = (os.environ.get("MISP_URL", "") or "").rstrip("/")
        self._misp_key = os.environ.get("MISP_KEY", "") or ""
        self._vt_key   = os.environ.get("VT_API_KEY", "") or ""

        self._vt_limiter     = _RateLimiter(_VT_PER_MINUTE)
        self._shodan_limiter = _RateLimiter(_SHODAN_PER_MINUTE)

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    async def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._session = aiohttp.ClientSession(
            timeout=_HTTP_TIMEOUT,
            headers={"User-Agent": _USER_AGENT},
        )
        if self._misp_enabled:
            self._tasks.append(asyncio.create_task(self._misp_loop()))
            log.info("EnrichmentWorker: MISP loop enabled (%s)", self._misp_url)
        else:
            log.info("EnrichmentWorker: MISP disabled (MISP_URL/MISP_KEY not set)")
        if self._vt_enabled:
            self._tasks.append(asyncio.create_task(self._vt_loop()))
            log.info("EnrichmentWorker: VirusTotal loop enabled")
        else:
            log.info("EnrichmentWorker: VirusTotal disabled (VT_API_KEY not set)")
        # Shodan InternetDB is keyless — always on
        self._tasks.append(asyncio.create_task(self._shodan_loop()))
        log.info("EnrichmentWorker: Shodan InternetDB loop enabled")

    async def stop(self) -> None:
        self._running = False
        for t in self._tasks:
            t.cancel()
        for t in self._tasks:
            try:
                await t
            except (asyncio.CancelledError, Exception):
                pass
        self._tasks = []
        if self._session is not None:
            try:
                await self._session.close()
            except Exception:
                pass
            self._session = None

    @property
    def _misp_enabled(self) -> bool:
        return bool(self._misp_url and self._misp_key)

    @property
    def _vt_enabled(self) -> bool:
        return bool(self._vt_key)

    # ── On-demand ─────────────────────────────────────────────────────────────

    async def enrich_finding_now(self, finding_id: str | int) -> dict:
        """Run all enabled enrichment paths against a single finding immediately."""
        try:
            fid = int(finding_id)
        except (TypeError, ValueError):
            return {}
        finding = await self._idb.get_finding_by_id(fid)
        if not finding:
            return {}
        ev = self._evidence(finding)

        async def _safe(coro: Any) -> None:
            try:
                await coro
            except Exception as exc:
                log.debug("on-demand enrichment subtask failed: %s", exc)

        ioc = self._extract_ioc(finding, ev)
        sha256 = self._extract_sha256(finding, ev)
        ip = self._extract_ip(finding, ev)

        if self._misp_enabled and ioc:
            await _safe(self._misp_check(finding, ioc))
        if self._vt_enabled and sha256:
            await _safe(self._vt_check(finding, sha256))
        if ip:
            await _safe(self._shodan_check(finding, ip))

        refreshed = await self._idb.get_finding_by_id(fid)
        return refreshed or finding

    # ── Loops ─────────────────────────────────────────────────────────────────

    async def _misp_loop(self) -> None:
        while self._running:
            try:
                findings = await self._unresolved(limit=_BATCH_SIZE)
                for f in findings:
                    if not self._running:
                        break
                    ioc = self._extract_ioc(f, self._evidence(f))
                    if not ioc:
                        continue
                    try:
                        await self._misp_check(f, ioc)
                    except Exception as exc:
                        log.debug("MISP check failed for %s: %s", ioc, exc)
            except asyncio.CancelledError:
                break
            except Exception as exc:
                log.warning("MISP loop iteration error: %s", exc)
            try:
                await asyncio.sleep(_MISP_INTERVAL)
            except asyncio.CancelledError:
                break

    async def _vt_loop(self) -> None:
        while self._running:
            try:
                findings = await self._unresolved(limit=_BATCH_SIZE)
                for f in findings:
                    if not self._running:
                        break
                    sha = self._extract_sha256(f, self._evidence(f))
                    if not sha:
                        continue
                    try:
                        await self._vt_check(f, sha)
                    except Exception as exc:
                        log.debug("VT check failed for %s: %s", sha[:12], exc)
            except asyncio.CancelledError:
                break
            except Exception as exc:
                log.warning("VT loop iteration error: %s", exc)
            try:
                await asyncio.sleep(_VT_INTERVAL)
            except asyncio.CancelledError:
                break

    async def _shodan_loop(self) -> None:
        while self._running:
            try:
                findings = await self._unresolved(limit=_BATCH_SIZE, category="connection")
                for f in findings:
                    if not self._running:
                        break
                    ip = self._extract_ip(f, self._evidence(f))
                    if not ip:
                        continue
                    try:
                        await self._shodan_check(f, ip)
                    except Exception as exc:
                        log.debug("Shodan check failed for %s: %s", ip, exc)
            except asyncio.CancelledError:
                break
            except Exception as exc:
                log.warning("Shodan loop iteration error: %s", exc)
            try:
                await asyncio.sleep(_SHODAN_INTERVAL)
            except asyncio.CancelledError:
                break

    # ── Source: MISP ──────────────────────────────────────────────────────────

    async def _misp_check(self, finding: dict, ioc: str) -> None:
        if not (self._misp_enabled and self._session):
            return
        url = f"{self._misp_url}/attributes/restSearch"
        headers = {
            "Authorization": self._misp_key,
            "Accept":        "application/json",
            "Content-Type":  "application/json",
        }
        body = {"value": ioc, "limit": 5}
        try:
            async with self._session.post(url, json=body, headers=headers, ssl=False) as r:
                if r.status != 200:
                    log.debug("MISP %s for %s", r.status, ioc)
                    return
                payload = await r.json()
        except Exception as exc:
            log.debug("MISP request error for %s: %s", ioc, exc)
            return

        attrs = (
            payload.get("response", {}).get("Attribute")
            if isinstance(payload, dict) else None
        )
        if not attrs:
            return
        log.info("MISP match for %s (finding=%s)", ioc, finding.get("id"))
        await self._add_tag(finding, "misp:confirmed")

    # ── Source: VirusTotal ────────────────────────────────────────────────────

    async def _vt_check(self, finding: dict, sha256: str) -> None:
        if not (self._vt_enabled and self._session):
            return
        await self._vt_limiter.acquire()
        url = f"https://www.virustotal.com/api/v3/files/{sha256}"
        headers = {"x-apikey": self._vt_key, "Accept": "application/json"}
        try:
            async with self._session.get(url, headers=headers) as r:
                if r.status == 404:
                    return
                if r.status != 200:
                    log.debug("VT %s for %s", r.status, sha256[:12])
                    return
                payload = await r.json()
        except Exception as exc:
            log.debug("VT request error for %s: %s", sha256[:12], exc)
            return

        data = payload.get("data") if isinstance(payload, dict) else None
        if not data:
            return
        attrs = data.get("attributes", {}) if isinstance(data, dict) else {}
        stats = attrs.get("last_analysis_stats", {}) or {}
        try:
            malicious = int(stats.get("malicious", 0))
        except (TypeError, ValueError):
            malicious = 0
        if malicious <= 0:
            return

        log.info(
            "VT match for %s: %d engines flagged (finding=%s)",
            sha256[:12], malicious, finding.get("id"),
        )
        await self._add_tag(finding, f"vt:{malicious}")
        if malicious >= 3:
            current = (finding.get("severity") or "info").lower()
            if current in ("info", "low", "medium"):
                await self._update_severity(finding, "high")

    # ── Source: Shodan InternetDB ─────────────────────────────────────────────

    async def _shodan_check(self, finding: dict, ip: str) -> None:
        if not self._session:
            return
        if _is_private(ip):
            return
        await self._shodan_limiter.acquire()
        url = f"https://internetdb.shodan.io/{ip}"
        try:
            async with self._session.get(url) as r:
                if r.status == 404:
                    return
                if r.status != 200:
                    log.debug("Shodan %s for %s", r.status, ip)
                    return
                payload = await r.json()
        except Exception as exc:
            log.debug("Shodan request error for %s: %s", ip, exc)
            return

        vulns = payload.get("vulns") if isinstance(payload, dict) else None
        if not vulns:
            return

        log.info(
            "Shodan vulns for %s: %d CVE(s) (finding=%s)",
            ip, len(vulns), finding.get("id"),
        )
        await self._add_tag(finding, "shodan:vulns")
        await self._emit_shodan_finding(finding, ip, list(vulns))

    # ── IntelDB helpers ───────────────────────────────────────────────────────

    async def _unresolved(self, *, limit: int, category: str | None = None) -> list[dict]:
        try:
            findings = await self._idb.get_findings(
                agent_id="", category=category, active_only=True, limit=limit,
            )
        except TypeError:
            # Older signature without agent_id="" support
            findings = []
        if findings:
            return findings
        # Fallback: drive a raw read so the loop still works regardless of the
        # IntelDB query helper signature.
        try:
            rows = await self._idb._fetchall(  # type: ignore[attr-defined]
                "SELECT * FROM findings WHERE is_active=1 "
                + ("AND category=? " if category else "")
                + "ORDER BY last_detected_at DESC LIMIT ?",
                ((category, limit) if category else (limit,)),
            )
            return [dict(r) for r in rows]
        except Exception:
            return []

    async def _add_tag(self, finding: dict, tag: str) -> None:
        tags = finding.get("tags")
        if isinstance(tags, str):
            try:
                tags = json.loads(tags)
            except Exception:
                tags = []
        if not isinstance(tags, list):
            tags = []
        if tag in tags:
            return
        tags.append(tag)
        try:
            await self._idb._conn.execute(  # type: ignore[attr-defined]
                "UPDATE findings SET tags=? WHERE id=?",
                (json.dumps(tags), finding.get("id")),
            )
            await self._idb._conn.commit()  # type: ignore[attr-defined]
        except Exception as exc:
            log.debug("tag update failed for finding=%s: %s", finding.get("id"), exc)

    async def _update_severity(self, finding: dict, severity: str) -> None:
        try:
            await self._idb._conn.execute(  # type: ignore[attr-defined]
                "UPDATE findings SET severity=? WHERE id=?",
                (severity, finding.get("id")),
            )
            await self._idb._conn.commit()  # type: ignore[attr-defined]
            log.info(
                "severity escalated to %s for finding=%s",
                severity, finding.get("id"),
            )
        except Exception as exc:
            log.debug("severity update failed: %s", exc)

    async def _emit_shodan_finding(self, parent: dict, ip: str, vulns: list) -> None:
        f = {
            "agent_id":        parent.get("agent_id", ""),
            "category":        "connection",
            "item_key":        f"shodan:{ip}",
            "severity":        "high",
            "score":           7.5,
            "title":           f"Shodan: known vulns on {ip}",
            "description":     f"InternetDB lists {len(vulns)} CVE(s) on this peer.",
            "evidence":        {"ip": ip, "vulns": vulns[:50]},
            "source":          "shodan",
            "rule_id":         "shodan",
            "mitre_technique": "T1071",
            "mitre_tactic":    "command-and-control",
            "cve_ids":         [v for v in vulns if isinstance(v, str)][:50],
            "cvss_score":      None,
            "cvss_vector":     "",
            "tags":            ["connection", "shodan", "internetdb"],
        }
        try:
            await self._idb.upsert_finding(f, time.time())
        except Exception as exc:
            log.debug("shodan emit upsert failed: %s", exc)

    # ── Field extraction ──────────────────────────────────────────────────────

    @staticmethod
    def _evidence(finding: dict) -> dict:
        ev = finding.get("evidence")
        if isinstance(ev, str):
            try:
                ev = json.loads(ev)
            except Exception:
                ev = {}
        return ev if isinstance(ev, dict) else {}

    @staticmethod
    def _extract_ioc(finding: dict, ev: dict) -> str:
        for key in ("indicator", "ioc", "value", "domain", "url", "ip", "remote_ip"):
            v = ev.get(key)
            if isinstance(v, str) and v:
                return v
        ik = finding.get("item_key") or ""
        if isinstance(ik, str) and ":" in ik:
            return ik.split(":", 1)[1]
        return ""

    @staticmethod
    def _extract_sha256(finding: dict, ev: dict) -> str:
        for key in ("sha256", "hash_sha256", "file_sha256"):
            v = ev.get(key)
            if isinstance(v, str) and len(v) == 64:
                return v.lower()
        return ""

    @staticmethod
    def _extract_ip(finding: dict, ev: dict) -> str:
        for key in ("remote_ip", "peer_ip", "ip", "dest_ip", "destination"):
            v = ev.get(key)
            if isinstance(v, str) and _looks_like_ip(v):
                return v
        ik = finding.get("item_key") or ""
        if isinstance(ik, str) and ":" in ik:
            cand = ik.split(":", 1)[1]
            if _looks_like_ip(cand):
                return cand
        return ""


def _looks_like_ip(s: str) -> bool:
    if not s:
        return False
    parts = s.split(".")
    if len(parts) == 4:
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except ValueError:
            return False
    return ":" in s and len(s) <= 45  # crude IPv6 sniff


def _is_private(ip: str) -> bool:
    if ip.startswith(("10.", "127.", "169.254.", "192.168.")):
        return True
    if ip.startswith("172."):
        try:
            second = int(ip.split(".")[1])
            if 16 <= second <= 31:
                return True
        except (ValueError, IndexError):
            return False
    if ip in ("::1",) or ip.startswith("fe80:") or ip.startswith("fc") or ip.startswith("fd"):
        return True
    return False
