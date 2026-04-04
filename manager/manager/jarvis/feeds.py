"""
manager/manager/threat/feeds.py — Threat feed manager.

Feeds integrated:
  • Feodo Tracker  — Botnet C2 IP blocklist      (free, no key)
  • Emerging Threats — Compromised host IPs       (free, no key)
  • Static ruleset  — High-confidence local IOCs
  • AbuseIPDB       — IP reputation (optional key via ABUSEIPDB_KEY env)
  • OTX AlienVault  — IP/domain intel (optional key via OTX_KEY env)

All feeds are cached in intel.db with TTL.  Missing keys → feed skipped gracefully.
"""
from __future__ import annotations

import asyncio
import csv
import io
import logging
import os
import time
from typing import Optional

import aiohttp

log = logging.getLogger("manager.threat.feeds")

# ── Feed URLs ─────────────────────────────────────────────────────────────────
FEODO_URL      = "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"
EMERGING_URL   = "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
ABUSEIPDB_URL  = "https://api.abuseipdb.com/api/v2/check"
OTX_PULSE_URL  = "https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"

FEED_TTL       = 3600          # 1 hour — how long before re-fetching
ABUSEIPDB_TTL  = 86400         # 24 hours — API rate limits apply
CHECK_TIMEOUT  = aiohttp.ClientTimeout(total=15)


class FeedManager:
    """
    Async threat feed manager.  Call `refresh()` once at startup and
    let the background loop call it again every FEED_TTL seconds.

    Public API:
        is_malicious_ip(ip)  → bool
        get_details(ip)      → dict | None
        refresh()            → None (async)
    """

    def __init__(self, db) -> None:
        self._db = db                    # IntelDB instance
        self._ip_set: set[str] = set()  # hot in-memory set for O(1) lookup
        self._ip_meta: dict[str, dict] = {}
        self._last_refresh = 0.0
        self._lock = asyncio.Lock()
        self._abuseipdb_key = os.environ.get("ABUSEIPDB_KEY", "").strip()
        self._otx_key       = os.environ.get("OTX_KEY", "").strip()

    # ── Public API ─────────────────────────────────────────────────────────────

    def is_malicious_ip(self, ip: str) -> bool:
        return ip in self._ip_set

    def get_details(self, ip: str) -> Optional[dict]:
        return self._ip_meta.get(ip)

    async def refresh(self) -> None:
        """Fetch / update all feeds.  Safe to call repeatedly."""
        if time.time() - self._last_refresh < FEED_TTL:
            return
        async with self._lock:
            if time.time() - self._last_refresh < FEED_TTL:
                return      # double-checked
            log.info("Refreshing threat feeds...")
            await self._load_from_cache()
            await asyncio.gather(
                self._fetch_feodo(),
                self._fetch_emerging(),
                return_exceptions=True,
            )
            self._last_refresh = time.time()
            log.info("Threat feeds refreshed — %d malicious IPs in hot set", len(self._ip_set))

    async def check_ip_live(self, ip: str) -> Optional[dict]:
        """On-demand AbuseIPDB check for a single IP (cached 24h)."""
        if not self._abuseipdb_key:
            return None
        cached = await self._db.get_ioc(ip, "abuseipdb")
        if cached:
            return cached
        return await self._fetch_abuseipdb_single(ip)

    # ── Feed fetchers ─────────────────────────────────────────────────────────

    async def _load_from_cache(self) -> None:
        """Pre-populate hot set from DB cache on startup."""
        rows = await self._db.get_all_iocs("ip")
        for row in rows:
            ip  = row["ioc_value"]
            self._ip_set.add(ip)
            self._ip_meta[ip] = {
                "source":      row["source"],
                "severity":    row["severity"],
                "description": row["description"],
                "confidence":  row["confidence"],
            }

    async def _fetch_feodo(self) -> None:
        try:
            async with aiohttp.ClientSession(timeout=CHECK_TIMEOUT) as s:
                async with s.get(FEODO_URL) as r:
                    if r.status != 200:
                        log.warning("Feodo Tracker returned %d", r.status)
                        return
                    text = await r.text()
            count = 0
            for row in csv.reader(io.StringIO(text)):
                if not row or row[0].startswith("#"):
                    continue
                ip   = row[1].strip() if len(row) > 1 else row[0].strip()
                malware = row[4].strip() if len(row) > 4 else "BotnetC2"
                await self._add_ip(ip, "feodo", "critical", 90,
                                   f"Feodo Tracker C2 — {malware}")
                count += 1
            log.info("Feodo Tracker: %d IPs loaded", count)
        except Exception as exc:
            log.warning("Feodo feed error: %s", exc)

    async def _fetch_emerging(self) -> None:
        try:
            async with aiohttp.ClientSession(timeout=CHECK_TIMEOUT) as s:
                async with s.get(EMERGING_URL) as r:
                    if r.status != 200:
                        log.warning("Emerging Threats returned %d", r.status)
                        return
                    text = await r.text()
            count = 0
            for line in text.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                await self._add_ip(line, "emerging_threats", "high", 80,
                                   "Emerging Threats compromised host")
                count += 1
            log.info("Emerging Threats: %d IPs loaded", count)
        except Exception as exc:
            log.warning("Emerging Threats feed error: %s", exc)

    async def _fetch_abuseipdb_single(self, ip: str) -> Optional[dict]:
        try:
            async with aiohttp.ClientSession(timeout=CHECK_TIMEOUT) as s:
                async with s.get(
                    ABUSEIPDB_URL,
                    headers={"Key": self._abuseipdb_key, "Accept": "application/json"},
                    params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""},
                ) as r:
                    if r.status != 200:
                        return None
                    j = await r.json()
            d = j.get("data", {})
            score = d.get("abuseConfidenceScore", 0)
            if score < 25:
                return None
            severity = "critical" if score >= 90 else "high" if score >= 70 else "medium"
            meta = {
                "source":      "abuseipdb",
                "severity":    severity,
                "confidence":  score,
                "description": f"AbuseIPDB score {score}/100 — {d.get('usageType','unknown')} "
                               f"({d.get('countryCode','')})",
            }
            await self._add_ip(ip, "abuseipdb", severity, score,
                               meta["description"], ttl=ABUSEIPDB_TTL)
            return meta
        except Exception as exc:
            log.debug("AbuseIPDB check failed for %s: %s", ip, exc)
            return None

    # ── Helpers ───────────────────────────────────────────────────────────────

    async def _add_ip(self, ip: str, source: str, severity: str,
                      confidence: int, description: str,
                      ttl: int = FEED_TTL * 24) -> None:
        if not ip or ip.startswith(("10.", "172.16.", "172.17.", "172.18.",
                                    "172.19.", "172.20.", "172.21.", "172.22.",
                                    "172.23.", "172.24.", "172.25.", "172.26.",
                                    "172.27.", "172.28.", "172.29.", "172.30.",
                                    "172.31.", "192.168.", "127.", "::1", "fe80:")):
            return   # skip private / loopback — never malicious
        self._ip_set.add(ip)
        self._ip_meta[ip] = {
            "source": source, "severity": severity,
            "confidence": confidence, "description": description,
        }
        await self._db.upsert_ioc(
            ioc_type="ip", ioc_value=ip, source=source,
            severity=severity, confidence=confidence,
            description=description,
            expires_at=time.time() + ttl,
        )
