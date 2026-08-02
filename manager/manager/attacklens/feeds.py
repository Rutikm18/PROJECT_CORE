"""
manager/manager/attacklens/feeds.py — Extended threat feed manager.

Feeds integrated:
  • Feodo Tracker      — Botnet C2 IP blocklist            (free, no key)
  • Emerging Threats   — Compromised host IPs              (free, no key)
  • URLhaus            — Malware URL domains/IPs           (free, no key)
  • ThreatFox          — IOC feed (IPs, domains, hashes)   (free, no key)
  • Spamhaus DROP      — Known bad CIDR ranges             (free, no key)
  • CISA KEV           — Known Exploited Vulnerabilities   (free, no key)
  • ransomware.live    — Active ransomware groups/victims  (free, no key)
  • HackerNews         — Security news stories             (free, no key)
  • AbuseIPDB          — IP reputation (optional key via ABUSEIPDB_KEY)
  • OTX AlienVault     — IP/domain intel (optional key via OTX_KEY)
  • GreyNoise          — Mass-scanner detection (optional key via GREYNOISE_KEY)
  • Shodan InternetDB  — Per-IP tags (free, no key, on-demand)
  • EPSS               — CVE exploit probability (free, no key)

All feeds are cached in intel.db with TTL. Missing keys → feed skipped gracefully.
"""
from __future__ import annotations

import asyncio
import csv
import ipaddress
import io
import json
import logging
import os
import re
import time
from typing import Optional

import aiohttp

log = logging.getLogger("manager.threat.feeds")

# ── Feed URLs ─────────────────────────────────────────────────────────────────
FEODO_URL            = "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"
EMERGING_URL         = "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
URLHAUS_URL          = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
THREATFOX_URL        = "https://threatfox-api.abuse.ch/api/v1/"
SPAMHAUS_DROP_URL    = "https://www.spamhaus.org/drop/drop.txt"
SPAMHAUS_EDROP_URL   = "https://www.spamhaus.org/drop/edrop.txt"
CISA_KEV_URL         = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
# Ordered KEV sources, tried in sequence until one returns a valid catalog.
# Primary is the official CISA feed; the cisagov/kev-data GitHub mirror is a
# continuously-updated fallback used when cisa.gov rate-limits / blocks / times
# out. Both expose the identical {"vulnerabilities":[...]} schema. (label, url)
KEV_SOURCES = [
    ("cisa.gov",                 CISA_KEV_URL),
    ("github:cisagov/kev-data",  "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"),
    ("github:cisagov/kev-data",  "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json"),
]
RANSOMWARE_GROUPS_URL = "https://api.ransomware.live/groups"
RANSOMWARE_VICTIMS_URL = "https://api.ransomware.live/recentvictims"
HN_NEW_STORIES_URL   = "https://hacker-news.firebaseio.com/v0/newstories.json"
HN_ITEM_URL          = "https://hacker-news.firebaseio.com/v0/item/{id}.json"
ABUSEIPDB_URL        = "https://api.abuseipdb.com/api/v2/check"
OTX_PULSE_URL        = "https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
GREYNOISE_URL        = "https://api.greynoise.io/v3/community/{ip}"
SHODAN_IDB_URL       = "https://internetdb.shodan.io/{ip}"
EPSS_API_URL         = "https://api.first.org/data/v1/epss"

FEED_TTL       = 3600          # 1 hour
CENTRAL_SYNC_TTL = 60          # manager-side snapshot refresh interval
ABUSEIPDB_TTL  = 86400         # 24 hours
NEWS_TTL       = 3600 * 6      # 6 hours
CHECK_TIMEOUT  = aiohttp.ClientTimeout(total=20)
HN_FETCH_LIMIT = 30            # max HN stories to fetch per refresh

# Security keywords for filtering HN stories
_SEC_KEYWORDS = frozenset([
    "cve", "vulnerability", "exploit", "ransomware", "breach", "malware",
    "hack", "attack", "zero-day", "zero day", "rce", "sql injection",
    "phishing", "botnet", "trojan", "backdoor", "supply chain", "apt",
    "cybersecurity", "security", "patch", "critical", "infosec",
])

_PRIVATE_RE = re.compile(
    r"^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|::1|fe80:|169\.254\.)"
)


class FeedRefreshError(RuntimeError):
    """A scheduled feed refresh failed and must be recorded as unhealthy."""


def _is_private(ip: str) -> bool:
    if _PRIVATE_RE.match(ip):
        return True
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def _normalize_ip(value: object) -> str | None:
    try:
        address = ipaddress.ip_address(str(value or "").strip().strip("[]"))
    except ValueError:
        return None
    if not address.is_global:
        return None
    return str(address)


def _normalize_domain(value: object) -> str | None:
    raw = str(value or "").strip().lower().rstrip(".")
    if not raw or "://" in raw or "/" in raw:
        return None
    try:
        domain = raw.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    if len(domain) > 253 or "." not in domain:
        return None
    labels = domain.split(".")
    if any(not label or len(label) > 63 or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
           for label in labels):
        return None
    return domain


def _parse_ip_ioc(value: object) -> str | None:
    raw = str(value or "").strip()
    direct = _normalize_ip(raw)
    if direct:
        return direct
    if raw.startswith("[") and "]:" in raw:
        return _normalize_ip(raw[1:raw.index("]:")])
    host, separator, port = raw.rpartition(":")
    if separator and port.isdigit():
        return _normalize_ip(host)
    return None


class FeedManager:
    """
    Async threat feed manager.  Call `refresh()` once at startup and
    let the background loop call `refresh_*` methods on schedule.

    Public API:
        is_malicious_ip(ip)         → bool
        get_details(ip)             → dict | None
        is_malicious_domain(domain) → bool
        is_kev_cve(cve_id)          → bool
        get_actor_info(name)        → dict | None
        get_recent_news(n)          → list[dict]
        refresh()                   → int  (async, initial load)
        refresh_feodo()             → int
        refresh_emerging()          → int
        refresh_urlhaus()           → int
        refresh_threatfox()         → int
        refresh_spamhaus()          → int
        refresh_cisa_kev()          → int
        refresh_ransomware_live()   → int
        refresh_security_news()     → int
        check_ip_live(ip)           → dict | None  (AbuseIPDB on-demand)
        check_ip_shodan(ip)         → dict | None
        check_ip_greynoise(ip)      → dict | None
        get_epss(cve_id)            → dict | None
        bulk_epss(cve_ids)          → dict[str, float]
    """

    def __init__(self, db, central_url: str = "") -> None:
        self._db = db
        self._central_url = central_url.strip().rstrip("/")
        self._ip_set:    set[str]        = set()
        self._ip_meta:   dict[str, dict] = {}
        self._domain_set:  set[str]       = set()
        self._domain_meta: dict[str, dict] = {}
        self._hash_set:  set[str]        = set()
        self._hash_meta: dict[str, dict] = {}
        self._kev_set:   set[str]        = set()   # CISA KEV CVE IDs
        self._kev_source:    str | None  = None     # which source last succeeded
        self._kev_synced_at: float       = 0.0      # epoch of last successful KEV load
        self._actor_meta: dict[str, dict] = {}      # threat actors by lowercase name
        self._news_cache: list[dict]     = []       # recent security news
        self._spamhaus_cidrs: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self._lock = asyncio.Lock()
        self._last_refresh = 0.0
        self._central_status = {
            "enabled": bool(self._central_url), "fresh": False,
            "last_success": 0.0, "last_error": "",
        }
        self._abuseipdb_key = os.environ.get("ABUSEIPDB_KEY", "").strip()
        self._otx_key       = os.environ.get("OTX_KEY", "").strip()
        self._greynoise_key = os.environ.get("GREYNOISE_KEY", "").strip()

    # ── Public sync API ───────────────────────────────────────────────────────

    def is_malicious_ip(self, ip: str) -> bool:
        if ip in self._ip_set:
            return True
        # Also check Spamhaus CIDRs
        try:
            addr = ipaddress.ip_address(ip)
            for net in self._spamhaus_cidrs:
                if addr in net:
                    return True
        except ValueError:
            pass
        return False

    def get_details(self, ip: str) -> Optional[dict]:
        return self._ip_meta.get(ip)

    def is_malicious_domain(self, domain: str) -> bool:
        return domain.lower() in self._domain_set

    def get_domain_details(self, domain: str) -> Optional[dict]:
        return self._domain_meta.get(domain.lower())

    def is_malicious_hash(self, value: str) -> bool:
        return str(value or "").lower() in self._hash_set

    def get_hash_details(self, value: str) -> Optional[dict]:
        return self._hash_meta.get(str(value or "").lower())

    def is_kev_cve(self, cve_id: str) -> bool:
        return cve_id.upper() in self._kev_set

    def get_actor_info(self, name: str) -> Optional[dict]:
        return self._actor_meta.get(name.lower())

    def get_recent_news(self, n: int = 20) -> list[dict]:
        return self._news_cache[:n]

    def get_stats(self) -> dict:
        from collections import Counter
        ip_sources  = Counter(m["source"] for m in self._ip_meta.values())
        dom_sources = Counter(m["source"] for m in self._domain_meta.values())
        return {
            "total_ips":       len(self._ip_set),
            "total_domains":   len(self._domain_set),
            "total_hashes":    len(self._hash_set),
            "kev_cves":        len(self._kev_set),
            "kev_source":      self._kev_source,
            "kev_age_sec":     int(time.time() - self._kev_synced_at) if self._kev_synced_at else None,
            "threat_actors":   len(self._actor_meta),
            "spamhaus_cidrs":  len(self._spamhaus_cidrs),
            "news_items":      len(self._news_cache),
            "ip_by_source":    dict(ip_sources),
            "domain_by_source": dict(dom_sources),
            "central": dict(self._central_status),
        }

    @property
    def central_enabled(self) -> bool:
        return bool(self._central_url)

    def export_snapshot(self) -> dict:
        """Serializable IOC/KEV snapshot for managers using the central service."""
        def _rows(meta: dict[str, dict]) -> list[dict]:
            return [{"value": value, **details} for value, details in meta.items()]

        return {
            "generated_at": time.time(),
            "ips": _rows(self._ip_meta),
            "domains": _rows(self._domain_meta),
            "hashes": _rows(self._hash_meta),
            "kev_ids": sorted(self._kev_set),
            "spamhaus_cidrs": [str(net) for net in self._spamhaus_cidrs],
            "stats": self.get_stats(),
        }

    # ── Initial load ──────────────────────────────────────────────────────────

    async def refresh(self) -> int:
        """Refresh the embedded cache or atomically pull the central snapshot."""
        ttl = CENTRAL_SYNC_TTL if self.central_enabled else FEED_TTL
        if time.time() - self._last_refresh < ttl:
            return 0
        async with self._lock:
            if time.time() - self._last_refresh < ttl:
                return 0
            log.info("Refreshing threat feeds...")
            if not self._last_refresh:
                await self._load_from_cache()
            if self.central_enabled:
                try:
                    await self._load_from_central()
                except Exception as exc:
                    self._central_status["fresh"] = False
                    self._central_status["last_error"] = str(exc)[:300]
                    log.warning("Central threat-intel snapshot refresh failed; using stale cache: %s", exc)
            else:
                await asyncio.gather(
                    self._fetch_feodo(),
                    self._fetch_emerging(),
                    return_exceptions=True,
                )
            self._last_refresh = time.time()
            log.info("Threat feeds refreshed — %d IPs, %d domains, %d KEVs, %d actors",
                     len(self._ip_set), len(self._domain_set),
                     len(self._kev_set), len(self._actor_meta))
        return len(self._ip_set)

    # ── Individual feed refresh methods (called by background loops) ──────────

    async def refresh_feodo(self) -> int:
        async with self._lock:
            count = await self._fetch_feodo()
            self._last_refresh = time.time()
            return count

    async def refresh_emerging(self) -> int:
        async with self._lock:
            count = await self._fetch_emerging()
            self._last_refresh = time.time()
            return count

    async def refresh_urlhaus(self) -> int:
        async with self._lock:
            return await self._fetch_urlhaus()

    async def refresh_threatfox(self) -> int:
        async with self._lock:
            return await self._fetch_threatfox()

    async def refresh_spamhaus(self) -> int:
        async with self._lock:
            return await self._fetch_spamhaus()

    async def refresh_cisa_kev(self) -> int:
        async with self._lock:
            return await self._fetch_cisa_kev()

    async def refresh_ransomware_live(self) -> int:
        async with self._lock:
            return await self._fetch_ransomware_live()

    async def refresh_security_news(self) -> int:
        async with self._lock:
            return await self._fetch_security_news()

    # ── On-demand lookups ─────────────────────────────────────────────────────

    async def check_ip_live(self, ip: str) -> Optional[dict]:
        """AbuseIPDB live lookup, cached 24h."""
        if not self._abuseipdb_key:
            return None
        cached = await self._db.get_ioc(ip, "abuseipdb")
        if cached:
            return cached
        return await self._fetch_abuseipdb_single(ip)

    async def check_ip_shodan(self, ip: str) -> Optional[dict]:
        """Shodan InternetDB free lookup — tags, ports, vulns."""
        if _is_private(ip):
            return None
        try:
            url = SHODAN_IDB_URL.format(ip=ip)
            async with aiohttp.ClientSession(timeout=CHECK_TIMEOUT) as s:
                async with s.get(url) as r:
                    if r.status == 404:
                        return None
                    if r.status != 200:
                        return None
                    data = await r.json()
            tags  = data.get("tags", [])
            vulns = data.get("vulns", [])
            ports = data.get("ports", [])
            if tags or vulns:
                severity = "high" if "malware" in tags or "botnet" in tags else "medium"
                desc = f"Shodan: tags={tags} vulns={vulns} ports={ports}"
                await self._add_ip(ip, "shodan", severity, 70, desc, ttl=ABUSEIPDB_TTL)
            return {"tags": tags, "vulns": vulns, "ports": ports}
        except Exception as exc:
            log.debug("Shodan InternetDB error for %s: %s", ip, exc)
            return None

    async def check_ip_greynoise(self, ip: str) -> Optional[dict]:
        """GreyNoise Community API — scanner / noise detection."""
        if not self._greynoise_key or _is_private(ip):
            return None
        try:
            url = GREYNOISE_URL.format(ip=ip)
            async with aiohttp.ClientSession(timeout=CHECK_TIMEOUT) as s:
                async with s.get(url, headers={"key": self._greynoise_key}) as r:
                    if r.status == 404:
                        return {"noise": False, "riot": False}
                    if r.status != 200:
                        return None
                    data = await r.json()
            if data.get("classification") == "malicious":
                severity = "high"
                desc = f"GreyNoise: {data.get('name','')} — malicious scanner"
                await self._add_ip(ip, "greynoise", severity, 75, desc, ttl=ABUSEIPDB_TTL)
            return data
        except Exception as exc:
            log.debug("GreyNoise error for %s: %s", ip, exc)
            return None

    async def get_epss(self, cve_id: str) -> Optional[dict]:
        """Fetch EPSS score for a single CVE."""
        cached = await self._db.get_epss(cve_id)
        if cached and (time.time() - cached.get("cached_at", 0)) < 86400 * 7:
            return cached
        if self.central_enabled:
            try:
                return await self._central_json("GET", f"/api/v1/intel/epss/{cve_id}")
            except Exception as exc:
                log.debug("Central EPSS lookup failed for %s: %s", cve_id, exc)
                return cached
        try:
            async with aiohttp.ClientSession(timeout=CHECK_TIMEOUT) as s:
                async with s.get(EPSS_API_URL, params={"cve": cve_id}) as r:
                    if r.status != 200:
                        return cached
                    data = await r.json()
            items = data.get("data", [])
            if items:
                item = items[0]
                epss_val    = float(item.get("epss", 0))
                percentile  = float(item.get("percentile", 0))
                model_date  = str(item.get("date", ""))
                await self._db.upsert_epss(cve_id, epss_val, percentile, model_date)
                return {"cve_id": cve_id, "epss": epss_val,
                        "percentile": percentile, "model_date": model_date}
        except Exception as exc:
            log.debug("EPSS lookup failed for %s: %s", cve_id, exc)
        return cached

    async def bulk_epss(self, cve_ids: list[str]) -> dict[str, float]:
        """Return EPSS scores for multiple CVEs from cache (no live fetch)."""
        if self.central_enabled and cve_ids:
            try:
                payload = await self._central_json(
                    "POST", "/api/v1/intel/epss/bulk", json_body={"cve_ids": cve_ids[:100]},
                )
                return {str(k): float(v) for k, v in (payload.get("scores") or {}).items()}
            except Exception as exc:
                log.debug("Central bulk EPSS lookup failed: %s", exc)
        return await self._db.get_epss_bulk(cve_ids)

    # ── Feed fetchers ─────────────────────────────────────────────────────────

    async def _load_from_cache(self) -> None:
        rows = await self._db.get_all_iocs("ip")
        ip_set: set[str] = set()
        ip_meta: dict[str, dict] = {}
        for row in rows:
            ip = _normalize_ip(row["ioc_value"])
            if not ip:
                continue
            ip_set.add(ip)
            ip_meta[ip] = {
                "source":      row["source"],
                "severity":    row["severity"],
                "description": row["description"],
                "confidence":  row["confidence"],
            }
        rows_dom = await self._db.get_all_iocs("domain")
        domain_set: set[str] = set()
        domain_meta: dict[str, dict] = {}
        for row in rows_dom:
            dom = _normalize_domain(row["ioc_value"])
            if not dom:
                continue
            domain_set.add(dom)
            domain_meta[dom] = {
                "source":      row["source"],
                "severity":    row["severity"],
                "description": row["description"],
                "confidence":  row["confidence"],
            }
        hash_set: set[str] = set()
        hash_meta: dict[str, dict] = {}
        for row in await self._db.get_all_iocs("hash"):
            value = row["ioc_value"].lower()
            if not re.fullmatch(r"[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64}", value):
                continue
            hash_set.add(value)
            hash_meta[value] = {
                "source": row["source"], "severity": row["severity"],
                "description": row["description"], "confidence": row["confidence"],
            }
        kev_set: set[str] = set()
        try:
            kev_rows = await self._db.list_kev(limit=10000)
            for r in kev_rows:
                kev_set.add(r["cve_id"].upper())
        except Exception:
            pass
        self._ip_set, self._ip_meta = ip_set, ip_meta
        self._domain_set, self._domain_meta = domain_set, domain_meta
        self._hash_set, self._hash_meta = hash_set, hash_meta
        self._kev_set = kev_set
        # Load threat actors
        try:
            actors = await self._db.get_threat_actors(active_only=False, limit=1000)
            for a in actors:
                self._actor_meta[a["name"].lower()] = a
        except Exception:
            pass
        try:
            self._news_cache = await self._db.get_recent_news(hours=72, limit=100)
        except Exception:
            pass

    async def _central_json(
        self, method: str, path: str, *, json_body: dict | None = None,
    ) -> dict:
        if not self._central_url:
            raise FeedRefreshError("central threat-intel URL is not configured")
        async with aiohttp.ClientSession(timeout=CHECK_TIMEOUT) as session:
            async with session.request(
                method, f"{self._central_url}{path}", json=json_body,
            ) as response:
                if response.status != 200:
                    raise FeedRefreshError(
                        f"central threat-intel {path} returned HTTP {response.status}"
                    )
                payload = await response.json(content_type=None)
        if not isinstance(payload, dict):
            raise FeedRefreshError(f"central threat-intel {path} returned invalid JSON")
        return payload

    async def _load_from_central(self) -> None:
        payload = await self._central_json("GET", "/api/v1/intel/snapshot")
        required_lists = ("ips", "domains", "hashes", "kev_ids", "spamhaus_cidrs")
        invalid = [name for name in required_lists if not isinstance(payload.get(name), list)]
        if invalid:
            raise FeedRefreshError(
                "central threat-intel snapshot missing list field(s): " + ", ".join(invalid)
            )

        def _parse(rows: object, normalizer) -> tuple[set[str], dict[str, dict]]:
            values: set[str] = set()
            metadata: dict[str, dict] = {}
            for row in rows if isinstance(rows, list) else []:
                if not isinstance(row, dict):
                    continue
                value = normalizer(row.get("value"))
                if not value:
                    continue
                values.add(value)
                metadata[value] = {
                    "source": str(row.get("source") or "central"),
                    "severity": str(row.get("severity") or "medium"),
                    "confidence": int(row.get("confidence") or 0),
                    "description": str(row.get("description") or ""),
                }
            return values, metadata

        ip_set, ip_meta = _parse(payload.get("ips"), _normalize_ip)
        domain_set, domain_meta = _parse(payload.get("domains"), _normalize_domain)
        hash_set, hash_meta = _parse(
            payload.get("hashes"),
            lambda value: str(value or "").lower().strip()
            if re.fullmatch(r"[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", str(value or "").strip())
            else None,
        )
        kev_set = {
            str(cve).upper() for cve in (payload.get("kev_ids") or []) if cve
        }
        cidrs: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        for raw in payload.get("spamhaus_cidrs") or []:
            try:
                cidrs.append(ipaddress.ip_network(str(raw), strict=False))
            except ValueError:
                continue

        # Swap only after the complete response validates. A failed refresh keeps
        # the previous snapshot intact instead of converting dependency failure
        # into a false "clean" verdict.
        self._ip_set, self._ip_meta = ip_set, ip_meta
        self._domain_set, self._domain_meta = domain_set, domain_meta
        self._hash_set, self._hash_meta = hash_set, hash_meta
        self._kev_set = kev_set
        self._spamhaus_cidrs = cidrs
        now = time.time()
        self._kev_source = "central"
        self._kev_synced_at = float(payload.get("generated_at") or now)
        self._central_status.update({
            "fresh": True, "last_success": now, "last_error": "",
            "snapshot_generated_at": float(payload.get("generated_at") or now),
        })
    async def _fetch_feodo(self) -> int:
        try:
            async with aiohttp.ClientSession(timeout=CHECK_TIMEOUT) as s:
                async with s.get(FEODO_URL) as r:
                    if r.status != 200:
                        raise FeedRefreshError(f"Feodo Tracker returned HTTP {r.status}")
                    text = await r.text()
            count = 0
            for row in csv.reader(io.StringIO(text)):
                if not row or row[0].startswith("#"):
                    continue
                ip      = row[1].strip() if len(row) > 1 else row[0].strip()
                malware = row[4].strip() if len(row) > 4 else "BotnetC2"
                count += int(await self._add_ip(
                    ip, "feodo", "critical", 90, f"Feodo C2 — {malware}"
                ))
            log.info("Feodo Tracker: %d IPs loaded", count)
            return count
        except Exception as exc:
            log.warning("Feodo feed error: %s", exc)
            raise FeedRefreshError(f"Feodo refresh failed: {exc}") from exc

    async def _fetch_emerging(self) -> int:
        try:
            async with aiohttp.ClientSession(timeout=CHECK_TIMEOUT) as s:
                async with s.get(EMERGING_URL) as r:
                    if r.status != 200:
                        raise FeedRefreshError(f"Emerging Threats returned HTTP {r.status}")
                    text = await r.text()
            count = 0
            for line in text.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                count += int(await self._add_ip(
                    line, "emerging_threats", "high", 80,
                    "Emerging Threats compromised host",
                ))
            log.info("Emerging Threats: %d IPs loaded", count)
            return count
        except Exception as exc:
            log.warning("Emerging Threats feed error: %s", exc)
            raise FeedRefreshError(f"Emerging Threats refresh failed: {exc}") from exc

    async def _fetch_urlhaus(self) -> int:
        try:
            async with aiohttp.ClientSession(timeout=CHECK_TIMEOUT) as s:
                async with s.post(URLHAUS_URL, data={"limit": 1000}) as r:
                    if r.status != 200:
                        raise FeedRefreshError(f"URLhaus returned HTTP {r.status}")
                    j = await r.json(content_type=None)
            count = 0
            for item in j.get("urls", []):
                if item.get("url_status") not in ("online", "unknown"):
                    continue
                host   = str(item.get("host", "") or "").strip()
                threat = str(item.get("threat", "malware") or "malware")
                if not host:
                    continue
                if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
                    accepted = await self._add_ip(host, "urlhaus", "high", 80, f"URLhaus {threat}")
                else:
                    accepted = await self._add_domain(host, "urlhaus", "high", 80, f"URLhaus {threat}")
                count += int(accepted)
            log.info("URLhaus: %d entries loaded", count)
            return count
        except Exception as exc:
            log.warning("URLhaus feed error: %s", exc)
            raise FeedRefreshError(f"URLhaus refresh failed: {exc}") from exc

    async def _fetch_threatfox(self) -> int:
        """ThreatFox recent IOCs — IPs and domains with malware family context."""
        try:
            payload = {"query": "get_iocs", "days": 1}
            async with aiohttp.ClientSession(timeout=CHECK_TIMEOUT) as s:
                async with s.post(THREATFOX_URL, json=payload) as r:
                    if r.status != 200:
                        raise FeedRefreshError(f"ThreatFox returned HTTP {r.status}")
                    j = await r.json(content_type=None)
            count = 0
            for ioc in j.get("data", []) or []:
                ioc_type  = str(ioc.get("ioc_type", "") or "")
                ioc_value = str(ioc.get("ioc", "") or "").strip()
                malware   = str(ioc.get("malware", "unknown") or "unknown")
                confidence = int(ioc.get("confidence_level", 50))
                threat_type = str(ioc.get("threat_type", "") or "")
                desc = f"ThreatFox {malware} ({threat_type})"
                severity = "critical" if confidence >= 90 else "high" if confidence >= 70 else "medium"
                if ioc_type in ("ip:port", "ip"):
                    ip_value = _parse_ip_ioc(ioc_value)
                    count += int(bool(ip_value) and await self._add_ip(
                        ip_value, "threatfox", severity, confidence, desc
                    ))
                elif ioc_type == "domain":
                    count += int(await self._add_domain(
                        ioc_value, "threatfox", severity, confidence, desc
                    ))
                elif ioc_type in ("sha256_hash", "md5_hash", "sha1_hash", "hash"):
                    count += int(await self._add_hash(
                        ioc_value, "threatfox", severity, confidence, desc
                    ))
                elif ioc_type == "url":
                    try:
                        from urllib.parse import urlparse
                        host = urlparse(ioc_value).hostname or ""
                        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
                            accepted = await self._add_ip(host, "threatfox", severity, confidence, desc)
                        elif host:
                            accepted = await self._add_domain(host, "threatfox", severity, confidence, desc)
                        else:
                            accepted = False
                        count += int(accepted)
                    except Exception:
                        pass
            log.info("ThreatFox: %d IOCs loaded", count)
            return count
        except Exception as exc:
            log.warning("ThreatFox feed error: %s", exc)
            raise FeedRefreshError(f"ThreatFox refresh failed: {exc}") from exc

    async def _fetch_spamhaus(self) -> int:
        """Spamhaus DROP + EDROP — known bad CIDR ranges stored for in-memory lookup."""
        count = 0
        cidrs: list[ipaddress.IPv4Network] = []
        for url, label in [(SPAMHAUS_DROP_URL, "DROP"), (SPAMHAUS_EDROP_URL, "EDROP")]:
            try:
                async with aiohttp.ClientSession(timeout=CHECK_TIMEOUT) as s:
                    async with s.get(url) as r:
                        if r.status != 200:
                            log.warning("Spamhaus %s returned %d", label, r.status)
                            continue
                        text = await r.text()
                for line in text.splitlines():
                    line = line.strip()
                    if not line or line.startswith(";"):
                        continue
                    cidr_part = line.split(";")[0].strip()
                    try:
                        net = ipaddress.IPv4Network(cidr_part, strict=False)
                        cidrs.append(net)
                        count += 1
                    except ValueError:
                        continue
            except Exception as exc:
                log.warning("Spamhaus %s feed error: %s", label, exc)
        self._spamhaus_cidrs = cidrs
        if count == 0:
            raise FeedRefreshError("Spamhaus DROP and EDROP both returned no usable CIDRs")
        log.info("Spamhaus DROP+EDROP: %d CIDR ranges loaded", count)
        return count

    async def _fetch_cisa_kev(self) -> int:
        """CISA Known Exploited Vulnerabilities catalog.

        Resilient multi-source load: tries the official CISA feed first, then the
        cisagov/kev-data GitHub mirror(s). The first source that returns a valid,
        non-empty catalog wins; the rest are skipped. On total failure the
        in-memory set and DB cache from the previous successful load are kept
        (we never wipe KEV state just because every upstream is briefly down).
        """
        last_exc: Exception | None = None
        for label, url in KEV_SOURCES:
            try:
                async with aiohttp.ClientSession(timeout=CHECK_TIMEOUT) as s:
                    async with s.get(url, headers={"User-Agent": "AttackLens/1.0"}) as r:
                        if r.status != 200:
                            log.warning("KEV source %s returned %d", label, r.status)
                            continue
                        j = await r.json(content_type=None)

                vulns = j.get("vulnerabilities", []) if isinstance(j, dict) else []
                if not vulns:
                    log.warning("KEV source %s returned no vulnerabilities", label)
                    continue

                count = 0
                for vuln in vulns:
                    cve_id = str(vuln.get("cveID", "") or "").upper().strip()
                    if not cve_id:
                        continue
                    self._kev_set.add(cve_id)
                    await self._db.upsert_cisa_kev(cve_id, vuln)
                    count += 1

                if count:
                    self._kev_source    = label
                    self._kev_synced_at = time.time()
                    log.info("CISA KEV: %d vulnerabilities loaded from %s", count, label)
                    return count
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                last_exc = exc
                log.warning("KEV source %s failed: %s — trying next", label, exc)
                continue

        log.error("All KEV sources failed (last error: %s) — keeping cached catalog (%d CVEs)",
                  last_exc, len(self._kev_set))
        raise FeedRefreshError("all CISA KEV sources failed") from last_exc

    async def _fetch_ransomware_live(self) -> int:
        """ransomware.live — active groups and recent victims."""
        count = 0
        # Fetch active groups
        try:
            async with aiohttp.ClientSession(timeout=CHECK_TIMEOUT) as s:
                async with s.get(RANSOMWARE_GROUPS_URL,
                                 headers={"User-Agent": "AttackLens/1.0"}) as r:
                    if r.status == 200:
                        groups = await r.json(content_type=None)
            for grp in groups if isinstance(groups, list) else []:
                name = str(grp.get("name", "") or "").strip()
                if not name:
                    continue
                data = {
                    "description": grp.get("description", ""),
                    "aliases":     grp.get("aliases", []),
                    "countries":   grp.get("locations", []) or grp.get("countries", []),
                    "active":      True,
                    "first_seen":  str(grp.get("first_seen", "") or ""),
                    "last_active": str(grp.get("last_active", "") or ""),
                }
                self._actor_meta[name.lower()] = {"name": name, **data}
                await self._db.upsert_threat_actor(name, "ransomware.live", data)
                count += 1
        except Exception as exc:
            log.warning("ransomware.live groups error: %s", exc)

        # Fetch recent victims to extract IOC context (domain names)
        try:
            async with aiohttp.ClientSession(timeout=CHECK_TIMEOUT) as s:
                async with s.get(RANSOMWARE_VICTIMS_URL,
                                 headers={"User-Agent": "AttackLens/1.0"}) as r:
                    if r.status == 200:
                        victims = await r.json(content_type=None)
            for v in (victims if isinstance(victims, list) else [])[:200]:
                website = str(v.get("website", "") or "").strip().lower()
                if website and "." in website:
                    # Extract hostname only, strip protocol
                    website = website.replace("https://", "").replace("http://", "").split("/")[0]
                    group_name = str(v.get("group_name", "ransomware") or "ransomware")
                    await self._add_domain(website, "ransomware.live", "high", 85,
                                           f"Ransomware victim — group: {group_name}")
        except Exception as exc:
            log.warning("ransomware.live victims error: %s", exc)

        log.info("ransomware.live: %d groups loaded", count)
        return count

    async def _fetch_security_news(self) -> int:
        """HackerNews — fetch top new stories filtered by security keywords."""
        try:
            async with aiohttp.ClientSession(timeout=CHECK_TIMEOUT) as s:
                async with s.get(HN_NEW_STORIES_URL) as r:
                    if r.status != 200:
                        return 0
                    story_ids = await r.json()

            security_stories: list[dict] = []
            for story_id in story_ids[:200]:
                if len(security_stories) >= HN_FETCH_LIMIT:
                    break
                try:
                    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=5)) as s:
                        async with s.get(HN_ITEM_URL.format(id=story_id)) as r:
                            if r.status != 200:
                                continue
                            item = await r.json()
                    title = str(item.get("title", "") or "").lower()
                    text  = str(item.get("text", "") or "").lower()
                    if not any(kw in title or kw in text for kw in _SEC_KEYWORDS):
                        continue
                    cve_refs = re.findall(r"cve-\d{4}-\d+", title + " " + text, re.IGNORECASE)
                    cve_refs = list({c.upper() for c in cve_refs})
                    keywords = [kw for kw in _SEC_KEYWORDS if kw in title]
                    severity = "high" if cve_refs else ("medium" if any(
                        w in title for w in ("zero-day", "zero day", "rce", "critical", "exploit")
                    ) else "info")
                    story = {
                        "title":       item.get("title", ""),
                        "url":         item.get("url", f"https://news.ycombinator.com/item?id={story_id}"),
                        "summary":     item.get("text", "")[:500],
                        "keywords":    keywords,
                        "cve_refs":    cve_refs,
                        "severity":    severity,
                        "published_at": float(item.get("time", time.time())),
                    }
                    security_stories.append(story)
                    await self._db.upsert_news("hackernews", str(story_id), story)
                except Exception:
                    continue

            self._news_cache = security_stories
            log.info("HackerNews security: %d stories fetched", len(security_stories))
            return len(security_stories)
        except Exception as exc:
            log.warning("HackerNews feed error: %s", exc)
            return 0

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
            d     = j.get("data", {})
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
                      ttl: int = FEED_TTL * 24) -> bool:
        ip = _normalize_ip(ip)
        if not ip:
            return False
        self._ip_set.add(ip)
        self._ip_meta[ip] = {
            "source":      source,
            "severity":    severity,
            "confidence":  confidence,
            "description": description,
        }
        await self._db.upsert_ioc(
            ioc_type="ip", ioc_value=ip, source=source,
            severity=severity, confidence=confidence,
            description=description,
            expires_at=time.time() + ttl,
        )
        return True

    async def _add_domain(self, domain: str, source: str, severity: str,
                          confidence: int, description: str,
                          ttl: int = FEED_TTL * 24) -> bool:
        domain = _normalize_domain(domain)
        if not domain:
            return False
        self._domain_set.add(domain)
        self._domain_meta[domain] = {
            "source":      source,
            "severity":    severity,
            "confidence":  confidence,
            "description": description,
        }
        await self._db.upsert_ioc(
            ioc_type="domain", ioc_value=domain, source=source,
            severity=severity, confidence=confidence,
            description=description,
            expires_at=time.time() + ttl,
        )
        return True

    async def _add_hash(self, value: str, source: str, severity: str,
                        confidence: int, description: str,
                        ttl: int = FEED_TTL * 24) -> bool:
        value = value.lower().strip()
        if not re.fullmatch(r"[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64}", value):
            return False
        self._hash_set.add(value)
        self._hash_meta[value] = {
            "source": source, "severity": severity,
            "confidence": confidence, "description": description,
        }
        await self._db.upsert_ioc(
            ioc_type="hash", ioc_value=value, source=source,
            severity=severity, confidence=confidence,
            description=description, expires_at=time.time() + ttl,
        )
        return True
