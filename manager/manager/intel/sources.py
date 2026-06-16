"""
manager/manager/intel/sources.py — Threat-intel source adapters.

Each adapter wraps a CircuitBreaker so one flaky source cannot cascade
into the rest of the pipeline.  Adapters never raise — they return empty
data and let the caller decide whether to proceed with partial results.

Sources:
  ExploitDBSource   — offline CSV (GitLab mirror, refreshed weekly)
  MetasploitSource  — CVE→module JSON (GitHub, refreshed weekly)
  PocGithubSource   — poc-in-github.motikan2010.net API (on-demand, cached 24h)
  OsvSource         — api.osv.dev (on-demand, cached 24h)
  GhsaSource        — api.github.com/advisories (on-demand, cached 6h)
  CveCirclSource    — cve.circl.lu NVD mirror (NVD fallback, cached 6h)
"""
from __future__ import annotations

import asyncio
import csv
import io
import json
import logging
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

import aiohttp

log = logging.getLogger("manager.intel.sources")

# ── Constants ─────────────────────────────────────────────────────────────────

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)

_EXPLOITDB_URLS = [
    "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv",
    "https://raw.githubusercontent.com/offensive-security/exploitdb/master/files_exploits.csv",
]
_MSF_URLS = [
    "https://raw.githubusercontent.com/nicowillis/metasploit-cve-list/main/cve_module_list.json",
    # fallback: extract CVEs from modules metadata text index
    "https://raw.githubusercontent.com/hahwul/metabigor/master/static/metasploit.json",
]
_POC_GITHUB_URL = "https://poc-in-github.motikan2010.net/api/v1/"
_OSV_VULN_URL   = "https://api.osv.dev/v1/vulns/{osv_id}"
_OSV_QUERY_URL  = "https://api.osv.dev/v1/query"
_GHSA_URL       = "https://api.github.com/advisories"
_CIRCL_URL      = "https://cve.circl.lu/api/cve/{cve_id}"

_TIMEOUT        = aiohttp.ClientTimeout(total=20)
_LONG_TIMEOUT   = aiohttp.ClientTimeout(total=90)   # for large file downloads


# ── Circuit Breaker ───────────────────────────────────────────────────────────

class _CBState(Enum):
    CLOSED    = "closed"
    OPEN      = "open"
    HALF_OPEN = "half_open"


@dataclass
class CircuitBreaker:
    """
    Three-state circuit breaker.
    CLOSED → normal.  After failure_threshold failures → OPEN (reject requests).
    After reset_timeout seconds → HALF_OPEN (allow one probe).
    Successful probe → CLOSED.  Failed probe → OPEN again.
    """
    name:              str
    failure_threshold: int   = 3
    reset_timeout:     float = 300.0

    _failures:  int      = field(default=0,              init=False, repr=False)
    _state:     _CBState = field(default=_CBState.CLOSED, init=False, repr=False)
    _opened_at: float    = field(default=0.0,            init=False, repr=False)

    def allow(self) -> bool:
        if self._state == _CBState.CLOSED:
            return True
        if self._state == _CBState.OPEN:
            if time.time() - self._opened_at >= self.reset_timeout:
                self._state = _CBState.HALF_OPEN
                log.info("CB[%s]: half-open probe", self.name)
                return True
            return False
        return True  # HALF_OPEN: allow one probe

    def on_success(self) -> None:
        if self._state != _CBState.CLOSED:
            log.info("CB[%s]: recovered → closed", self.name)
        self._failures = 0
        self._state    = _CBState.CLOSED

    def on_failure(self, exc: BaseException) -> None:
        self._failures += 1
        if self._state == _CBState.HALF_OPEN or self._failures >= self.failure_threshold:
            self._state     = _CBState.OPEN
            self._opened_at = time.time()
            log.warning("CB[%s]: open after %d failures (%s)", self.name, self._failures, exc)

    @property
    def state(self) -> str:
        return self._state.value

    def to_dict(self) -> dict:
        return {
            "state":    self.state,
            "failures": self._failures,
            "opened_at": self._opened_at or None,
        }


# ── Base helper ───────────────────────────────────────────────────────────────

async def _get(url: str, timeout: aiohttp.ClientTimeout = _TIMEOUT,
               headers: Optional[dict] = None, params: Optional[dict] = None) -> Any:
    """GET request, returns parsed JSON or raises."""
    async with aiohttp.ClientSession(timeout=timeout) as s:
        async with s.get(url, headers=headers, params=params) as r:
            if r.status == 404:
                return None
            if r.status == 429:
                raise RuntimeError(f"Rate-limited by {url}")
            if r.status == 403:
                raise RuntimeError(f"Forbidden {url}")
            if r.status != 200:
                raise RuntimeError(f"HTTP {r.status} from {url}")
            return await r.json(content_type=None)


# ── ExploitDB ─────────────────────────────────────────────────────────────────

class ExploitDBSource:
    """
    Downloads the ExploitDB CSV file (~35 MB) from the GitLab mirror
    and builds an in-memory reverse index: CVE-ID → [exploit_row, ...].

    Refresh TTL: 7 days.  Falls back to stale index if download fails.
    """
    TTL = 86400 * 7

    def __init__(self) -> None:
        self._cb       = CircuitBreaker("exploitdb", failure_threshold=3, reset_timeout=600)
        self._index:   dict[str, list[dict]] = {}
        self._loaded_at: float = 0.0
        self._lock     = asyncio.Lock()

    async def ensure_loaded(self) -> bool:
        if time.time() - self._loaded_at < self.TTL and self._index:
            return True
        async with self._lock:
            if time.time() - self._loaded_at < self.TTL and self._index:
                return True
            if not self._cb.allow():
                return bool(self._index)
            try:
                await self._download()
                return True
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                self._cb.on_failure(exc)
                log.warning("ExploitDB load failed: %s", exc)
                return bool(self._index)

    async def lookup(self, cve_id: str) -> list[dict]:
        if not await self.ensure_loaded():
            return []
        return list(self._index.get(cve_id.upper(), []))

    def has_exploit(self, cve_id: str) -> bool:
        return bool(self._index.get(cve_id.upper()))

    def stats(self) -> dict:
        return {"total_cves": len(self._index), "loaded_at": self._loaded_at,
                "circuit": self._cb.to_dict()}

    async def _download(self) -> None:
        for url in _EXPLOITDB_URLS:
            try:
                async with aiohttp.ClientSession(timeout=_LONG_TIMEOUT) as s:
                    async with s.get(url) as r:
                        if r.status != 200:
                            continue
                        text = await r.text(encoding="utf-8", errors="replace")

                index: dict[str, list[dict]] = {}
                reader = csv.DictReader(io.StringIO(text))
                for row in reader:
                    codes = row.get("codes", "") or ""
                    for part in re.split(r"[;,\s]+", codes):
                        part = part.strip().upper()
                        if CVE_RE.match(part):
                            index.setdefault(part, []).append({
                                "edb_id":      (row.get("id") or "").strip(),
                                "description": (row.get("description") or "")[:200],
                                "verified":    (row.get("verified") or "0").strip() == "1",
                                "type":        (row.get("type") or "").strip(),
                                "platform":    (row.get("platform") or "").strip(),
                                "date":        (row.get("date_published") or row.get("date_added") or "").strip(),
                            })

                self._index    = index
                self._loaded_at = time.time()
                self._cb.on_success()
                log.info("ExploitDB: %d CVEs indexed from %s", len(index), url)
                return
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                log.debug("ExploitDB URL %s failed: %s", url, exc)
        raise RuntimeError("All ExploitDB URLs failed")


# ── Metasploit ────────────────────────────────────────────────────────────────

class MetasploitSource:
    """
    Downloads a curated CVE→Metasploit module mapping JSON from GitHub.
    Falls back to extracting CVE patterns from raw JSON text.
    Refresh TTL: 7 days.
    """
    TTL = 86400 * 7

    def __init__(self) -> None:
        self._cb      = CircuitBreaker("metasploit", failure_threshold=3, reset_timeout=600)
        self._cves:   set[str] = set()
        self._loaded_at: float = 0.0
        self._lock    = asyncio.Lock()

    async def ensure_loaded(self) -> bool:
        if time.time() - self._loaded_at < self.TTL and self._cves:
            return True
        async with self._lock:
            if time.time() - self._loaded_at < self.TTL and self._cves:
                return True
            if not self._cb.allow():
                return bool(self._cves)
            try:
                await self._download()
                return True
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                self._cb.on_failure(exc)
                log.warning("Metasploit load failed: %s", exc)
                return bool(self._cves)

    async def has_module(self, cve_id: str) -> bool:
        if not await self.ensure_loaded():
            return False
        return cve_id.upper() in self._cves

    def stats(self) -> dict:
        return {"total_cves": len(self._cves), "loaded_at": self._loaded_at,
                "circuit": self._cb.to_dict()}

    async def _download(self) -> None:
        for url in _MSF_URLS:
            try:
                async with aiohttp.ClientSession(timeout=_LONG_TIMEOUT) as s:
                    async with s.get(url) as r:
                        if r.status != 200:
                            continue
                        raw_text = await r.text(encoding="utf-8", errors="replace")

                # Extract all CVE patterns from raw text (handles any JSON shape)
                cves: set[str] = {m.group(0).upper() for m in CVE_RE.finditer(raw_text)}

                # Also parse structured data if possible
                try:
                    data = json.loads(raw_text)
                    if isinstance(data, dict):
                        for key in data:
                            if CVE_RE.match(key):
                                cves.add(key.upper())
                    elif isinstance(data, list):
                        for item in data:
                            if isinstance(item, str) and CVE_RE.match(item):
                                cves.add(item.upper())
                except json.JSONDecodeError:
                    pass

                if cves:
                    self._cves      = cves
                    self._loaded_at = time.time()
                    self._cb.on_success()
                    log.info("Metasploit: %d CVEs with modules (url=%s)", len(cves), url)
                    return
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                log.debug("Metasploit URL %s failed: %s", url, exc)
        raise RuntimeError("All Metasploit URLs failed")


# ── PoC-in-GitHub ─────────────────────────────────────────────────────────────

class PocGithubSource:
    """
    On-demand lookup via poc-in-github.motikan2010.net.
    Free, no auth.  Results cached in-memory 24h.
    """
    TTL = 86400

    def __init__(self) -> None:
        self._cb    = CircuitBreaker("poc_github", failure_threshold=3, reset_timeout=300)
        self._cache: dict[str, tuple[float, list[dict]]] = {}

    async def lookup(self, cve_id: str) -> list[dict]:
        cid = cve_id.upper()
        entry = self._cache.get(cid)
        if entry and time.time() - entry[0] < self.TTL:
            return entry[1]
        if not self._cb.allow():
            return entry[1] if entry else []
        try:
            pocs = await self._fetch(cid)
            self._cache[cid] = (time.time(), pocs)
            self._cb.on_success()
            return pocs
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self._cb.on_failure(exc)
            log.debug("PocGithub failed %s: %s", cve_id, exc)
            return entry[1] if entry else []

    def stats(self) -> dict:
        return {"cached": len(self._cache), "circuit": self._cb.to_dict()}

    async def _fetch(self, cve_id: str) -> list[dict]:
        data = await _get(_POC_GITHUB_URL, params={"cve_id": cve_id})
        if data is None:
            return []
        items = (data.get("pocs") or []) if isinstance(data, dict) else (data if isinstance(data, list) else [])
        return [
            {
                "url":        str(i.get("html_url") or i.get("url") or ""),
                "stars":      int(i.get("stargazers_count") or 0),
                "created_at": str(i.get("created_at") or ""),
                "full_name":  str(i.get("full_name") or ""),
            }
            for i in items if isinstance(i, dict)
        ]


# ── OSV ───────────────────────────────────────────────────────────────────────

class OsvSource:
    """
    Google Open Source Vulnerabilities API.
    Covers PyPI, npm, Maven, Go, Cargo, Hex, RubyGems, crates.io.
    Free, no auth.  Accepts CVE IDs directly.
    """
    TTL = 86400

    def __init__(self) -> None:
        self._cb    = CircuitBreaker("osv", failure_threshold=3, reset_timeout=300)
        self._cache: dict[str, tuple[float, Optional[dict]]] = {}

    async def lookup_cve(self, cve_id: str) -> Optional[dict]:
        cid = cve_id.upper()
        entry = self._cache.get(cid)
        if entry and time.time() - entry[0] < self.TTL:
            return entry[1]
        if not self._cb.allow():
            return entry[1] if entry else None
        try:
            result = await self._fetch(cid)
            self._cache[cid] = (time.time(), result)
            self._cb.on_success()
            return result
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self._cb.on_failure(exc)
            log.debug("OSV failed %s: %s", cve_id, exc)
            return entry[1] if entry else None

    async def lookup_package(self, name: str, version: str, ecosystem: str) -> list[dict]:
        key = f"{ecosystem}:{name}:{version}"
        entry_p = self._cache.get(key)
        if entry_p and time.time() - entry_p[0] < self.TTL:
            return entry_p[1] or []  # type: ignore[return-value]
        if not self._cb.allow():
            return (entry_p[1] or []) if entry_p else []  # type: ignore[return-value]
        try:
            payload = {"version": version, "package": {"name": name, "ecosystem": ecosystem}}
            async with aiohttp.ClientSession(timeout=_TIMEOUT) as s:
                async with s.post(_OSV_QUERY_URL, json=payload) as r:
                    if r.status != 200:
                        raise RuntimeError(f"HTTP {r.status}")
                    data = await r.json()
            vulns = [self._parse(v) for v in (data.get("vulns") or [])]
            self._cache[key] = (time.time(), vulns)  # type: ignore[assignment]
            self._cb.on_success()
            return vulns
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self._cb.on_failure(exc)
            log.debug("OSV package failed %s %s: %s", name, version, exc)
            return (entry_p[1] or []) if entry_p else []  # type: ignore[return-value]

    def stats(self) -> dict:
        return {"cached": len(self._cache), "circuit": self._cb.to_dict()}

    async def _fetch(self, cve_id: str) -> Optional[dict]:
        data = await _get(_OSV_VULN_URL.format(osv_id=cve_id))
        return self._parse(data) if data else None

    def _parse(self, v: dict) -> dict:
        if not isinstance(v, dict):
            return {}
        cvss_score = None
        for sev in (v.get("severity") or []):
            if not isinstance(sev, dict):
                continue
            try:
                val = float(sev.get("score", "0"))
                cvss_score = val
                break
            except (ValueError, TypeError):
                pass
        affected = [
            {"name": (p.get("package") or {}).get("name", ""),
             "ecosystem": (p.get("package") or {}).get("ecosystem", "")}
            for p in (v.get("affected") or [])[:5]
            if isinstance(p, dict)
        ]
        aliases = [a for a in (v.get("aliases") or []) if isinstance(a, str) and CVE_RE.match(a)]
        return {
            "osv_id":           v.get("id", ""),
            "summary":          (v.get("summary") or "")[:300],
            "cvss_score":       cvss_score,
            "aliases":          aliases,
            "affected_packages": affected,
            "published":        v.get("published", ""),
        }


# ── GHSA ──────────────────────────────────────────────────────────────────────

class GhsaSource:
    """
    GitHub Security Advisories — high-quality data for npm/PyPI/Go/Maven.
    Unauthenticated: 60 req/h.  Set GITHUB_TOKEN for 5000 req/h.
    """
    TTL = 3600 * 6

    def __init__(self, token: str = "") -> None:
        self._cb    = CircuitBreaker("ghsa", failure_threshold=3, reset_timeout=600)
        self._token = token
        self._cache: dict[str, tuple[float, list[dict]]] = {}
        self._hdrs  = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            **({"Authorization": f"Bearer {token}"} if token else {}),
        }

    async def lookup(self, cve_id: str) -> list[dict]:
        cid = cve_id.upper()
        entry = self._cache.get(cid)
        if entry and time.time() - entry[0] < self.TTL:
            return entry[1]
        if not self._cb.allow():
            return entry[1] if entry else []
        try:
            results = await self._fetch(cid)
            self._cache[cid] = (time.time(), results)
            self._cb.on_success()
            return results
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self._cb.on_failure(exc)
            log.debug("GHSA failed %s: %s", cve_id, exc)
            return entry[1] if entry else []

    def stats(self) -> dict:
        return {"cached": len(self._cache), "circuit": self._cb.to_dict()}

    async def _fetch(self, cve_id: str) -> list[dict]:
        data = await _get(_GHSA_URL, headers=self._hdrs, params={"cve_id": cve_id})
        if not isinstance(data, list):
            return []
        return [
            {
                "ghsa_id":   a.get("ghsa_id", ""),
                "summary":   (a.get("summary") or "")[:300],
                "severity":  (a.get("severity") or "unknown").lower(),
                "cvss_score": (a.get("cvss") or {}).get("score") if isinstance(a.get("cvss"), dict) else None,
                "epss":      a.get("epss"),
                "kev":       a.get("cisaExploitAdd") is not None,
                "ecosystems": [
                    (v.get("package") or {}).get("ecosystem", "")
                    for v in (a.get("vulnerabilities") or [])[:3]
                    if isinstance(v, dict)
                ],
                "url":       a.get("html_url", ""),
                "published": a.get("published_at", ""),
            }
            for a in data if isinstance(a, dict)
        ]


# ── CIRCL CVE (NVD fallback) ──────────────────────────────────────────────────

class CveCirclSource:
    """
    cve.circl.lu — NVD mirror with extra reference enrichment.
    Used as a fallback when NVD rate-limits fire.  Free, no auth.
    """
    TTL = 3600 * 6

    def __init__(self) -> None:
        self._cb    = CircuitBreaker("circl", failure_threshold=3, reset_timeout=300)
        self._cache: dict[str, tuple[float, Optional[dict]]] = {}

    async def lookup(self, cve_id: str) -> Optional[dict]:
        cid = cve_id.upper()
        entry = self._cache.get(cid)
        if entry and time.time() - entry[0] < self.TTL:
            return entry[1]
        if not self._cb.allow():
            return entry[1] if entry else None
        try:
            result = await self._fetch(cid)
            self._cache[cid] = (time.time(), result)
            self._cb.on_success()
            return result
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self._cb.on_failure(exc)
            log.debug("CIRCL failed %s: %s", cve_id, exc)
            return entry[1] if entry else None

    def stats(self) -> dict:
        return {"cached": len(self._cache), "circuit": self._cb.to_dict()}

    async def _fetch(self, cve_id: str) -> Optional[dict]:
        data = await _get(_CIRCL_URL.format(cve_id=cve_id))
        if not data:
            return None
        cvss = None
        for key in ("cvss3", "cvss"):
            try:
                cvss = float(data[key]); break
            except (KeyError, TypeError, ValueError):
                pass
        refs = []
        for r in (data.get("references") or [])[:5]:
            refs.append(r if isinstance(r, str) else (r.get("url", "") if isinstance(r, dict) else ""))
        return {
            "cve_id":     cve_id,
            "cvss_score": cvss,
            "summary":    (data.get("summary") or "")[:500],
            "references": [r for r in refs if r],
            "published":  data.get("Published", ""),
            "modified":   data.get("Modified", ""),
        }
