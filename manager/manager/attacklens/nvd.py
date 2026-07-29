"""
manager/manager/threat/nvd.py — NVD CVE database integration.

Uses the NVD REST API v2 (no auth key required for basic use).
Results are cached in intel.db for 24 hours to respect rate limits.

API reference: https://nvd.nist.gov/developers/vulnerabilities
Rate limit (no key): 5 requests / 30 seconds.

Accuracy notes:
  • NVD keywordSearch is fuzzy — versionStart/versionEnd query params are only
    honoured with virtualMatchString (CPE). For keyword searches we post-filter
    using CPE version ranges from each CVE's configurations block.
  • Minimum keyword length is enforced to suppress absurd matches (e.g. "go"
    matching every Golang CVE).
  • _parse_cve now extracts references and per-CPE version ranges so downstream
    intel enrichment (KEV/exploit/version filtering) works.
"""
from __future__ import annotations

import asyncio
import logging
import re
import time
from datetime import datetime, timedelta, timezone
from typing import Optional

import aiohttp

try:
    from packaging.version import InvalidVersion, Version
except Exception:  # pragma: no cover — packaging is a stdlib-adjacent dep
    Version = None         # type: ignore[assignment]
    InvalidVersion = Exception  # type: ignore[assignment]

log = logging.getLogger("manager.threat.nvd")

NVD_API_URL    = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CVE_TTL        = 86400        # 24 hours
REQUEST_DELAY  = 7.0          # seconds between NVD requests (rate limit)
MAX_RESULTS    = 10           # max CVEs per package lookup
SYNC_PAGE_SIZE = 200          # bounded page size for continuous modified sync
TIMEOUT        = aiohttp.ClientTimeout(total=20)

# Suppress lookups for absurdly short / common keywords that produce mostly noise
MIN_KEYWORD_LEN = 4
COMMON_NOISY_KEYWORDS = frozenset({
    "git", "go", "vi", "lib", "ssh", "tls", "ssl", "core", "util", "base",
    "test", "demo", "data", "main", "tool", "node", "html",
})

# CVSS → severity mapping
def cvss_to_severity(score: Optional[float]) -> str:
    if score is None:
        return "info"
    if score >= 9.0:   return "critical"
    if score >= 7.0:   return "high"
    if score >= 4.0:   return "medium"
    if score >= 0.1:   return "low"
    return "info"

# Normalise package name to a keyword suitable for NVD search
def _pkg_keyword(name: str, version: str = "") -> str:
    kw = re.sub(r"[^a-zA-Z0-9\.\-_]", " ", name).strip()
    return kw


def _parse_version(v: str):
    """Best-effort version parse; returns None on garbage so callers can skip filtering."""
    if not v or v in ("*", "-", "any"):
        return None
    try:
        return Version(v) if Version else None
    except InvalidVersion:
        # Fallback: take leading numeric.dotted prefix
        m = re.match(r"\d+(?:\.\d+){0,3}", v)
        if not m:
            return None
        try:
            return Version(m.group(0)) if Version else None
        except InvalidVersion:
            return None


def _versions_equal(a: str, b: str) -> bool:
    """
    Equality that is stricter than _parse_version for CPE exact-match comparisons.
    Handles vendor suffixes like OpenSSL's 1.0.1f / 1.0.1g that strip to the same
    numeric prefix but are distinct releases.
    """
    if not a or not b:
        return False
    if a.strip().lower() == b.strip().lower():
        return True
    pa, pb = _parse_version(a), _parse_version(b)
    if pa is None or pb is None:
        return False
    if pa != pb:
        return False
    # Numeric prefix matches — require the trailing suffixes match too
    suf_a = re.sub(r"^\d+(?:\.\d+){0,3}", "", a).strip().lower()
    suf_b = re.sub(r"^\d+(?:\.\d+){0,3}", "", b).strip().lower()
    return suf_a == suf_b


def cve_affects_version(cve: dict, installed_version: str) -> bool:
    """
    Decide whether `cve` applies to the installed version using its CPE matches.

    Returns True if ANY cpe_match's range covers the installed version. If the
    CVE has no usable version range data, we conservatively return True
    (preserves existing behaviour for old cached entries).
    """
    if not installed_version:
        return True
    inst = _parse_version(installed_version)
    if inst is None:
        return True

    matches = cve.get("affected_cpe_matches") or []
    if not matches:
        return True

    saw_range = False
    for m in matches:
        if not m.get("vulnerable", True):
            continue
        criteria   = m.get("criteria", "")
        # CPE format: cpe:2.3:part:vendor:product:version:...
        cpe_parts  = criteria.split(":")
        cpe_ver    = cpe_parts[5] if len(cpe_parts) > 5 else "*"
        v_start_i  = m.get("versionStartIncluding")
        v_start_e  = m.get("versionStartExcluding")
        v_end_i    = m.get("versionEndIncluding")
        v_end_e    = m.get("versionEndExcluding")

        if not any([v_start_i, v_start_e, v_end_i, v_end_e, cpe_ver not in ("*", "-")]):
            continue
        saw_range = True

        # Exact-version CPE entry: only matches if equal.
        if cpe_ver not in ("*", "-") and not any([v_start_i, v_start_e, v_end_i, v_end_e]):
            if _versions_equal(cpe_ver, installed_version):
                return True
            continue

        ok = True
        for bound, op in (
            (v_start_i, "ge"), (v_start_e, "gt"),
            (v_end_i,   "le"), (v_end_e,   "lt"),
        ):
            if not bound:
                continue
            b = _parse_version(bound)
            if b is None:
                continue
            if op == "ge" and not (inst >= b): ok = False
            if op == "gt" and not (inst >  b): ok = False
            if op == "le" and not (inst <= b): ok = False
            if op == "lt" and not (inst <  b): ok = False
        if ok:
            return True

    # If every match had a range and none covered us, the CVE doesn't apply.
    return not saw_range


def _nvd_dt(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

_last_nvd_call: float = 0.0
_nvd_lock = asyncio.Lock()


class CVELookup:
    """
    NVD CVE lookup with local caching.

    Usage:
        cve = CVELookup(db)
        results = await cve.lookup("openssl", "3.0.0")
        # → [{"cve_id": "CVE-2024-...", "cvss_score": 9.1, ...}, ...]
    """

    def __init__(self, db) -> None:
        self._db = db

    async def lookup(self, package: str, version: str = "") -> list[dict]:
        """Return cached or freshly-fetched CVEs for a package."""
        cache_key = f"{package.lower()}:{version}"
        cached = await self._db.get_cve_cache(cache_key)
        if cached:
            return cached

        cves = await self._fetch_nvd(package, version)
        if cves:
            await self._db.set_cve_cache(cache_key, cves, ttl=CVE_TTL)
        return cves

    async def get_cve(self, cve_id: str) -> Optional[dict]:
        """Fetch a single CVE by ID."""
        cached = await self._db.get_cve_by_id(cve_id)
        if cached:
            return cached
        return await self._fetch_single_cve(cve_id)

    async def sync_recent(self, hours: int = 48, max_pages: int = 3) -> int:
        """
        Pull recently modified CVEs from NVD and store them in the local intel DB.
        This keeps threat intelligence fresh even when agents are not sending
        new package telemetry.
        """
        now = datetime.now(timezone.utc)
        start = now - timedelta(hours=max(1, hours))
        count = 0
        start_index = 0
        for _ in range(max(1, max_pages)):
            page = await self._fetch_modified_window(start, now, start_index)
            if not page:
                break
            for cve in page:
                await self._db.upsert_cve(cve)
                count += 1
            if len(page) < SYNC_PAGE_SIZE:
                break
            start_index += SYNC_PAGE_SIZE
        return count

    # ── NVD API calls ─────────────────────────────────────────────────────────

    async def _fetch_nvd(self, package: str, version: str) -> list[dict]:
        # Suppress noisy keywords that produce mostly false positives
        kw_norm = package.lower().strip()
        if len(kw_norm) < MIN_KEYWORD_LEN or kw_norm in COMMON_NOISY_KEYWORDS:
            log.debug("Skipping NVD lookup for short/noisy keyword: %r", package)
            return []

        global _last_nvd_call
        async with _nvd_lock:
            # Rate limiting: wait if we called too recently
            elapsed = time.time() - _last_nvd_call
            if elapsed < REQUEST_DELAY:
                await asyncio.sleep(REQUEST_DELAY - elapsed)

            keyword = _pkg_keyword(package, version)
            params: dict = {
                "keywordSearch":     keyword,
                "keywordExactMatch": "",   # presence-only flag → exact substring match
                "noRejected":        "",
                "resultsPerPage":    MAX_RESULTS,
            }
            # versionStart/versionEnd are only honoured with virtualMatchString
            # (CPE-based). For keyword searches we post-filter using
            # cve_affects_version() below.

            try:
                async with aiohttp.ClientSession(timeout=TIMEOUT) as s:
                    async with s.get(NVD_API_URL, params=params) as r:
                        _last_nvd_call = time.time()
                        if r.status == 403:
                            log.warning("NVD rate limited — slow down")
                            return []
                        if r.status != 200:
                            log.debug("NVD returned %d for %s", r.status, package)
                            return []
                        data = await r.json()

                results = []
                for vuln in data.get("vulnerabilities", []):
                    parsed = self._parse_cve(vuln.get("cve", {}))
                    if not parsed:
                        continue
                    # Post-filter by installed version using CPE version ranges
                    if version and not cve_affects_version(parsed, version):
                        log.debug("NVD: %s does not affect %s %s — dropping",
                                  parsed["cve_id"], package, version)
                        continue
                    results.append(parsed)
                    await self._db.upsert_cve(parsed)
                return results

            except Exception as exc:
                log.debug("NVD fetch failed for %s: %s", package, exc)
                return []

    async def _fetch_single_cve(self, cve_id: str) -> Optional[dict]:
        global _last_nvd_call
        async with _nvd_lock:
            elapsed = time.time() - _last_nvd_call
            if elapsed < REQUEST_DELAY:
                await asyncio.sleep(REQUEST_DELAY - elapsed)
            try:
                async with aiohttp.ClientSession(timeout=TIMEOUT) as s:
                    async with s.get(
                        NVD_API_URL,
                        params={"cveId": cve_id, "noRejected": ""},
                    ) as r:
                        _last_nvd_call = time.time()
                        if r.status != 200:
                            return None
                        data = await r.json()
                vulns = data.get("vulnerabilities", [])
                if not vulns:
                    return None
                parsed = self._parse_cve(vulns[0].get("cve", {}))
                if parsed:
                    await self._db.upsert_cve(parsed)
                return parsed
            except Exception as exc:
                log.debug("NVD single CVE fetch failed %s: %s", cve_id, exc)
                return None

    async def _fetch_modified_window(
        self,
        start: datetime,
        end: datetime,
        start_index: int,
    ) -> list[dict]:
        global _last_nvd_call
        async with _nvd_lock:
            elapsed = time.time() - _last_nvd_call
            if elapsed < REQUEST_DELAY:
                await asyncio.sleep(REQUEST_DELAY - elapsed)
            params = {
                "lastModStartDate": _nvd_dt(start),
                "lastModEndDate": _nvd_dt(end),
                "resultsPerPage": SYNC_PAGE_SIZE,
                "startIndex": start_index,
                "noRejected": "",
            }
            try:
                async with aiohttp.ClientSession(timeout=TIMEOUT) as s:
                    async with s.get(NVD_API_URL, params=params) as r:
                        _last_nvd_call = time.time()
                        if r.status == 403:
                            log.warning("NVD modified sync rate limited")
                            return []
                        if r.status != 200:
                            log.debug("NVD modified sync returned %d", r.status)
                            return []
                        data = await r.json()
                results = []
                for vuln in data.get("vulnerabilities", []):
                    parsed = self._parse_cve(vuln.get("cve", {}))
                    if parsed:
                        results.append(parsed)
                return results
            except Exception as exc:
                log.debug("NVD modified sync failed: %s", exc)
                return []

    def _parse_cve(self, cve: dict) -> Optional[dict]:
        cve_id = cve.get("id", "")
        if not cve_id:
            return None

        # Description (prefer English)
        desc = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break

        # CVSS score — try v3.1 then v3.0 then v2
        cvss_score  = None
        cvss_vector = ""
        metrics = cve.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key, [])
            if entries:
                cv = entries[0].get("cvssData", {})
                cvss_score  = cv.get("baseScore")
                cvss_vector = cv.get("vectorString", "")
                break

        severity = cvss_to_severity(cvss_score)

        # CWE
        cwes = []
        for w in cve.get("weaknesses", []):
            for d in w.get("description", []):
                if d.get("lang") == "en" and d.get("value", "").startswith("CWE-"):
                    cwes.append(d["value"])

        # CPE affected — preserve version ranges so callers can filter by installed version.
        cpe_list:    list[str] = []
        cpe_matches: list[dict] = []
        for cfg in cve.get("configurations", []):
            for node in cfg.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    if not cpe_match.get("vulnerable"):
                        continue
                    crit = cpe_match.get("criteria", "")
                    if crit:
                        cpe_list.append(crit)
                    cpe_matches.append({
                        "criteria":              crit,
                        "vulnerable":            cpe_match.get("vulnerable", True),
                        "versionStartIncluding": cpe_match.get("versionStartIncluding"),
                        "versionStartExcluding": cpe_match.get("versionStartExcluding"),
                        "versionEndIncluding":   cpe_match.get("versionEndIncluding"),
                        "versionEndExcluding":   cpe_match.get("versionEndExcluding"),
                    })

        # References — needed for exploit-availability heuristics downstream.
        refs:        list[str] = []
        ref_tags:    set[str]  = set()
        for ref in cve.get("references", []):
            url = ref.get("url", "")
            if url:
                refs.append(url)
            for t in ref.get("tags", []) or []:
                ref_tags.add(t)

        ref_blob = " ".join(refs).lower() + " " + desc.lower()
        exploit_available = bool(
            "Exploit" in ref_tags
            or "exploit-db" in ref_blob
            or "metasploit" in ref_blob
            or "proof-of-concept" in ref_blob
            or "poc" in ref_blob
        )

        published = cve.get("published", "")
        modified  = cve.get("lastModified", "")

        return {
            "cve_id":               cve_id,
            "vuln_status":          cve.get("vulnStatus", ""),
            "description":          desc,
            "cvss_score":           cvss_score,
            "cvss_vector":          cvss_vector,
            "severity":             severity,
            "cwe_ids":              cwes,
            "published_at":         published,
            "modified_at":          modified,
            "affected_cpe":         cpe_list[:20],
            "affected_cpe_matches": cpe_matches[:20],
            "references":           refs[:20],
            "reference_tags":       sorted(ref_tags),
            "exploit_available":    exploit_available,
        }
