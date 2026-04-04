"""
manager/manager/threat/nvd.py — NVD CVE database integration.

Uses the NVD REST API v2 (no auth key required for basic use).
Results are cached in intel.db for 24 hours to respect rate limits.

API reference: https://nvd.nist.gov/developers/vulnerabilities
Rate limit (no key): 5 requests / 30 seconds.
"""
from __future__ import annotations

import asyncio
import logging
import re
import time
from typing import Optional

import aiohttp

log = logging.getLogger("manager.threat.nvd")

NVD_API_URL    = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CVE_TTL        = 86400        # 24 hours
REQUEST_DELAY  = 7.0          # seconds between NVD requests (rate limit)
MAX_RESULTS    = 10           # max CVEs per package lookup
TIMEOUT        = aiohttp.ClientTimeout(total=20)

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

    # ── NVD API calls ─────────────────────────────────────────────────────────

    async def _fetch_nvd(self, package: str, version: str) -> list[dict]:
        global _last_nvd_call
        async with _nvd_lock:
            # Rate limiting: wait if we called too recently
            elapsed = time.time() - _last_nvd_call
            if elapsed < REQUEST_DELAY:
                await asyncio.sleep(REQUEST_DELAY - elapsed)

            keyword = _pkg_keyword(package, version)
            params: dict = {
                "keywordSearch": keyword,
                "resultsPerPage": MAX_RESULTS,
            }
            if version:
                params["versionStart"] = version
                params["versionStartType"] = "including"

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
                    if parsed:
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
                    async with s.get(NVD_API_URL, params={"cveId": cve_id}) as r:
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

        # CPE affected
        cpe_list: list[str] = []
        for cfg in cve.get("configurations", []):
            for node in cfg.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    if cpe_match.get("vulnerable"):
                        cpe_list.append(cpe_match.get("criteria", ""))

        published = cve.get("published", "")
        modified  = cve.get("lastModified", "")

        return {
            "cve_id":       cve_id,
            "description":  desc,
            "cvss_score":   cvss_score,
            "cvss_vector":  cvss_vector,
            "severity":     severity,
            "cwe_ids":      cwes,
            "published_at": published,
            "modified_at":  modified,
            "affected_cpe": cpe_list[:20],  # cap to avoid huge blobs
        }
