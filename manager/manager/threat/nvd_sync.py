"""
manager/manager/threat/nvd_sync.py — Continuous NVD CVE database mirror worker.

Keeps a local copy of the entire NVD CVE database in intel.db (nvd_cve_local table)
so package → CVE matching never needs a live API call.

Sync schedule:
  • Full sync  — on startup if table is empty or >7 days stale, then every 24h
  • Delta sync — every 1h using NVD lastModStartDate / lastModEndDate params

NVD API rate limits (v2):
  • No key     : 5 req / 30s  →  7s delay between requests (~250k CVEs in ~5h)
  • NVD_API_KEY: 50 req / 30s  →  0.6s delay between requests (~250k CVEs in ~25min)

Set NVD_API_KEY env var to speed up initial full sync significantly.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import time
from datetime import datetime, timezone
from typing import Optional, TYPE_CHECKING

import aiohttp

if TYPE_CHECKING:
    from ..indexer import IntelDB

log = logging.getLogger("manager.threat.nvd_sync")

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PAGE_SIZE   = 2000                # max allowed by NVD API v2
TIMEOUT     = aiohttp.ClientTimeout(total=60)

_FULL_SYNC_INTERVAL  = 86_400       # re-check every 24h
_DELTA_SYNC_INTERVAL = 3_600        # delta every 1h
_FULL_SYNC_MAX_AGE   = 86_400 * 7   # trigger new full sync if >7 days old

_STATE_FULL  = "nvd_full_sync_at"
_STATE_DELTA = "nvd_delta_sync_at"

_NOISE = frozenset({
    "the", "and", "for", "are", "via", "with", "that", "this", "from",
    "can", "not", "all", "has", "use", "its", "may", "which", "when",
    "version", "before", "allows", "remote", "attack", "could", "user",
    "local", "vulnerability", "affected", "multiple", "systems",
})


def _cvss_to_severity(score: Optional[float]) -> str:
    if score is None: return "info"
    if score >= 9.0:  return "critical"
    if score >= 7.0:  return "high"
    if score >= 4.0:  return "medium"
    if score >= 0.1:  return "low"
    return "info"


def _build_keywords(desc: str, cpe_uris: list[str]) -> str:
    words: set[str] = set()
    for cpe in cpe_uris[:50]:
        parts = cpe.split(":")
        if len(parts) >= 5:
            for segment in (parts[3], parts[4]):  # vendor, product
                for w in re.split(r"[_\-\.]", segment.lower()):
                    if len(w) > 2:
                        words.add(w)
    for w in re.findall(r"[a-z][a-z0-9\-\.]{2,}", desc[:300].lower()):
        words.add(w)
    words -= _NOISE
    return " ".join(sorted(words))


def _parse_vuln(vuln: dict) -> Optional[dict]:
    cve    = vuln.get("cve", {})
    cve_id = cve.get("id", "")
    if not cve_id:
        return None

    desc = ""
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            desc = d.get("value", "")
            break

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

    cwes: list[str] = []
    for w in cve.get("weaknesses", []):
        for d in w.get("description", []):
            if d.get("lang") == "en" and d.get("value", "").startswith("CWE-"):
                cwes.append(d["value"])

    cpe_list: list[str] = []
    for cfg in cve.get("configurations", []):
        for node in cfg.get("nodes", []):
            for m in node.get("cpeMatch", []):
                if m.get("vulnerable"):
                    cpe_list.append(m.get("criteria", ""))

    return {
        "cve_id":       cve_id,
        "description":  desc[:500],
        "cvss_score":   cvss_score,
        "cvss_vector":  cvss_vector,
        "severity":     _cvss_to_severity(cvss_score),
        "cwe_ids":      json.dumps(cwes[:10]),
        "cpe_uris":     json.dumps(cpe_list[:30]),
        "pkg_keywords": _build_keywords(desc, cpe_list),
        "published_at": cve.get("published", ""),
        "modified_at":  cve.get("lastModified", ""),
        "synced_at":    time.time(),
    }


class NVDSyncWorker:
    """
    Maintains a local NVD CVE mirror.
    Create once at startup; call start() then await stop() on shutdown.

    Public lookup API (no network):
        results = await worker.lookup_local("openssl")
    """

    def __init__(self, intel_db: "IntelDB") -> None:
        self._db      = intel_db
        self._api_key = os.environ.get("NVD_API_KEY", "").strip()
        # Rate limit: 7s without key, 0.6s with key
        self._delay   = 0.6 if self._api_key else 7.0
        self._tasks:  list[asyncio.Task] = []
        self._session: Optional[aiohttp.ClientSession] = None

    async def start(self) -> None:
        headers = {"apiKey": self._api_key} if self._api_key else {}
        self._session = aiohttp.ClientSession(timeout=TIMEOUT, headers=headers)
        self._tasks = [
            asyncio.create_task(self._full_sync_loop(),  name="nvd:full"),
            asyncio.create_task(self._delta_sync_loop(), name="nvd:delta"),
        ]
        log.info("NVDSyncWorker started (key=%s, delay=%.1fs)",
                 "yes" if self._api_key else "no", self._delay)

    async def stop(self) -> None:
        for t in self._tasks:
            t.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        if self._session:
            await self._session.close()
        log.info("NVDSyncWorker stopped")

    async def lookup_local(self, package: str, limit: int = 20) -> list[dict]:
        """Fast FTS5 search against local NVD mirror — no network call."""
        keyword = re.sub(r"[^a-z0-9]", " ", package.lower()).strip()
        if not keyword:
            return []
        return await self._db.search_nvd_local(keyword, limit=limit)

    # ── Sync loops ────────────────────────────────────────────────────────────

    async def _full_sync_loop(self) -> None:
        while True:
            try:
                last = float(await self._db.get_nvd_state(_STATE_FULL) or "0")
                if time.time() - last > _FULL_SYNC_MAX_AGE:
                    await self._run_full_sync()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                log.error("NVD full sync loop error: %s", exc)
            await asyncio.sleep(_FULL_SYNC_INTERVAL)

    async def _delta_sync_loop(self) -> None:
        await asyncio.sleep(60)  # let full sync start first
        while True:
            try:
                await self._run_delta_sync()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                log.warning("NVD delta sync loop error: %s", exc)
            await asyncio.sleep(_DELTA_SYNC_INTERVAL)

    # ── Full sync ─────────────────────────────────────────────────────────────

    async def _run_full_sync(self) -> None:
        log.info("NVD full sync starting (delay=%.1fs/page)...", self._delay)
        total_upserted = 0
        start_index    = 0
        total_results: Optional[int] = None

        try:
            while True:
                page = await self._fetch_page({
                    "resultsPerPage": PAGE_SIZE,
                    "startIndex":     start_index,
                })
                if page is None:
                    log.warning("NVD full sync: fetch failed at index %d — aborting", start_index)
                    break

                if total_results is None:
                    total_results = page.get("totalResults", 0)
                    log.info("NVD full sync: %d CVEs to fetch", total_results)

                vulns = page.get("vulnerabilities", [])
                if not vulns:
                    break

                batch = [r for v in vulns if (r := _parse_vuln(v))]
                if batch:
                    await self._db.upsert_nvd_bulk(batch)
                    total_upserted += len(batch)

                start_index += len(vulns)
                pct = int(100 * start_index / total_results) if total_results else 0
                log.info("NVD full sync: %d/%d (%d%%) upserted=%d",
                         start_index, total_results or 0, pct, total_upserted)

                if total_results and start_index >= total_results:
                    break
                await asyncio.sleep(self._delay)

            now = str(time.time())
            await self._db.set_nvd_state(_STATE_FULL, now)
            await self._db.set_nvd_state(_STATE_DELTA, now)  # reset delta baseline
            await self._db.record_feed_attempt(
                "nvd:full_sync", success=True, entry_count=total_upserted)
            log.info("NVD full sync complete: %d CVEs upserted", total_upserted)

        except asyncio.CancelledError:
            log.warning("NVD full sync cancelled at index %d (%d upserted)",
                        start_index, total_upserted)
            raise
        except Exception as exc:
            log.error("NVD full sync failed: %s", exc)
            await self._db.record_feed_attempt(
                "nvd:full_sync", success=False, error=str(exc)[:200])

    # ── Delta sync ────────────────────────────────────────────────────────────

    async def _run_delta_sync(self) -> None:
        last_ts = float(await self._db.get_nvd_state(_STATE_DELTA) or "0")
        if not last_ts:
            return  # wait for first full sync to establish baseline

        # NVD allows at most 120-day window for lastMod queries
        since = datetime.fromtimestamp(
            max(last_ts, time.time() - 86400 * 119), tz=timezone.utc)
        until = datetime.now(tz=timezone.utc)
        since_s = since.strftime("%Y-%m-%dT%H:%M:%S.000")
        until_s = until.strftime("%Y-%m-%dT%H:%M:%S.000")

        total_upserted = 0
        start_index    = 0

        try:
            while True:
                page = await self._fetch_page({
                    "resultsPerPage":   PAGE_SIZE,
                    "startIndex":       start_index,
                    "lastModStartDate": since_s,
                    "lastModEndDate":   until_s,
                })
                if page is None:
                    break

                vulns = page.get("vulnerabilities", [])
                if not vulns:
                    break

                batch = [r for v in vulns if (r := _parse_vuln(v))]
                if batch:
                    await self._db.upsert_nvd_bulk(batch)
                    total_upserted += len(batch)

                total = page.get("totalResults", 0)
                start_index += len(vulns)
                if start_index >= total:
                    break
                await asyncio.sleep(self._delay)

            await self._db.set_nvd_state(_STATE_DELTA, str(time.time()))
            if total_upserted:
                log.info("NVD delta sync: %d CVEs updated", total_upserted)
                await self._db.record_feed_attempt(
                    "nvd:delta_sync", success=True, entry_count=total_upserted)

        except asyncio.CancelledError:
            raise
        except Exception as exc:
            log.warning("NVD delta sync failed: %s", exc)
            await self._db.record_feed_attempt(
                "nvd:delta_sync", success=False, error=str(exc)[:200])

    # ── HTTP helper ───────────────────────────────────────────────────────────

    async def _fetch_page(self, params: dict) -> Optional[dict]:
        for attempt in range(3):
            try:
                async with self._session.get(NVD_API_URL, params=params) as r:
                    if r.status == 403:
                        log.warning("NVD rate limited — backing off 35s")
                        await asyncio.sleep(35)
                        continue
                    if r.status in (503, 429):
                        backoff = 15 * (attempt + 1)
                        log.warning("NVD %d — retrying in %ds", r.status, backoff)
                        await asyncio.sleep(backoff)
                        continue
                    if r.status != 200:
                        log.warning("NVD returned HTTP %d", r.status)
                        return None
                    return await r.json(content_type=None)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                wait = 5 * (attempt + 1)
                log.debug("NVD fetch attempt %d failed (%s) — retry in %ds",
                          attempt + 1, exc, wait)
                await asyncio.sleep(wait)
        return None
