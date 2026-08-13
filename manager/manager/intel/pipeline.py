"""
manager/manager/intel/pipeline.py — Multi-source CVE enrichment pipeline.

Design principles:
  1. Parallel fetch: all sources queried concurrently via asyncio.gather
  2. Graceful degradation: scoring works with any subset of sources
  3. Source priority for conflicting data: NVD > GHSA > CIRCL > OSV
  4. Circuit breaker per source (see sources.py)
  5. No single source dependency: the pipeline returns enriched data even if
     NVD, EPSS, or KEV are all unreachable (using whatever sources respond)
  6. Validation layer: cross-source discrepancies flagged, not silently merged

Usage:
    pipeline = IntelPipeline(feeds, nvd_lookup)
    await pipeline.start()                          # loads offline indexes
    enriched = await pipeline.enrich_cve("CVE-2021-44228")
    scores   = await pipeline.bulk_enrich(cve_list)
    health   = pipeline.get_source_health()
    await pipeline.stop()
"""
from __future__ import annotations

import asyncio
import logging
import os
import time
from typing import Any, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from ..attacklens.feeds import FeedManager
    from ..attacklens.nvd   import CVELookup

from .sources import (
    ExploitDBSource, MetasploitSource, PocGithubSource,
    OsvSource, GhsaSource, CveCirclSource, CVE_RE,
)
from .validator import IntelValidator
from .scorer    import EnhancedScorer

log = logging.getLogger("manager.intel.pipeline")

_SOURCE_MAX_AGE_SECONDS = {
    "exploitdb": 7 * 86400,
    "metasploit": 7 * 86400,
}


def build_source_freshness(
    source_names: list[str],
    sources: dict[str, Any],
    errors: dict[str, str],
    *,
    observed_at: float,
    source_health: Optional[dict] = None,
) -> dict[str, dict]:
    """Build source provenance without treating a miss as a source failure."""
    health = source_health or {}
    freshness: dict[str, dict] = {}
    for name in source_names:
        details = health.get(name) if isinstance(health.get(name), dict) else {}
        source_updated_at = float(details.get("loaded_at") or observed_at)
        age_seconds = max(0.0, observed_at - source_updated_at)
        max_age = _SOURCE_MAX_AGE_SECONDS.get(name)
        error = str(errors.get(name) or "")
        freshness[name] = {
            "status": (
                "error" if error else "available" if name in sources else "not_found"
            ),
            "observed_at": observed_at,
            "source_updated_at": source_updated_at,
            "age_seconds": round(age_seconds, 3),
            "stale": bool(max_age is not None and age_seconds > max_age),
            "error": error,
        }
    return freshness


class IntelPipeline:
    """
    Coordinates all intel sources for CVE enrichment.
    Attach to app.state in server.py for route access.
    """

    def __init__(
        self,
        feeds:         "FeedManager",
        nvd:           "CVELookup",
        github_token:  str = "",
    ) -> None:
        self._feeds     = feeds
        self._nvd       = nvd
        # Offline-index sources (downloaded in background at startup)
        self._exploitdb = ExploitDBSource()
        self._msf       = MetasploitSource()
        # On-demand sources (per-CVE, cached)
        self._poc       = PocGithubSource()
        self._osv       = OsvSource()
        self._ghsa      = GhsaSource(github_token or os.environ.get("GITHUB_TOKEN", ""))
        self._circl     = CveCirclSource()
        # Validation + scoring
        self._validator = IntelValidator()
        self._scorer    = EnhancedScorer()
        self._start_task: Optional[asyncio.Task] = None

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    async def start(self) -> None:
        """Kick off background loading of ExploitDB + Metasploit indexes."""
        self._start_task = asyncio.create_task(
            self._load_offline(), name="intel:offline_load"
        )
        log.info("IntelPipeline: started — offline indexes loading in background")

    async def stop(self) -> None:
        if self._start_task and not self._start_task.done():
            self._start_task.cancel()
            try:
                await self._start_task
            except asyncio.CancelledError:
                pass
        log.info("IntelPipeline: stopped")

    async def refresh_offline(self) -> None:
        """Force refresh of ExploitDB and Metasploit indexes (called by weekly worker)."""
        # Reset TTL by zeroing loaded_at so ensure_loaded re-downloads
        self._exploitdb._loaded_at = 0.0
        self._msf._loaded_at       = 0.0
        await asyncio.gather(
            self._exploitdb.ensure_loaded(),
            self._msf.ensure_loaded(),
            return_exceptions=True,
        )
        log.info("IntelPipeline: offline indexes refreshed")

    # ── Main API ──────────────────────────────────────────────────────────────

    async def enrich_cve(self, cve_id: str) -> dict:
        """
        Enrich a single CVE from all available sources in parallel.
        Never raises — returns error key on invalid input.
        """
        cid = cve_id.strip().upper()
        if not CVE_RE.match(cid):
            return {"error": f"Invalid CVE ID: {cve_id!r}", "cve_id": cid}

        # Fire all sources concurrently
        raw = await asyncio.gather(
            self._src_nvd(cid),
            self._src_kev(cid),
            self._src_epss(cid),
            self._src_exploitdb(cid),
            self._src_metasploit(cid),
            self._src_poc_github(cid),
            self._src_osv(cid),
            self._src_ghsa(cid),
            self._src_circl(cid),
            return_exceptions=True,
        )
        keys = ["nvd", "kev", "epss", "exploitdb", "metasploit", "poc_github", "osv", "ghsa", "circl"]
        sources:  dict[str, Any] = {}
        s_errors: dict[str, str] = {}
        for k, v in zip(keys, raw):
            if isinstance(v, Exception):
                s_errors[k] = str(v)
                log.debug("IntelPipeline source %s failed for %s: %s", k, cid, v)
            elif v is not None:
                sources[k] = v

        validation = self._validator.cross_validate(cid, sources)
        enriched   = self._merge(cid, sources, validation)
        fetched_at = time.time()
        enriched["_source_errors"] = s_errors
        enriched["_fetched_at"]    = fetched_at
        enriched["_source_freshness"] = build_source_freshness(
            keys,
            sources,
            s_errors,
            observed_at=fetched_at,
            source_health=self.get_source_health(),
        )
        return enriched

    async def bulk_enrich(self, cve_ids: list[str], concurrency: int = 5) -> list[dict]:
        """Enrich multiple CVEs with controlled concurrency (semaphore guard)."""
        sem = asyncio.Semaphore(concurrency)

        async def _one(cid: str) -> dict:
            async with sem:
                return await self.enrich_cve(cid)

        return list(await asyncio.gather(*[_one(c) for c in cve_ids]))

    def compute_score(self, enriched: dict) -> float:
        return self._scorer.compute(enriched)

    def get_source_health(self) -> dict:
        return {
            "exploitdb":  self._exploitdb.stats(),
            "metasploit": self._msf.stats(),
            "poc_github": self._poc.stats(),
            "osv":        self._osv.stats(),
            "ghsa":       self._ghsa.stats(),
            "circl":      self._circl.stats(),
        }

    # ── Source fetch helpers (each swallows its own errors) ───────────────────

    async def _src_nvd(self, cve_id: str) -> Optional[dict]:
        try:
            return await self._nvd.get_cve(cve_id)
        except Exception as exc:
            log.debug("NVD fetch %s: %s", cve_id, exc)
            return None

    async def _src_kev(self, cve_id: str) -> Optional[dict]:
        try:
            if self._feeds.is_kev_cve(cve_id):
                return {"cve_id": cve_id, "kev": True}
            return None
        except Exception:
            return None

    async def _src_epss(self, cve_id: str) -> Optional[dict]:
        try:
            return await self._feeds.get_epss(cve_id)
        except Exception as exc:
            log.debug("EPSS fetch %s: %s", cve_id, exc)
            return None

    async def _src_exploitdb(self, cve_id: str) -> Optional[dict]:
        try:
            exploits = await self._exploitdb.lookup(cve_id)
            if not exploits:
                return None
            verified = [e for e in exploits if e.get("verified")]
            return {
                "total":    len(exploits),
                "verified": len(verified),
                "exploits": exploits[:5],
            }
        except Exception as exc:
            log.debug("ExploitDB fetch %s: %s", cve_id, exc)
            return None

    async def _src_metasploit(self, cve_id: str) -> Optional[bool]:
        try:
            return True if await self._msf.has_module(cve_id) else None
        except Exception:
            return None

    async def _src_poc_github(self, cve_id: str) -> Optional[dict]:
        try:
            pocs = await self._poc.lookup(cve_id)
            if not pocs:
                return None
            return {
                "count":     len(pocs),
                "top_pocs":  pocs[:3],
                "max_stars": max((p.get("stars", 0) for p in pocs), default=0),
            }
        except Exception as exc:
            log.debug("PocGitHub fetch %s: %s", cve_id, exc)
            return None

    async def _src_osv(self, cve_id: str) -> Optional[dict]:
        try:
            return await self._osv.lookup_cve(cve_id)
        except Exception:
            return None

    async def _src_ghsa(self, cve_id: str) -> Optional[list]:
        try:
            res = await self._ghsa.lookup(cve_id)
            return res or None
        except Exception:
            return None

    async def _src_circl(self, cve_id: str) -> Optional[dict]:
        try:
            return await self._circl.lookup(cve_id)
        except Exception:
            return None

    # ── Merge ─────────────────────────────────────────────────────────────────

    def _merge(self, cve_id: str, s: dict[str, Any], validation: dict) -> dict:
        """
        Merge multi-source data.  Source priority for conflicting fields:
        NVD > GHSA > CIRCL > OSV
        """
        from ..attacklens.nvd import cvss_to_severity

        # ── CVSS ─────────────────────────────────────────────────────────────
        cvss_score  = None
        cvss_vector = ""
        cvss_src    = "none"

        nvd = s.get("nvd") or {}
        if isinstance(nvd, dict) and nvd.get("cvss_score") is not None:
            cvss_score, cvss_vector, cvss_src = float(nvd["cvss_score"]), nvd.get("cvss_vector", ""), "nvd"

        ghsa_list = s.get("ghsa") or []
        if cvss_score is None and isinstance(ghsa_list, list):
            for g in ghsa_list:
                if isinstance(g, dict) and g.get("cvss_score") is not None:
                    cvss_score, cvss_src = float(g["cvss_score"]), "ghsa"
                    break

        circl = s.get("circl") or {}
        if cvss_score is None and isinstance(circl, dict) and circl.get("cvss_score") is not None:
            cvss_score, cvss_src = float(circl["cvss_score"]), "circl"

        osv = s.get("osv") or {}
        if cvss_score is None and isinstance(osv, dict) and osv.get("cvss_score") is not None:
            cvss_score, cvss_src = float(osv["cvss_score"]), "osv"

        # ── EPSS ─────────────────────────────────────────────────────────────
        epss_d      = s.get("epss") or {}
        epss_score  = float(epss_d.get("epss", 0.0) or 0.0) if isinstance(epss_d, dict) else 0.0
        epss_pct    = float(epss_d.get("percentile", 0.0) or 0.0) if isinstance(epss_d, dict) else 0.0
        epss_date   = epss_d.get("model_date", "") if isinstance(epss_d, dict) else ""

        # ── KEV ──────────────────────────────────────────────────────────────
        kev_d        = s.get("kev")
        is_kev       = kev_d is not None
        kev_due      = kev_d.get("due_date", "") if isinstance(kev_d, dict) else ""
        kev_rans     = kev_d.get("known_ransomware_campaign_use", "Unknown") if isinstance(kev_d, dict) else "Unknown"
        kev_product  = kev_d.get("product", "") if isinstance(kev_d, dict) else ""
        kev_vendor   = kev_d.get("vendor", "") if isinstance(kev_d, dict) else ""

        # ── Exploits ─────────────────────────────────────────────────────────
        edb         = s.get("exploitdb")
        msf         = s.get("metasploit")
        poc         = s.get("poc_github")

        exploit_available = bool(edb or msf or poc)
        exploit_sources   = []
        if isinstance(edb, dict) and edb.get("total", 0) > 0:
            v = edb.get("verified", 0)
            exploit_sources.append(
                f"exploitdb({edb['total']} exploit" + ("s" if edb["total"] != 1 else "")
                + (f", {v} verified" if v else "") + ")"
            )
        if msf:
            exploit_sources.append("metasploit")
        if isinstance(poc, dict) and poc.get("count", 0) > 0:
            exploit_sources.append(f"poc_github({poc['count']})")

        # ── Description ──────────────────────────────────────────────────────
        desc = ""
        for candidate in [
            nvd.get("description") if isinstance(nvd, dict) else None,
            circl.get("summary") if isinstance(circl, dict) else None,
            (ghsa_list[0].get("summary") if ghsa_list and isinstance(ghsa_list[0], dict) else None),
            (osv.get("summary") if isinstance(osv, dict) else None),
        ]:
            if candidate:
                desc = candidate; break

        # ── Affected packages (OSV best) ──────────────────────────────────────
        affected_pkgs = []
        if isinstance(osv, dict):
            affected_pkgs = osv.get("affected_packages", [])[:5]

        # ── Composite score ───────────────────────────────────────────────────
        pre = {
            "cvss_score":       cvss_score,
            "epss_score":       epss_score,
            "kev":              is_kev,
            "kev_due_date":     kev_due,
            "exploitdb":        edb,
            "metasploit":       bool(msf),
            "poc_github":       poc,
            "intel_confidence": validation.get("confidence", 0.5),
        }
        composite = self._scorer.compute(pre)
        severity  = cvss_to_severity(cvss_score)

        return {
            "cve_id":            cve_id,
            "description":       desc,
            "severity":          severity,
            "composite_score":   composite,
            # CVSS
            "cvss_score":        cvss_score,
            "cvss_vector":       cvss_vector,
            "cvss_source":       cvss_src,
            # EPSS
            "epss_score":        epss_score,
            "epss_percentile":   epss_pct,
            "epss_model_date":   epss_date,
            # KEV
            "kev":               is_kev,
            "kev_due_date":      kev_due,
            "kev_ransomware":    kev_rans,
            "kev_product":       kev_product,
            "kev_vendor":        kev_vendor,
            # Exploits
            "exploit_available": exploit_available,
            "exploit_sources":   exploit_sources,
            "exploitdb":         edb,
            "metasploit":        bool(msf),
            "poc_github":        poc,
            # Package intel
            "affected_packages": affected_pkgs,
            # Secondary sources
            "ghsa":              ghsa_list[:3] if isinstance(ghsa_list, list) else [],
            "osv":               osv if isinstance(osv, dict) else {},
            "circl_refs":        circl.get("references", []) if isinstance(circl, dict) else [],
            # Metadata
            "sources_used":      list(s.keys()),
            "intel_confidence":  validation.get("confidence", 0.5),
            "validation":        validation,
        }

    async def _load_offline(self) -> None:
        try:
            await asyncio.gather(
                self._exploitdb.ensure_loaded(),
                self._msf.ensure_loaded(),
                return_exceptions=True,
            )
            edb_s = self._exploitdb.stats()
            msf_s = self._msf.stats()
            log.info(
                "IntelPipeline offline ready: exploitdb=%d CVEs  metasploit=%d CVEs",
                edb_s["total_cves"], msf_s["total_cves"],
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            log.warning("IntelPipeline offline load error: %s", exc)
