"""
manager/manager/workers/intel.py — ThreatIntelWorker.

Runs the continuous threat intelligence collection pipeline as independent
asyncio tasks — one per feed, each on its own schedule.

Responsibilities
----------------
  1. Feodo Tracker IP feed          — every 1 h
  2. Emerging Threats IP feed       — every 1 h
  3. URLhaus domain/URL feed        — every 2 h
  4. CISA KEV catalog               — every 24 h
     Downloads the full Known Exploited Vulnerabilities JSON from CISA,
     upserts each entry into intel.db, and hydrates the in-memory _kev_set
     so finding correlation picks up new KEV entries immediately.
  5. Proactive CVE re-scan          — every 6 h
     Queries the latest packages payload per agent, checks each package
     against the NVD cache, and emits new critical/high findings directly
     into IntelDB — without waiting for fresh telemetry from the agent.
  6. NVD modified CVE sync          — every 2 h
     Pulls recently changed CVEs into the local threat-intel cache so package
     correlation can use fresh intelligence without blocking ingest requests.
  7. ExploitDB + Metasploit offline index refresh — every 7 days
     Forces re-download of the ExploitDB CSV (~35 MB) and Metasploit CVE list
     via IntelPipeline.refresh_offline().  Only runs when IntelPipeline is
     attached (embedded_threat_intel=True).

Design
------
- One asyncio.Task per scheduled job (not queue-based — scheduled I/O only).
- Each task runs immediately on startup, then sleeps for its interval.
- Feed health is persisted to intel.db after every attempt (success or fail).
- Proactive CVE scan uses the existing CVELookup instance (shared rate-limit
  lock with the AttackLensEngine NVD worker — they serialize fairly).
- Fully cancellable: stop() cancels all tasks and awaits them.
"""
from __future__ import annotations

import asyncio
import logging
import time
from typing import TYPE_CHECKING, Callable, Awaitable

if TYPE_CHECKING:
    from ..indexer           import IntelDB
    from ..db                import Database
    from ..attacklens.feeds  import FeedManager
    from ..attacklens.nvd    import CVELookup
    from ..intel.pipeline    import IntelPipeline

log = logging.getLogger("manager.workers.intel")

# Schedules (seconds)
_INTERVAL_FEODO    =   3_600   # 1 h
_INTERVAL_EMERGING =   3_600   # 1 h
_INTERVAL_URLHAUS  =   7_200   # 2 h
_INTERVAL_NVD_SYNC =   7_200   # 2 h
_INTERVAL_CVE_SCAN =  21_600   # 6 h
_INTERVAL_KEV      =  86_400   # 24 h — CISA updates KEV daily
_INTERVAL_OFFLINE  = 604_800   # 7 days — ExploitDB + Metasploit CSV refresh

# Proactive CVE scan: only emit findings at or above this CVSS threshold
_CVE_MIN_SCORE = 7.0


class ThreatIntelWorker:
    """
    Continuous threat intelligence collection worker.
    Create once at server startup; call start() then await stop() on shutdown.
    """

    def __init__(
        self,
        intel_db:       "IntelDB",
        db:             "Database",
        feeds:          "FeedManager",
        nvd:            "CVELookup",
        intel_pipeline: "IntelPipeline | None" = None,
    ) -> None:
        self._intel_db        = intel_db
        self._db              = db
        self._feeds           = feeds
        self._nvd             = nvd
        self._intel_pipeline  = intel_pipeline
        self._tasks:          list[asyncio.Task] = []

    async def start(self) -> None:
        """Spawn one asyncio task per scheduled job."""
        self._tasks = [
            asyncio.create_task(
                self._feed_loop("feodo",       self._feeds.refresh_feodo,       _INTERVAL_FEODO),
                name="intel:feodo",
            ),
            asyncio.create_task(
                self._feed_loop("emerging",    self._feeds.refresh_emerging,    _INTERVAL_EMERGING),
                name="intel:emerging",
            ),
            asyncio.create_task(
                self._feed_loop("urlhaus",     self._feeds.refresh_urlhaus,     _INTERVAL_URLHAUS),
                name="intel:urlhaus",
            ),
            asyncio.create_task(
                self._feed_loop("cisa_kev",    self._feeds.refresh_cisa_kev,   _INTERVAL_KEV),
                name="intel:cisa_kev",
            ),
            asyncio.create_task(
                self._feed_loop("nvd_recent",  self._nvd_recent_sync,           _INTERVAL_NVD_SYNC),
                name="intel:nvd_recent",
            ),
            asyncio.create_task(
                self._feed_loop("proactive_cve", self._proactive_cvescan,       _INTERVAL_CVE_SCAN),
                name="intel:proactive_cve",
            ),
        ]
        # Offline exploit-index refresh (ExploitDB + Metasploit) — only when
        # IntelPipeline is attached.  Indexes are already loaded at pipeline.start();
        # this task forces a re-download every 7 days so new CVE mappings land.
        if self._intel_pipeline is not None:
            self._tasks.append(asyncio.create_task(
                self._feed_loop("offline_indexes", self._offline_refresh, _INTERVAL_OFFLINE),
                name="intel:offline_indexes",
            ))
        log.info("ThreatIntelWorker started — %d feed tasks", len(self._tasks))

    async def stop(self) -> None:
        """Cancel all tasks and wait for them to exit."""
        for t in self._tasks:
            t.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        log.info("ThreatIntelWorker stopped")

    # ── Feed loop ─────────────────────────────────────────────────────────────

    # Retry policy: up to 3 attempts with exponential backoff before giving up
    # and waiting for the next scheduled interval.
    _MAX_RETRIES    = 3
    _RETRY_BASE_SEC = 30   # 30s → 60s → 120s

    async def _feed_loop(
        self,
        name:     str,
        fn:       Callable[[], Awaitable[int]],
        interval: int,
    ) -> None:
        """
        Run *fn* immediately, then every *interval* seconds.
        On failure, retries up to _MAX_RETRIES times with exponential backoff
        before recording a health failure and waiting for the next interval.
        Records health in intel.db after every final outcome.
        """
        delay = 0  # run on first iteration without waiting
        while True:
            await asyncio.sleep(delay)
            delay = interval  # subsequent iterations use full interval

            last_exc: Exception | None = None
            for attempt in range(1, self._MAX_RETRIES + 1):
                try:
                    count = await fn()
                    await self._intel_db.record_feed_attempt(
                        name, success=True, entry_count=count,
                    )
                    if attempt > 1:
                        log.info("Feed '%s': recovered on attempt %d — %d entries", name, attempt, count)
                    else:
                        log.info("Feed '%s': %d entries refreshed", name, count)
                    last_exc = None
                    break  # success — stop retrying
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    last_exc = exc
                    if attempt < self._MAX_RETRIES:
                        backoff = self._RETRY_BASE_SEC * (2 ** (attempt - 1))
                        log.warning(
                            "Feed '%s' attempt %d/%d failed: %s — retrying in %ds",
                            name, attempt, self._MAX_RETRIES, exc, backoff,
                        )
                        try:
                            await asyncio.sleep(backoff)
                        except asyncio.CancelledError:
                            raise

            if last_exc is not None:
                log.error("Feed '%s' failed after %d attempts: %s", name, self._MAX_RETRIES, last_exc)
                try:
                    await self._intel_db.record_feed_attempt(
                        name, success=False, error=str(last_exc),
                    )
                except Exception:
                    pass  # don't let health recording crash the loop

    # ── Offline exploit index refresh ────────────────────────────────────────

    async def _offline_refresh(self) -> int:
        """
        Force re-download of ExploitDB and Metasploit offline indexes.
        Called weekly; returns 0 (count not meaningful for offline indexes).
        """
        if self._intel_pipeline is None:
            return 0
        try:
            await self._intel_pipeline.refresh_offline()
            health = self._intel_pipeline.get_source_health()
            edb_cves = health.get("exploitdb", {}).get("total_cves", 0)
            msf_cves = health.get("metasploit", {}).get("total_cves", 0)
            log.info(
                "Offline indexes refreshed: exploitdb=%d CVEs  metasploit=%d CVEs",
                edb_cves, msf_cves,
            )
            return edb_cves + msf_cves
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            log.warning("Offline index refresh failed: %s", exc)
            raise

    # ── Proactive CVE scanner ─────────────────────────────────────────────────

    async def _proactive_cvescan(self) -> int:
        """
        Query the latest packages payload for every enrolled agent and run
        NVD CVE lookups for any package not already in the CVE cache.
        Emits findings directly to IntelDB for critical/high CVEs.

        Returns the number of new CVE findings emitted.
        """
        new_findings = 0
        try:
            agent_packages = await self._db.get_latest_packages_per_agent()
        except Exception as exc:
            log.warning("Proactive CVE scan: DB query failed: %s", exc)
            raise

        for agent_id, packages in agent_packages:
            if not isinstance(packages, list):
                continue
            for pkg in packages:
                if not isinstance(pkg, dict):
                    continue
                name    = str(pkg.get("name", "")    or "").strip().lower()
                version = str(pkg.get("version", "") or "").strip()
                if not name:
                    continue

                try:
                    cves = await self._nvd.lookup(name, version)
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    log.debug("CVE lookup failed %s: %s", name, exc)
                    continue

                for cve in cves:
                    score = cve.get("cvss_score") or 0.0
                    if score < _CVE_MIN_SCORE:
                        continue
                    sev = cve.get("severity", "high")
                    finding = {
                        "agent_id":        agent_id,
                        "category":        "package",
                        "item_key":        f"cve:{name}:{cve['cve_id']}",
                        "severity":        sev,
                        "score":           round(float(score), 2),
                        "title":           f"CVE in {name}: {cve['cve_id']} (CVSS {score})",
                        "description":     (cve.get("description") or "")[:300],
                        "evidence":        {"package": name, "version": version, "cve": cve},
                        "source":          "nvd:proactive",
                        "rule_id":         "nvd:proactive",
                        "mitre_technique": "T1190",
                        "mitre_tactic":    "Initial Access",
                        "cve_ids":         [cve["cve_id"]],
                        "cvss_score":      score,
                        "cvss_vector":     cve.get("cvss_vector", ""),
                        "tags":            ["cve", "package", "proactive", name],
                    }
                    try:
                        result = await self._intel_db.upsert_finding(finding, time.time())
                        if result == "new":
                            new_findings += 1
                            log.info(
                                "Proactive CVE: new finding agent=%s pkg=%s cve=%s score=%.1f",
                                agent_id, name, cve["cve_id"], score,
                            )
                    except asyncio.CancelledError:
                        raise
                    except Exception as exc:
                        log.debug("CVE finding upsert failed: %s", exc)

        log.info(
            "Proactive CVE scan complete: %d agents, %d new findings",
            len(agent_packages), new_findings,
        )
        return new_findings

    async def _nvd_recent_sync(self) -> int:
        """
        Continuously hydrate the local CVE cache from NVD's modified feed.
        Kept deliberately bounded so a slow NVD response cannot starve ingest,
        Jarvis work, or the dashboard.
        """
        try:
            count = await self._nvd.sync_recent(hours=48, max_pages=3)
            log.info("NVD recent sync complete: %d CVEs cached", count)
            return count
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            log.warning("NVD recent sync failed: %s", exc)
            raise
