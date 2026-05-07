"""
manager/manager/workers/intel.py — ThreatIntelWorker.

Runs the continuous threat intelligence collection pipeline as independent
asyncio tasks — one per feed, each on its own schedule.

Responsibilities
----------------
  1. Feodo Tracker IP feed          — every 1 h
  2. Emerging Threats IP feed       — every 1 h
  3. URLhaus domain/URL feed        — every 2 h
  4. Proactive CVE re-scan          — every 6 h
     Queries the latest packages payload per agent, checks each package
     against the NVD cache, and emits new critical/high findings directly
     into IntelDB — without waiting for fresh telemetry from the agent.
  5. NVD modified CVE sync          — every 2 h
     Pulls recently changed CVEs into the local threat-intel cache so package
     correlation can use fresh intelligence without blocking ingest requests.

Design
------
- One asyncio.Task per scheduled job (not queue-based — scheduled I/O only).
- Each task runs immediately on startup, then sleeps for its interval.
- Feed health is persisted to intel.db after every attempt (success or fail).
- Proactive CVE scan uses the existing CVELookup instance (shared rate-limit
  lock with the JarvisEngine NVD worker — they serialize fairly).
- Fully cancellable: stop() cancels all tasks and awaits them.
"""
from __future__ import annotations

import asyncio
import logging
import time
from typing import TYPE_CHECKING, Callable, Awaitable

if TYPE_CHECKING:
    from ..indexer       import IntelDB
    from ..db            import Database
    from ..jarvis.feeds  import FeedManager
    from ..jarvis.nvd    import CVELookup

log = logging.getLogger("manager.workers.intel")

# Schedules (seconds)
_INTERVAL_FEODO    =  3_600   # 1 h
_INTERVAL_EMERGING =  3_600   # 1 h
_INTERVAL_URLHAUS  =  7_200   # 2 h
_INTERVAL_NVD_SYNC =  7_200   # 2 h
_INTERVAL_CVE_SCAN = 21_600   # 6 h

# Proactive CVE scan: only emit findings at or above this CVSS threshold
_CVE_MIN_SCORE = 7.0


class ThreatIntelWorker:
    """
    Continuous threat intelligence collection worker.
    Create once at server startup; call start() then await stop() on shutdown.
    """

    def __init__(
        self,
        intel_db: "IntelDB",
        db:       "Database",
        feeds:    "FeedManager",
        nvd:      "CVELookup",
    ) -> None:
        self._intel_db = intel_db
        self._db       = db
        self._feeds    = feeds
        self._nvd      = nvd
        self._tasks:   list[asyncio.Task] = []

    async def start(self) -> None:
        """Spawn one asyncio task per scheduled job."""
        self._tasks = [
            asyncio.create_task(
                self._feed_loop("feodo",       self._feeds.refresh_feodo,    _INTERVAL_FEODO),
                name="intel:feodo",
            ),
            asyncio.create_task(
                self._feed_loop("emerging",    self._feeds.refresh_emerging, _INTERVAL_EMERGING),
                name="intel:emerging",
            ),
            asyncio.create_task(
                self._feed_loop("urlhaus",     self._feeds.refresh_urlhaus,  _INTERVAL_URLHAUS),
                name="intel:urlhaus",
            ),
            asyncio.create_task(
                self._feed_loop("nvd_recent",  self._nvd_recent_sync,        _INTERVAL_NVD_SYNC),
                name="intel:nvd_recent",
            ),
            asyncio.create_task(
                self._feed_loop("proactive_cve", self._proactive_cvescan,    _INTERVAL_CVE_SCAN),
                name="intel:proactive_cve",
            ),
        ]
        log.info("ThreatIntelWorker started — %d feed tasks", len(self._tasks))

    async def stop(self) -> None:
        """Cancel all tasks and wait for them to exit."""
        for t in self._tasks:
            t.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        log.info("ThreatIntelWorker stopped")

    # ── Feed loop ─────────────────────────────────────────────────────────────

    async def _feed_loop(
        self,
        name:     str,
        fn:       Callable[[], Awaitable[int]],
        interval: int,
    ) -> None:
        """
        Run *fn* immediately, then every *interval* seconds.
        Records health in intel.db after every attempt.
        """
        delay = 0  # run on first iteration without waiting
        while True:
            await asyncio.sleep(delay)
            delay = interval  # subsequent iterations use full interval

            attempt_ts = time.time()
            try:
                count = await fn()
                await self._intel_db.record_feed_attempt(
                    name, success=True, entry_count=count,
                )
                log.info("Feed '%s': %d entries refreshed", name, count)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                log.warning("Feed '%s' failed: %s", name, exc)
                try:
                    await self._intel_db.record_feed_attempt(
                        name, success=False, error=str(exc),
                    )
                except Exception:
                    pass  # don't let health recording crash the loop

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
            return 0

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
            return 0
