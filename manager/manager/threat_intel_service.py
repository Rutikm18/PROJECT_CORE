"""
Standalone central Threat Intel service.

This app owns threat-intel collection and read APIs when AttackLens is deployed
centrally for multiple dashboards. It intentionally does not depend on agent
ingest or dashboard state; manager services can keep using their own raw agent
DB while this service maintains the shared intel DB.
"""
from __future__ import annotations

import asyncio
import logging
import os
import time
from typing import Any

from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware

from .indexer import IntelDB
from .pg_pool import _redact_dsn
from .attacklens.feeds import FeedManager
from .attacklens.nvd import CVELookup
from .threat.nvd_sync import NVDSyncWorker

log = logging.getLogger("threat_intel")

FEED_INTERVAL_SECONDS = int(os.environ.get("THREAT_FEED_INTERVAL_SECONDS", "3600"))
NVD_INTERVAL_SECONDS = int(os.environ.get("NVD_SYNC_INTERVAL_SECONDS", "7200"))
NVD_SYNC_HOURS = int(os.environ.get("NVD_SYNC_HOURS", "48"))
NVD_SYNC_MAX_PAGES = int(os.environ.get("NVD_SYNC_MAX_PAGES", "3"))
NVD_MIRROR_ENABLED = os.environ.get("NVD_MIRROR_ENABLED", "true").strip().lower() in {
    "1", "true", "yes", "on",
}


class CentralThreatIntelWorker:
    """Bounded background loops for feeds and NVD modified-CVE sync."""

    def __init__(self, intel_db: IntelDB) -> None:
        self.intel_db = intel_db
        self.feeds = FeedManager(intel_db)
        self.nvd = CVELookup(intel_db)
        self.nvd_mirror = NVDSyncWorker(intel_db) if NVD_MIRROR_ENABLED else None
        self._tasks: list[asyncio.Task] = []

    async def start(self) -> None:
        await self.feeds.refresh()
        if self.nvd_mirror:
            await self.nvd_mirror.start()
        self._tasks = [
            # Core IP/domain threat feeds
            asyncio.create_task(self._loop("feodo",           self.feeds.refresh_feodo,           FEED_INTERVAL_SECONDS)),
            asyncio.create_task(self._loop("emerging",        self.feeds.refresh_emerging,         FEED_INTERVAL_SECONDS)),
            asyncio.create_task(self._loop("urlhaus",         self.feeds.refresh_urlhaus,          FEED_INTERVAL_SECONDS * 2)),
            asyncio.create_task(self._loop("threatfox",       self.feeds.refresh_threatfox,        FEED_INTERVAL_SECONDS * 2)),
            asyncio.create_task(self._loop("spamhaus",        self.feeds.refresh_spamhaus,         FEED_INTERVAL_SECONDS * 6)),
            # Vulnerability intel
            asyncio.create_task(self._loop("cisa_kev",        self.feeds.refresh_cisa_kev,         FEED_INTERVAL_SECONDS * 4)),
            # Threat actors + news
            asyncio.create_task(self._loop("ransomware_live", self.feeds.refresh_ransomware_live,  FEED_INTERVAL_SECONDS * 3)),
            asyncio.create_task(self._loop("security_news",   self.feeds.refresh_security_news,    FEED_INTERVAL_SECONDS * 2)),
        ]
        if not self.nvd_mirror:
            self._tasks.append(asyncio.create_task(
                self._loop("nvd_recent", self._sync_nvd_recent, NVD_INTERVAL_SECONDS)
            ))
        log.info("Central threat-intel worker started (%d feed loops)", len(self._tasks))

    async def stop(self) -> None:
        for task in self._tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        if self.nvd_mirror:
            await self.nvd_mirror.stop()

    async def _loop(self, source: str, fn, interval: int, initial_delay: int = 0) -> None:
        delay = initial_delay
        while True:
            await asyncio.sleep(delay)
            delay = interval
            try:
                count = await fn()
                await self.intel_db.record_feed_attempt(source, success=True, entry_count=count)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                log.warning("%s refresh failed: %s", source, exc)
                await self.intel_db.record_feed_attempt(source, success=False, error=str(exc))

    async def _sync_nvd_recent(self) -> int:
        return await self.nvd.sync_recent(hours=NVD_SYNC_HOURS, max_pages=NVD_SYNC_MAX_PAGES)

    async def correlate_packages(self, packages: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Return CVE matches for a supplied package inventory."""
        matches: list[dict[str, Any]] = []
        for pkg in packages:
            if not isinstance(pkg, dict):
                continue
            name = str(pkg.get("name", "") or "").strip().lower()
            version = str(pkg.get("version", "") or "").strip()
            manager = str(pkg.get("manager", "") or "").strip()
            if not name:
                continue
            for cve in await self.nvd.lookup(name, version):
                score = cve.get("cvss_score") or 0
                if score < 4.0:
                    continue
                matches.append({
                    "package": name,
                    "version": version,
                    "manager": manager,
                    "cve": cve,
                    "severity": cve.get("severity", "medium"),
                    "score": score,
                    "matched_at": time.time(),
                })
        return matches


def create_app() -> FastAPI:
    default_data_dir = os.path.join(
        os.path.dirname(os.path.dirname(__file__)), "data", "threat-intel"
    )
    data_dir = os.environ.get("THREAT_INTEL_DATA_DIR") or os.environ.get("DATA_DIR", default_data_dir)
    os.makedirs(data_dir, exist_ok=True)
    # This service's intel DB is intentionally a SEPARATE Postgres database
    # from the per-manager-instance one in server.py (it's the centrally
    # shared store described in the module docstring, not the same "intel"
    # database) — own env var, own default database name.
    database_url = os.environ.get(
        "DATABASE_URL", "postgresql://attacklens:attacklens@localhost:5432"
    ).rstrip("/")
    db_path = os.environ.get("THREAT_INTEL_DATABASE_URL", f"{database_url}/threat_intel")

    app = FastAPI(
        title="AttackLens Central Threat Intel",
        version="1.0.0",
        docs_url="/docs",
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=os.environ.get("CORS_ORIGINS", "*").split(","),
        allow_methods=["*"],
        allow_headers=["*"],
    )

    intel_db = IntelDB(db_path)
    worker = CentralThreatIntelWorker(intel_db)

    @app.on_event("startup")
    async def startup() -> None:
        logging.basicConfig(
            level=getattr(logging, os.environ.get("LOG_LEVEL", "INFO").upper(), logging.INFO),
            format="%(asctime)s %(name)s %(levelname)s %(message)s",
        )
        await intel_db.init()
        await worker.start()
        app.state.intel_db = intel_db
        app.state.worker = worker
        log.info("Threat intel service started DB=%s", _redact_dsn(db_path))

    @app.on_event("shutdown")
    async def shutdown() -> None:
        await worker.stop()
        await intel_db.close()

    @app.get("/health")
    async def health() -> dict[str, Any]:
        return {"status": "ok", "service": "threat-intel", "db": _redact_dsn(db_path)}

    @app.get("/api/v1/intel/summary")
    async def summary() -> dict[str, Any]:
        overview = await intel_db.get_threat_intel_overview()
        nvd = await intel_db.get_nvd_stats()
        if nvd.get("total", 0):
            overview["cves"] = nvd["total"]
            overview["cve_by_severity"] = nvd.get("by_severity", {})
        return overview

    @app.get("/api/v1/intel/feeds")
    async def feeds() -> dict[str, Any]:
        rows = await intel_db.get_all_feed_health()
        return {"feeds": rows, "count": len(rows)}

    @app.get("/api/v1/intel/snapshot")
    async def snapshot() -> dict[str, Any]:
        """Atomic hot-cache snapshot consumed by manager detection engines."""
        return worker.feeds.export_snapshot()

    @app.get("/api/v1/intel/nvd/stats")
    async def nvd_stats() -> dict[str, Any]:
        return await intel_db.get_nvd_stats()

    @app.get("/api/v1/intel/nvd/search")
    async def nvd_search(
        q: str = Query(..., min_length=1, max_length=256),
        limit: int = Query(20, ge=1, le=200),
    ) -> dict[str, Any]:
        rows = await intel_db.search_nvd_local(q.lower(), limit=limit)
        return {"results": rows, "count": len(rows), "query": q}

    @app.get("/api/v1/intel/nvd/{cve_id}")
    async def nvd_by_id(cve_id: str) -> dict[str, Any]:
        from fastapi import HTTPException
        cve = await intel_db.get_nvd_local_by_id(cve_id)
        if not cve:
            cve = await intel_db.get_cve_by_id(cve_id.upper())
        if not cve:
            raise HTTPException(404, f"CVE not found: {cve_id}")
        return {"cve": CVELookup._normalize_local_row(cve)}

    @app.get("/api/v1/intel/iocs")
    async def iocs(
        ioc_type: str = Query("ip", pattern="^(ip|domain|hash)$"),
        source: str | None = Query(None, max_length=80),
        limit: int = Query(100, ge=1, le=1000),
        offset: int = Query(0, ge=0),
    ) -> dict[str, Any]:
        rows = await intel_db.get_all_iocs(ioc_type)
        if source:
            rows = [row for row in rows if row.get("source") == source]
        return {
            "iocs": rows[offset:offset + limit], "total": len(rows),
            "offset": offset, "limit": limit,
        }

    @app.get("/api/v1/intel/cves")
    async def cves(
        severity: str | None = Query(None),
        limit: int = Query(100, ge=1, le=1000),
        offset: int = Query(0, ge=0),
    ) -> dict[str, Any]:
        rows = await intel_db.list_nvd_local(
            severity=severity, limit=limit, offset=offset,
        )
        if not rows:
            rows = await intel_db.list_cves(severity=severity, limit=limit, offset=offset)
        return {"cves": rows, "count": len(rows), "offset": offset}

    @app.post("/api/v1/intel/correlate/packages")
    async def correlate_packages(payload: dict[str, Any]) -> dict[str, Any]:
        packages = payload.get("packages", [])
        if not isinstance(packages, list):
            packages = []
        matches = await worker.correlate_packages(packages)
        return {"matches": matches, "count": len(matches)}

    @app.get("/api/v1/intel/kev")
    async def kev_list(
        limit: int = Query(200, ge=1, le=2000),
    ) -> dict[str, Any]:
        rows  = await intel_db.list_kev(limit=limit)
        count = await intel_db.kev_count()
        return {"vulnerabilities": rows, "total": count, "returned": len(rows)}

    @app.get("/api/v1/intel/actors")
    async def actors_list(
        active_only: bool = Query(True),
        limit: int = Query(100, ge=1, le=500),
    ) -> dict[str, Any]:
        actors = await intel_db.get_threat_actors(active_only=active_only, limit=limit)
        total  = await intel_db.actor_count()
        return {"actors": actors, "total_active": total, "returned": len(actors)}

    @app.get("/api/v1/intel/news")
    async def news_list(
        hours: int = Query(48, ge=1, le=168),
        limit: int = Query(50, ge=1, le=200),
    ) -> dict[str, Any]:
        news = await intel_db.get_recent_news(hours=hours, limit=limit)
        return {"news": news, "count": len(news), "window_hours": hours}

    @app.get("/api/v1/intel/epss/top")
    async def epss_top(limit: int = Query(20, ge=1, le=100)) -> dict[str, Any]:
        rows = await intel_db._fetchall(
            "SELECT cve_id, epss, percentile, model_date FROM epss_scores "
            "ORDER BY epss DESC LIMIT ?", (limit,),
        )
        return {"scores": [dict(row) for row in rows], "count": len(rows)}

    @app.post("/api/v1/intel/epss/bulk")
    async def epss_bulk(payload: dict[str, Any]) -> dict[str, Any]:
        ids = payload.get("cve_ids") or []
        if not isinstance(ids, list):
            ids = []
        clean = [str(cve).upper() for cve in ids[:100] if str(cve).strip()]
        return {"scores": await intel_db.get_epss_bulk(clean)}

    @app.get("/api/v1/intel/epss/{cve_id}")
    async def epss_score(cve_id: str) -> dict[str, Any]:
        result = await worker.feeds.get_epss(cve_id.upper())
        if not result:
            from fastapi import HTTPException
            raise HTTPException(404, f"EPSS not available for {cve_id}")
        return result

    @app.get("/api/v1/intel/architecture")
    async def architecture() -> dict[str, Any]:
        return {
            "service": "central-threat-intel",
            "stores": [
                {
                    "name": "intel.db",
                    "owner": "threat-intel service",
                    "purpose": "NVD CVEs, IOC cache, feed health, findings metadata, and correlation inputs",
                },
                {
                    "name": "manager.db",
                    "owner": "manager service",
                    "purpose": "agent sessions, raw telemetry payload index, enrollment, and keys",
                },
            ],
            "flow": [
                "central threat-intel continuously syncs NVD and IOC feeds",
                "managers and dashboards query the central intel API",
                "agent telemetry remains in manager-owned raw stores",
                "correlation requests send normalized inventories or findings to central intel",
                "RabbitMQ and chunking remain in the manager ingest path for high-volume telemetry",
            ],
            "failure_handling": [
                "feed failures are recorded in feed_health and use cached intel",
                "NVD requests are rate-limited and bounded by page count",
                "manager ingest does not block on central intel availability",
                "dashboards can degrade to local findings while central intel recovers",
            ],
        }

    return app


app = create_app()
