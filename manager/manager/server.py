"""
manager/server.py — FastAPI application factory.

Endpoints (via api/ routers):
  POST /api/v1/ingest
  GET  /api/v1/agents
  GET  /api/v1/agents/{id}
  GET  /api/v1/agents/{id}/sections
  GET  /api/v1/agents/{id}/{section}
  GET  /health
  WS   /ws/{agent_id}
  GET  /

Run:
  ./scripts/run_manager.sh
  or:
  uvicorn manager.server:app --ssl-keyfile certs/server.key \\
      --ssl-certfile certs/server.crt --host 0.0.0.0 --port 8443
"""
from __future__ import annotations

import asyncio
import logging
import logging.handlers
import os
import sys
import time

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from .db        import Database
from .store     import TelemetryStore
from .ws_hub    import WebSocketHub
from .indexer   import IntelDB
from .attacklens  import AttackLensEngine
from .pool        import AgentRateLimiter
from .queue.producer      import QueueProducer
from .workers.telemetry   import TelemetryWorker
from .workers.attacklens  import AttackLensWorker
from .chunk_tracker       import ChunkTracker
from .workers.intel       import ThreatIntelWorker
from .workers.enrichment  import EnrichmentWorker
from .workers.consumer    import TelemetryConsumer
from .threat.nvd_sync     import NVDSyncWorker
from .ai_analyst          import AIAnalyst
from .notifications.email import EmailNotifier
from .api.remediation     import router as remediation_router
from shared.wire import REPLAY_WINDOW_SECONDS

log = logging.getLogger("manager")


def setup_logging(
    level: str = "INFO",
    logfile: str = "manager/logs/manager.log",
    max_mb: int = 50,
    backups: int = 5,
) -> None:
    """Configure rotating file + stderr logging for the manager."""
    os.makedirs(os.path.dirname(logfile), exist_ok=True)
    lvl = getattr(logging, level.upper(), logging.INFO)
    handler = logging.handlers.RotatingFileHandler(
        logfile,
        maxBytes=max_mb * 1024 * 1024,
        backupCount=backups,
    )
    fmt = logging.Formatter("%(asctime)s %(name)s %(levelname)s %(message)s")
    handler.setFormatter(fmt)
    root = logging.getLogger()
    root.setLevel(lvl)
    if not any(isinstance(h, logging.handlers.RotatingFileHandler) for h in root.handlers):
        root.addHandler(handler)


def create_app() -> FastAPI:
    # ── Config from env ───────────────────────────────────────────────────────
    # API_KEY is now optional — used only for WebSocket token auth.
    # Per-agent keys are stored in the agent_keys SQLite table after enrollment.
    api_key = os.environ.get("API_KEY", "")

    data_dir = os.environ.get("DATA_DIR", os.path.join(
        os.path.dirname(os.path.dirname(__file__)), "data"
    ))
    db_path    = os.path.join(data_dir, "manager.db")
    intel_path = os.path.join(data_dir, "intel.db")
    os.makedirs(data_dir, exist_ok=True)

    rabbitmq_url = os.environ.get("RABBITMQ_URL", "").strip()
    threat_intel_url = os.environ.get("THREAT_INTEL_URL", "").strip().rstrip("/")
    embedded_threat_intel = os.environ.get(
        "MANAGER_EMBEDDED_THREAT_INTEL", "true"
    ).lower() not in ("false", "0", "no", "off")

    db       = Database(db_path)
    store    = TelemetryStore(data_dir)
    hub      = WebSocketHub()
    intel_db = IntelDB(intel_path)
    engine   = AttackLensEngine(db, intel_db)
    producer: QueueProducer | None = QueueProducer(rabbitmq_url) if rabbitmq_url else None
    chunk_tracker = ChunkTracker()

    # Per-agent rate limiter: 10 req/s sustained, burst 30, max 4 concurrent per agent.
    # Override via env: AGENT_RATE=20 AGENT_BURST=60 AGENT_SLOTS=8
    rate_limiter = AgentRateLimiter(
        rate=float(os.environ.get("AGENT_RATE",  "10")),
        burst=float(os.environ.get("AGENT_BURST", "30")),
        max_slots=int(os.environ.get("AGENT_SLOTS", "4")),
    )
    _tel_worker:    TelemetryWorker | None = None
    _al_worker:     AttackLensWorker | None = None
    _intel_worker:  ThreatIntelWorker | None = None
    _enrich_worker: EnrichmentWorker | None = None
    _tel_consumer:  TelemetryConsumer | None = None
    _nvd_sync:      NVDSyncWorker | None = None

    # ── App ───────────────────────────────────────────────────────────────────
    app = FastAPI(title="mac_intel Manager", version="1.0.0", docs_url=None)

    # CORS: default to same-origin only in production.
    # Set CORS_ORIGINS=https://your-dashboard.example.com in production env.
    # Use CORS_ORIGINS=* only for local development.
    _cors_origins = [
        o.strip()
        for o in os.environ.get("CORS_ORIGINS", "").split(",")
        if o.strip()
    ] or ["*"]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_cors_origins,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
        allow_credentials=True,
        max_age=600,
    )

    # Nonce cache is now DB-backed (nonce_cache table in manager.db).
    # This dict is kept for API compatibility with make_ingest_router signature
    # but is no longer used for deduplication logic.
    nonce_cache: dict[str, float] = {}

    async def _cleanup_store():
        """Hourly file-store cleanup job."""
        while True:
            await asyncio.sleep(3600)
            try:
                stats = await store.cleanup()
                log.info("Store cleanup: %s", stats)
            except Exception as exc:
                log.warning("Store cleanup error: %s", exc)

    async def _expire_chunks():
        """Periodic chunk-tracker expiry — prevents unbounded memory growth."""
        while True:
            await asyncio.sleep(300)
            n = await chunk_tracker.expire_old()
            if n:
                log.warning("Chunk tracker expired %d stale chunk set(s)", n)

    async def _dev_bootstrap_agent_key():
        """
        Local dev: agent.toml and manager share one key via API_KEY, but ingest
        looks up HMAC keys in agent_keys. Seed the row so crypto matches without
        a separate enroll step. Enable with MACOS_INTEL_DEV_BOOTSTRAP=1 (run_manager.sh).
        """
        if os.environ.get("MACOS_INTEL_DEV_BOOTSTRAP") != "1":
            return
        raw = (api_key or "").strip()
        if len(raw) != 64 or any(c not in "0123456789abcdefABCDEF" for c in raw):
            log.warning(
                "Dev bootstrap skipped: API_KEY must be 64 hex chars (same as [manager] api_key)"
            )
            return
        key = raw.lower()
        aid = os.environ.get("BOOTSTRAP_AGENT_ID", "agent-001").strip()
        name = os.environ.get("BOOTSTRAP_AGENT_NAME", "dev")
        await db.upsert_agent(aid, name, "127.0.0.1")
        await db.upsert_agent_key(aid, key, enrolled_ip="dev-bootstrap")
        log.info("Dev bootstrap: agent_keys synced for agent_id=%s (ingest HMAC will match)", aid)

    @app.on_event("startup")
    async def startup():
        nonlocal _tel_worker, _al_worker, _intel_worker, _enrich_worker, _tel_consumer, _nvd_sync
        setup_logging(
            logfile=os.environ.get("LOG_FILE", "manager/logs/manager.log"),
            level=os.environ.get("LOG_LEVEL", "INFO"),
        )
        await db.init()  # initialises the SQLitePool (readers=4)
        await _dev_bootstrap_agent_key()
        await store.init()
        await intel_db.init()
        await engine.start()
        asyncio.create_task(_cleanup_store())
        asyncio.create_task(_expire_chunks())

        if producer is not None:
            await producer.start()
            _tel_worker = TelemetryWorker(rabbitmq_url, db, store, hub, producer)
            _al_worker  = AttackLensWorker(rabbitmq_url, engine, chunk_tracker)
            asyncio.create_task(_tel_worker.run())
            asyncio.create_task(_al_worker.run())
            _tel_consumer = TelemetryConsumer(rabbitmq_url, db, store, hub, producer, engine)
            asyncio.create_task(_tel_consumer.run())
            log.info("RabbitMQ: producer + workers + consumer started (url=%s)", rabbitmq_url)
        else:
            log.info("RabbitMQ: not configured — sync pipeline active")

        if embedded_threat_intel:
            _intel_worker = ThreatIntelWorker(intel_db, db, engine.feeds, engine.nvd)
            await _intel_worker.start()
        else:
            log.info("Threat intel: central mode enabled (url=%s)", threat_intel_url or "not set")

        # AI analyst + email notifier — attach to app.state for route access
        ai_analyst     = AIAnalyst(intel_db, engine.feeds)
        email_notifier = EmailNotifier()
        app.state.intel_db      = intel_db
        app.state.ai_analyst    = ai_analyst
        app.state.email_notifier = email_notifier
        app.state.feeds         = engine.feeds
        log.info("AI Analyst enabled=%s  Email enabled=%s",
                 ai_analyst.enabled, email_notifier.enabled)

        _enrich_worker = EnrichmentWorker(intel_db, rabbitmq_url or None)
        await _enrich_worker.start()

        _nvd_sync = NVDSyncWorker(intel_db)
        await _nvd_sync.start()

        log.info("Manager started. DB=%s  Intel=%s  Data=%s",
                 db_path, intel_path, data_dir)
        log.info("Enrollment mode: %s",
                 "OPEN (no token required)" if open_enrollment else
                 f"TOKEN ({len(enrollment_tokens)} token(s) configured)")

    @app.on_event("shutdown")
    async def shutdown():
        if _nvd_sync:
            await _nvd_sync.stop()
        if _enrich_worker:
            await _enrich_worker.stop()
        if _tel_consumer:
            await _tel_consumer.stop()
        if _intel_worker:
            await _intel_worker.stop()
        if _tel_worker:
            await _tel_worker.stop()
        if _al_worker:
            await _al_worker.stop()
        if producer is not None:
            await producer.stop()
        await store.close()
        await intel_db.close()   # closes the SQLitePool
        await db.close()         # closes the SQLitePool

    # ── Mount routers ─────────────────────────────────────────────────────────
    from .api.ingest    import make_ingest_router
    from .api.agents    import make_agents_router
    from .api.enroll    import make_enroll_router
    from .api.attacklens import make_attacklens_router
    from .api.keys      import make_keys_router
    from .api.findings  import make_findings_router
    from .api.threat    import make_threat_router
    from .api.raw       import make_raw_router
    from .api.assets    import make_assets_router
    from .api.posture    import make_posture_router
    from .api.detection  import make_detection_router
    from .api.accuracy   import make_accuracy_router
    from .api.settings   import make_settings_router

    enrollment_tokens = os.environ.get("ENROLLMENT_TOKENS", "").split(",")
    enrollment_tokens = [t.strip() for t in enrollment_tokens if t.strip()]

    # Open enrollment: accept any agent without a token.
    # Default: True (no token needed — just provide manager IP on agent install).
    # Set OPEN_ENROLLMENT=false in env to require tokens.
    _open_env     = os.environ.get("OPEN_ENROLLMENT", "true").lower()
    open_enrollment = _open_env not in ("false", "0", "no", "off")

    admin_token = os.environ.get("ADMIN_TOKEN", "").strip()

    ingest_router    = make_ingest_router(
        db, store, hub, nonce_cache, engine,
        producer=producer,
        rate_limiter=rate_limiter,
    )
    agents_router      = make_agents_router(db, store)
    enroll_router      = make_enroll_router(db, enrollment_tokens, open_enrollment)
    attacklens_router  = make_attacklens_router(intel_db, engine)
    keys_router      = make_keys_router(db, admin_token)
    findings_router  = make_findings_router(intel_db)
    threat_router    = make_threat_router(intel_db, central_url=threat_intel_url)

    raw_router    = make_raw_router(db)
    assets_router  = make_assets_router(db, intel_db)
    posture_router    = make_posture_router(db, intel_db)
    detection_router  = make_detection_router(intel_db)
    accuracy_router   = make_accuracy_router(intel_db)
    settings_router   = make_settings_router(intel_db)

    app.include_router(ingest_router,       prefix="/api/v1")
    app.include_router(agents_router,       prefix="/api/v1/agents")
    app.include_router(enroll_router,       prefix="/api/v1")
    app.include_router(attacklens_router,   prefix="/api/v1/attacklens")
    app.include_router(keys_router,      prefix="/api/v1/keys")
    app.include_router(findings_router,  prefix="/api/v1/soc")
    app.include_router(threat_router,    prefix="/api/v1/threat")
    app.include_router(raw_router,       prefix="/api/v1/raw")
    app.include_router(assets_router,    prefix="/api/v1/assets")
    app.include_router(posture_router,    prefix="/api/v1/posture")
    app.include_router(detection_router,  prefix="/api/v1/detection")
    app.include_router(accuracy_router,   prefix="/api/v1/accuracy")
    app.include_router(settings_router,   prefix="/api/v1/settings")
    app.include_router(remediation_router)  # prefixes defined inline

    # ── Global exception handler ──────────────────────────────────────────────
    @app.exception_handler(Exception)
    async def global_exception_handler(request: Request, exc: Exception):
        log.exception("Unhandled error on %s %s", request.method, request.url.path)
        return JSONResponse(
            status_code=500,
            content={"error": "Internal server error", "detail": str(exc)},
        )

    # ── Health ────────────────────────────────────────────────────────────────
    @app.get("/health")
    async def health():
        try:
            ok = await db.ping()
        except Exception:
            ok = False
        try:
            idx_stats = await store.index.stats()
        except Exception:
            idx_stats = {}
        try:
            intel_stats = await intel_db.stats()
        except Exception:
            intel_stats = {}
        status = "ok" if ok else "degraded"
        return {
            "status": status,
            "db":     "ok" if ok else "error",
            "store":  idx_stats,
            "intel":  intel_stats,
        }

    # ── Enrichment ────────────────────────────────────────────────────────────
    @app.post("/api/v1/enrich/{finding_id}")
    async def enrich_finding(finding_id: str):
        if _enrich_worker is None:
            raise HTTPException(status_code=503, detail="Enrichment worker not running")
        try:
            updated = await _enrich_worker.enrich_finding_now(finding_id)
        except Exception as exc:
            log.exception("enrichment failed for finding=%s", finding_id)
            raise HTTPException(status_code=500, detail=str(exc))
        if not updated:
            raise HTTPException(status_code=404, detail="finding not found")
        return updated

    # ── WebSocket ─────────────────────────────────────────────────────────────
    @app.get("/api/v1/dashboard/ws-token")
    async def dashboard_ws_token():
        """Return the WS auth token for the browser dashboard. Internal use only."""
        return {"token": (api_key or "").strip()}

    @app.websocket("/ws/{agent_id}")
    async def ws_endpoint(websocket: WebSocket, agent_id: str):
        token = websocket.query_params.get("token", "").strip()
        master = (api_key or "").strip()
        ok = False
        if not master:
            ok = True  # no API_KEY set → open WS (dev / internal mode)
        elif token and token.lower() == master.lower():
            ok = True
        elif token:
            agent_key = await db.get_agent_key(agent_id)
            if agent_key and token.lower() == agent_key.lower():
                ok = True
        if not ok:
            await websocket.close(code=4001)
            return

        await websocket.accept()
        await hub.connect(agent_id, websocket)
        try:
            await websocket.send_json({
                "type":        "hello",
                "agent_id":    agent_id,
                "server_time": int(time.time()),
            })
            while True:
                await websocket.receive_text()
        except WebSocketDisconnect:
            pass
        finally:
            await hub.disconnect(agent_id, websocket)

    # ── Dashboard ─────────────────────────────────────────────────────────────
    _pkg_root     = os.path.dirname(os.path.dirname(__file__))
    dashboard_dir = os.path.join(_pkg_root, "dashboard", "static")
    if os.path.isdir(dashboard_dir):
        app.mount("/static", StaticFiles(directory=dashboard_dir), name="static")

    @app.get("/", response_class=HTMLResponse)
    async def dashboard():
        # Serve from static/index.html — vite build keeps this current.
        # templates/index.html is a stale copy; reading from static avoids drift.
        for candidate in [
            os.path.join(_pkg_root, "dashboard", "static", "index.html"),
            os.path.join(_pkg_root, "dashboard", "templates", "index.html"),
        ]:
            if os.path.isfile(candidate):
                with open(candidate) as f:
                    return f.read()
        log.error("Dashboard index.html not found under dashboard/static or dashboard/templates")
        return HTMLResponse(
            "<h1>Dashboard unavailable</h1><p>Run: npm run build inside the frontend directory.</p>",
            status_code=503,
        )

    return app


app = create_app()

if __name__ == "__main__":
    import uvicorn
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    _root  = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
    _certs = os.path.join(_root, "certs")
    uvicorn.run(
        "manager.server:app",
        host=os.environ.get("BIND_HOST", "0.0.0.0"),
        port=int(os.environ.get("BIND_PORT", "8443")),
        ssl_keyfile=os.environ.get("TLS_KEY",  os.path.join(_certs, "server.key")),
        ssl_certfile=os.environ.get("TLS_CERT", os.path.join(_certs, "server.crt")),
        log_level="info",
    )
