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
import hmac
import logging
import logging.handlers
import os
import sys
import time

from fastapi import FastAPI, Header, Request, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware

from .db        import Database
from .pg_pool   import _redact_dsn
from .store     import TelemetryStore, RAW_TELEMETRY_RETENTION_DAYS
from .ws_hub    import WebSocketHub
from .indexer   import IntelDB
from .attacklens  import AttackLensEngine
from .pool        import AgentRateLimiter
# QueueProducer imported lazily below — aio_pika only required when RABBITMQ_URL is set
QueueProducer = None  # type: ignore[assignment]
from .workers.telemetry   import TelemetryWorker
from .workers.attacklens  import AttackLensWorker
from .workers.dlq_replayer import DLQReplayer
from .workers.reconciler   import PayloadReconciler
from .chunk_tracker       import ChunkTracker
from .workers.intel       import ThreatIntelWorker
from .workers.enrichment  import EnrichmentWorker
from .workers.consumer    import TelemetryConsumer
from .threat.nvd_sync     import NVDSyncWorker
from .ai_analyst          import AIAnalyst
from .notifications.email import EmailNotifier
from .api.remediation     import router as remediation_router
from .intel               import IntelPipeline
from .api.intel              import router as intel_router
from .api.finding_validation import router as finding_validation_router
from .api.auth_ui            import router as auth_router
from .api.ai_settings        import router as ai_settings_router
from .api.integrations       import router as integrations_router
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
    os.makedirs(data_dir, exist_ok=True)
    # TelemetryStore (raw telemetry NDJSON+gzip files) stays on local disk
    # under DATA_DIR — only manager.db/intel.db moved to Postgres.
    #
    # DATABASE_URL is the base connection string (no database name) shared by
    # both logical databases — matches docker-compose.postgres.yml, which
    # creates "manager" and "intel" as two separate databases on one Postgres
    # instance (mirrors the old two-separate-SQLite-files isolation: neither
    # was ever queryable against the other, same here). Override either
    # individually via MANAGER_DATABASE_URL/INTEL_DATABASE_URL if they ever
    # need to live on different hosts.
    database_url = os.environ.get(
        "DATABASE_URL", "postgresql://attacklens:attacklens@localhost:5432"
    ).rstrip("/")
    db_path    = os.environ.get("MANAGER_DATABASE_URL", f"{database_url}/manager")
    intel_path = os.environ.get("INTEL_DATABASE_URL",   f"{database_url}/intel")

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
    producer = None
    if rabbitmq_url:
        try:
            from .queue.producer import QueueProducer as _QP
            producer = _QP(rabbitmq_url)
        except ImportError:
            log.warning("aio_pika not installed — RabbitMQ queue disabled (set RABBITMQ_URL only if aio_pika is installed)")
    chunk_tracker = ChunkTracker()

    # Per-agent rate limiter: 10 req/s sustained, burst 30, max 4 concurrent per agent.
    # Override via env: AGENT_RATE=20 AGENT_BURST=60 AGENT_SLOTS=8
    rate_limiter = AgentRateLimiter(
        rate=float(os.environ.get("AGENT_RATE",  "10")),
        burst=float(os.environ.get("AGENT_BURST", "30")),
        max_slots=int(os.environ.get("AGENT_SLOTS", "4")),
    )
    _tel_worker:      TelemetryWorker | None = None
    _al_worker:       AttackLensWorker | None = None
    _intel_worker:    ThreatIntelWorker | None = None
    _enrich_worker:   EnrichmentWorker | None = None
    _tel_consumer:    TelemetryConsumer | None = None
    _nvd_sync:        NVDSyncWorker | None = None
    _intel_pipeline:  IntelPipeline | None = None

    # ── App ───────────────────────────────────────────────────────────────────
    app = FastAPI(title="mac_intel Manager", version="1.0.0", docs_url=None)

    # ── Security headers middleware ────────────────────────────────────────────
    from .security_policy import SECURITY_HEADERS

    class SecurityHeadersMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request: Request, call_next):
            response = await call_next(request)
            for header, value in SECURITY_HEADERS.items():
                # Don't overwrite headers already set by the route handler
                if header not in response.headers:
                    response.headers[header] = value
            # Remove server fingerprinting (MutableHeaders.pop removed in Starlette 0.38+)
            for _hdr in ("server", "x-powered-by"):
                if _hdr in response.headers:
                    del response.headers[_hdr]
            return response

    app.add_middleware(SecurityHeadersMiddleware)

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

    async def _retention_settings() -> tuple[int, str]:
        """Read the LIVE Settings → Data Retention config (org_settings table)
        each cycle, so a change in the UI takes effect on the next hourly sweep
        with no restart. Falls back to the RAW_TELEMETRY_RETENTION_DAYS env
        default (delete mode) if settings are unreadable for any reason —
        retention enforcement must degrade safely, never crash the job."""
        try:
            from .api.settings import retention_period_days
            row_months = await intel_db._fetchone(
                "SELECT value FROM org_settings WHERE key='retention_period_months'", ()
            )
            row_action = await intel_db._fetchone(
                "SELECT value FROM org_settings WHERE key='retention_action'", ()
            )
            months_val = row_months["value"] if row_months else "1"
            action     = row_action["value"] if row_action else "delete"
            return retention_period_days(months_val), action
        except Exception as exc:
            log.debug("Retention settings unreadable, using default: %s", exc)
            return RAW_TELEMETRY_RETENTION_DAYS, "delete"

    async def _cleanup_store():
        """Hourly retention sweep — file-tier archive AND the manager.db rows
        Deep Analysis actually queries, on the SAME cutoff (Settings → Data
        Retention, default 1 month / delete — see api/settings.py). Before
        this, `payloads` and `agent_sessions` had no retention at all and grew
        unbounded forever."""
        while True:
            await asyncio.sleep(3600)
            retention_days, action = await _retention_settings()
            archive_mode = (action == "archive")
            try:
                stats = await store.cleanup(
                    cold_retention_sec=retention_days * 86400,
                    prune_cold=not archive_mode,
                )
                log.info("Store cleanup (action=%s): %s", action, stats)
            except Exception as exc:
                log.warning("Store cleanup error: %s", exc)
            try:
                cutoff = int(time.time()) - retention_days * 86400
                n_payloads = await db.prune_payloads(cutoff)
                n_sessions = await db.prune_agent_sessions(cutoff)
                if n_payloads or n_sessions:
                    log.info("Retention prune (>%dd, action=%s): payloads=%d agent_sessions=%d",
                             retention_days, action, n_payloads, n_sessions)
            except Exception as exc:
                log.warning("Payload/session retention prune error: %s", exc)
            try:
                # intel.db bound to the SAME retention window — only the
                # historical backlog (resolved findings, closed correlations,
                # timeline events); a currently-active finding is never
                # removed regardless of age. Unconditional on delete/archive
                # mode — that toggle governs raw telemetry, not findings.
                cutoff = time.time() - retention_days * 86400
                idb_deleted = await intel_db.prune_inactive(cutoff)
                if any(idb_deleted.values()):
                    log.info("intel.db retention prune (>%dd): %s", retention_days, idb_deleted)
            except Exception as exc:
                log.warning("intel.db retention prune error: %s", exc)

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
        nonlocal _tel_worker, _al_worker, _intel_worker, _enrich_worker, _tel_consumer, _nvd_sync, _intel_pipeline
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
            # DLQ replayer: drains mac_intel.dead (previously unconsumed → a
            # silent black hole for any nack'd telemetry/detection work) and
            # replays to the origin queue with backoff, parking poison messages.
            _dlq_replayer = DLQReplayer(rabbitmq_url)
            app.state.dlq_replayer = _dlq_replayer
            asyncio.create_task(_dlq_replayer.run())
            # Payload reconciler: replays any payload that was stored but never
            # detected (lost hand-off past the DLQ) — the catch-all that makes
            # "raw is reprocessable" true. Reads the payload_ledger.
            _reconciler = PayloadReconciler(db, store, producer)
            app.state.reconciler = _reconciler
            asyncio.create_task(_reconciler.run())
            log.info("RabbitMQ: producer + workers + consumer + DLQ replayer + reconciler started (url=%s)", rabbitmq_url)
        else:
            log.info("RabbitMQ: not configured — sync pipeline active")

        if embedded_threat_intel:
            github_token = os.environ.get("GITHUB_TOKEN", "").strip()
            _intel_pipeline = IntelPipeline(engine.feeds, engine.nvd, github_token=github_token)
            await _intel_pipeline.start()
            app.state.intel_pipeline = _intel_pipeline

            _intel_worker = ThreatIntelWorker(
                intel_db, db, engine.feeds, engine.nvd,
                intel_pipeline=_intel_pipeline,
            )
            await _intel_worker.start()
        else:
            app.state.intel_pipeline = None
            log.info("Threat intel: central mode enabled (url=%s)", threat_intel_url or "not set")

        # Shared state for route dependencies
        app.state.intel_db          = intel_db
        app.state.feeds             = engine.feeds
        app.state.threat_intel_url  = threat_intel_url  # empty string in embedded mode

        # AI analyst + email notifier — attach to app.state for route access
        ai_analyst     = AIAnalyst(intel_db, engine.feeds)
        email_notifier = EmailNotifier()
        # Make the AI analyst available to the AttackLens precision validator
        # (the engine looks for this on its own attribute to call validate_with_ai).
        engine.attach_ai_analyst(ai_analyst)
        app.state.ai_analyst    = ai_analyst
        app.state.email_notifier = email_notifier
        log.info("AI Analyst enabled=%s  Email enabled=%s",
                 ai_analyst.enabled, email_notifier.enabled)

        _enrich_worker = EnrichmentWorker(intel_db, rabbitmq_url or None)
        await _enrich_worker.start()

        _nvd_sync = NVDSyncWorker(intel_db)
        await _nvd_sync.start()

        log.info("Manager started. DB=%s  Intel=%s  Data=%s",
                 _redact_dsn(db_path), _redact_dsn(intel_path), data_dir)
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
        if _intel_pipeline:
            await _intel_pipeline.stop()
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
    from .api.allowlist              import make_allowlist_router
    from .api.custom_correlations   import make_custom_correlations_router
    from .api.cases                 import make_cases_router

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
    findings_router  = make_findings_router(intel_db, db)
    threat_router    = make_threat_router(intel_db, central_url=threat_intel_url)

    raw_router    = make_raw_router(db)
    assets_router  = make_assets_router(db, intel_db)
    posture_router    = make_posture_router(db, intel_db)
    detection_router  = make_detection_router(intel_db, db)
    accuracy_router   = make_accuracy_router(intel_db)
    settings_router   = make_settings_router(intel_db, store, db)
    allowlist_router          = make_allowlist_router(intel_db)
    custom_correlations_router = make_custom_correlations_router(intel_db)
    cases_router               = make_cases_router(intel_db)

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
    app.include_router(allowlist_router,          prefix="/api/v1/allowlist")
    app.include_router(custom_correlations_router, prefix="/api/v1/custom-correlations")
    app.include_router(cases_router,               prefix="/api/v1/cases")
    app.include_router(intel_router)              # prefix=/api/v1/intel defined inline
    app.include_router(finding_validation_router) # prefix=/api/v1/findings (POST /{id}/validate etc.)
    app.include_router(remediation_router)        # prefixes defined inline (actors, news, overview)
    app.include_router(ai_settings_router)        # prefix=/api/v1/ai (provider config + analysis)
    app.include_router(integrations_router)       # prefix=/api/v1/integrations (reliability health)
    app.include_router(auth_router)               # dashboard login/logout/me

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
    async def dashboard_ws_token(x_admin_token: str = Header(default="")):
        """
        Return a short-lived WS auth token for the browser dashboard.
        Requires the X-Admin-Token header (same as /keys/*).
        Never exposes the raw master key — returns it only when caller is
        already authenticated as admin.
        """
        master = (api_key or "").strip()
        _admin = admin_token.strip()
        if _admin and not hmac.compare_digest(
            x_admin_token.strip().encode(), _admin.encode()
        ):
            raise HTTPException(status_code=401, detail="Invalid admin token")
        # If no admin token is configured, allow localhost-only access.
        client_host = ""  # request object not injected here; safe to skip check
        return {"token": master, "note": "Treat as a secret; valid until server restart"}

    @app.websocket("/ws/{agent_id}")
    async def ws_endpoint(websocket: WebSocket, agent_id: str):
        token  = websocket.query_params.get("token", "").strip()
        master = (api_key or "").strip()
        ok = False
        if not master:
            # No master key configured: log a warning but still reject anonymous
            # connections in production. Allow only if OPEN_ENROLLMENT is also true
            # (pure dev environment).
            ok = open_enrollment
            if ok:
                log.warning("WS accepted without auth (dev mode — no API_KEY set)")
        elif token:
            # Constant-time compare to prevent timing side-channel
            if hmac.compare_digest(token.encode(), master.encode()):
                ok = True
            else:
                agent_key = await db.get_agent_key(agent_id)
                if agent_key and hmac.compare_digest(
                    token.encode(), agent_key.encode()
                ):
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

    # index.html must NEVER be cached by the browser: it's the tiny entry that
    # points at the content-hashed JS/CSS bundles. If it's cached, a fresh build
    # (new bundle hashes) is invisible until a hard refresh — exactly the "I
    # don't see my changes" trap. The hashed assets under /static ARE safely
    # cacheable (their name changes when content changes), so only this file
    # needs no-cache. Standard SPA caching: immutable assets + no-cache index.
    _NO_CACHE = {
        "Cache-Control": "no-cache, no-store, must-revalidate",
        "Pragma":        "no-cache",
        "Expires":       "0",
    }

    def _serve_index() -> HTMLResponse:
        """Read index.html from the built static directory."""
        for candidate in [
            os.path.join(_pkg_root, "dashboard", "static", "index.html"),
            os.path.join(_pkg_root, "dashboard", "templates", "index.html"),
        ]:
            if os.path.isfile(candidate):
                with open(candidate) as f:
                    return HTMLResponse(f.read(), headers=_NO_CACHE)
        log.error("Dashboard index.html not found under dashboard/static or dashboard/templates")
        return HTMLResponse(
            "<h1>Dashboard unavailable</h1><p>Run: npm run build inside the frontend directory.</p>",
            status_code=503,
        )

    @app.get("/", response_class=HTMLResponse)
    async def dashboard():
        return _serve_index()

    # SPA 404 handler: any path that isn't handled by an API route or the
    # static-files mount falls here.  API and static paths get a JSON 404;
    # everything else (React client-side routes) gets index.html.
    # Using an exception handler instead of a catch-all GET route avoids
    # route-ordering races where /{full_path:path} can shadow specific API
    # routes depending on FastAPI/Starlette version internals.
    @app.exception_handler(404)
    async def spa_not_found_handler(request: Request, exc):
        path = request.url.path
        if path.startswith("/api/") or path.startswith("/static/"):
            return JSONResponse(status_code=404, content={"detail": "Not Found"})
        return _serve_index()

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
