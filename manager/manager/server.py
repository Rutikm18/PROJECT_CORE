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

from fastapi import (
    Depends, FastAPI, Header, Request, WebSocket, WebSocketDisconnect, HTTPException,
)
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
from .workers.intel       import ThreatIntelWorker
from .workers.enrichment  import EnrichmentWorker
from .threat.nvd_sync     import NVDSyncWorker
from .ai_analyst          import AIAnalyst
from .notifications.email import EmailNotifier
from .notifications.dispatcher import FindingNotificationDispatcher
from .ai.investigation_graph import InvestigationService
from .api.remediation     import router as remediation_router
from .intel               import IntelPipeline
from .api.intel              import router as intel_router
from .api.finding_validation import router as finding_validation_router
from .api.auth_ui            import router as auth_router
from .api.ai_settings        import router as ai_settings_router
from .api.integrations       import router as integrations_router
from .api.authz              import require_session
from shared.wire import REPLAY_WINDOW_SECONDS

log = logging.getLogger("manager")

_MANAGER_ROLES = frozenset({"api", "telemetry", "detection", "maintenance", "intel"})


def _parse_manager_roles(raw: str | None) -> frozenset[str]:
    """Validate the independently scalable responsibilities for this process."""
    if raw is None or not raw.strip():
        return _MANAGER_ROLES
    roles = frozenset(part.strip().lower() for part in raw.split(",") if part.strip())
    unknown = sorted(roles - _MANAGER_ROLES)
    if unknown:
        raise ValueError(
            "Unknown MANAGER_ROLES value(s): " + ", ".join(unknown)
            + "; allowed: " + ", ".join(sorted(_MANAGER_ROLES))
        )
    if not roles:
        raise ValueError("MANAGER_ROLES must contain at least one role")
    return roles


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


async def _retry_init(operation, name: str, attempts: int = 20, delay: float = 3.0) -> None:
    """Run an async init step, retrying transient failures.

    ``depends_on: service_healthy`` gates container start on Postgres/RabbitMQ
    being healthy, but a dependency can still blip in the seconds between the
    healthcheck passing and the manager connecting (broker failover, a slow
    first connection, a restart). Without this the manager would exit on the
    first hiccup and Docker would churn it through the restart policy. Retrying
    a bounded number of times turns those transients into a short wait.
    """
    last_error: Exception | None = None
    for attempt in range(1, attempts + 1):
        try:
            await operation()
            if attempt > 1:
                log.info("%s initialised on attempt %d/%d", name, attempt, attempts)
            return
        except Exception as exc:  # noqa: BLE001 — surface after final attempt
            last_error = exc
            log.warning("%s init failed (attempt %d/%d): %s", name, attempt, attempts, exc)
            if attempt < attempts:
                await asyncio.sleep(delay)
    raise RuntimeError(f"{name} failed to initialise after {attempts} attempts") from last_error


def create_app() -> FastAPI:
    # ── Config from env ───────────────────────────────────────────────────────
    # API_KEY is now optional — used only for WebSocket token auth.
    # Per-agent keys are stored in the agent_keys SQLite table after enrollment.
    api_key = os.environ.get("API_KEY", "")
    roles = _parse_manager_roles(os.environ.get("MANAGER_ROLES"))

    data_dir = os.environ.get("DATA_DIR", os.path.join(
        os.path.dirname(os.path.dirname(__file__)), "data"
    ))
    os.makedirs(data_dir, exist_ok=True)
    # PostgreSQL is the authoritative raw-event store. TelemetryStore is an
    # optional local archive and must be disabled when replicas share DATA_DIR.
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
    engine   = AttackLensEngine(db, intel_db, central_intel_url=threat_intel_url)
    investigations_enabled = os.environ.get(
        "LANGGRAPH_INVESTIGATIONS_ENABLED", "true"
    ).lower() not in ("false", "0", "no", "off")
    investigation_service = InvestigationService(
        intel_db,
        engine.feeds,
        dsn=intel_path,
        max_review_rounds=int(os.environ.get("LANGGRAPH_MAX_REVIEW_ROUNDS", "2")),
    )
    producer = None
    producer_roles = roles & {"api", "telemetry", "maintenance"}
    if rabbitmq_url:
        try:
            from .queue.producer import QueueProducer as _QP
            producer = _QP(rabbitmq_url)
        except ImportError:
            log.warning("aio_pika not installed — RabbitMQ queue disabled (set RABBITMQ_URL only if aio_pika is installed)")

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
    _nvd_sync:        NVDSyncWorker | None = None
    _intel_pipeline:  IntelPipeline | None = None
    _dlq_replayer:    DLQReplayer | None = None
    _reconciler:      PayloadReconciler | None = None
    _service_tasks:   list[asyncio.Task] = []

    # ── App ───────────────────────────────────────────────────────────────────
    from .version import get_version_info

    _version_info = get_version_info()
    # Swagger was already disabled, but ReDoc and the raw OpenAPI schema were
    # not — so the complete route map, parameters and models stayed public on
    # every deployment. They are opt-in now, and off by default, matching the
    # existing intent of docs_url=None.
    _expose_api_docs = os.environ.get(
        "ATTACKLENS_EXPOSE_API_DOCS", "false",
    ).strip().lower() in ("1", "true", "yes", "on")

    app = FastAPI(
        title="mac_intel Manager",
        version=_version_info["version"],
        docs_url="/docs" if _expose_api_docs else None,
        redoc_url="/redoc" if _expose_api_docs else None,
        openapi_url="/openapi.json" if _expose_api_docs else None,
    )

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

    # Confines a customer principal on the shared operator routes: read-only,
    # operator-only paths refused, and a tenant scope attached for the query
    # layer. Registered here so it runs before routing — a route that has not
    # been scoped yet is unreachable to a customer rather than unfiltered.
    # Held behind the same flag as the portal routers — with no portal there is
    # no customer principal to confine, and the middleware would be pure
    # overhead on every operator request.
    _customer_portal_enabled = os.environ.get(
        "ATTACKLENS_CUSTOMER_PORTAL", "false",
    ).strip().lower() in ("1", "true", "yes", "on")

    if _customer_portal_enabled:
        from .api.tenant_scope import TenantScopeMiddleware
        app.add_middleware(TenantScopeMiddleware, intel_db=intel_db)

    # CORS: same-origin only unless an origin is explicitly configured.
    #
    # An unset CORS_ORIGINS used to fall back to ["*"], which is unsafe here
    # because credentials are allowed: with allow_credentials=True, Starlette
    # echoes the *requesting* origin back whenever a cookie is present rather
    # than sending a literal "*", so any site could make credentialed calls
    # riding a logged-in admin's al_session cookie. An empty list now means
    # exactly what it says — no cross-origin access. The dashboard is served
    # from this same origin through Caddy, so it needs no CORS grant at all.
    _cors_origins = [
        o.strip()
        for o in os.environ.get("CORS_ORIGINS", "").split(",")
        if o.strip()
    ]
    # A literal "*" stays available for local development, but never together
    # with credentials — that combination is what makes the wildcard dangerous,
    # and the CORS spec forbids it anyway.
    _cors_wildcard = "*" in _cors_origins
    if _cors_wildcard:
        log.warning(
            "CORS_ORIGINS=* — credentialed cross-origin requests are disabled "
            "for safety. Set an explicit origin to allow the dashboard to call "
            "this manager from another host."
        )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_cors_origins,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=[
            "Authorization", "Content-Type", "X-Request-ID", "Idempotency-Key",
        ],
        allow_credentials=not _cors_wildcard,
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
            from .api.settings import retention_action_value, retention_period_days
            row_months = await intel_db._fetchone(
                "SELECT value FROM org_settings WHERE key='retention_period_months'", ()
            )
            row_action = await intel_db._fetchone(
                "SELECT value FROM org_settings WHERE key='retention_action'", ()
            )
            months_val = row_months["value"] if row_months else "0"
            action     = row_action["value"] if row_action else "delete"
            return retention_period_days(months_val), retention_action_value(action)
        except Exception as exc:
            log.debug("Retention settings unreadable, using default: %s", exc)
            return RAW_TELEMETRY_RETENTION_DAYS, "delete"

    async def _cleanup_store():
        """Hourly retention sweep — file-tier archive AND the manager.db rows
        Deep Analysis actually queries, on the SAME cutoff (Settings → Data
        Retention, default 1 day / delete — see api/settings.py). Before
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
                n_events = await db.prune_ledger(cutoff)
                if n_payloads or n_sessions or n_events:
                    log.info(
                        "Retention prune (>%dd, action=%s): payloads=%d "
                        "agent_sessions=%d processed_detection_events=%d",
                        retention_days, action, n_payloads, n_sessions, n_events,
                    )
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
        nonlocal _tel_worker, _al_worker, _intel_worker, _enrich_worker
        nonlocal _nvd_sync, _intel_pipeline, _dlq_replayer, _reconciler
        setup_logging(
            logfile=os.environ.get("LOG_FILE", "manager/logs/manager.log"),
            level=os.environ.get("LOG_LEVEL", "INFO"),
        )
        await _retry_init(db.init, "PostgreSQL (manager)")
        await _dev_bootstrap_agent_key()
        await _retry_init(store.init, "Data store")
        await _retry_init(intel_db.init, "Intel database")
        if "detection" in roles:
            await engine.start()
        if investigations_enabled and roles & {"api", "detection"}:
            await investigation_service.start()
        if "maintenance" in roles:
            _service_tasks.append(asyncio.create_task(
                _cleanup_store(), name="manager:retention",
            ))

        if producer is not None and producer_roles:
            await producer.start()

        if producer is not None and "telemetry" in roles:
            _tel_worker = TelemetryWorker(rabbitmq_url, db, store, hub, producer)
            _service_tasks.append(asyncio.create_task(
                _tel_worker.run(), name="manager:telemetry",
            ))

        if producer is not None and "detection" in roles:
            _al_worker = AttackLensWorker(rabbitmq_url, engine)
            _service_tasks.append(asyncio.create_task(
                _al_worker.run(), name="manager:detection",
            ))

        if producer is not None and "maintenance" in roles:
            # DLQ replayer: drains mac_intel.dead (previously unconsumed → a
            # silent black hole for any nack'd telemetry/detection work) and
            # replays to the origin queue with backoff, parking poison messages.
            _dlq_replayer = DLQReplayer(rabbitmq_url)
            app.state.dlq_replayer = _dlq_replayer
            _service_tasks.append(asyncio.create_task(
                _dlq_replayer.run(), name="manager:dlq-replayer",
            ))
            # Payload reconciler: replays any payload that was stored but never
            # detected (lost hand-off past the DLQ) — the catch-all that makes
            # "raw is reprocessable" true. Reads the event-level detection outbox.
            _reconciler = PayloadReconciler(db, store, producer)
            app.state.reconciler = _reconciler
            _service_tasks.append(asyncio.create_task(
                _reconciler.run(), name="manager:reconciler",
            ))
        if producer is None:
            log.info("RabbitMQ: not configured — synchronous detection is available on detection-role instances")
        else:
            log.info("RabbitMQ components started for roles=%s", ",".join(sorted(roles)))

        # API instances initialise the pipeline for on-demand intel endpoints;
        # only the intel role owns continuous feed/NVD schedules.
        if embedded_threat_intel and roles & {"api", "intel"}:
            github_token = os.environ.get("GITHUB_TOKEN", "").strip()
            _intel_pipeline = IntelPipeline(engine.feeds, engine.nvd, github_token=github_token)
            await _intel_pipeline.start()
            app.state.intel_pipeline = _intel_pipeline

            if "intel" in roles:
                _intel_worker = ThreatIntelWorker(
                    intel_db, db, engine.feeds, engine.nvd,
                    intel_pipeline=_intel_pipeline,
                )
                await _intel_worker.start()
        else:
            app.state.intel_pipeline = None
            if not embedded_threat_intel:
                log.info("Threat intel: central mode enabled (url=%s)", threat_intel_url or "not set")

        # Shared state for route dependencies
        app.state.intel_db          = intel_db
        app.state.feeds             = engine.feeds
        app.state.threat_intel_url  = threat_intel_url  # empty string in embedded mode

        # Seed the encrypted AI provider store from AI_PROVIDER / AI_API_KEY on
        # first boot, so a deployment can ship its LLM config in .env instead of
        # requiring a dashboard visit before AI features work. No-ops once a
        # provider is configured, and never performs network I/O.
        try:
            from .ai.key_store import bootstrap_from_env as _ai_bootstrap
            _ai_bootstrap()
        except Exception as exc:   # never block startup on optional AI config
            log.warning("AI provider bootstrap skipped: %s", exc)

        async def _ai_catalog_refresher() -> None:
            """Keep the OpenRouter model catalog warm.

            Without this the catalog is only fetched when someone opens
            Settings, so on a fresh boot every lookup falls back to a heuristic:
            model IDs go unvalidated, and structured-output capability reads as
            "unknown" so a strict schema is sent to models that cannot honour
            it. Runs in the background — a provider outage must never delay or
            fail startup.
            """
            from .ai import catalog
            from .ai.key_store import load_config

            while True:
                try:
                    cfg = load_config()
                    if cfg is not None and cfg.provider == "openrouter":
                        # refresh() respects its own 6h TTL, so this is cheap.
                        await catalog.refresh()
                except Exception as exc:
                    log.debug("AI model catalog refresh skipped: %s", exc)
                await asyncio.sleep(3600)

        _service_tasks.append(asyncio.create_task(_ai_catalog_refresher()))

        # AI analyst + email notifier — attach to app.state for route access
        ai_analyst     = AIAnalyst(intel_db, engine.feeds)
        email_notifier = EmailNotifier()
        finding_notifications = FindingNotificationDispatcher(intel_db, email_notifier)

        async def _handle_investigation_lifecycle(
            finding: dict, event: str, run: dict,
        ) -> None:
            detail = str(run.get("feedback") or run.get("decision") or "")
            await finding_notifications.handle_workflow_event(
                finding,
                event=event,
                actor=str(run.get("actor") or "AttackLens"),
                detail=detail,
                run_id=str(run.get("run_id") or ""),
            )

        investigation_service.set_lifecycle_notification_handler(
            _handle_investigation_lifecycle,
        )

        async def _handle_finding_event(finding: dict, event: str) -> None:
            handlers = [finding_notifications.handle_finding_event(finding, event)]
            if investigations_enabled:
                handlers.append(investigation_service.handle_finding_event(finding, event))
            results = await asyncio.gather(*handlers, return_exceptions=True)
            for result in results:
                if isinstance(result, Exception):
                    log.warning("post-finding handler failed: %s", result)

        intel_db.set_finding_notification_handler(_handle_finding_event)
        # Make the AI analyst available to the AttackLens precision validator
        # (the engine looks for this on its own attribute to call validate_with_ai).
        engine.attach_ai_analyst(ai_analyst)
        app.state.ai_analyst    = ai_analyst
        app.state.email_notifier = email_notifier
        app.state.finding_notification_dispatcher = finding_notifications
        app.state.investigation_service = investigation_service
        if "maintenance" in roles:
            _service_tasks.append(asyncio.create_task(
                finding_notifications.run(), name="manager:email-delivery",
            ))
        log.info("AI Analyst enabled=%s  Email enabled=%s",
                 ai_analyst.enabled, email_notifier.enabled)

        if roles & {"api", "intel"}:
            _enrich_worker = EnrichmentWorker(intel_db, rabbitmq_url or None)
            await _enrich_worker.start(periodic="intel" in roles)

        if embedded_threat_intel and "intel" in roles:
            _nvd_sync = NVDSyncWorker(intel_db)
            await _nvd_sync.start()

        log.info("Manager started. roles=%s DB=%s Intel=%s Data=%s archive=%s",
                 ",".join(sorted(roles)), _redact_dsn(db_path),
                 _redact_dsn(intel_path), data_dir, store.enabled)
        log.info("Enrollment mode: %s",
                 "OPEN (no token required)" if open_enrollment else
                 f"TOKEN ({len(enrollment_tokens)} token(s) configured)")

    @app.on_event("shutdown")
    async def shutdown():
        if _reconciler:
            await _reconciler.stop()
        if _dlq_replayer:
            await _dlq_replayer.stop()
        if _nvd_sync:
            await _nvd_sync.stop()
        if _enrich_worker:
            await _enrich_worker.stop()
        if _intel_worker:
            await _intel_worker.stop()
        if _intel_pipeline:
            await _intel_pipeline.stop()
        if _tel_worker:
            await _tel_worker.stop()
        if _al_worker:
            await _al_worker.stop()
        # Do not close the engine or databases while consumer/reconciler tasks
        # can still be using them. Cancellation leaves unacked RabbitMQ messages
        # eligible for durable redelivery.
        for task in _service_tasks:
            task.cancel()
        if _service_tasks:
            await asyncio.gather(*_service_tasks, return_exceptions=True)
            _service_tasks.clear()
        if "detection" in roles:
            await engine.stop()
        if investigations_enabled and roles & {"api", "detection"}:
            await investigation_service.stop()
        if producer is not None and producer_roles:
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
    from .api.investigations        import make_investigations_router

    enrollment_tokens = os.environ.get("ENROLLMENT_TOKENS", "").split(",")
    enrollment_tokens = [t.strip() for t in enrollment_tokens if t.strip()]

    # Open enrollment: accept any agent without a token.
    # Default: True (no token needed — just provide manager IP on agent install).
    # Set OPEN_ENROLLMENT=false in env to require tokens.
    _open_env     = os.environ.get("OPEN_ENROLLMENT", "true").lower()
    open_enrollment = _open_env not in ("false", "0", "no", "off")

    admin_token = os.environ.get("ADMIN_TOKEN", "").strip()

    ingest_router    = make_ingest_router(
        db, store, hub, nonce_cache, engine if "detection" in roles else None,
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
    cases_router               = make_cases_router(intel_db, auth_required=True)
    investigations_router      = make_investigations_router(investigation_service)

    # ── Authentication boundary ───────────────────────────────────────────────
    #
    # Deny by default. Every router below carries `dependencies=_SESSION`, so a
    # route is protected by being registered — not by remembering to decorate
    # each endpoint. Per-endpoint auth is how one gets missed, and this codebase
    # had missed all of them: before this, every /api/v1/* data route answered
    # anonymous callers with 200 and the full fleet.
    #
    # THE ALLOWLIST — three routers are deliberately left open, each because it
    # carries its own credential scheme that predates the dashboard session:
    #
    #   ingest_router   POST /api/v1/ingest is the agent telemetry path. Agents
    #                   authenticate per-payload with an HMAC signature + nonce,
    #                   not a browser cookie. Its one non-agent endpoint
    #                   (/ingest/health) is protected individually in ingest.py.
    #   enroll_router   Agents must reach enrolment *before* they hold any
    #                   credential. Gated by ENROLLMENT_TOKENS / OPEN_ENROLLMENT.
    #   auth_router     Login cannot require a session to obtain a session.
    #                   /logout and /me verify their own token.
    #
    # Anything added outside that list must be session-protected. The route
    # coverage test in manager/tests/unit/test_api_auth_coverage.py walks
    # app.routes and fails when a new /api/v1/* route is neither protected nor
    # explicitly listed, so this boundary cannot regress silently.
    _SESSION = [Depends(require_session)]

    app.include_router(ingest_router,       prefix="/api/v1")   # allowlisted: agent HMAC
    app.include_router(enroll_router,       prefix="/api/v1")   # allowlisted: enrolment tokens
    app.include_router(auth_router)                             # allowlisted: issues the session

    # ── Customer portal (off by default) ──────────────────────────────────────
    #
    # The whole feature is built and tested, but it is held behind this flag
    # until a real customer is put on it. "Coming soon" means the routes are not
    # registered at all, not merely hidden in the UI — a portal login that still
    # answered while the dashboard showed a placeholder would be the worst of
    # both. Must be kept in step with CUSTOMER_PORTAL_LIVE in the frontend's
    # featureFlags.ts.
    if _customer_portal_enabled:
        # Portal authentication — allowlisted for the same reason as the
        # operator login: it issues the session, so it cannot require one. Its
        # own endpoints authenticate individually (require_portal_user), and
        # the aud=portal token it mints is refused by every operator router.
        from .api.portal_auth import make_portal_auth_router
        app.include_router(make_portal_auth_router(intel_db))

        # The customer data API. Gated at the router by require_portal_user, so
        # a portal endpoint cannot exist without a resolved tenant scope.
        from .api.portal import make_portal_router
        app.include_router(make_portal_router(intel_db))

        # Operator-side provisioning. Gated by require_admin at the router, so a
        # portal token is refused before any handler runs.
        from .api.customers import make_customers_router
        app.include_router(make_customers_router(intel_db))
        log.info("Customer portal ENABLED — /portal and /api/v1/customers are live")
    else:
        log.info(
            "Customer portal disabled (set ATTACKLENS_CUSTOMER_PORTAL=true to "
            "enable /portal, /api/v1/portal and /api/v1/customers)"
        )

    app.include_router(agents_router,       prefix="/api/v1/agents",     dependencies=_SESSION)
    app.include_router(attacklens_router,   prefix="/api/v1/attacklens", dependencies=_SESSION)
    app.include_router(keys_router,         prefix="/api/v1/keys",       dependencies=_SESSION)
    app.include_router(findings_router,     prefix="/api/v1/soc",        dependencies=_SESSION)
    app.include_router(threat_router,       prefix="/api/v1/threat",     dependencies=_SESSION)
    app.include_router(raw_router,          prefix="/api/v1/raw",        dependencies=_SESSION)
    app.include_router(assets_router,       prefix="/api/v1/assets",     dependencies=_SESSION)
    app.include_router(posture_router,      prefix="/api/v1/posture",    dependencies=_SESSION)
    app.include_router(detection_router,    prefix="/api/v1/detection",  dependencies=_SESSION)
    app.include_router(accuracy_router,     prefix="/api/v1/accuracy",   dependencies=_SESSION)
    app.include_router(settings_router,     prefix="/api/v1/settings",   dependencies=_SESSION)
    app.include_router(allowlist_router,    prefix="/api/v1/allowlist",  dependencies=_SESSION)
    app.include_router(custom_correlations_router, prefix="/api/v1/custom-correlations", dependencies=_SESSION)
    app.include_router(cases_router,        prefix="/api/v1/cases",      dependencies=_SESSION)
    app.include_router(investigations_router, prefix="/api/v1/ai",       dependencies=_SESSION)
    app.include_router(intel_router,              dependencies=_SESSION)  # /api/v1/intel, prefix inline
    app.include_router(finding_validation_router, dependencies=_SESSION)  # /api/v1/findings
    app.include_router(remediation_router,        dependencies=_SESSION)  # prefixes inline
    app.include_router(ai_settings_router,        dependencies=_SESSION)  # /api/v1/ai provider config
    app.include_router(integrations_router,       dependencies=_SESSION)  # /api/v1/integrations

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
            idx_stats = await store.index.stats() if store.enabled else {"enabled": False}
        except Exception:
            idx_stats = {}
        try:
            intel_stats = await intel_db.stats()
        except Exception:
            intel_stats = {}
        status = "ok" if ok else "degraded"
        return {
            "status":  status,
            "version": _version_info["version"],
            "db":      "ok" if ok else "error",
            "store":   idx_stats,
            "intel":   intel_stats,
            "roles":   sorted(roles),
            "archive_enabled": store.enabled,
        }

    # ── Build / version metadata ──────────────────────────────────────────────
    # Session-gated: the login screen only calls /api/v1/auth/policy, so nothing
    # pre-auth needs this, and an unauthenticated build/version banner is free
    # fingerprinting for anyone deciding which CVEs to try.
    @app.get("/api/v1/meta", dependencies=[Depends(require_session)])
    async def meta():
        from shared.wire import UI_WINDOW_KEYS, WINDOW_SECONDS
        return {
            **_version_info,
            "time_range_presets": [
                {"key": key, "seconds": WINDOW_SECONDS[key]}
                for key in UI_WINDOW_KEYS
            ],
        }

    # ── Enrichment ────────────────────────────────────────────────────────────
    @app.post("/api/v1/enrich/{finding_id}", dependencies=[Depends(require_session)])
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
    @app.get("/api/v1/dashboard/ws-token", dependencies=[Depends(require_session)])
    async def dashboard_ws_token(x_admin_token: str = Header(default="")):
        """
        Return the WS auth token for the browser dashboard.

        This hands back the master API key, so it needs a real credential. It
        previously had an escape hatch: the X-Admin-Token check ran only `if
        _admin` — so on any deployment that had not set ADMIN_TOKEN (the
        default), the branch was skipped and the endpoint returned the master
        key to an anonymous caller. The trailing "allow localhost-only access"
        comment described a check that was never implemented.

        Now a dashboard session is required to reach the endpoint at all, and
        the admin-token comparison still applies on top when one is configured.
        """
        master = (api_key or "").strip()
        _admin = admin_token.strip()
        if _admin and not hmac.compare_digest(
            x_admin_token.strip().encode(), _admin.encode()
        ):
            raise HTTPException(status_code=401, detail="Invalid admin token")
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

    # SPA catch-all — must be registered LAST, after every include_router() call.
    #
    # WHY a catch-all route instead of @app.exception_handler(404):
    #   In some Starlette versions the Router satisfies "no route matched" by
    #   calling `await PlainTextResponse("Not Found", 404)(scope, receive, send)`
    #   directly — it never raises an HTTPException — so the exception handler
    #   is never invoked.  A catch-all route is evaluated during normal route
    #   matching and is therefore version-stable and guaranteed to fire.
    #
    # ROUTE ORDER SAFETY:
    #   All include_router() calls above have already added their routes to the
    #   app's route list.  Starlette evaluates routes in registration order; the
    #   `path` converter has the lowest specificity, so every concrete /api/*
    #   route registered earlier takes priority and the catch-all only fires when
    #   nothing else matched.
    @app.get("/{full_path:path}", response_class=HTMLResponse, include_in_schema=False)
    async def spa_catchall(request: Request, full_path: str):
        # Unmatched API or static paths get a JSON 404 — never HTML.
        if full_path.startswith(("api/", "static/")):
            raise HTTPException(status_code=404, detail="Not Found")
        # Everything else is a React client-side route — serve the SPA shell.
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
