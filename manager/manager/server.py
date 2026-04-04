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

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles

from .db        import Database
from .store     import TelemetryStore
from .ws_hub    import WebSocketHub
from .indexer   import IntelDB
from .jarvis    import JarvisEngine
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

    db       = Database(db_path)
    store    = TelemetryStore(data_dir)
    hub      = WebSocketHub()
    intel_db = IntelDB(intel_path)
    jarvis   = JarvisEngine(db, intel_db)

    # ── App ───────────────────────────────────────────────────────────────────
    app = FastAPI(title="mac_intel Manager", version="1.0.0", docs_url=None)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=os.environ.get("CORS_ORIGINS", "*").split(","),
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ── Nonce cache (replay prevention) ──────────────────────────────────────
    nonce_cache: dict[str, float] = {}

    async def _evict_nonces():
        while True:
            await asyncio.sleep(60)
            cutoff = time.time() - REPLAY_WINDOW_SECONDS
            stale  = [k for k, t in nonce_cache.items() if t < cutoff]
            for k in stale:
                del nonce_cache[k]

    async def _cleanup_store():
        """Hourly file-store cleanup job."""
        while True:
            await asyncio.sleep(3600)
            try:
                stats = await store.cleanup()
                log.info("Store cleanup: %s", stats)
            except Exception as exc:
                log.warning("Store cleanup error: %s", exc)

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
        setup_logging(
            logfile=os.environ.get("LOG_FILE", "manager/logs/manager.log"),
            level=os.environ.get("LOG_LEVEL", "INFO"),
        )
        await db.init()
        await _dev_bootstrap_agent_key()
        await store.init()
        await intel_db.init()
        await jarvis.start()
        asyncio.create_task(_evict_nonces())
        asyncio.create_task(_cleanup_store())
        log.info("Manager started. DB=%s  Intel=%s  Data=%s",
                 db_path, intel_path, data_dir)

    @app.on_event("shutdown")
    async def shutdown():
        await store.close()
        await intel_db.close()

    # ── Mount routers ─────────────────────────────────────────────────────────
    from .api.ingest  import make_ingest_router
    from .api.agents  import make_agents_router
    from .api.enroll  import make_enroll_router
    from .api.jarvis  import make_jarvis_router

    enrollment_tokens = os.environ.get("ENROLLMENT_TOKENS", "").split(",")
    enrollment_tokens = [t.strip() for t in enrollment_tokens if t.strip()]

    ingest_router  = make_ingest_router(db, store, hub, nonce_cache, jarvis)
    agents_router  = make_agents_router(db, store)
    enroll_router  = make_enroll_router(db, enrollment_tokens)
    jarvis_router  = make_jarvis_router(intel_db)

    app.include_router(ingest_router, prefix="/api/v1")
    app.include_router(agents_router, prefix="/api/v1/agents")
    app.include_router(enroll_router, prefix="/api/v1")
    app.include_router(jarvis_router, prefix="/api/v1/jarvis")

    # ── Health ────────────────────────────────────────────────────────────────
    @app.get("/health")
    async def health():
        ok = await db.ping()
        idx_stats = await store.index.stats()
        return {
                "status": "ok",
            "db":     "ok" if ok else "error",
            "store":  idx_stats,
            "intel":  await intel_db.stats(),
        }

    # ── WebSocket ─────────────────────────────────────────────────────────────
    @app.websocket("/ws/{agent_id}")
    async def ws_endpoint(websocket: WebSocket, agent_id: str):
        token = websocket.query_params.get("token", "").strip()
        master = (api_key or "").strip()
        ok = False
        if token and master and token.lower() == master.lower():
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
        html_path = os.path.join(_pkg_root, "dashboard", "templates", "index.html")
        with open(html_path) as f:
            return f.read()

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
