"""
manager/server.py — FastAPI backend

Endpoints:
  POST /api/v1/ingest           receive encrypted agent payload
  GET  /api/v1/agents           list all agents
  GET  /api/v1/agents/{id}      agent detail + last section timestamps
  GET  /api/v1/agents/{id}/{section}  time-series data for a section
  GET  /health                  liveness probe
  WS   /ws/{agent_id}          live dashboard updates
  GET  /                        dashboard HTML

Run:
  python3 manager/server.py
  or via uvicorn:
  uvicorn manager.server:app --ssl-keyfile certs/server.key \
      --ssl-certfile certs/server.crt --host 0.0.0.0 --port 8443
"""

import asyncio
import json
import logging
import os
import sys
import time

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

from .db import Database
from .auth import verify_envelope
from .ws_hub import WebSocketHub
from .crypto import derive_keys, decrypt

log = logging.getLogger("manager")

# ── App factory ───────────────────────────────────────────────────────────────

def create_app() -> FastAPI:
    api_key = os.environ.get("API_KEY", "")
    if not api_key:
        raise RuntimeError("API_KEY environment variable is required")

    enc_key, mac_key = derive_keys(api_key)
    db_path = os.environ.get("DB_PATH", os.path.join(
        os.path.dirname(os.path.dirname(__file__)), "data", "manager.db"))
    os.makedirs(os.path.dirname(db_path), exist_ok=True)

    db  = Database(db_path)
    hub = WebSocketHub()

    app = FastAPI(title="mac_intel Manager", version="1.0.0", docs_url=None)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ── Nonce cache (replay prevention) ──────────────────────────────────────
    nonce_cache: dict[str, float] = {}
    REPLAY_WINDOW = 300

    async def evict_nonces():
        while True:
            await asyncio.sleep(60)
            cutoff = time.time() - REPLAY_WINDOW
            stale  = [k for k, exp in nonce_cache.items() if exp < cutoff]
            for k in stale:
                del nonce_cache[k]

    @app.on_event("startup")
    async def startup():
        await db.init()
        asyncio.create_task(evict_nonces())
        log.info("Manager started. DB=%s", db_path)

    # ── Ingest ────────────────────────────────────────────────────────────────
    @app.post("/api/v1/ingest")
    async def ingest(request: Request):
        try:
            envelope = await request.json()
        except Exception:
            raise HTTPException(400, "Invalid JSON")

        # 1. Schema check
        for field in ("v", "agent_id", "timestamp", "nonce", "ct", "hmac"):
            if field not in envelope:
                raise HTTPException(400, f"Missing field: {field}")

        # 2. Timestamp window (replay prevention — cheap check first)
        skew = abs(time.time() - envelope["timestamp"])
        if skew > REPLAY_WINDOW:
            raise HTTPException(401, "Timestamp out of window")

        # 3. Nonce dedup
        nonce = envelope["nonce"]
        if nonce in nonce_cache:
            raise HTTPException(401, "Duplicate nonce")
        nonce_cache[nonce] = time.time() + REPLAY_WINDOW

        # 4. HMAC + decrypt
        try:
            payload = decrypt(envelope, enc_key, mac_key)
        except ValueError as exc:
            log.warning("Decrypt failed agent=%s: %s",
                        envelope.get("agent_id"), exc)
            raise HTTPException(401, "Verification failed")

        # 5. Store
        agent_id   = payload.get("agent_id",    envelope["agent_id"])
        section    = payload.get("section",      envelope.get("section", "unknown"))
        collected  = payload.get("collected_at", envelope["timestamp"])
        agent_name = payload.get("agent_name", "")
        data       = payload.get("data", {})
        client_ip  = request.client.host if request.client else ""

        await db.upsert_agent(agent_id, agent_name, client_ip)
        await db.insert_payload(agent_id, section, collected, data)

        # 6. Broadcast to WebSocket subscribers
        ws_msg = {
            "type":         "payload",
            "agent_id":     agent_id,
            "section":      section,
            "collected_at": collected,
            "data":         data,
        }
        await hub.broadcast(agent_id, ws_msg)

        return {"status": "ok"}

    # ── Agents ────────────────────────────────────────────────────────────────
    @app.get("/api/v1/agents")
    async def list_agents():
        agents = await db.get_all_agents()
        now    = time.time()
        return [
            {**a, "online": (now - a.get("last_seen", 0)) < 300}
            for a in agents
        ]

    @app.get("/api/v1/agents/{agent_id}")
    async def get_agent(agent_id: str):
        agent = await db.get_agent(agent_id)
        if not agent:
            raise HTTPException(404, "Agent not found")
        sections = await db.get_section_last_times(agent_id)
        return {**agent, "sections": sections,
                "online": (time.time() - agent.get("last_seen", 0)) < 300}

    @app.get("/api/v1/agents/{agent_id}/{section}")
    async def get_section_data(agent_id: str, section: str,
                               limit: int = 100, start: int = 0, end: int = 0):
        VALID = set(
            "metrics connections processes ports network battery openfiles "
            "services users hardware containers arp mounts storage tasks "
            "security sysctl configs apps packages binaries sbom".split()
        )
        if section not in VALID:
            raise HTTPException(400, "Invalid section name")
        rows = await db.query_section(agent_id, section,
                                     limit=min(limit, 1000),
                                     start=start or 0, end=end or int(time.time()))
        return rows

    # ── Health ────────────────────────────────────────────────────────────────
    @app.get("/health")
    async def health():
        ok = await db.ping()
        return {"status": "ok", "db": "ok" if ok else "error"}

    # ── WebSocket ─────────────────────────────────────────────────────────────
    @app.websocket("/ws/{agent_id}")
    async def ws_endpoint(websocket: WebSocket, agent_id: str):
        token = websocket.query_params.get("token", "")
        if token != api_key:
            await websocket.close(code=4001)
            return

        await websocket.accept()
        await hub.connect(agent_id, websocket)
        try:
            await websocket.send_json({
                "type": "hello", "agent_id": agent_id,
                "server_time": int(time.time()),
            })
            while True:
                # keep connection alive; client sends pings
                await websocket.receive_text()
        except WebSocketDisconnect:
            pass
        finally:
            await hub.disconnect(agent_id, websocket)

    # ── Dashboard ─────────────────────────────────────────────────────────────
    _pkg_root   = os.path.dirname(os.path.dirname(__file__))   # manager/
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
    _certs = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "certs")
    uvicorn.run(
        "manager.server:app",
        host=os.environ.get("BIND_HOST", "0.0.0.0"),
        port=int(os.environ.get("BIND_PORT", "8443")),
        ssl_keyfile=os.environ.get("TLS_KEY",  os.path.join(_certs, "server.key")),
        ssl_certfile=os.environ.get("TLS_CERT", os.path.join(_certs, "server.crt")),
        log_level="info",
    )
