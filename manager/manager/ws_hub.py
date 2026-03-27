"""manager/ws_hub.py — WebSocket connection registry."""

import asyncio
import logging
from fastapi import WebSocket

log = logging.getLogger("manager.ws")


class WebSocketHub:
    def __init__(self):
        self._subs: dict[str, list[WebSocket]] = {}

    async def connect(self, agent_id: str, ws: WebSocket):
        self._subs.setdefault(agent_id, []).append(ws)
        self._subs.setdefault("*", []).append(ws)
        log.debug("WS connected agent=%s total=%d", agent_id,
                  len(self._subs.get(agent_id, [])))

    async def disconnect(self, agent_id: str, ws: WebSocket):
        for key in (agent_id, "*"):
            lst = self._subs.get(key, [])
            if ws in lst:
                lst.remove(ws)
        log.debug("WS disconnected agent=%s", agent_id)

    async def broadcast(self, agent_id: str, message: dict):
        targets = list(self._subs.get(agent_id, []))
        if not targets:
            return
        dead = []
        results = await asyncio.gather(
            *[ws.send_json(message) for ws in targets],
            return_exceptions=True,
        )
        for ws, result in zip(targets, results):
            if isinstance(result, Exception):
                dead.append(ws)
        for ws in dead:
            await self.disconnect(agent_id, ws)
