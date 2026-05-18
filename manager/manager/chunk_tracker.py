"""
manager/manager/chunk_tracker.py — In-memory chunk-completion tracker.

Tracks which chunks of a logical ChunkSet have been processed so that
AttackLensWorker can trigger cross-section correlation exactly once — when
the last chunk in a set completes — rather than once per chunk.

Design
------
- Pure-asyncio; all mutations are protected by a single asyncio.Lock so
  concurrent AttackLensWorker tasks cannot race.
- TTL-based expiry (default 1 h) prevents unbounded memory growth when
  a chunk set is abandoned (e.g. a message was nack'd to the DLQ).
- register() is idempotent — safe to call from any chunk, in any order.
- mark_done() returns True only for the *one* caller that completes the set.
"""
from __future__ import annotations

import asyncio
import logging
import time

log = logging.getLogger("manager.chunk_tracker")

_TTL_SECONDS: int = 3600   # abandon chunk sets after 1 h


class ChunkTracker:
    """
    Register chunk sets, mark individual chunks done, detect set completion.
    Create a single instance at server startup and share it with AttackLensWorker.
    """

    def __init__(self) -> None:
        # chunk_set_id → {"total": int, "done": set[int], "created": float}
        self._sets: dict[str, dict] = {}
        self._lock: asyncio.Lock = asyncio.Lock()

    # ── Public API ────────────────────────────────────────────────────────────

    async def register(self, chunk_set_id: str, total: int) -> None:
        """
        Declare that a new chunk set with *total* chunks is in-flight.
        Idempotent — subsequent calls for the same ID are no-ops.
        """
        async with self._lock:
            if chunk_set_id not in self._sets:
                self._sets[chunk_set_id] = {
                    "total":   total,
                    "done":    set(),
                    "created": time.time(),
                }

    async def mark_done(self, chunk_set_id: str, chunk_index: int) -> bool:
        """
        Mark *chunk_index* (0-based) as complete.

        Returns True exactly once — for the caller that completes the set.
        Returns False for all other callers.
        If the set is unknown (already expired or never registered) returns True
        so the caller can safely skip the completion action.
        """
        async with self._lock:
            entry = self._sets.get(chunk_set_id)
            if entry is None:
                return True   # already expired or not registered — treat as done
            entry["done"].add(chunk_index)
            all_done = len(entry["done"]) >= entry["total"]
            if all_done:
                del self._sets[chunk_set_id]
            return all_done

    async def expire_old(self) -> int:
        """
        Remove chunk sets that have been in-flight longer than the TTL.
        Returns the number of sets expired.
        Call periodically from a background task.
        """
        cutoff = time.time() - _TTL_SECONDS
        async with self._lock:
            stale = [k for k, v in self._sets.items() if v["created"] < cutoff]
            for k in stale:
                log.warning("ChunkTracker: expiring stale chunk_set_id=%s", k)
                del self._sets[k]
        return len(stale)

    @property
    def in_flight(self) -> int:
        """Number of active (non-expired) chunk sets. Useful for metrics."""
        return len(self._sets)
