"""
manager/manager/chunker.py — Splits large list payloads into fixed-size chunks.

When a telemetry section (processes, packages, apps, connections, binaries)
carries a list with hundreds of items, processing it as one Jarvis task
saturates the event loop and wastes all work on any single-item failure.

PayloadChunker fans out large lists into fixed-size slices.  Each slice is
published as an independent attacklens.work message and processed in parallel.
Non-list data (dicts, scalars) passes through as a single chunk so callers
need no special-casing.

Constants
---------
CHUNK_THRESHOLD  lists longer than this trigger fan-out (inclusive edge: > N)
CHUNK_SIZE       items per chunk
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any

CHUNK_THRESHOLD: int = 50   # fan out lists longer than this
CHUNK_SIZE:      int = 50   # items per output chunk


@dataclass(slots=True)
class Chunk:
    chunk_set_id: str
    chunk_index:  int    # 0-based
    chunk_total:  int    # total chunks in the set
    data:         Any


def split(data: Any, chunk_size: int = CHUNK_SIZE) -> list[Chunk]:
    """
    Split *data* into one or more Chunk objects.

    - list with len > CHUNK_THRESHOLD → N Chunks of *chunk_size* items each
    - everything else                 → single Chunk(chunk_total=1)

    A unique chunk_set_id (hex UUID) is assigned to every call so that
    workers can correlate chunks back to the same logical payload.
    """
    cid = uuid.uuid4().hex
    if not isinstance(data, list) or len(data) <= CHUNK_THRESHOLD:
        return [Chunk(chunk_set_id=cid, chunk_index=0, chunk_total=1, data=data)]

    slices = [data[i : i + chunk_size] for i in range(0, len(data), chunk_size)]
    return [
        Chunk(chunk_set_id=cid, chunk_index=idx, chunk_total=len(slices), data=sl)
        for idx, sl in enumerate(slices)
    ]
