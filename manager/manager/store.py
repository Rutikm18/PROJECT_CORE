"""
manager/manager/store.py — Three-tier NDJSON+gzip time-series store.

Storage layout
--------------
    data/
    ├── hot/   {agent_id}/{section}/{YYYY-MM-DD}/{HH-MM}.ndjson.gz
    │          Granularity: per-minute bucket   Retention: 0–24 h
    │
    ├── warm/  {agent_id}/{section}/{YYYY-MM-DD}/{HH}.ndjson.gz
    │          Granularity: per-hour bucket      Retention: 1–90 d
    │
    ├── cold/  {agent_id}/{section}/{YYYY-MM}/{DD}.ndjson.gz
    │          Granularity: per-day bucket        Retention: 90 d–1 yr
    │
    └── index.db   SQLite index (agent_id, section, ts_min, ts_max, tier, filepath)

Why NDJSON + gzip
-----------------
- Self-describing: each line is a complete JSON object — no external schema needed
- Stream-appendable: append without reading the whole file
- Universal tooling: jq, grep, Python stdlib, Elasticsearch-compatible
- Excellent compression: telemetry JSON compresses 8–15×
- Human-readable for debugging: gzip -d | head

Window → tier mapping
---------------------
    5m,  15m      →  hot   (sub-hour windows need per-event precision)
    1h,  8h, 1d   →  warm  (hourly buckets cover up to 7-day windows)
    7d,  30d, 90d →  warm + cold (depends on how old the data is)

Record format (one JSON line per record)
-----------------------------------------
    {"schema":1,"ts":1712345678.0,"agent_id":"a001","os":"macos",
     "hostname":"Macbook","section":"metrics","data":{...}}
"""
from __future__ import annotations

import asyncio
import gzip
import json
import logging
import os
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any

from .index import TelemetryIndex

log = logging.getLogger("manager.store")

# ── Time window → tier mapping ───────────────────────────────────────────────
WINDOW_SECONDS: dict[str, int] = {
    "5m":  300,
    "15m": 900,
    "1h":  3600,
    "8h":  28800,
    "1d":  86400,
    "7d":  604800,
    "30d": 2592000,
    "90d": 7776000,
}

# Windows where we query only hot tier
_HOT_WINDOWS  = {"5m", "15m"}
# Windows where we query warm tier (hourly rollup data)
_WARM_WINDOWS = {"1h", "8h", "1d", "7d", "30d"}
# Windows where we query cold tier (daily rollup data)
_COLD_WINDOWS = {"30d", "90d"}

# Retention thresholds
HOT_RETENTION_SEC  = 86400       # 24 hours
WARM_RETENTION_SEC = 7776000     # 90 days
COLD_RETENTION_SEC = 31536000    # 365 days


class TelemetryStore:
    """
    Three-tier NDJSON+gzip store with SQLite index.

    Tier selection at write time:
      - hot:  always written (every ingest event)
      - warm: written when the hour bucket changes
      - cold: written when the day bucket changes

    Tier selection at query time:
      - driven by the requested time window (see WINDOW_SECONDS mapping)
      - the index is consulted first to get file paths — no directory scan
    """

    def __init__(self, data_dir: str):
        self.root  = Path(data_dir)
        self.hot   = self.root / "hot"
        self.warm  = self.root / "warm"
        self.cold  = self.root / "cold"
        self.index = TelemetryIndex(str(self.root / "index.db"))
        self._lock: asyncio.Lock | None = None  # lazy init inside event loop

    @property
    def _write_lock(self) -> asyncio.Lock:
        if self._lock is None:
            self._lock = asyncio.Lock()
        return self._lock

    async def init(self) -> None:
        """Create directories and initialise the index."""
        for d in (self.hot, self.warm, self.cold):
            d.mkdir(parents=True, exist_ok=True)
        await self.index.init()

    async def close(self) -> None:
        await self.index.close()

    # ── Write ─────────────────────────────────────────────────────────────────

    async def write(
        self,
        agent_id: str,
        section:  str,
        ts:       float,
        data:     Any,
        os:       str = "",
        hostname: str = "",
        schema:   int = 1,
    ) -> None:
        """
        Persist one telemetry record and update rollup buckets + index.

        This method is async to avoid blocking the event loop during I/O,
        but the actual file writes are synchronous (run in the default
        thread pool via asyncio.to_thread for large payloads).
        """
        record = {
            "schema":   schema,
            "ts":       ts,
            "agent_id": agent_id,
            "os":       os,
            "hostname": hostname,
            "section":  section,
            "data":     data,
        }

        dt = datetime.fromtimestamp(ts, tz=timezone.utc)
        async with self._write_lock:
            await asyncio.to_thread(self._write_sync, agent_id, section, dt, record)

        # Update index (async, doesn't block)
        await self._index_hot_file(agent_id, section, dt, ts, os, hostname)
        await self._index_warm_file(agent_id, section, dt, ts, os, hostname)
        await self._index_cold_file(agent_id, section, dt, ts, os, hostname)

    def _write_sync(
        self,
        agent_id: str,
        section:  str,
        dt:       datetime,
        record:   dict,
    ) -> None:
        """Synchronous file I/O — called in thread pool."""
        line = json.dumps(record, separators=(",", ":"), default=str) + "\n"

        # 1. Hot tier — per-minute bucket
        hot_path = self._hot_path(agent_id, section, dt)
        hot_path.parent.mkdir(parents=True, exist_ok=True)
        _append_ndjson_gz(hot_path, line)

        # 2. Warm tier — per-hour bucket (append; same file reused during the hour)
        warm_path = self._warm_path(agent_id, section, dt)
        warm_path.parent.mkdir(parents=True, exist_ok=True)
        _append_ndjson_gz(warm_path, line)

        # 3. Cold tier — per-day bucket
        cold_path = self._cold_path(agent_id, section, dt)
        cold_path.parent.mkdir(parents=True, exist_ok=True)
        _append_ndjson_gz(cold_path, line)

        # 4. Latest snapshot (overwrite — always the most recent record)
        latest_path = self.root / "latest" / agent_id / f"{section}.ndjson.gz"
        latest_path.parent.mkdir(parents=True, exist_ok=True)
        _write_ndjson_gz(latest_path, line)

    # ── Read ──────────────────────────────────────────────────────────────────

    async def query(
        self,
        agent_id: str,
        section:  str,
        window:   str = "1h",
        limit:    int = 500,
        start:    float = 0.0,
        end:      float = 0.0,
    ) -> list[dict]:
        """
        Return records for agent+section within the requested time window.

        Parameters
        ----------
        window : one of 5m,15m,1h,8h,1d,7d,30d,90d (ignored if start/end given)
        limit  : max records to return (applied after filtering)
        start  : Unix epoch start (overrides window if > 0)
        end    : Unix epoch end   (overrides window if > 0)
        """
        now = time.time()
        if start <= 0:
            secs = WINDOW_SECONDS.get(window, 3600)
            start = now - secs
        if end <= 0:
            end = now

        # Determine which tiers to query
        tiers = _tiers_for_range(start, end, now)

        # Ask index for file paths
        files = await self.index.query_files(agent_id, section, start, end, tiers=tiers)
        if not files:
            return []

        # Read and filter records
        results: list[dict] = []
        for fmeta in files:
            recs = await asyncio.to_thread(
                _read_ndjson_gz, fmeta["filepath"], start, end
            )
            results.extend(recs)
            if len(results) >= limit:
                break

        # Sort by ts ascending, apply limit
        results.sort(key=lambda r: r.get("ts", 0))
        return results[:limit]

    async def latest(self, agent_id: str, section: str) -> dict | None:
        """Return the most recent record for this agent+section."""
        path = self.root / "latest" / agent_id / f"{section}.ndjson.gz"
        if not path.exists():
            return None
        recs = await asyncio.to_thread(_read_ndjson_gz, str(path), 0, float("inf"))
        return recs[-1] if recs else None

    # ── Maintenance ───────────────────────────────────────────────────────────

    async def cleanup(self) -> dict:
        """Delete files beyond retention and prune the index. Returns deleted counts."""
        now = datetime.now(tz=timezone.utc)
        deleted: dict[str, int] = {"hot": 0, "warm": 0, "cold": 0, "index": 0}

        # Hot: delete files older than 24 h
        hot_cutoff = now - timedelta(seconds=HOT_RETENTION_SEC)
        deleted["hot"] = await asyncio.to_thread(
            _prune_dir, self.hot, hot_cutoff, "%Y-%m-%d"
        )

        # Warm: delete files older than 90 d
        warm_cutoff = now - timedelta(seconds=WARM_RETENTION_SEC)
        deleted["warm"] = await asyncio.to_thread(
            _prune_dir, self.warm, warm_cutoff, "%Y-%m-%d"
        )

        # Cold: delete files older than 365 d
        cold_cutoff = now - timedelta(seconds=COLD_RETENTION_SEC)
        deleted["cold"] = await asyncio.to_thread(
            _prune_dir, self.cold, cold_cutoff, "%Y-%m"
        )

        # Prune stale index rows
        cutoff_ts = (now - timedelta(seconds=COLD_RETENTION_SEC)).timestamp()
        deleted["index"] = await self.index.prune_before(cutoff_ts)

        log.info("Cleanup done: %s", deleted)
        return deleted

    # ── Path helpers ──────────────────────────────────────────────────────────

    def _hot_path(self, agent_id: str, section: str, dt: datetime) -> Path:
        minute_bucket = dt.replace(second=0, microsecond=0).strftime("%H-%M")
        return (
            self.hot / agent_id / section
            / dt.strftime("%Y-%m-%d") / f"{minute_bucket}.ndjson.gz"
        )

    def _warm_path(self, agent_id: str, section: str, dt: datetime) -> Path:
        return (
            self.warm / agent_id / section
            / dt.strftime("%Y-%m-%d") / f"{dt.strftime('%H')}.ndjson.gz"
        )

    def _cold_path(self, agent_id: str, section: str, dt: datetime) -> Path:
        return (
            self.cold / agent_id / section
            / dt.strftime("%Y-%m") / f"{dt.strftime('%d')}.ndjson.gz"
        )

    # ── Index update helpers ──────────────────────────────────────────────────

    async def _index_hot_file(
        self, agent_id: str, section: str, dt: datetime,
        ts: float, os: str, hostname: str,
    ) -> None:
        path = self._hot_path(agent_id, section, dt)
        stat = path.stat() if path.exists() else None
        await self.index.upsert_file(
            agent_id=agent_id, section=section, os=os, hostname=hostname,
            tier="hot", filepath=str(path),
            ts_min=ts, ts_max=ts,   # will be updated on next write to same bucket
            size_bytes=stat.st_size if stat else 0,
        )

    async def _index_warm_file(
        self, agent_id: str, section: str, dt: datetime,
        ts: float, os: str, hostname: str,
    ) -> None:
        path = self._warm_path(agent_id, section, dt)
        stat = path.stat() if path.exists() else None
        await self.index.upsert_file(
            agent_id=agent_id, section=section, os=os, hostname=hostname,
            tier="warm", filepath=str(path),
            ts_min=ts, ts_max=ts,
            size_bytes=stat.st_size if stat else 0,
        )

    async def _index_cold_file(
        self, agent_id: str, section: str, dt: datetime,
        ts: float, os: str, hostname: str,
    ) -> None:
        path = self._cold_path(agent_id, section, dt)
        stat = path.stat() if path.exists() else None
        await self.index.upsert_file(
            agent_id=agent_id, section=section, os=os, hostname=hostname,
            tier="cold", filepath=str(path),
            ts_min=ts, ts_max=ts,
            size_bytes=stat.st_size if stat else 0,
        )


# ── Module-level helpers ──────────────────────────────────────────────────────

def _append_ndjson_gz(path: Path, line: str) -> None:
    """Append a NDJSON line to a gzip file (decompress → append → recompress)."""
    existing: bytes = b""
    if path.exists():
        try:
            with gzip.open(path, "rb") as f:
                existing = f.read()
        except Exception:
            existing = b""

    new_content = existing + line.encode("utf-8")
    with gzip.open(path, "wb", compresslevel=6) as f:
        f.write(new_content)


def _write_ndjson_gz(path: Path, line: str) -> None:
    """Overwrite a gzip file with a single NDJSON line."""
    with gzip.open(path, "wt", encoding="utf-8", compresslevel=6) as f:
        f.write(line)


def _read_ndjson_gz(
    filepath: str, start: float, end: float
) -> list[dict]:
    """
    Read a NDJSON+gzip file and return records with start <= ts <= end.
    Silently skips malformed lines.
    """
    results = []
    try:
        with gzip.open(filepath, "rt", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                ts = rec.get("ts", 0)
                if start <= ts <= end:
                    results.append(rec)
    except FileNotFoundError:
        pass
    except Exception as exc:
        log.debug("Failed to read %s: %s", filepath, exc)
    return results


def _tiers_for_range(start: float, end: float, now: float) -> list[str]:
    """
    Determine which storage tiers to query for the given time range.

    Rules:
      - hot:  range overlaps last 24 hours
      - warm: range overlaps last 90 days
      - cold: range older than 1 day (may have daily-only records)
    """
    tiers = []
    hot_boundary  = now - HOT_RETENTION_SEC
    warm_boundary = now - WARM_RETENTION_SEC

    if end >= hot_boundary:
        tiers.append("hot")
    if end >= warm_boundary:
        tiers.append("warm")
    if start < now - 86400:
        tiers.append("cold")

    return tiers or ["hot"]  # fallback


def _prune_dir(root: Path, cutoff: datetime, date_fmt: str) -> int:
    """
    Remove date-bucketed directories older than cutoff.
    date_fmt: "%Y-%m-%d" for hot/warm, "%Y-%m" for cold.
    Returns number of directories deleted.
    """
    if not root.exists():
        return 0

    deleted = 0
    for agent_dir in root.iterdir():
        if not agent_dir.is_dir():
            continue
        for section_dir in agent_dir.iterdir():
            if not section_dir.is_dir():
                continue
            for bucket_dir in sorted(section_dir.iterdir()):
                if not bucket_dir.is_dir():
                    continue
                try:
                    bucket_dt = datetime.strptime(bucket_dir.name, date_fmt).replace(
                        tzinfo=timezone.utc
                    )
                except ValueError:
                    continue
                if bucket_dt < cutoff.replace(day=1 if date_fmt == "%Y-%m" else cutoff.day,
                                              hour=0, minute=0, second=0, microsecond=0):
                    import shutil
                    shutil.rmtree(bucket_dir, ignore_errors=True)
                    deleted += 1
                    log.debug("Pruned %s", bucket_dir)
    return deleted
