"""
manager/manager/store.py — Three-tier NDJSON+gzip time-series store.

Storage layout
--------------
    data/
    ├── hot/   {agent_id}/{section}/{YYYY-MM-DD}/{HH-MM}.ndjson.gz
    │          Granularity: per-minute bucket   Retention: 0–24 h
    │
    ├── warm/  {agent_id}/{section}/{YYYY-MM-DD}/{HH}.ndjson.gz
    │          Granularity: per-hour bucket      Retention: 0–7 d
    │
    ├── cold/  {agent_id}/{section}/{YYYY-MM}/{DD}.ndjson.gz
    │          Granularity: per-day bucket        Retention: 0–RAW_TELEMETRY_RETENTION_DAYS (default 30d)
    │
    └── index.db   SQLite index (agent_id, section, ts_min, ts_max, tier, filepath)

Retention is governed by RAW_TELEMETRY_RETENTION_DAYS (env-overridable, default
30) — nothing in any tier survives past that bound. The SAME bound is applied
to manager.db's `payloads` table (the row store Deep Analysis actually queries)
and `agent_sessions` — see Database.prune_payloads()/prune_agent_sessions() in
db.py, called from the same hourly cleanup job as TelemetryStore.cleanup().

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
from shared.wire import WINDOW_SECONDS

log = logging.getLogger("manager.store")

# Windows where we query only hot tier
_HOT_WINDOWS  = {"30s", "1m", "5m", "15m"}
# Windows where we query warm tier (hourly rollup data)
_WARM_WINDOWS = {"1h", "6h", "8h", "1d", "7d", "15d", "30d"}
# Windows where we query cold tier (daily rollup data)
_COLD_WINDOWS = {"30d", "90d"}

# Retention thresholds — single source of truth, overridable via
# RAW_TELEMETRY_RETENTION_DAYS so ops can tune it without a code change.
# Nothing survives past RAW_TELEMETRY_RETENTION_DAYS in ANY tier; hot/warm
# stay well inside that bound so the fine-grained buckets are pruned long
# before the coarse daily ones (recent data has full resolution, the tail
# end of the window only has daily cold buckets) — by design, not because
# data "moves" between tiers (every write lands in all three independently).
RAW_TELEMETRY_RETENTION_DAYS = int(os.environ.get("RAW_TELEMETRY_RETENTION_DAYS", "30"))

HOT_RETENTION_SEC  = 86400                                  # 24 hours — unchanged
WARM_RETENTION_SEC = min(7 * 86400, RAW_TELEMETRY_RETENTION_DAYS * 86400)
COLD_RETENTION_SEC = RAW_TELEMETRY_RETENTION_DAYS * 86400    # the outer bound


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
        self.enabled = os.environ.get(
            "TELEMETRY_ARCHIVE_ENABLED", "true"
        ).strip().lower() not in {"0", "false", "no", "off"}
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
        if not self.enabled:
            log.info("Telemetry file archive disabled; PostgreSQL is the raw source of truth")
            return
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
        event_id: str = "",
    ) -> None:
        """
        Persist one telemetry record and update rollup buckets + index.

        This method is async to avoid blocking the event loop during I/O,
        but the actual file writes are synchronous (run in the default
        thread pool via asyncio.to_thread for large payloads).
        """
        if not self.enabled:
            return
        record = {
            "schema":   schema,
            "ts":       ts,
            "agent_id": agent_id,
            "os":       os,
            "hostname": hostname,
            "section":  section,
            "data":     data,
            "event_id": event_id,
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
        if not self.enabled:
            return []
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
        if not self.enabled:
            return None
        path = self.root / "latest" / agent_id / f"{section}.ndjson.gz"
        if not path.exists():
            return None
        recs = await asyncio.to_thread(_read_ndjson_gz, str(path), 0, float("inf"))
        return recs[-1] if recs else None

    # ── Maintenance ───────────────────────────────────────────────────────────

    async def cleanup(self, *, cold_retention_sec: int | None = None,
                      prune_cold: bool = True) -> dict:
        """Delete files beyond retention and prune the index. Returns deleted counts.

        cold_retention_sec : override for COLD_RETENTION_SEC — server.py's
                              _cleanup_store reads the LIVE org_settings
                              retention period each cycle and passes it here,
                              so a Settings change takes effect on the next
                              hourly sweep without a restart.
        prune_cold          : when False, the cold tier (and its index rows)
                              is left untouched. This is what makes "Archive"
                              mode work: hot/warm (short-lived, fine-grained)
                              still prune on their normal schedule, but cold's
                              per-day NDJSON+gzip buckets become a permanent
                              archive instead of being deleted. No separate
                              archive pipeline needed — cold already IS the
                              compressed archive once it stops being pruned.
        """
        deleted: dict[str, int] = {"hot": 0, "warm": 0, "cold": 0, "index": 0}
        if not self.enabled:
            return deleted
        now = datetime.now(tz=timezone.utc)

        # Hot: delete files older than 24 h
        hot_cutoff = now - timedelta(seconds=HOT_RETENTION_SEC)
        deleted["hot"] = await asyncio.to_thread(
            _prune_dir, self.hot, hot_cutoff, "%Y-%m-%d"
        )

        # Warm: delete files older than 7 d
        warm_cutoff = now - timedelta(seconds=WARM_RETENTION_SEC)
        deleted["warm"] = await asyncio.to_thread(
            _prune_dir, self.warm, warm_cutoff, "%Y-%m-%d"
        )

        if not prune_cold:
            # Archive mode: cold tier (and its index rows) preserved forever.
            await self.index.prune_before(hot_cutoff.timestamp(), tier="hot")
            await self.index.prune_before(warm_cutoff.timestamp(), tier="warm")
            log.info("Cleanup done (archive mode — cold tier preserved): %s", deleted)
            return deleted

        # Cold: delete files older than the configured retention (default
        # COLD_RETENTION_SEC; settings-driven callers pass cold_retention_sec)
        cold_sec   = cold_retention_sec if cold_retention_sec is not None else COLD_RETENTION_SEC
        cold_cutoff = now - timedelta(seconds=cold_sec)
        deleted["cold"] = await asyncio.to_thread(
            _prune_dir, self.cold, cold_cutoff, "%Y-%m"
        )

        # Prune stale index rows (all tiers, same cutoff basis as cold — the
        # widest window — since hot/warm cutoffs are always inside it)
        cutoff_ts = cold_cutoff.timestamp()
        deleted["index"] = await self.index.prune_before(cutoff_ts)

        log.info("Cleanup done: %s", deleted)
        return deleted

    async def archive_stats(self) -> dict:
        """Authoritative (filesystem-walk, not index-derived) size/location of
        the cold tier — i.e. the archive when "Archive" retention mode is
        active. Deliberately does NOT trust self.index.stats() for the byte
        total: that index is known to lag behind what's actually on disk
        (confirmed separately — total_rows can read 0 while real files exist),
        so a dashboard-facing size figure must come from the real files."""
        if not self.enabled:
            return {"enabled": False, "path": None, "file_count": 0, "total_bytes": 0}
        return await asyncio.to_thread(self._archive_stats_sync)

    def _archive_stats_sync(self) -> dict:
        file_count = 0
        total_bytes = 0
        oldest_ts: float | None = None
        newest_ts: float | None = None
        for root, _dirs, files in os.walk(self.cold):
            for fname in files:
                if not fname.endswith(".ndjson.gz"):
                    continue
                fpath = os.path.join(root, fname)
                try:
                    st = os.stat(fpath)
                except OSError:
                    continue
                file_count += 1
                total_bytes += st.st_size
                oldest_ts = st.st_mtime if oldest_ts is None else min(oldest_ts, st.st_mtime)
                newest_ts = st.st_mtime if newest_ts is None else max(newest_ts, st.st_mtime)
        return {
            "path": str(self.cold),
            "file_count": file_count,
            "total_bytes": total_bytes,
            "oldest_file_ts": oldest_ts,
            "newest_file_ts": newest_ts,
        }

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
    Remove data older than cutoff. Returns number of files/directories deleted.

    date_fmt: "%Y-%m-%d" for hot/warm — each bucket directory covers exactly
              one day, so deleting the whole directory once that day is past
              cutoff is already day-precise.

              "%Y-%m" for cold — each bucket directory covers a WHOLE MONTH
              and contains one file per day (_cold_path: {YYYY-MM}/{DD}.ndjson.gz).
              Deleting the directory as one atomic unit only once the ENTIRE
              month has passed cutoff under-prunes by up to ~2 months for any
              cutoff that isn't exactly day 1 of a month — a rounding error at
              the old 365-day default, but a real correctness gap now that
              30-day retention is the default (configured "delete after 1
              month" could actually retain data for close to 3 months). Cold
              therefore prunes individual DAY FILES inside each month
              directory, then removes the directory once it's empty.
    """
    if not root.exists():
        return 0

    if date_fmt == "%Y-%m":
        return _prune_cold_dir(root, cutoff)

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
                if bucket_dt < cutoff.replace(hour=0, minute=0, second=0, microsecond=0):
                    import shutil
                    shutil.rmtree(bucket_dir, ignore_errors=True)
                    deleted += 1
                    log.debug("Pruned %s", bucket_dir)
    return deleted


def _prune_cold_dir(root: Path, cutoff: datetime) -> int:
    """Day-precise cold-tier pruning — see _prune_dir's docstring for why this
    can't just delete the whole {YYYY-MM} directory once any part of it ages
    past cutoff. Deletes individual {DD}.ndjson.gz files whose actual date is
    before cutoff, then removes the month directory once it's empty."""
    cutoff_midnight = cutoff.replace(hour=0, minute=0, second=0, microsecond=0)
    deleted = 0
    for agent_dir in root.iterdir():
        if not agent_dir.is_dir():
            continue
        for section_dir in agent_dir.iterdir():
            if not section_dir.is_dir():
                continue
            for month_dir in sorted(section_dir.iterdir()):
                if not month_dir.is_dir():
                    continue
                try:
                    month_dt = datetime.strptime(month_dir.name, "%Y-%m").replace(
                        tzinfo=timezone.utc
                    )
                except ValueError:
                    continue
                for day_file in sorted(month_dir.iterdir()):
                    day_str = day_file.name.split(".")[0]
                    try:
                        file_dt = month_dt.replace(day=int(day_str))
                    except (ValueError, TypeError):
                        continue
                    if file_dt < cutoff_midnight:
                        try:
                            day_file.unlink()
                            deleted += 1
                        except OSError:
                            pass
                try:
                    if not any(month_dir.iterdir()):
                        month_dir.rmdir()
                except OSError:
                    pass
    return deleted
