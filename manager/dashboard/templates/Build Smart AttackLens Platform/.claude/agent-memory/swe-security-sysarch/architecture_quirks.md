---
name: architecture-quirks
description: Non-obvious design quirks in AttackLens manager worth knowing before changing it
metadata:
  type: project
---

1. **IntelDB write path leaks pool internals.** `IntelDB.init()` aliases `self._conn = self._pool._write_conn` and many API modules (`api/settings.py`, `api/findings.py`, `api/remediation.py`, `api/accuracy.py`) reach in through `intel_db._conn`, `intel_db._fetchone`, `intel_db._fetchall`, `intel_db._lock`. ~24 call sites.

2. **Bulk update is a Python loop (N+1).** `IntelDB.bulk_update_findings` iterates and calls `update_finding` per id — each iteration takes the lock, executes UPDATE, COMMIT, and 1-2 activity inserts. A 200-id bulk = ~400-600 commits. See [[performance-findings]].

3. **Settings router commits multiple writes under a single `intel_db._lock` then calls `_load()` outside the lock** — readers can see a partial state for a few ms.

4. **CORS default is wildcard `*`** when `CORS_ORIGINS` env unset (server.py:129), combined with `allow_credentials=True` — invalid CORS combo, browsers ignore; in practice this is permissive.

5. **WebSocket auth is "no API_KEY = open"** (server.py:375-376). Same master `API_KEY` accepted as the token for any agent_id, in addition to per-agent keys.

6. **HMAC verification happens BEFORE nonce dedup** in ingest, but the nonce check uses a DB upsert that double-acts as cleanup. A replay attacker who hasn't passed HMAC never reaches the nonce check.

7. **NDJSON+gzip append rewrites the whole file every event** (`store._append_ndjson_gz`: decompress → append → recompress). Hot-tier writes scale O(n) per minute bucket. Bad for high-volume agents.

8. **`payloads` table query uses `data LIKE '%term%'`** for raw search — full table scan, no FTS. Manager.db is 380 MB on disk in this checkout.

**Why:** Each of these was load-bearing for an audit conversation; rediscovering them from grep is slow.

**How to apply:** Treat any "tighten this" task in these areas as a refactor that touches >5 files. The IntelDB encapsulation break alone forces all SQL changes to be coordinated with API consumers.
