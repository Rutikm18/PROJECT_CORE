# mac_intel Platform — Architecture Reference

## Overview

mac_intel is a multi-OS endpoint telemetry platform. A lightweight **agent** runs on each
endpoint, collects security-relevant data, and ships it encrypted to a central **manager**.
The manager stores, indexes, and exposes the data through a REST + WebSocket API and a
security-analyst dashboard.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           mac_intel Platform                                │
│                                                                             │
│  Endpoints                          Manager                                 │
│  ─────────                          ───────                                 │
│                                                                             │
│  ┌──────────────┐                   ┌─────────────────────────────────┐    │
│  │ macOS Agent  │──┐                │                                 │    │
│  └──────────────┘  │  HTTPS/TLS1.3  │  POST /api/v1/ingest            │    │
│                    ├──────────────▶ │  (AES-256-GCM + HMAC-SHA256)   │    │
│  ┌──────────────┐  │                │                                 │    │
│  │ Linux Agent  │──┘                │  ┌──────────────────────────┐  │    │
│  └──────────────┘                   │  │  Normalizer              │  │    │
│                                     │  │  Raw → Canonical Schema  │  │    │
│  ┌──────────────┐                   │  └──────────────────────────┘  │    │
│  │ Windows Agent│ (planned)         │                                 │    │
│  └──────────────┘                   │  ┌──────────────────────────┐  │    │
│                                     │  │  Three-tier Storage      │  │    │
│  Dashboard / API clients            │  │  hot / warm / cold       │  │    │
│  ┌──────────────┐                   │  └──────────────────────────┘  │    │
│  │  Browser     │◀── WS + REST ─────│                                 │    │
│  └──────────────┘                   │  ┌──────────────────────────┐  │    │
│                                     │  │  SQLite Index            │  │    │
│  ┌──────────────┐                   │  │  (fast range queries)    │  │    │
│  │  CLI / SIEM  │◀──── REST ────────│  └──────────────────────────┘  │    │
│  └──────────────┘                   └─────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Data Flow — Step by Step

```
 Agent                        Network                      Manager
 ──────                       ───────                      ───────

 [Collector runs]
   │  raw OS data (platform-specific)
   ▼
 [Normalizer]
   │  canonical schema (OS-agnostic dict)
   ▼
 [Envelope builder]
   │  gzip + AES-256-GCM encrypt
   │  HMAC-SHA256 sign
   │  add: v, agent_id, timestamp, nonce, section
   ▼
 [HTTPS POST /api/v1/ingest] ─────────────────────────────▶ [Ingest endpoint]
                                                              │
                                                              ├─ 1. Schema check (required fields)
                                                              ├─ 2. Timestamp window ±5 min
                                                              ├─ 3. Nonce dedup cache
                                                              ├─ 4. HMAC verify
                                                              ├─ 5. AES-256-GCM decrypt
                                                              ├─ 6. Normalizer (if needed)
                                                              ├─ 7. Write NDJSON+gz → hot tier
                                                              ├─ 8. Update SQLite index row
                                                              ├─ 9. Upsert agent registry
                                                              └─10. WebSocket broadcast
```

---

## Wire Format

### Why: Encrypted JSON Envelope

| Requirement                        | Choice                  | Reason                                    |
|------------------------------------|-------------------------|-------------------------------------------|
| Confidentiality                    | AES-256-GCM             | NIST-recommended, authenticated cipher    |
| Integrity (whole envelope)         | HMAC-SHA256             | Covers all fields before decryption       |
| Replay prevention                  | Timestamp + nonce dedup | ±5 min window + per-nonce in-memory cache |
| Transport security                 | TLS 1.3                 | Defense-in-depth; crypto-in-motion        |
| Readability for debugging          | JSON base64             | Operator can inspect fields without tools |

### Envelope Schema (v1)

```json
{
  "v":         1,
  "agent_id":  "agent-macbook-air-001",
  "timestamp": 1712345678.123,
  "nonce":     "base64(12 random bytes)",
  "ct":        "base64(AES-256-GCM(gzip(payload_json)) + 16-byte GCM tag)",
  "hmac":      "hex(HMAC-SHA256(agent_id:timestamp:nonce:ct))",
  "section":   "metrics"
}
```

> `section` in the envelope is an **untrusted routing hint only**.
> The authoritative section name is inside the encrypted `ct` payload.

### Decrypted Payload (Canonical)

```json
{
  "schema":       1,
  "section":      "metrics",
  "agent_id":     "agent-macbook-air-001",
  "agent_name":   "Rutik's MacBook Air",
  "os":           "macos",
  "os_version":   "14.4.1",
  "arch":         "arm64",
  "hostname":     "Rutiks-MacBook-Air",
  "collected_at": 1712345678,
  "data":         { ... }
}
```

---

## Storage Format

### Why: NDJSON + gzip

| Alternative          | Why not                                                        |
|----------------------|----------------------------------------------------------------|
| SQLite (all in one)  | Single-writer bottleneck; hard to shard; hard to stream/export |
| Parquet              | Write-once; needs full file to append; complex tooling         |
| MessagePack/CBOR     | Binary; not human-readable; needs schema for inspection        |
| CSV                  | Cannot represent nested structures (processes, connections)    |
| Plain JSON           | Cannot append without parsing; 1 record = 1 file or whole file |
| **NDJSON + gzip**    | ✅ Stream-append, self-describing, universal tooling            |

**NDJSON** = one JSON object per line. Each line is independent.

```
{"schema":1,"ts":1712345678,"agent_id":"a001","os":"macos","section":"metrics","data":{...}}\n
{"schema":1,"ts":1712345688,"agent_id":"a001","os":"macos","section":"metrics","data":{...}}\n
```

**Why gzip**: JSON telemetry compresses 8–15×. A metrics record ~1 KB → ~100–150 bytes on disk.
**Why not brotli**: gzip is universally supported (Python stdlib, curl, jq, Splunk, ELK).

---

## Three-Tier Storage

```
data/
├── hot/                    # 0–24 hours — raw per-collection records
│   └── {agent_id}/
│       └── {section}/
│           └── {YYYY-MM-DD}/
│               └── {HH-MM}.ndjson.gz      ← one file per minute bucket
│
├── warm/                   # 1–90 days — hourly rollup
│   └── {agent_id}/
│       └── {section}/
│           └── {YYYY-MM-DD}/
│               └── {HH}.ndjson.gz         ← one file per hour
│
├── cold/                   # 90+ days — daily rollup
│   └── {agent_id}/
│       └── {section}/
│           └── {YYYY-MM}/
│               └── {DD}.ndjson.gz         ← one file per day
│
└── index.db                # SQLite index — no data, only pointers
    └── telemetry (agent_id, section, ts_min, ts_max, tier, filepath, os, hostname)
```

### Tier Boundaries

| Tier  | Retention   | Granularity     | Query windows          |
|-------|-------------|-----------------|------------------------|
| hot   | 0–24 h      | per-event        | 5m, 15m                |
| warm  | 1–90 days   | hourly rollup    | 1h, 8h, 1d, 7d, 30d   |
| cold  | 90 d–1 year | daily rollup     | 30d, 90d               |

### Index-First Query Pattern

The SQLite index stores `(ts_min, ts_max, tier, filepath)` per file. A time-range query
never scans the filesystem — it asks the index for matching file paths, then reads only
those files. This keeps query latency predictable regardless of how many agents/sections exist.

```
Query: agent_id=a001, section=metrics, start=now-1h, end=now
  │
  ├─ SELECT filepath FROM telemetry
  │    WHERE agent_id='a001' AND section='metrics'
  │      AND ts_max >= start AND ts_min <= end
  │      AND tier='hot'
  │
  └─ Open each .ndjson.gz, stream records, filter ts in [start, end]
```

---

## Multi-OS Normalizer Pattern

Every OS agent implements a `BaseNormalizer` that maps platform-specific collector output
to the **canonical section schema** defined in `shared/schema.py`.

```
                ┌──────────────────────┐
                │  shared/schema.py    │
                │  Canonical schemas   │◀──────────────────────┐
                └──────────────────────┘                       │
                                                               │
  macOS agent              Linux agent           Windows agent │
  ─────────────            ────────────          ─────────────  │
                                                               │
  [MetricsCollector]       [MetricsCollector]    [MetricsCollector]
  uses: vm_stat, top       uses: /proc/meminfo   uses: WMI / psutil
       │                        │                     │
       ▼                        ▼                     ▼
  [macOS Normalizer]       [Linux Normalizer]    [Windows Normalizer]
  maps → canonical  ───────maps → canonical ────maps → canonical
```

### Canonical Metrics Schema (example)

```python
# shared/schema.py
METRICS_SCHEMA = {
    "cpu_pct":      float,   # 0–100, system-wide CPU utilization
    "mem_pct":      float,   # 0–100, RAM utilization
    "mem_used_mb":  int,     # MB used
    "mem_total_mb": int,     # MB total
    "swap_pct":     float,   # 0–100, swap utilization
    "load_1m":      float,   # 1-minute load average (Linux/macOS) or CPU queue (Windows)
    "load_5m":      float,
    "load_15m":     float,
}
```

The manager receives only canonical payloads. It is **fully OS-agnostic at the API layer**.
OS-specific fields live in `data._raw` (optional, for forensic detail) and never appear in
canonical fields.

---

## Canonical Section Schemas

See `shared/schema.py` for the full definition. Summary:

| Section     | Key canonical fields                                              |
|-------------|-------------------------------------------------------------------|
| metrics     | cpu_pct, mem_pct, mem_used_mb, load_1m/5m/15m                    |
| connections | proto, local_addr, local_port, remote_addr, remote_port, state, pid |
| processes   | pid, ppid, name, user, cpu_pct, mem_pct, cmdline                  |
| ports       | proto, port, bind_addr, state, pid, process                       |
| network     | interfaces[], dns_servers[], default_gw, hostname                 |
| users       | name, uid, gid, shell, home, last_login                           |
| services    | name, status, enabled, pid, type                                  |
| security    | sip, gatekeeper, filevault, firewall, xprotect, secure_boot       |
| storage     | volumes[] with mount, total_gb, used_gb, pct                      |
| packages    | manager, name, version, installed_at                              |

---

## Agent Configuration: agent.toml

```
agent.toml
├── [agent]           — identity (id, name, group, tags, os, arch)
├── [manager]         — server URL, api_key, tls settings, config poll interval
├── [collection]      — global tick_sec, max_payload_bytes
│   └── [collection.sections.*]  — per-section enable/interval/send
├── [retention]       — local data retention before upload
└── [logging]         — level, file, rotation
```

The manager can **override** any `[collection.sections.*]` setting via `GET /api/v1/config`
without restarting the agent. Agents poll this endpoint every `poll_config_sec` seconds.

---

## Manager Configuration: manager.conf

```
manager.conf
├── [server]          — host, port, TLS cert/key
├── [auth]            — api_key, replay_window_sec, max_payload_bytes
├── [storage]         — data_dir, retention per tier, cleanup_interval_sec
├── [cors]            — allowed origins
├── [logging]         — level, file, rotation
└── [policy.*]        — agent policy pushed down to all/group/specific agents
    ├── [policy.global.sections.*]
    ├── [policy.group.<name>.sections.*]
    └── [policy.agent.<id>.sections.*]
```

---

## Security Architecture

### Layers

| Layer            | Control                                                 |
|------------------|---------------------------------------------------------|
| Transport        | TLS 1.3 — encrypt + authenticate channel                |
| Payload          | AES-256-GCM — encrypt payload independently of TLS     |
| Integrity        | HMAC-SHA256 — envelope-level signing                    |
| Replay           | ±5 min timestamp window + per-nonce dedup               |
| Identity         | Pre-shared API key + HKDF key derivation                |
| Authorization    | WebSocket token = API key; ingest is key-authenticated  |
| Validation       | Schema check → timestamp → nonce → HMAC → decrypt       |

### Key Derivation

```
API_KEY (shared secret)
    │
    ▼
HKDF-SHA256
    ├── info="enc" → enc_key  (AES-256-GCM encryption)
    └── info="mac" → mac_key  (HMAC-SHA256 signing)
```

One API key derives two independent keys — compromise of one does not expose the other.

---

## Extending the Platform

### Adding a new section

1. `shared/sections.py` — add `SectionDef` entry
2. `shared/schema.py` — add canonical field definitions
3. `agent/agent/collectors/<category>.py` — implement collector
4. `agent/agent/collectors/__init__.py` — register collector
5. `agent/agent/normalizer.py` — add normalizer mapping
6. `agent.toml.example` — add `[collection.sections.<name>]` block
7. `manager.conf.example` — add `[policy.global.sections.<name>]` block
8. `manager/dashboard/templates/index.html` — add UI rendering
9. `tests/` — add unit + integration tests
10. `make test` — confirm all green

### Adding a new OS agent

1. Create `agents/<os>/` directory mirroring `agent/` structure
2. Implement collectors using OS-native APIs
3. Implement `agents/<os>/normalizer.py` mapping to `shared/schema.py`
4. Reuse `shared/wire.py`, `shared/sections.py`, `shared/schema.py` unchanged
5. The manager requires **zero changes** — it receives canonical payloads

---

## Directory Structure

```
macbook_data/
├── agent/                          macOS agent
│   └── agent/
│       ├── collectors/             22 data collectors
│       │   ├── base.py             BaseCollector ABC
│       │   ├── volatile.py         metrics, connections, processes (10s)
│       │   ├── network.py          ports, network, arp, mounts (30s-2min)
│       │   ├── system.py           battery, services, users, hardware... (2min)
│       │   ├── posture.py          security, sysctl, configs (1hr)
│       │   └── inventory.py        apps, packages, binaries, sbom (24hr)
│       ├── normalizer.py           macOS → canonical schema
│       ├── core.py                 main collection loop
│       ├── config.py               AgentConfig dataclass
│       ├── crypto.py               AES-256-GCM + HMAC
│       └── sender.py               HTTPS POST with retry
│
├── agents/                         future OS agents
│   ├── linux/                      Linux agent (planned)
│   └── windows/                    Windows agent (planned)
│
├── manager/                        Central manager
│   └── manager/
│       ├── api/
│       │   ├── ingest.py           POST /api/v1/ingest
│       │   └── agents.py           GET /api/v1/agents[/{id}[/{section}]]
│       ├── store.py                NDJSON+gz three-tier file store
│       ├── index.py                SQLite index for fast range queries
│       ├── db.py                   agent registry (SQLite)
│       ├── server.py               FastAPI app factory
│       ├── config.py               ManagerSettings from env
│       ├── crypto.py               AES-256-GCM + HMAC (server-side)
│       ├── auth.py                 envelope verification
│       └── ws_hub.py               WebSocket broadcast hub
│
├── shared/                         Shared between agent and manager
│   ├── sections.py                 Section definitions (single source of truth)
│   ├── schema.py                   Canonical per-section field schemas
│   └── wire.py                     Wire protocol constants
│
├── dashboard/
│   └── templates/index.html        Security analyst UI
│
├── tests/
│   ├── unit/                       Crypto, auth, collector tests
│   └── integration/                Full ingest pipeline tests
│
├── agent.toml.example              Agent config template
├── manager.conf.example            Manager config template
├── Makefile                        Dev workflow
├── docker-compose.yml              Production deploy
└── ARCHITECTURE.md                 This file
```
