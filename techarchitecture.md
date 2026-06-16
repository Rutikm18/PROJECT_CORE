# AttackLens — Technical Architecture Deep Dive

## Table of Contents
1. [System Design Principles](#1-system-design-principles)
2. [Directory Structure](#2-directory-structure)
3. [Wire Protocol](#3-wire-protocol)
4. [Agent Internals](#4-agent-internals)
5. [Manager Internals](#5-manager-internals)
6. [Detection Engine — Technical Detail](#6-detection-engine--technical-detail)
7. [Behavioral Analysis Algorithms](#7-behavioral-analysis-algorithms)
8. [Correlation Engine](#8-correlation-engine)
9. [Threat Feed Pipeline](#9-threat-feed-pipeline)
10. [AI Integration](#10-ai-integration)
11. [Composite Risk Scoring](#11-composite-risk-scoring)
12. [Storage Engine](#12-storage-engine)
13. [RabbitMQ Queue Topology](#13-rabbitmq-queue-topology)
14. [Database Schema](#14-database-schema)
15. [API Reference](#15-api-reference)
16. [Performance Characteristics](#16-performance-characteristics)

---

## 1. System Design Principles

### Async-First
Every component that touches I/O is async. The HTTP ingest path does zero I/O except for crypto verification — it publishes to RabbitMQ and returns 202 in < 5 ms. All storage, detection, and enrichment runs in background workers.

### Allowlist-First Detection
Before any rule fires, each telemetry item passes through pple system processes, trusted CDN IP ranges, and benign IDE→tool process spawns are suppressed or downgraded. This is the primary`allowlist.py`. A mechanism for false-positive reduction.

### Defense in Depth
Four detection layers operate independently and in sequence:
1. Static rules (signature-based, high precision)
2. Behavioral baselines (statistical anomaly, context-aware)
3. Cross-section correlation (multi-signal, time-gated)
4. AI triage (language model contextualisation)

### Graceful Degradation
Every external dependency (RabbitMQ, threat feeds, Claude API, SMTP) has a fallback:
- RabbitMQ down → direct in-process processing (slower but functional)
- Threat feeds unavailable → cached intel from last successful sync
- Claude API unavailable → findings emit without AI enrichment
- SMTP down → findings still stored, alerts queued

### Schema-Forward SQLite
Both SQLite databases use `executescript()` for idempotent schema application. Migrations run via `ALTER TABLE ... ADD COLUMN IF NOT EXISTS` pattern before schema execution. UNIQUE constraints use non-empty synthetic keys (`AL-F-XXXXXXXX` format) rather than empty strings.

---

## 2. Directory Structure

```
attacklens/
│
├── agent/                              # macOS endpoint agent
│   ├── agent/
│   │   ├── core.py                     # SectionOrchestrator: scheduler + circuit breakers
│   │   ├── enrollment.py               # First-run enrollment + key exchange
│   │   └── sender.py                   # Encrypted payload dispatch + offline spool
│   ├── os/
│   │   └── macos/
│   │       ├── collectors/
│   │       │   ├── base.py             # BaseCollector ABC
│   │       │   ├── volatile.py         # metrics, connections, processes
│   │       │   ├── system.py           # services, users, hardware, containers, battery
│   │       │   ├── inventory.py        # apps, packages, binaries, sbom
│   │       │   ├── posture.py          # security, sysctl, configs
│   │       │   └── network.py          # ports, network, arp, mounts, openfiles, storage
│   │       ├── installer/
│   │       │   ├── build_pkg.sh        # Builds macOS PKG installer
│   │       │   ├── generate_config.sh  # Generates agent.toml from flags
│   │       │   ├── install.sh          # PKG postinstall script
│   │       │   └── uninstall.sh        # Full removal script
│   │       └── keystore.py             # macOS System Keychain wrapper
│   ├── config/
│   │   └── agent.toml.example          # Full config reference (200+ lines)
│   └── requirements.txt
│
├── manager/
│   ├── manager/
│   │   ├── api/
│   │   │   ├── ingest.py               # POST /api/v1/ingest (auth + decrypt + queue)
│   │   │   ├── agents.py               # Agent CRUD, section data, timelines
│   │   │   ├── enroll.py               # Enrollment handshake
│   │   │   ├── findings.py             # SOC case management (mounted at /api/v1/soc)
│   │   │   ├── intel.py                # Multi-source CVE/KEV/EPSS/exploit intel (/api/v1/intel)
│   │   │   ├── keys.py                 # Key management (rotate, expire, revoke)
│   │   │   ├── remediation.py          # AI remediation + asset registry + threat actors/news
│   │   │   ├── threat.py               # Threat feed stats + IOC + NVD search (/api/v1/threat)
│   │   │   ├── detection.py            # Per-category detection endpoints (/api/v1/detection)
│   │   │   ├── attacklens.py           # AttackLens engine API (/api/v1/attacklens)
│   │   │   ├── posture.py              # Security posture endpoints (/api/v1/posture)
│   │   │   ├── accuracy.py             # Detection accuracy + coverage (/api/v1/accuracy)
│   │   │   ├── assets.py               # Asset registry (/api/v1/assets)
│   │   │   ├── raw.py                  # Raw telemetry query (/api/v1/raw)
│   │   │   └── settings.py             # Platform settings (/api/v1/settings)
│   │   ├── attacklens/                 # Detection engine (primary)
│   │   │   ├── allowlist.py            # FP suppression library
│   │   │   ├── behavioral.py           # Welford z-score + entropy + velocity
│   │   │   ├── correlator.py           # 21 time-gated ATT&CK correlation rules
│   │   │   ├── engine.py               # AttackLensEngine: main dispatcher
│   │   │   ├── feeds.py                # Threat feed manager (in-memory + DB)
│   │   │   ├── nvd.py                  # NVD CVE lookup + caching
│   │   │   └── rules.py                # Static detection rules
│   │   ├── intel/                      # Multi-source vulnerability intelligence pipeline
│   │   │   ├── pipeline.py             # IntelPipeline: orchestrates all intel sources
│   │   │   ├── sources.py              # NVD, CISA KEV, EPSS, ExploitDB, Metasploit, GitHub PoC, GHSA, OSV, CIRCL
│   │   │   ├── scorer.py               # Intel-aware composite risk scorer
│   │   │   └── validator.py            # CVE ID validation + normalisation
│   │   ├── notifications/
│   │   │   ├── __init__.py
│   │   │   └── email.py                # EmailNotifier (SMTP + Graph API)
│   │   ├── queue/
│   │   │   ├── connection.py           # RabbitMQ topology declaration
│   │   │   ├── producer.py             # QueueProducer (publish)
│   │   │   └── schemas.py              # Queue names + message schemas
│   │   ├── threat/                     # Threat data helpers
│   │   │   ├── scoring.py              # Composite risk score matrix
│   │   │   ├── feeds.py                # Feed manager aliases
│   │   │   ├── nvd.py                  # NVD lookup aliases
│   │   │   ├── nvd_sync.py             # NVDSyncWorker (7-day rolling NVD sync)
│   │   │   └── rules.py                # Rule aliases
│   │   ├── workers/
│   │   │   ├── telemetry.py            # TelemetryWorker (store + broadcast + queue)
│   │   │   ├── attacklens.py           # AttackLensWorker (detection pipeline consumer)
│   │   │   ├── intel.py                # ThreatIntelWorker (feed refresh loops)
│   │   │   ├── enrichment.py           # EnrichmentWorker (background AI analysis)
│   │   │   └── consumer.py             # TelemetryConsumer (RabbitMQ main consumer)
│   │   ├── ai_analyst.py               # AIAnalyst (Claude API integration)
│   │   ├── auth.py                     # API key verification middleware
│   │   ├── chunk_tracker.py            # Large payload chunk assembly + dedup
│   │   ├── chunker.py                  # Payload size splitter (> 1 MB → chunks)
│   │   ├── config.py                   # Environment-based config loader
│   │   ├── crypto.py                   # AES-256-GCM + HMAC crypto helpers
│   │   ├── db.py                       # Database (manager.db) + agent registry
│   │   ├── index.py                    # Hot-tier payload index queries
│   │   ├── indexer.py                  # IntelDB (intel.db) — all intelligence tables
│   │   ├── models.py                   # Pydantic request/response models
│   │   ├── pool.py                     # Async connection pool helpers
│   │   ├── server.py                   # FastAPI app factory + startup wiring
│   │   ├── store.py                    # Three-tier NDJSON+gzip file store
│   │   ├── threat_intel_service.py     # Central threat intel microservice (standalone)
│   │   └── ws_hub.py                   # WebSocket hub for live dashboard push
│   ├── dashboard/                      # Static SOC dashboard (HTML/CSS/JS)
│   ├── Dockerfile
│   ├── ThreatIntel.Dockerfile
│   └── requirements.txt
│
├── shared/
│   └── wire.py                         # Wire protocol constants (replay window, etc.)
│
├── docker-compose.yml                  # Full production stack
├── env.sh                              # Interactive setup wizard
└── .env.example                        # Full environment variable reference
```

---

## 3. Wire Protocol

### Payload Format

Each telemetry payload is a signed, encrypted envelope:

```
HTTP POST /api/v1/ingest
Headers:
  Authorization: Bearer <agent_api_key>
  X-Agent-ID: mac-<hardware-uuid>
  X-Section: <section_name>
  X-Timestamp: <unix_epoch_float>
  X-Nonce: <base64-encoded-96bit-random>
  X-Signature: <hex-hmac-sha256>
  Content-Encoding: gzip
  Content-Type: application/octet-stream

Body:
  AES-256-GCM(
    plaintext = gzip(json_encode(section_data)),
    key = agent_session_key,
    nonce = 96-bit random (from X-Nonce header),
    aad = f"{agent_id}:{section}:{timestamp}"  ← authenticated but not encrypted
  )
```

### Replay Protection

```python
# manager/shared/wire.py
REPLAY_WINDOW_SECONDS = 300  # ±5 minutes

# Check in manager/manager/api/ingest.py
if abs(time.time() - timestamp) > REPLAY_WINDOW_SECONDS:
    raise HTTPException(401, "Timestamp outside replay window")
if await db.nonce_exists(nonce):
    raise HTTPException(401, "Replay detected — nonce already seen")
await db.store_nonce(nonce, expires_at=timestamp + REPLAY_WINDOW_SECONDS)
```

### Large Payload Chunking

Payloads > 1 MB are split by `chunker.py` on the agent:
```
Original payload → split into 512 KB chunks
Each chunk has:
  X-Chunk-Index: 0
  X-Chunk-Total: 3
  X-Chunk-ID: <uuid>
```

Manager `ChunkTracker` reassembles chunks and fires detection when the last chunk arrives.

---

## 4. Agent Internals

### Section Orchestrator (`core.py`)

```python
class SectionOrchestrator:
    def __init__(self, config):
        self._sections = {
            # volatile tier (10 s)
            "metrics":     VolatileCollector.metrics,
            "connections": VolatileCollector.connections,
            "processes":   VolatileCollector.processes,
            # ...all 25+ sections
        }
        self._timers: dict[str, float] = {}      # last run timestamps
        self._breakers: dict[str, CircuitBreaker] = {}  # per-section
        self._pool = ThreadPoolExecutor(max_workers=auto)

    async def tick(self):
        """Called every config.collection.tick_sec (5 s by default)."""
        now = time.time()
        tasks = []
        for section, fn in self._sections.items():
            interval = self._config.interval_for(section)
            if now - self._timers.get(section, 0) >= interval:
                if not self._breakers[section].is_open():
                    tasks.append(self._run_section(section, fn))
        await asyncio.gather(*tasks)
```

### Circuit Breaker State Machine

```
        ┌─────────────────────────────────────────────────┐
        │                                                 │
   ┌────▼────┐  3 consecutive failures  ┌──────────────┐  │
   │ CLOSED  │──────────────────────────▶   OPEN       │  │
   │ (normal)│                          │ (skip 60 s)  │  │
   └────▲────┘                          └──────┬───────┘  │
        │                                      │          │
        │  probe success                       │ 60 s     │
        │                               ┌──────▼───────┐  │
        └───────────────────────────────│  HALF-OPEN   │  │
                                        │  (one probe) │  │
                                        └──────────────┘  │
                                               │          │
                                               └──────────┘
                                           probe failure → OPEN
```

### Offline Spool Queue

```
Network failure during send:
  │
  ▼ Write to /Library/AttackLens/spool/
    Filename: {timestamp}-{section}-{nonce}.ndjson.gz
    Format: one payload per file, same wire format as live send
  │
  ▼ On reconnect:
    Drain spool in chronological order
    Delete file on successful send
    Max spool size: configurable (default 500 MB)
```

---

## 5. Manager Internals

### Startup Sequence (`server.py`)

```python
@app.on_event("startup")
async def startup():
    # 1. Setup logging (rotating file handler)
    setup_logging(level=LOG_LEVEL, logfile=LOG_FILE)

    # 2. Init databases
    await db.init()        # manager.db — agents, keys, nonces (SQLitePool readers=4)
    await store.init()     # three-tier NDJSON+gzip file store
    await intel_db.init()  # intel.db  — findings, baselines, AI cache

    # 3. Start detection engine (loads feed cache, initialises NVD index)
    await engine.start()   # AttackLensEngine

    # 4. Start background maintenance tasks
    asyncio.create_task(_cleanup_store())   # hourly hot→warm demotion
    asyncio.create_task(_expire_chunks())   # 5-min chunk-tracker expiry

    # 5. If RabbitMQ is configured, start queue workers
    if producer is not None:
        await producer.start()
        asyncio.create_task(TelemetryWorker(rabbitmq_url, db, store, hub, producer).run())
        asyncio.create_task(AttackLensWorker(rabbitmq_url, engine, chunk_tracker).run())
        asyncio.create_task(TelemetryConsumer(rabbitmq_url, db, store, hub, producer, engine).run())
    # else: sync pipeline — ingest handler calls engine.process() inline

    # 6. Start threat intel subsystem (embedded mode, default)
    if embedded_threat_intel:
        _intel_pipeline = IntelPipeline(engine.feeds, engine.nvd, github_token=...)
        await _intel_pipeline.start()
        app.state.intel_pipeline = _intel_pipeline
        await ThreatIntelWorker(intel_db, db, engine.feeds, engine.nvd,
                                intel_pipeline=_intel_pipeline).start()

    # 7. Start AI enrichment + NVD sync workers
    await EnrichmentWorker(intel_db, rabbitmq_url or None).start()
    await NVDSyncWorker(intel_db).start()

    # 8. Wire shared state for route dependencies
    app.state.intel_db         = intel_db
    app.state.feeds            = engine.feeds
    app.state.threat_intel_url = threat_intel_url  # empty in embedded mode
    app.state.ai_analyst       = AIAnalyst(intel_db, engine.feeds)
    app.state.email_notifier   = EmailNotifier()
```

### Worker Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  RabbitMQ  (optional — sync fallback if RABBITMQ_URL unset)     │
│                                                                 │
│  Exchanges:                                                     │
│    mac_intel.telemetry (direct)                                 │
│    mac_intel.attacklens (direct)                                │
│                                                                 │
│  Queues:                                                        │
│    agent.telemetry  → TelemetryConsumer (prefetch=20)           │
│    attacklens.work  → AttackLensWorker  (prefetch=10)           │
│    mac_intel.dead   → Dead letter queue (nack'd messages)       │
└─────────────────────────────────────────────────────────────────┘
         │                              │
         ▼                              ▼
  TelemetryConsumer           AttackLensWorker
  ┌─────────────────┐       ┌───────────────────────────────────┐
  │ 1. Decrypt      │       │ 1. AttackLensEngine.process()     │
  │ 2. Write store  │       │    a. _dispatch(section, data)    │
  │ 3. Index SQLite │       │    b. BehavioralAnalyzer.analyze  │
  │ 4. WS broadcast │       │    c. Upsert findings to DB       │
  │ 5. Pub al.work  │       │    d. CorrelationEngine (every 3) │
  │ 6. ACK          │       │ 2. ACK                            │
  └─────────────────┘       └───────────────────────────────────┘

  Background workers (always-on, no queue dependency):
  ┌─────────────────┐  ┌──────────────────┐  ┌─────────────────┐
  │ ThreatIntelWorker│  │ EnrichmentWorker │  │  NVDSyncWorker  │
  │ 7 feed loops    │  │ AI background    │  │ 7-day NVD sync  │
  │ (see §9)        │  │ enrichment queue │  │ FTS5 rebuild    │
  └─────────────────┘  └──────────────────┘  └─────────────────┘
```

---

## 6. Detection Engine — Technical Detail

### Allowlist Evaluation (`allowlist.py`)

The allowlist runs before any rule matching. It uses O(1) set lookups and sorted CIDR matching:

```python
# Apple system process check
APPLE_SYSTEM_PROCS: frozenset[str]  # 60+ names, O(1) lookup
APPLE_SYSTEM_PATH_PREFIXES: tuple[str, ...]  # path prefix match

# Trusted IP check
_TRUSTED_NETS: list[ipaddress.IPv4Network]  # pre-compiled CIDR objects
def is_trusted_ip(ip: str) -> bool:
    addr = ipaddress.ip_address(ip)
    return any(addr in net for net in _TRUSTED_NETS)  # O(n) n≈30

# Dual-use tool check
DUAL_USE_TOOLS: dict[str, dict]  # 19 tools with severity_cap
def get_dual_use_info(name, cmd) -> dict | None:
    # substring match on both name and cmdline
```

### Process Rule Matching (`rules.py`)

Each rule carries a `confidence` score (0.0–1.0) that scales the raw severity score:

```python
PROCESS_RULES = [
    {
        "pattern":    r"(?i)(xmrig|xmr-?stak|...)",
        "compiled":   re.compile(...),   # pre-compiled at module load
        "severity":   "critical",
        "confidence": 0.97,              # very high precision rule
        "dual_use":   False,
        "desc":       "Cryptominer process",
        "mitre":      "T1496",
    },
    ...
]

# In engine._processes():
score = severity_to_score(rule["severity"]) * rule.get("confidence", 0.8)
```

### Parent-Child Lineage Detection

```python
# Build pid→item map from current batch
pid_map = {int(item.get("pid", 0)): item for item in data}

for item in data:
    ppid = item.get("ppid") or item.get("parent_pid")
    if ppid:
        parent_item = pid_map.get(int(ppid), {})
        parent_name = parent_item.get("name", "")

    # Check: is this a suspicious spawn?
    for lrule in PARENT_CHILD_RULES:
        if parent_name and lrule["parent_re"].search(parent_name):
            if lrule["child_re"].search(name) or lrule["child_re"].search(cmd):
                # Office app spawning bash = T1566.001
                emit_finding(confidence=lrule["confidence"])
```

### Finding Deduplication

Findings are deduplicated by `(agent_id, category, item_key)` in `intel.db`:

```sql
INSERT INTO findings (agent_id, category, item_key, ...)
VALUES (?, ?, ?, ...)
ON CONFLICT (agent_id, category, item_key) DO UPDATE SET
  severity = excluded.severity,
  score    = excluded.score,
  updated_at = excluded.updated_at,
  active   = 1
```

The `item_key` is constructed to be stable across re-detections:
- Process: `proc:{name}:{sha256(exe+cmd)[:12]}`
- Connection: `conn:{ip}`
- Port: `{proto}:{port}`
- Package CVE: `cve:{name}:{cve_id}`

---

## 7. Behavioral Analysis Algorithms

### Welford Online Algorithm (mean + variance, O(1))

Used for all numeric metrics. No need to store the full sample window.

```python
def _welford_update(n, mean, m2, value):
    n += 1
    delta = value - mean
    mean += delta / n
    delta2 = value - mean
    m2 += delta * delta2
    stddev = math.sqrt(m2 / (n - 1)) if n > 1 else 0.0
    return n, mean, m2, stddev
```

Stored state per agent+metric: `{mean, m2, stddev, sample_count, min_val, max_val}`

### Z-Score Anomaly Detection

```python
ZSCORE_THRESHOLD = 3.0  # 3 standard deviations = 0.3% of normal distribution

def _zscore_check(baseline, value):
    z = (value - baseline.mean) / baseline.stddev
    if abs(z) > ZSCORE_THRESHOLD:
        return {"zscore": z, "mean": baseline.mean, "stddev": baseline.stddev}
    return None
```

Requires `MIN_SAMPLES = 10` before firing to avoid early false positives.

### Velocity Detection (rate-of-change)

```python
VELOCITY_THRESHOLD = 2.5  # current value > 2.5× baseline mean

# In _metrics():
if prev_mean > 5.0 and (value / prev_mean) >= VELOCITY_THRESHOLD:
    emit_finding("high", "Rapid spike: 3.1× above baseline mean")
```

Designed to catch cryptominer startup: CPU jumps from 5% to 98% in one tick.

### Shannon Entropy (connection beaconing detection)

```python
def _shannon_entropy(items: list[str]) -> float:
    """Bits of entropy in the destination IP distribution."""
    counts = Counter(items)
    total = len(items)
    return -sum((c/total) * math.log2(c/total) for c in counts.values())
```

Interpretation:
- **Entropy < 1.2**: Same destination appears > 80% of the time → C2 beaconing candidate
- **Entropy > 4.5** with 10+ connections: Highly diverse destinations → scanning/recon
- Normal browsing: entropy 2.5–3.5

### Entity State Tracking

First-seen detection for services, users, tasks, and network interfaces:

```sql
entity_state (agent_id, section, entity_key, fingerprint, seen_at)
```

```python
prev = await db.get_entity_state(agent_id, "service", "svc:com.example.daemon")
if prev is None:
    # First time seen — flag for review (low severity)
    await db.set_entity_state(...)
    emit_finding("low", "New service observed")
elif prev.fingerprint != current_fingerprint:
    # Configuration changed — flag with age-based severity
    age = now - prev.seen_at
    severity = "high" if age < 300 else "medium" if age < 3600 else "low"
    emit_finding(severity, "Service configuration changed")
```

---

## 8. Correlation Engine

### Time-Gated Evaluation

Every correlation rule now declares `time_window_hours`. Findings are filtered by `detected_at` before category matching:

```python
async def correlate(self, agent_id):
    all_rows = await self._idb.get_findings(agent_id, active_only=True, limit=500)
    now = time.time()

    for rule in CORRELATION_RULES:
        window_secs = rule["time_window_hours"] * 3600
        # Only consider findings within the rule's time window
        gated = [r for r in all_rows
                 if (r.get("detected_at") or r.get("created_at") or 0) >= now - window_secs]
        by_cat = group_by_category(gated)
        by_src = group_by_source(gated)
        if self._eval_rule(rule, by_cat, by_src, gated, agent_id):
            emit_correlation(rule)
```

### Scoring Formula

```python
confidence = rule["confidence"] + (5 * bonus_for_optional_categories)
intel_boost = min(1.0,
    0.4 * any(f["kev"] for f in signals) +
    0.3 * any(f["exploit_available"] for f in signals) +
    0.3 * any(f.get("epss_score", 0) >= 0.7 for f in signals)
)
score = min(10.0, rule["score"] + 0.25 * bonus + intel_boost)
```

### Correlation Rules Quick Reference

| Rule | Time Window | Required Categories | Severity |
|---|---|---|---|
| C2 Beacon + Tool | 24 h | process + connection | critical |
| Defense Evasion Chain | 48 h | security + app | high |
| Persistence Trifecta | 72 h | service + task + config | critical |
| Privilege Escalation | 24 h | binary + process | high |
| LOLBin + Temp Path | 12 h | process + port | high |
| Cryptominer Full Stack | 24 h | process + port | critical |
| Account Takeover | 24 h | user + connection | critical |
| Vulnerable Pkg + Port | 168 h | package + port | high |
| Security + Config Tamper | 48 h | security + config | high |
| Cred Dump + Lateral | 24 h | process + user | critical |
| Ransomware Precursor | 12 h | service + security + process | critical |
| Beacon + Implant | 12 h | behavioral + service | critical |
| LOLBin + Anomaly | 6 h | process + behavioral | high |
| Supply Chain + Connection | 168 h | package + connection | critical |
| New Admin + C2 | 24 h | behavioral + connection | critical |
| Unsigned App + Config | 48 h | app + config | high |
| Process Spawn + C2 | 6 h | process + connection | critical |
| Internal Recon | 12 h | behavioral + port | high |
| Triple Exposure | 168 h | security + package + port | critical |
| SUID + Cred Access | 48 h | binary + user | high |
| Tunnel + Exfil | 12 h | process + behavioral | high |

---

## 9. Threat Feed Pipeline

### FeedManager (`attacklens/feeds.py`)

```python
class FeedManager:
    # In-memory structures (rebuilt on each refresh)
    _malicious_ips: dict[str, dict]   # ip → {severity, source, description}
    _malicious_domains: set[str]
    _kev_set: set[str]                 # CVE-IDs in CISA KEV
    _spamhaus_cidrs: list[ipaddress.IPv4Network]  # bad CIDR ranges

    def is_malicious_ip(self, ip: str) -> bool:
        # O(1) dict lookup after loading
        if ip in self._malicious_ips:
            return True
        # CIDR check for Spamhaus (O(n) n≈500 networks)
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in self._spamhaus_cidrs)
```

### Feed Refresh Intervals

```
┌──────────────────────────────────────────────────────┐
│ ThreatIntelWorker starts 7 async loops on startup:   │
│                                                      │
│  feodo           → every  1 h   (_INTERVAL_FEODO)    │
│  emerging        → every  1 h   (_INTERVAL_EMERGING) │
│  urlhaus         → every  2 h   (_INTERVAL_URLHAUS)  │
│  cisa_kev        → every 24 h   (_INTERVAL_KEV)      │
│  nvd_recent      → every  2 h   (_INTERVAL_NVD_SYNC) │
│  proactive_cve   → every  6 h   (_INTERVAL_CVE_SCAN) │
│  offline_indexes → every  7 d   (_INTERVAL_OFFLINE)  │
└──────────────────────────────────────────────────────┘
```

Each loop: `sleep(delay)` → `fn()` → `record_feed_attempt(success/fail)` → repeat.
First iteration: `delay=0` (immediate refresh at startup).

`offline_indexes` refreshes ExploitDB and Metasploit CSV files from GitHub; the 7-day interval avoids hammering the large archives. In-memory KEV lookup uses `engine.feeds._kev_set` (a `set[str]` of CVE IDs) for O(1) checks during finding emission.

### NVD CVE Lookup Architecture

```
Package telemetry arrives
  │
  ▼ engine._packages()
    Put ("nvd", agent_id, name, version, raw) on asyncio.Queue(maxsize=200)
  │
  ▼ (async, non-blocking) _nvd_worker()
    Pop from queue (rate-limited: 2 s between pops)
    CVELookup.lookup(name, version)
      └── SELECT FROM nvd_cves WHERE name MATCH ? (FTS5)
          → filter CVSS ≥ 4.0
          → attach EPSS + KEV metadata
          → emit finding
```

---

## 10. AI Integration

### Claude API Call Pattern

```python
async def _call_claude(self, prompt: str, max_tokens: int) -> dict:
    message = await self._client.messages.create(
        model="claude-sonnet-4-6",    # configurable via AI_ANALYST_MODEL env
        max_tokens=max_tokens,
        system="You are an expert cybersecurity analyst. Always respond with valid JSON only.",
        messages=[{"role": "user", "content": prompt}],
    )
    return {
        "text":        message.content[0].text,
        "tokens_used": message.usage.input_tokens + message.usage.output_tokens,
    }
```

### JSON Robustness

The response parser handles markdown code fences that some models emit despite system instructions:

```python
def _parse_json_response(self, result: dict) -> dict:
    text = result["text"].strip()
    if text.startswith("```"):
        text = text.split("```")[1].lstrip("json\n")
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        # Fallback: extract first {...} block
        start, end = text.find("{"), text.rfind("}") + 1
        return json.loads(text[start:end])
```

### Enabled Check

```python
@property
def enabled(self) -> bool:
    # Both conditions required — prevents 500 errors when package installed but no key
    return self._client is not None and bool(self._api_key)
```

---

## 11. Composite Risk Scoring

### Scoring Formula (`threat/scoring.py`)

```
composite_score = (
    CVSS_normalized  × 0.30   +   # CVE severity / 10
    EPSS             × 0.25   +   # exploit probability [0,1]
    KEV_flag         × 0.20   +   # 1.0 if CISA KEV, else 0
    recency_score    × 0.10   +   # 1.0 if < 24h, 0.5 if < 7d, 0.2 if < 30d
    behavioral_score × 0.10   +   # 1.0 if z-score anomaly present
    asset_importance × 0.05       # crown_jewel=1.0, server=0.9, workstation=0.55
) × 10.0
```

### Recency Decay

```python
def _recency_score(collected_ts, now):
    age_hours = (now - collected_ts) / 3600
    if age_hours < 24:    return 1.0
    if age_hours < 168:   return 0.5   # < 1 week
    if age_hours < 720:   return 0.2   # < 30 days
    return 0.0
```

### Severity Bucketing

```python
_BUCKETS = (
    (8.5, "critical"),   # composite ≥ 8.5
    (6.5, "high"),       # composite ≥ 6.5
    (4.0, "medium"),     # composite ≥ 4.0
    (1.5, "low"),        # composite ≥ 1.5
)
```

---

## 12. Storage Engine

### Three-Tier File Store (`store.py`)

```python
class TelemetryStore:
    HOT_DAYS  = 7    # keep in hot tier
    WARM_DAYS = 90   # keep in warm tier (auto-demoted from hot)
    # cold: indefinite (explicitly managed)

    def hot_path(self, agent_id, section, ts):
        return f"hot/{agent_id}/{date(ts)}/{section}.ndjson.gz"

    def warm_path(self, agent_id, section, ts):
        return f"warm/{agent_id}/{year(ts)}/{month(ts)}/{section}.ndjson.gz"

    async def write(self, agent_id, section, data, ts):
        path = self.hot_path(agent_id, section, ts)
        with gzip.open(path, "ab") as f:
            f.write((json.dumps(data) + "\n").encode())

    async def read_range(self, agent_id, section, start_ts, end_ts):
        """Stream records from hot + warm that fall in [start_ts, end_ts]."""
        # Hot: fast (indexed in SQLite)
        # Warm: full-scan of compressed file (streaming decompression)
        yield from self._stream_hot(...)
        yield from self._stream_warm(...)
```

### SQLite Write Pattern

All writes to `intel.db` use `upsert_finding()` which is idempotent:

```python
async def upsert_finding(self, finding: dict, ts: float):
    await self._conn.execute("""
        INSERT INTO findings (...) VALUES (...)
        ON CONFLICT(agent_id, category, item_key) DO UPDATE SET
            severity = excluded.severity,
            composite_score = excluded.composite_score,
            ...
            updated_at = ?
    """, (*values, ts))
    await self._conn.commit()
```

---

## 13. RabbitMQ Queue Topology

```
Exchange: mac_intel.telemetry (direct)
  │
  ├── Routing key: "agent.telemetry"
  │       └── Queue: agent.telemetry
  │             Dead-letter exchange: mac_intel.dead
  │             DLQ: mac_intel.dead
  │
Exchange: mac_intel.jarvis (direct)
  │
  └── Routing key: "jarvis.work"
          └── Queue: jarvis.work
                Dead-letter exchange: mac_intel.dead
                Message TTL: 3600000 ms (1 hour)
                x-max-length: 10000

Exchange: mac_intel.dead (direct)
  └── Queue: mac_intel.dead  (manual review / alerting)
```

### Message Schema

```json
// agent.telemetry message
{
  "agent_id":  "mac-abc123",
  "section":   "processes",
  "timestamp": 1715000000.5,
  "payload":   "<base64-encoded encrypted bytes>",
  "version":   "1",
  "chunk_id":  null,
  "chunk_index": null,
  "chunk_total": null
}

// jarvis.work message
{
  "agent_id": "mac-abc123",
  "section":  "processes",
  "data":     [{...}, {...}],  // decrypted, parsed
  "ts":       1715000000.5
}
```

---

## 14. Database Schema

### `manager.db` (operational)

```sql
-- Enrolled agents
CREATE TABLE agents (
    id TEXT PRIMARY KEY,           -- "mac-<hardware-uuid>"
    name TEXT,
    os TEXT,
    hostname TEXT,
    enrolled_at REAL,
    last_seen REAL,
    ip TEXT,
    version TEXT
);

-- Per-agent API keys
CREATE TABLE agent_keys (
    agent_id TEXT PRIMARY KEY REFERENCES agents(id),
    key_hash TEXT NOT NULL,        -- SHA-256 of key (never store plaintext)
    created_at REAL,
    expires_at REAL,               -- NULL = never expire
    revoked INTEGER DEFAULT 0
);

-- Replay protection nonces (TTL 600 s)
CREATE TABLE nonces (
    nonce TEXT PRIMARY KEY,
    agent_id TEXT,
    timestamp REAL,
    expires_at REAL
);
```

### `intel.db` (intelligence)

```sql
-- Core findings (deduplicated)
CREATE TABLE findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    external_id TEXT UNIQUE,       -- "AL-F-XXXXXXXX" synthetic stable key
    agent_id TEXT NOT NULL,
    category TEXT NOT NULL,
    item_key TEXT NOT NULL,
    severity TEXT,
    score REAL,
    composite_score REAL,
    title TEXT,
    description TEXT,
    evidence TEXT,                 -- JSON blob
    source TEXT,
    rule_id TEXT,
    mitre_technique TEXT,
    mitre_tactic TEXT,
    cve_ids TEXT,                  -- JSON array
    cvss_score REAL,
    kev INTEGER DEFAULT 0,
    epss_score REAL,
    ai_analysed INTEGER DEFAULT 0,
    threat_actor_match TEXT,
    news_refs TEXT,                -- JSON array
    active INTEGER DEFAULT 1,
    created_at REAL,
    updated_at REAL,
    detected_at REAL
);

CREATE UNIQUE INDEX idx_findings_key
    ON findings(agent_id, category, item_key);
CREATE INDEX idx_findings_active ON findings(active, agent_id, severity);
CREATE INDEX idx_findings_detected ON findings(detected_at);

-- Behavioral baselines (Welford state)
CREATE TABLE baselines (
    agent_id TEXT NOT NULL,
    metric TEXT NOT NULL,
    mean REAL DEFAULT 0,
    m2 REAL DEFAULT 0,
    stddev REAL DEFAULT 0,
    min_val REAL,
    max_val REAL,
    sample_count INTEGER DEFAULT 0,
    updated_at REAL,
    PRIMARY KEY (agent_id, metric)
);

-- NVD CVE mirror (FTS5 full-text search)
CREATE VIRTUAL TABLE nvd_cves USING fts5(
    cve_id,
    description,
    published_date,
    modified_date,
    cvss_score,
    severity,
    references,
    content='nvd_cves_data'
);

-- AI cache
CREATE TABLE ai_analysis (
    finding_id INTEGER PRIMARY KEY,
    model TEXT,
    analysis TEXT,
    threat_context TEXT,
    risk_factors TEXT,
    ioc_matches TEXT,
    news_context TEXT,
    actor_context TEXT,
    confidence REAL,
    tokens_used INTEGER,
    created_at REAL
);

CREATE TABLE remediation_plans (
    finding_id INTEGER,
    agent_id TEXT,
    os_type TEXT,
    model TEXT,
    summary TEXT,
    steps TEXT,
    verification TEXT,
    long_term TEXT,
    effort TEXT,
    risk_level TEXT,
    created_at REAL,
    PRIMARY KEY (finding_id, os_type)
);
```

---

## 15. API Reference

### Ingest & Enrollment

| Method | Path | Auth | Description |
|---|---|---|---|
| POST | `/api/v1/ingest` | Agent key | Receive encrypted + signed telemetry payload |
| POST | `/api/v1/enroll` | Enrollment token (or open) | Register new agent, receive session key |

### Agent Management (`/api/v1/agents`)

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/api/v1/agents` | Admin token | List all enrolled agents |
| GET | `/api/v1/agents/{id}` | Admin token | Agent detail + last-seen sections |
| GET | `/api/v1/agents/{id}/sections` | Admin token | List sections with data for agent |
| GET | `/api/v1/agents/{id}/{section}` | Admin token | Latest section data for agent |
| DELETE | `/api/v1/agents/{id}` | Admin token | Deregister agent |

### Key Management (`/api/v1/keys`)

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/api/v1/keys` | Admin token | List agent keys + expiry status |
| POST | `/api/v1/keys/{agent_id}/rotate` | Admin token | Issue new session key for agent |
| POST | `/api/v1/keys/{agent_id}/revoke` | Admin token | Revoke agent key |
| POST | `/api/v1/keys/{agent_id}/expire` | Admin token | Set key expiry date |

### SOC Case Management (`/api/v1/soc`)

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/api/v1/soc/dashboard` | Admin token | Aggregate SOC dashboard metrics |
| GET | `/api/v1/soc/sla` | Admin token | SLA compliance metrics |
| GET | `/api/v1/soc/findings` | Admin token | All findings (filterable by agent, severity, category, status) |
| GET | `/api/v1/soc/findings/{id}` | Admin token | Single finding detail |
| PATCH | `/api/v1/soc/findings/{id}` | Admin token | Update finding fields (assignee, priority, notes) |
| GET | `/api/v1/soc/findings/{id}/comments` | Admin token | Get analyst comments on finding |
| POST | `/api/v1/soc/findings/{id}/comments` | Admin token | Add analyst comment |
| GET | `/api/v1/soc/findings/{id}/activity` | Admin token | Finding audit trail |
| GET | `/api/v1/soc/findings/{id}/exploitability` | Admin token | Exploit intelligence for finding CVEs |
| POST | `/api/v1/soc/findings/{id}/close` | Admin token | Close / suppress finding |
| POST | `/api/v1/soc/findings/{id}/accept-risk` | Admin token | Mark as accepted risk |
| POST | `/api/v1/soc/findings/{id}/false-positive` | Admin token | Mark as false positive |
| POST | `/api/v1/soc/findings/{id}/reopen` | Admin token | Reopen closed finding |
| POST | `/api/v1/soc/findings/{id}/open` | Admin token | Transition to open state |
| POST | `/api/v1/soc/bulk` | Admin token | Bulk status update across multiple findings |
| GET | `/api/v1/soc/historical` | Admin token | Historical finding trends |
| GET | `/api/v1/soc/metrics` | Admin token | SOC operational metrics |

### AttackLens Engine (`/api/v1/attacklens`)

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/api/v1/attacklens/stats` | Admin token | Engine-wide detection statistics |
| GET | `/api/v1/attacklens/{agent_id}/summary` | Admin token | Agent detection summary |
| GET | `/api/v1/attacklens/{agent_id}/findings` | Admin token | Agent findings (engine view) |
| GET | `/api/v1/attacklens/{agent_id}/findings/{id}` | Admin token | Single finding detail (engine view) |
| GET | `/api/v1/attacklens/{agent_id}/timeline` | Admin token | Finding timeline for agent |
| GET | `/api/v1/attacklens/{agent_id}/search` | Admin token | Full-text search across agent findings |
| POST | `/api/v1/attacklens/{agent_id}/resolve/{id}` | Admin token | Resolve finding |
| GET | `/api/v1/attacklens/{agent_id}/correlations` | Admin token | Active attack-chain correlations for agent |

### Detection Categories (`/api/v1/detection`)

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/api/v1/detection/summary` | Admin token | Cross-category detection summary |
| GET | `/api/v1/detection/packages` | Admin token | Vulnerable packages with CVE detail |
| GET | `/api/v1/detection/ports` | Admin token | Exposed ports and services |
| GET | `/api/v1/detection/persistence` | Admin token | Persistence mechanisms (services, tasks, startup) |
| GET | `/api/v1/detection/network` | Admin token | Network anomalies and C2 indicators |
| GET | `/api/v1/detection/processes` | Admin token | Suspicious process detections |
| GET | `/api/v1/detection/all` | Admin token | All categories in one response |

### Threat Intelligence (`/api/v1/threat`)

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/api/v1/threat/intel/dashboard` | Admin token | Threat intel overview panel data |
| GET | `/api/v1/threat/intel/actors` | Admin token | Active threat actor / ransomware group list |
| GET | `/api/v1/threat/intel/news` | Admin token | Recent security news items |
| GET | `/api/v1/threat/intel/kev` | Admin token | CISA KEV catalog (from threat router) |
| GET | `/api/v1/threat/intel/epss/top` | Admin token | Top EPSS-scored CVEs in current environment |
| GET | `/api/v1/threat/intel/summary` | Admin token | Aggregated feed summary |
| GET | `/api/v1/threat/intel/cves` | Admin token | CVE list enriched with EPSS + KEV flags |
| GET | `/api/v1/threat/intel/architecture` | Admin token | Architecture/topology intel |
| GET | `/api/v1/threat/stats` | Admin token | Feed health + IOC counts |
| GET | `/api/v1/threat/nvd/stats` | Admin token | NVD sync statistics |
| GET | `/api/v1/threat/nvd/search` | Admin token | NVD FTS5 CVE search |
| GET | `/api/v1/threat/feeds` | Admin token | Feed status and last-sync timestamps |
| GET | `/api/v1/threat/iocs` | Admin token | Current IOC (IP/domain) list |
| GET | `/api/v1/threat/{agent_id}/summary` | Admin token | Per-agent threat summary |
| GET | `/api/v1/threat/{agent_id}/findings` | Admin token | Agent findings (threat view) |
| GET | `/api/v1/threat/{agent_id}/findings/{id}` | Admin token | Single finding (threat view) |
| GET | `/api/v1/threat/{agent_id}/timeline` | Admin token | Agent threat timeline |
| GET | `/api/v1/threat/{agent_id}/search` | Admin token | Search findings for agent |
| POST | `/api/v1/threat/{agent_id}/resolve/{id}` | Admin token | Resolve finding (threat view) |

### Intel Pipeline (`/api/v1/intel`)

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/api/v1/intel/status` | Admin token | Pipeline health + circuit breaker states |
| GET | `/api/v1/intel/cve/{cve_id}` | Admin token | Full multi-source CVE enrichment (NVD, KEV, EPSS, exploits, GHSA, OSV, CIRCL) |
| POST | `/api/v1/intel/enrich` | Admin token | Batch enrich up to 50 CVE IDs |
| GET | `/api/v1/intel/kev` | Admin token | CISA KEV catalog (paginated + searchable) |
| GET | `/api/v1/intel/epss/{cve_id}` | Admin token | EPSS score for single CVE |
| GET | `/api/v1/intel/exploits/{cve_id}` | Admin token | Exploit presence (ExploitDB + Metasploit + GitHub PoC) |

### Remediation & AI (`/api/v1/remediation`)

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/api/v1/remediation/{id}` | Admin token | Get cached OS-specific remediation plan |
| POST | `/api/v1/remediation/{id}/generate` | Admin token | Generate AI remediation plan via Claude |
| GET | `/api/v1/remediation/{id}/analysis` | Admin token | Get cached AI threat analysis |
| POST | `/api/v1/remediation/{id}/analysis/generate` | Admin token | Generate AI threat analysis |
| POST | `/api/v1/remediation/prioritize` | Admin token | AI-ranked finding prioritization |

### Asset Registry (`/api/v1/assets`)

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/api/v1/assets` | Admin token | List all assets with tier and group |
| GET | `/api/v1/assets/{agent_id}` | Admin token | Get asset tier/group/owner |
| PUT | `/api/v1/assets/{agent_id}` | Admin token | Update tier, owner, department, crown-jewel flag |
| GET | `/api/v1/org-groups` | Admin token | List org groups |
| POST | `/api/v1/org-groups` | Admin token | Create/update org group |

### Security Posture (`/api/v1/posture`)

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/api/v1/posture/agents` | Admin token | Posture summary across all agents |
| GET | `/api/v1/posture/{agent_id}` | Admin token | Detailed posture for single agent |

### Detection Accuracy (`/api/v1/accuracy`)

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/api/v1/accuracy/report` | Admin token | Full accuracy + coverage report |
| GET | `/api/v1/accuracy/fp_risk` | Admin token | False-positive risk analysis |
| GET | `/api/v1/accuracy/calibration` | Admin token | Severity calibration metrics |
| GET | `/api/v1/accuracy/correlation` | Admin token | Correlation rule effectiveness |

### Raw Telemetry (`/api/v1/raw`)

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/api/v1/raw/{agent_id}/{section}` | Admin token | Query raw telemetry from hot/warm store |

### Platform Settings (`/api/v1/settings`)

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/api/v1/settings` | Admin token | Get platform configuration |
| PUT | `/api/v1/settings` | Admin token | Update platform configuration |
| GET | `/api/v1/settings/license` | Admin token | License information |
| GET | `/api/v1/settings/roles` | Admin token | Role and permission definitions |
| GET | `/api/v1/settings/audit` | Admin token | Settings change audit log |
| POST | `/api/v1/settings/reset` | Admin token | Reset settings to defaults |
| GET | `/api/v1/settings/export` | Admin token | Export settings as JSON |
| POST | `/api/v1/settings/import` | Admin token | Import settings from JSON |

### Enrichment & Misc

| Method | Path | Auth | Description |
|---|---|---|---|
| POST | `/api/v1/enrich/{finding_id}` | — | Trigger on-demand AI enrichment for a finding |
| GET | `/api/v1/dashboard/ws-token` | Admin token (`X-Admin-Token`) | Issue short-lived WebSocket token for browser dashboard |
| GET | `/health` | None | Database + store + intel health check |

### WebSocket

| Protocol | Path | Auth | Description |
|---|---|---|---|
| WS | `/ws/{agent_id}` | `?token=` query param | Live telemetry + finding push stream |

---

## 16. Performance Characteristics

| Operation | Latency | Notes |
|---|---|---|
| HTTP ingest (crypto + queue) | < 5 ms | No I/O, just HMAC verify + AMQP publish |
| TelemetryWorker write (file + SQLite) | 10–50 ms | Async, off HTTP path |
| JarvisEngine.process() | 5–30 ms | Rules + behavioral (no network I/O) |
| CorrelationEngine.correlate() | 10–100 ms | SQLite query + 21 rule evals |
| NVD CVE lookup (FTS5) | 1–5 ms | Indexed SQLite full-text search |
| AbuseIPDB live check | 200–2000 ms | Network I/O, queued async |
| Claude API call | 1–10 s | Cached after first call per finding |
| Threat feed in-memory lookup | < 1 μs | Set/dict O(1) |
| CIDR range check (Spamhaus) | < 10 μs | O(n) n≈500 pre-compiled networks |
| Behavioral z-score check | < 1 ms | SQLite read + arithmetic |

### Capacity Estimates

| Agents | Payloads/min | RabbitMQ queue depth | SQLite writes/s |
|---|---|---|---|
| 10 | ~50 | < 10 | ~2 |
| 50 | ~250 | < 50 | ~10 |
| 100 | ~500 | < 100 | ~20 |
| 500 | ~2500 | < 500 | ~100 |

For 500+ agents, consider:
- Dedicated RabbitMQ cluster
- Separate `intel.db` per tenant or PostgreSQL migration
- Horizontal scaling via multiple JarvisWorker instances
