# AttackLens Platform — Architecture Reference

## Table of Contents
1. [System Overview](#1-system-overview)
2. [Component Map](#2-component-map)
3. [Agent Architecture](#3-agent-architecture)
4. [Manager Architecture](#4-manager-architecture)
5. [Ingest Pipeline](#5-ingest-pipeline)
6. [Detection Engine](#6-detection-engine)
7. [Threat Intelligence Layer](#7-threat-intelligence-layer)
8. [AI Analysis Layer](#8-ai-analysis-layer)
9. [Storage Architecture](#9-storage-architecture)
10. [Notification System](#10-notification-system)
11. [Security Architecture](#11-security-architecture)
12. [Deployment Architecture](#12-deployment-architecture)
13. [Data Flow Summary](#13-data-flow-summary)

---

## 1. System Overview

AttackLens is a **three-tier endpoint security intelligence platform**:

```
Tier 1 — Collection   : macOS agent collects 25+ telemetry sections
Tier 2 — Processing   : Manager correlates, detects, and enriches with threat intel
Tier 3 — Intelligence : AI analysis + human-readable findings + email notifications
```

The platform is designed around these principles:

- **Async everywhere**: HTTP handler returns in < 5 ms; all heavy processing is off-path
- **Allowlist-first detection**: 60+ Apple system procs and CDN IPs suppressed before any rule fires
- **Defense in depth**: Rules → behavioral baselines → cross-section correlation → AI triage
- **Graceful degradation**: Each subsystem fails independently; ingest never blocks on intel
- **Privacy by design**: Raw telemetry never leaves your infrastructure; only findings are AI-analysed

---

## 2. Component Map

```
┌─────────────────────────────────────────────────────────────────────────┐
│  macOS Endpoint                                                         │
│                                                                         │
│  ┌──────────────────────┐   ┌────────────────────────────────────────┐  │
│  │  attacklens-watchdog │──▶│  attacklens-agent                      │  │
│  │  (launchd supervisor)│   │  ┌──────────────────────────────────┐  │  │
│  └──────────────────────┘   │  │  Section Orchestrator            │  │  │
│                             │  │  (25+ collectors, 5 tiers)       │  │  │
│                             │  └────────────────┬─────────────────┘  │  │
│                             │                   │                    │  │
│                             │  ┌────────────────▼─────────────────┐  │  │
│                             │  │  Sender                          │  │  │
│                             │  │  gzip → AES-256-GCM → HTTPS      │  │  │
│                             │  │  Spool queue on network failure  │  │  │
│                             │  └──────────────────────────────────┘  │  │
│                             └────────────────────────────────────────┘  │
└─────────────────────────────────────┬───────────────────────────────────┘
                                      │ HTTPS / TLS 1.3
┌─────────────────────────────────────▼───────────────────────────────────┐
│  Infrastructure Layer (Docker Compose)                                  │
│                                                                         │
│  ┌──────────────┐   ┌──────────────────────────────────────────────┐   │
│  │  Caddy       │──▶│  Manager  (FastAPI + Uvicorn)                │   │
│  │  TLS proxy   │   │                                              │   │
│  └──────────────┘   │  ┌──────────┐  ┌────────────┐  ┌─────────┐  │   │
│                     │  │ Ingest   │  │ RabbitMQ   │  │ Workers │  │   │
│  ┌──────────────┐   │  │ API      │─▶│ Queue      │─▶│ (async) │  │   │
│  │  RabbitMQ    │◀──│  └──────────┘  └────────────┘  └────┬────┘  │   │
│  │  3.13        │   │                                      │       │   │
│  └──────────────┘   │              ┌───────────────────────▼────┐  │   │
│                     │              │  Jarvis AI Engine          │  │   │
│  ┌──────────────┐   │              │  Allowlist + Rules         │  │   │
│  │  Threat Intel│   │              │  Behavioral + Correlator   │  │   │
│  │  Service     │◀──│──────────────│  NVD + Feed lookups        │  │   │
│  │  (separate   │   │              └───────────────┬────────────┘  │   │
│  │  container)  │   │                              │               │   │
│  └──────────────┘   │              ┌───────────────▼────────────┐  │   │
│                     │              │  AI Analyst (Claude API)   │  │   │
│                     │              │  Email Notifier            │  │   │
│                     │              └────────────────────────────┘  │   │
│                     │                                              │   │
│                     │  intel.db (findings, baselines, AI cache)    │   │
│                     │  manager.db (agents, keys, enrollment)       │   │
│                     └──────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Agent Architecture

### Collection Tiers

| Tier | Interval | Sections |
|---|---|---|
| Volatile | 10 s | metrics, connections, processes |
| Network | 30 s – 2 min | ports, network, arp, mounts |
| System | 2 min | services, users, hardware, containers, battery, openfiles |
| Storage | 10 min | storage, tasks |
| Security | 1 hr | security, sysctl, configs |
| Inventory | 24 hr | apps, packages, binaries, sbom |

### Section Orchestrator (`agent/agent/core.py`)

```
launchd
  └── attacklens-watchdog (PLIST: com.attacklens.watchdog)
        └── attacklens-agent (PLIST: com.attacklens.agent)
              └── SectionOrchestrator
                    ├── Thread pool (max(4, num_sections) workers)
                    ├── Per-section timer with circuit breaker
                    │     3 failures → OPEN (skipped)
                    │     60 s cooldown → HALF-OPEN (probe)
                    │     probe success → CLOSED (resumed)
                    └── Sender (async queue + spool)
```

### Payload Security Pipeline

```
Raw section data (Python dict)
  │
  ▼  json.dumps()
NDJSON string
  │
  ▼  gzip.compress(level=6)
Compressed bytes
  │
  ▼  AES-256-GCM(key=agent_key, nonce=96-bit random)
Ciphertext + 16-byte auth tag
  │
  ▼  HMAC-SHA256(payload_bytes, signing_key)
Integrity signature
  │
  ▼  HTTP POST with headers:
     X-Agent-ID, X-Nonce, X-Timestamp, X-Signature, X-Section
```

### Enrollment Flow

```
Agent first run
  │
  ▼  Generate hardware UUID → agent_id = "mac-<uuid>"
  │
  ▼  POST /api/v1/enroll (agent_id, enrollment_token, pub_key)
  │
  ▼  Manager generates AES-256 session key + HMAC signing key
  │
  ▼  Keys returned encrypted to agent public key
  │
  ▼  Agent stores keys in macOS System Keychain
     (service: com.attacklens.agent, account: agent_id)
```

### Resilience

- **Offline spool**: Failed sends write NDJSON+gzip to `/Library/AttackLens/spool/`; drained in order on reconnect
- **Circuit breakers**: Per-section; prevents a slow collector (e.g. binary scan) from blocking others
- **Watchdog**: launchd supervisor with rate-limited restart (max 5 restarts in 5 min)
- **Hot config reload**: `SIGHUP` → re-reads `agent.toml` without restart

---

## 4. Manager Architecture

### FastAPI Application Structure

```
manager/manager/server.py  (create_app factory)
  │
  ├── Database (manager.db — agents, keys, sessions, nonces)
  ├── TelemetryStore (three-tier file store)
  ├── IntelDB (intel.db — findings, baselines, timelines, AI cache)
  ├── WebSocketHub (live broadcast to dashboard subscribers)
  │
  ├── QueueProducer (publishes to RabbitMQ)
  ├── TelemetryWorker (consumes agent.telemetry queue)
  ├── JarvisWorker (consumes jarvis.work queue → detection)
  ├── ThreatIntelWorker (feed refresh loops)
  ├── EnrichmentWorker (background AI enrichment)
  ├── NVDSyncWorker (NVD 7-day rolling CVE sync)
  │
  ├── JarvisEngine (detection pipeline)
  ├── AIAnalyst (Claude API)
  ├── EmailNotifier (SMTP + Graph API)
  │
  └── Routers:
      ├── /api/v1/ingest     (ingest.py)
      ├── /api/v1/agents     (agents.py)
      ├── /api/v1/findings   (findings.py)
      ├── /api/v1/remediation(remediation.py)
      ├── /api/v1/intel      (threat.py + remediation.py)
      └── /ws/{agent_id}     (WebSocket hub)
```

### SQLite Databases

**`manager.db`** — Operational data
- `agents` — enrolled agent registry
- `agent_keys` — per-agent API keys + expiry
- `nonces` — replay-protection nonce store (TTL 600 s)
- `payload_log` — ingest audit log

**`intel.db`** — Intelligence data
- `findings` — deduplicated security findings (agent+category+item_key)
- `finding_timeline` — history of finding state changes
- `baselines` — Welford statistical baselines per agent+metric
- `entity_state` — first-seen / fingerprint tracking per agent entity
- `correlations` — cross-section attack-chain results
- `nvd_cves` — NVD CVE mirror (FTS5 full-text search)
- `ioc_cache` — threat feed IOC cache
- `cisa_kev` — CISA Known Exploited Vulnerabilities
- `epss_scores` — EPSS exploit probability scores
- `threat_actors` — ransomware.live actor data
- `security_news` — HackerNews + security feed items
- `ai_analysis` — cached Claude finding analysis
- `remediation_plans` — cached Claude remediation plans
- `asset_registry` — asset tier and org group metadata
- `feed_health` — feed refresh status and error tracking

---

## 5. Ingest Pipeline

```
Agent POST /api/v1/ingest
  │
  ▼ (< 1 ms) Verify X-Agent-ID exists in manager.db
  │
  ▼ (< 1 ms) HMAC-SHA256 signature verification
  │
  ▼ (< 1 ms) Replay window check: timestamp ±300 s + nonce uniqueness
  │
  ▼ (< 2 ms) AES-256-GCM decrypt → gunzip → JSON parse
  │
  ▼ (< 1 ms) QueueProducer.publish("agent.telemetry", payload)
  │
  ▼ HTTP 202 Accepted  ← total < 5 ms
  
  ── async (off HTTP path) ──────────────────────────────────────

RabbitMQ → TelemetryWorker (prefetch=20, manual ACK)
  │
  ├── Write to three-tier file store (NDJSON+gzip)
  ├── Update SQLite payload index (section timestamps)
  ├── WebSocket broadcast to dashboard subscribers
  └── Publish to "jarvis.work" queue

RabbitMQ → JarvisWorker
  │
  └── JarvisEngine.process(agent_id, section, data)
        ├── _dispatch() → section-specific analyzer
        ├── BehavioralAnalyzer.analyze()
        ├── Upsert findings to intel.db
        └── CorrelationEngine.correlate() (every 3rd payload)
```

---

## 6. Detection Engine

### Pipeline

```
Raw telemetry section data
  │
  ▼ allowlist.py — Suppress / adjust before any rule fires
  │   • is_apple_system_process() → skip entirely
  │   • is_trusted_ip() → skip CDN/cloud IP connections
  │   • get_dual_use_info() → cap severity for nmap/ngrok/wireshark
  │   • has_benign_parent() → suppress child if IDE/shell parent
  │
  ▼ rules.py — Static pattern matching
  │   • PROCESS_RULES (26 rules): cmdline regex with confidence scores
  │   • PARENT_CHILD_RULES (5 rules): Office/browser → shell spawn
  │   • OBFUSCATION_RULES (5 rules): base64 eval, hex shellcode, IEX
  │   • MALICIOUS_PORTS (47 ports): known C2/RAT/miner ports
  │   • SUSPICIOUS_PATHS: /tmp, /dev/shm, /var/tmp execution
  │   • RISKY_PACKAGES: known malicious/dual-use packages
  │
  ▼ behavioral.py — Statistical anomaly detection (13 sections)
  │   • Welford z-score: |z| > 3.0 = anomaly flag
  │   • Velocity detection: value / baseline_mean > 2.5x = spike
  │   • Shannon entropy: low entropy = beaconing, high = scanning
  │   • Entity tracking: first-seen per service/user/task/interface
  │   • Admin grant detection: privilege escalation via user change
  │
  ▼ NVD CVE worker (async, non-blocking)
  │   • Package name + version → NVD API lookup
  │   • CVSS score ≥ 4.0 → emit finding with CVE metadata
  │   • EPSS + CISA KEV flags attached
  │
  ▼ composite scoring (threat/scoring.py)
  │   composite = (CVSS×0.30) + (EPSS×0.25) + (KEV×0.20)
  │             + (recency×0.10) + (behavioral×0.10) + (asset×0.05)
  │   → scaled to 0–10
  │
  ▼ correlator.py — Cross-section attack chain detection (every 3rd payload)
      • 21 rules, each time-gated (6 h–168 h window)
      • Required category + source matching
      • Confidence boosted by optional categories + intel signals
      • Outputs: severity, attack_chain, blast_radius, likely_next_steps
```

### Detection Rules Summary

| Rule Set | Count | Key Patterns |
|---|---|---|
| Process rules | 26 | Miners, C2 (Sliver/Cobalt/Empire), cred dumpers, DNS tunnels, LOLBins |
| Parent-child lineage | 5 | Office/browser/PDF spawning bash/python/osascript |
| Obfuscation | 5 | base64 eval, hex shellcode, PowerShell IEX, char-code |
| Malicious ports | 47 | Metasploit 4444, CS 50050, Tor 9050, IRC 6667, miner 3333/14444 |
| Suspicious paths | 5 | /tmp, /dev/shm, /var/tmp, path traversal, Downloads |
| Config patterns | 7 | pipe-to-shell, eval base64, reverse shell patterns |
| Risky packages | 22 | miners, exploit frameworks, scanners, tunnellers |
| Service patterns | 4 | numeric-suffix LaunchDaemons, temp-path services |
| Behavioral metrics | 13 | z-score, velocity, entropy, entity first-seen |
| Correlation rules | 21 | Multi-section time-gated ATT&CK kill chains |

---

## 7. Threat Intelligence Layer

### Central Threat Intel Service

A separate Docker container (`attacklens-threat-intel`) owns all feed ingestion. The Manager queries it via HTTP proxy (falls back to local DB if unavailable).

```
Central Threat Intel Service
  │
  ├── Feodo Tracker       → C2 IPs (botnet infrastructure)       [1 hr]
  ├── Emerging Threats    → Compromised hosts                    [1 hr]
  ├── URLhaus             → Malware distribution URLs            [2 hr]
  ├── ThreatFox           → Multi-type IOCs (IPs, domains, URLs) [2 hr]
  ├── Spamhaus DROP+EDROP → Hijacked/botnet CIDR ranges          [6 hr]
  ├── CISA KEV            → Known Exploited Vulnerabilities       [4 hr]
  ├── ransomware.live     → Active ransomware group data          [3 hr]
  ├── HackerNews feed     → Security news (CVE keyword filter)   [2 hr]
  ├── NVD (NIST)          → CVE database (7-day rolling sync)    [2 hr]
  └── EPSS (FIRST.org)    → Exploit prediction scores           [on-demand]
```

**Optional enrichment** (API keys in `.env`):
- AbuseIPDB — IP abuse confidence scoring
- AlienVault OTX — IP/domain/hash threat intel
- GreyNoise Community — Scanner/noise IP detection
- Shodan InternetDB — On-demand internet exposure check

### IP Reputation Pipeline

```
Connection remote_addr
  │
  ▼ Private IP check → skip (RFC 1918)
  │
  ▼ Trusted IP check → skip (Apple/Cloudflare/Google/AWS CDN ranges)
  │
  ▼ feeds.is_malicious_ip(ip) → in-memory cache lookup
  │   Hit → emit finding immediately (< 1 μs)
  │   Miss → queue for AbuseIPDB live check (async, < 2 s)
```

---

## 8. AI Analysis Layer

### AIAnalyst (`manager/manager/ai_analyst.py`)

```python
AIAnalyst(intel_db, feeds)
  │
  ├── analyze_finding(finding_id, finding)
  │     Prompt: finding metadata + KEV/EPSS/news context
  │     Output: {analysis, threat_context, risk_factors, confidence, urgency}
  │     Cache: intel.db ai_analysis table
  │
  ├── generate_remediation(finding_id, finding, os_type)
  │     Prompt: finding + OS type (macos/windows/linux)
  │     Output: {summary, steps[], verification[], long_term[], effort, risk_level}
  │     Cache: intel.db remediation_plans table (per finding+OS)
  │
  ├── prioritize_findings(findings)
  │     Prompt: top-20 findings by composite score
  │     Output: AI-reranked list with priority_rank + reasoning
  │     No cache (real-time CISO view)
  │
  └── enrich_findings_batch(findings)
        Background: analyze up to 10 unanalysed active findings
        Rate-limited: 1 s pause between API calls
```

### Prompt Design Principles

- Structured JSON output only (no markdown in response)
- Finding metadata injected verbatim (no hallucination risk)
- KEV/EPSS/news context enriches threat landscape assessment
- Graceful degradation: `enabled = False` if no API key → all methods return `None`

---

## 9. Storage Architecture

### Three-Tier File Store (`manager/manager/store.py`)

```
/app/data/
├── hot/         (age < 7 days, actively indexed)
│   └── {agent_id}/{date}/{section}.ndjson.gz
├── warm/        (7–90 days, compressed, query via streaming)
│   └── {agent_id}/{year}/{month}/{section}.ndjson.gz
└── cold/        (> 90 days, archive-grade compression)
    └── {agent_id}/{year}/{section}.ndjson.gz.archive
```

- **Hot tier**: Fully indexed in SQLite for instant queries
- **Warm tier**: Streamed on demand; automatically promoted to hot on access
- **Cold tier**: gzip level 9 compression; tiered to cold via background worker
- **Retention**: Configurable per tier; default hot=7d, warm=90d, cold=indefinite

### IntelDB Schema Highlights

```sql
-- Core findings table (deduplicated by agent+category+item_key)
findings (id, agent_id, category, item_key, external_id UNIQUE,
          severity, score, composite_score, title, description,
          evidence JSON, source, rule_id, mitre_technique, mitre_tactic,
          cve_ids JSON, cvss_score, kev, epss_score,
          ai_analysed, threat_actor_match, news_refs JSON,
          active, created_at, updated_at, detected_at)

-- Behavioral baselines (Welford state per agent+metric)
baselines (agent_id, metric, mean, m2, stddev, min_val, max_val,
           sample_count, updated_at)

-- Entity state (first-seen tracking)
entity_state (agent_id, section, entity_key, fingerprint, seen_at)

-- AI cache
ai_analysis (finding_id PRIMARY KEY, model, analysis, threat_context,
             risk_factors JSON, confidence, tokens_used, created_at)

remediation_plans (finding_id, agent_id, os_type, model, summary,
                   steps JSON, verification JSON, long_term JSON,
                   effort, risk_level, created_at)
```

---

## 10. Notification System

### EmailNotifier (`manager/manager/notifications/email.py`)

**Delivery backends** (auto-selected based on config):
1. **SMTP** (aiosmtplib): Generic — works with Gmail, Office 365, Exchange, Postfix
2. **Microsoft Graph API**: Office 365 OAuth2 — no password, token cached in memory

**Notification types**:

| Type | Trigger | Content |
|---|---|---|
| Critical Alert | Finding severity = critical | Finding details, MITRE technique, evidence excerpt, immediate action |
| High Alert | Finding severity = high + KEV/EPSS | Finding context + remediation link |
| Daily Digest | Scheduled (configurable) | Summary: new findings count, top risks, unresolved criticals |
| SOC Action | Analyst closes/escalates finding | Audit trail notification |
| Remediation Ready | AI plan generated | Structured remediation steps for the OS |

---

## 11. Security Architecture

### Encryption Layers

```
Layer 1 — Transport:  TLS 1.3 (Caddy manages certs; ACME or self-signed)
Layer 2 — Payload:    AES-256-GCM with 96-bit random nonce per message
Layer 3 — Integrity:  HMAC-SHA256 over full encrypted payload
Layer 4 — Auth:       Per-agent API key (bearer token, 256-bit random)
Layer 5 — Replay:     ±300 s timestamp window + nonce dedup in manager.db
```

### Key Management

```
Enrollment:
  Agent generates ECDH keypair
  ↓
  POST /api/v1/enroll with public key + enrollment token
  ↓
  Manager generates: AES-256 session key + HMAC signing key
  ↓
  Manager encrypts both keys to agent public key (ECIES)
  ↓
  Agent decrypts and stores in macOS System Keychain
  (service: com.attacklens.agent, never written to disk as plaintext)

Key rotation:
  Admin POST /api/v1/keys/{agent_id}/rotate
  → Agent re-enrolls on next heartbeat (SIGHUP triggers reload)
```

### Network Isolation

```
Internet
  │
  ▼ Caddy (port 8443 or 443)
  │   Only Caddy has a public-facing port
  │   Manager is on Docker internal network only
  │
  ▼ jarvis_internal (Docker bridge network)
  │   manager ↔ rabbitmq ↔ threat-intel
  │   No public IP — only reachable via Caddy
  │
  ▼ Manager (port 8080, internal only)
```

---

## 12. Deployment Architecture

### Docker Compose Services

| Service | Image | Port | Purpose |
|---|---|---|---|
| `caddy` | `caddy:2-alpine` | 8443 / 443 / 80 | TLS reverse proxy |
| `manager` | `jarvis-manager:latest` | 8080 (internal) | Main application |
| `threat-intel` | `attacklens-threat-intel:latest` | 8090 (internal) | Feed sync + CVE DB |
| `rabbitmq` | `rabbitmq:3.13-management-alpine` | 5672 / 15672 | Async message queue |

### Volume Mounts

```
./data/           → /app/data       (SQLite DBs, hot/warm/cold telemetry)
./logs/           → /app/logs       (rotating log files)
./data/threat-intel/ → /app/data    (intel.db for threat-intel service)
./Caddyfile       → /etc/caddy/     (TLS configuration)
```

### Health Checks

All services define Docker health checks:
- Manager: `curl -fs http://localhost:8080/health`
- Threat Intel: `curl -fs http://localhost:8090/health`
- RabbitMQ: `rabbitmq-diagnostics ping`
- Caddy: `wget -qO- http://localhost:80/health`

Startup order: `rabbitmq` (healthy) → `threat-intel` (healthy) → `manager` (healthy) → `caddy`

---

## 13. Data Flow Summary

```
Collection (agent)
  25 collectors × configurable intervals
  → Section payload dict
  → gzip + AES-256-GCM encrypt
  → HTTPS POST to /api/v1/ingest

Ingest (manager, < 5 ms)
  → Verify HMAC + replay window
  → Decrypt + parse
  → Publish to RabbitMQ "agent.telemetry"
  → HTTP 202

Storage (TelemetryWorker, async)
  → Write NDJSON+gzip to hot tier
  → Update SQLite payload index
  → WebSocket broadcast to dashboard
  → Publish to "jarvis.work" queue

Detection (JarvisWorker + JarvisEngine, async)
  → Allowlist check (suppress Apple system procs, CDN IPs)
  → Rules matching (process/port/config/service/binary/user)
  → Behavioral baseline update + anomaly check
  → Parent-child lineage analysis
  → Obfuscation pattern scan
  → Upsert findings to intel.db (deduplicated)
  → Composite score calculation (CVSS+EPSS+KEV+recency+asset)
  → Correlation check every 3rd payload (21 time-gated rules)
  → Correlation upsert to intel.db

Enrichment (async workers)
  → NVD CVE lookup for packages (async queue, 2 s rate limit)
  → AbuseIPDB live check for unknown IPs (async queue)
  → AI analysis for new critical findings (Claude API, cached)
  → Email alert for critical findings (SMTP or Graph API)

Query (API / WebSocket)
  → Dashboard fetches findings, correlations, timelines
  → WebSocket pushes real-time updates
  → AI remediation generated on demand + cached
  → Threat intel proxy to central service (or local DB fallback)
```
