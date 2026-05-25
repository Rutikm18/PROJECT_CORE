---
name: project-attacklens
description: AttackLens platform overall architecture, components, and storage tiers
metadata:
  type: project
---

AttackLens is an AI-powered EDR/XDR. Manager: FastAPI Python, dual SQLite (manager.db for agents/payloads, intel.db for findings/CVE/threat intel). Agent->Manager via AES-256-GCM + HKDF-derived MAC (HMAC-SHA256) over `agent_id:timestamp:nonce:ct` with REPLAY_WINDOW_SECONDS=300 and DB-backed nonce dedup.

**Why:** Single shared product audited for security/correctness.

**How to apply:** When reasoning about ingest, remember the pipeline order in `manager/manager/api/ingest.py`: parse → schema → timestamp → rate limit → concurrency slot → per-agent HMAC key lookup → decrypt → nonce dedup → store/queue. Sync path writes to three-tier file store (hot/warm/cold under data/) plus SQLite payloads table plus AttackLensEngine via asyncio.create_task. Queue path (RABBITMQ_URL set) publishes to `agent.telemetry` and returns 202.

Major components: TelemetryStore (hot per-minute / warm per-hour / cold per-day NDJSON+gzip + index.db SQLite index), AttackLensEngine (rule-based + CVE + behavioral + correlation), QueueProducer/TelemetryConsumer/AttackLensWorker (RabbitMQ optional), AIAnalyst (Anthropic Claude). RBAC matrix is hard-coded in `manager/manager/api/settings.py` (admin/analyst/viewer) and not actually enforced on the API.
