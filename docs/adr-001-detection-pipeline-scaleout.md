# ADR-001 — Detection pipeline scale-out (Phase 3)

**Status:** Reliability and role isolation implemented; partitioned horizontal
detection remains gated on scale triggers.
**Date:** 2026-08-02.
**Context:** The pipeline now accepts many endpoint agents concurrently without
splitting one endpoint's temporal detector state. Cross-process horizontal
detection still requires sticky partitioning and remains execution-ready below.

---

## What Phases 1–2 already gave us

- **P1** — workers nack on critical-step failure (no more silent detection
  loss); DLQ replayer drains `mac_intel.dead` with backoff + poison parking;
  correlation fires on *every* event (was every 3rd).
- **P2** — exact `detection_events` outbox keyed by authenticated event ID,
  durable `detection_event_chunks`, and verbatim reconciliation. Completion is
  split into `processed_at` and `correlated_at`: an event stays replayable until
  every chunk, finding write, and required correlation write succeeds. Ledger
  lag is exposed on `/ingest/health`.
- **P2.5** — explicit `api`, `telemetry`, `detection`, `maintenance`, and `intel`
  roles. API/telemetry collectors can be replicated; singleton maintenance and
  intel schedules are no longer duplicated. PostgreSQL is the HA raw source;
  the shared gzip/SQLite archive is disabled.
- **P2.6** — the telemetry and detection consumers process different agents
  concurrently, bounded by broker prefetch, while an agent-keyed lock preserves
  each endpoint's temporal order within the detection process.
- **P2.7** — detector entity/baseline updates are buffered per event and flushed
  only after findings persist, preventing a failed write from advancing state
  and suppressing its own retry. Worker tasks are cancelled/drained before DB
  shutdown, and legacy/rich source shapes supported by detectors are enforced in
  the shared schema (`sysctl`, configs, and rich ARP wrappers).

Net: at-least-once, self-healing, real-time-correlated detection with bounded
parallelism across agents and serialized processing per agent. Phase 3 is only
about scaling the stateful detection role across processes without losing that
affinity.

## Adoption triggers (do NOT build before the relevant one fires)

| Trigger (sustained) | Adopt |
|---|---|
| `detection.queue_depth` regularly > 1k, or detection lag > 60 s | **3A** worker scale-out + partitioning |
| Correlation DB read is a measured hot-path cost (p95 `_run_correlations` > 50 ms, or >500 corr/s) | **3B** stateful windows |
| > ~5k agents, or broker/Postgres is the throughput ceiling, or HA/multi-region required | **3C** Kafka + HA datastores |

Single-number rule of thumb: one AttackLens worker comfortably handles
~hundreds of agents. Below that, **do not partition** — it adds a plugin
dependency and N shard queues for zero benefit.

---

## 3A — Partitioned, ordered worker scale-out

**Problem.** Today `attacklens.work` has one detection-role consumer with
agent-keyed in-process serialization. Adding detection processes distributes a
single agent across separate module-level temporal caches. Durable chunk
completion remains correct, but rate/beacon/churn windows could miss part of a
sequence.

**Design.** Route detection work by a consistent hash of `agent_id` so all of an
agent's events land on the same worker, in order. This is exactly how
Datadog/Crowdstrike shard telemetry.

- Enable the `rabbitmq_consistent_hash_exchange` plugin (ships with RabbitMQ —
  `rabbitmq-plugins enable rabbitmq_consistent_hash_exchange`; add to the broker
  image/init).
- New exchange `mac_intel.detect.hash` (type `x-consistent-hash`). Declare N
  shard queues `attacklens.work.{0..N-1}`, each bound with an integer weight
  routing key. Publish with `routing_key = agent_id` (the plugin hashes it).
- Each worker consumes exactly one shard queue → an agent is sticky to a shard;
  its in-process agent lock still prevents concurrent events within that shard.
- **Opt-in & reversible:** gate behind `ATTACKLENS_PARTITIONED_DETECTION`
  (default off). Off → today's single direct queue (zero change). The DLQ
  replayer routes back via `x-death` regardless.

**Touchpoints.** `queue/schemas.py` (shard names/exchange), `queue/connection.py`
(`declare_topology` conditional branch), `queue/producer.py`
(`publish_attacklens_work` routing key = agent_id when partitioned),
`workers/attacklens.py` (consume an assigned shard), `server.py` (spawn N
workers), the rebalancing note below.

**Rebalancing caveat.** Changing N remaps agents to shards (consistent hashing
minimizes but doesn't eliminate movement). In-flight per-agent in-memory state
(3B) must flush on shard reassignment. With DB-backed correlation (current),
remap is safe — the DB is shared truth. So **adopt 3A before 3B**.

## 3B — Per-agent stateful correlation windows

**Problem.** `_run_correlations` re-reads "recent signals" from Postgres on every
coalesced pass. At high correlation rates that is N DB queries/sec of pure
overhead — the signals are data we *just wrote*.

**Design (Flink/Kafka-Streams windowed-join model).** Keep a bounded, TTL'd
in-memory sliding window of recent signals per agent, owned by the worker that
the agent is sticky to (requires 3A for correctness across workers). Every new
signal incrementally updates the window and re-evaluates cross-layer rules in
O(1) — no per-pass DB fan-out. Postgres remains the durable record (async
write-behind) and the recovery source on worker restart / shard remap (warm the
window from `get_recent_signals` once).

- **Correctness gate:** only authoritative when the agent is sticky to this
  worker — i.e. `ATTACKLENS_PARTITIONED_DETECTION` on (or a single worker). When
  off with >1 worker, fall back to the DB path (an in-memory window would miss
  other workers' signals).
- **Memory bound:** cap window size/age per agent; evict oldest; cap agents/worker.
- **Data structure:** `CorrelationState{agent_id → deque[Signal] within window}`,
  held by `AttackLensEngine`; `_request_correlation` updates it instead of (or
  before) the DB pull.

**Touchpoints.** `attacklens/engine.py` (`_run_validation_pipeline` populates the
window; `_run_correlations` reads it when gated on), a new
`attacklens/correlation_state.py` (the windowed store + eviction),
`correlator.py` (accept an in-memory signal set instead of an idb handle).

## 3C — Kafka/Redpanda hot path + HA datastores

**Problem.** A one-node RabbitMQ and one-node Postgres deployment are SPOFs and
a throughput ceiling. Quorum queues only become replicated when the RabbitMQ
cluster has multiple nodes. RabbitMQ is excellent for work queues but not for replayable,
partitioned, high-throughput event logs at scale.

**Design (Kappa architecture).**
- Replace the `agent.telemetry`/`attacklens.work` hot path with Kafka/Redpanda
  topics partitioned by `agent_id` (native ordered partitions + consumer groups
  → 3A for free, and replay-from-offset makes the reconciler trivial).
- Keep the outbox: ingest writes payload + `payload_ledger` row in one Postgres
  tx; a Debezium/relay CDC publishes to Kafka. This is the textbook
  exactly-once-effect hand-off (removes the double-store-on-replay that the
  RabbitMQ path tolerates).
- Postgres → primary + read replicas (or Citus/CockroachDB) for findings/intel;
  consider ClickHouse as an analytics replica past ~100k findings.
- Broker/datastore HA: multi-AZ, quorum queues / replicated topics.

**Migration is incremental:** Kafka can sit behind the same producer/worker
interfaces (`QueueProducer`, `*Worker`) — swap the transport, keep the
`engine.process` contract. The ledger/reconciler/DLQ-replayer concepts all carry
over (offsets replace DLQ for the hot path; the DLQ pattern stays for poison
handling).

---

## Decision

Ship Phases 1–2 (done). Hold Phase 3 behind the triggers above. When a trigger
fires, implement in order **3A → 3B → 3C**, each independently shippable and
each gated/reversible. Revisit this ADR at the first trigger.
