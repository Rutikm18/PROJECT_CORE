# AttackLens — Project Technical Overview

**A self-hosted, multi-tenant endpoint detection & response (EDR) platform.**
Version `1.1.0` · Agent (macOS / Windows / Linux) → Manager (async ingest + detection + AI) → real-time SOC dashboard.

---

## 1. What it is (in one paragraph)

AttackLens collects rich, structured telemetry from endpoints, ships it encrypted and loss-lessly to a self-hosted manager, correlates it against static rules + behavioral baselines + a 21-rule time-gated MITRE ATT&CK kill-chain correlator + 10 live threat-intel feeds, layers Claude-powered analysis and remediation on top, and surfaces prioritized findings through a live WebSocket dashboard. It is designed to be **operated by one team on their own infrastructure** — no SaaS dependency, no per-seat licensing — while behaving like a production EDR: agents survive reboots and outages, the ingest path never blocks, and no detection is trusted that can't be proven authentic.

---

## 2. Design philosophy — the non-obvious decisions

These are the engineering choices that define the system. Each exists to solve a failure mode that naive implementations hit in the field.

| Principle | Decision | Why it matters |
|---|---|---|
| **Never silently lose telemetry** | Every payload is disk-spooled on any send failure and replayed on reconnect/reboot; the HMAC transport timestamp is **re-stamped at actual send time** so spooled data survives past the manager's replay window. | Store-and-forward EDRs routinely lose data during outages. Zero-loss is proven by an automated offline→online replay test (200 envelopes, in order, no dupes). |
| **The ingest HTTP path must not block** | The HTTP handler only verifies + decrypts + enqueues to RabbitMQ, returning `202` in **< 5 ms**. All storage, indexing, detection, and AI happen off-path on worker queues. | Decoupling HTTP from storage lets a single node absorb bursty fleet traffic without back-pressuring agents into 429 storms. |
| **Trust nothing you can't cryptographically prove** | Manager→agent policies are **signature-verified over the exact transmitted bytes** (verify *before* parse), audience-scoped, expiry-checked, and version-monotonic. Active response **fails closed**: absent a perfect proof, it stays off. | A control plane that can change agent behavior is a supply-chain attack surface. Fail-closed + verify-before-parse eliminates the "tampered policy" and "parser-gadget" classes. |
| **Degrade, don't die** | Per-section circuit breakers + a per-thread wall-clock budget: a hung/slow collector is skipped or returns *partial* data within its deadline and never overwrites the last-good snapshot with an error blob. | One stuck `system_profiler` call must not freeze a section forever or starve the worker pool. |
| **A root daemon has no user session at boot** | Boot-critical secrets live in a root-owned `0600` file, never the login keychain (locked until a user logs in). Persistence self-repairs a deleted/disabled plist. | "Works interactively, dead after reboot" is the classic macOS system-daemon trap — designed out. |
| **Unknown ≠ fail** | Missing privileged fields score **unknown** and are excluded from the CIS denominator, never counted as a false FAIL. | Avoids alarming operators with confidently-wrong compliance scores. |

---

## 3. End-to-end data flow

```
macOS / Windows / Linux endpoint
  ┌──────────────────────────────────────────────────────────┐
  │ attacklens-agent  (23 collectors + agent_health)         │
  │   NDJSON → gzip → AES-256-GCM (96-bit nonce)             │
  │        → HMAC-SHA256 → TLS 1.3                           │
  │   DiskSpool (append-only NDJSON, 50 MB cap, replay)      │
  └───────────────────────────┬──────────────────────────────┘
                              │ HTTPS  POST /api/v1/ingest
  ┌───────────────────────────▼──────────────────────────────┐
  │ Caddy (TLS termination: self-signed or ACME)             │
  └───────────────────────────┬──────────────────────────────┘
  ┌───────────────────────────▼──────────────────────────────┐
  │ Manager (FastAPI + Uvicorn)                              │
  │  Ingest: verify agent → HMAC → replay window (±300s +   │
  │  nonce) → AES-GCM decrypt → gunzip → publish → 202 <5ms  │
  │                          │                               │
  │            RabbitMQ  agent.telemetry ──► TelemetryWorker │
  │              │  three-tier file store (NDJSON+gzip)      │
  │              │  SQLite payload index · WS broadcast      │
  │              └─ publish jarvis.work ──► JarvisWorker     │
  │                   allowlist → rules → behavioral →       │
  │                   NVD CVE → composite score → correlator │
  │                   → findings (intel.db) → AI analysis    │
  └───────────────────────────┬──────────────────────────────┘
                              │ WebSocket
  ┌───────────────────────────▼──────────────────────────────┐
  │ SOC dashboard (React/Vite): findings, attack chains,     │
  │ asset registry, link health, remediation plans           │
  └──────────────────────────────────────────────────────────┘
```

---

## 4. Agent architecture (deep)

**Collection model.** 23 sections grouped by cadence tier, each an independent collector in the OS-specific registry, scheduled concurrently by the `Orchestrator` (`agent/agent/core.py`) on a thread pool:

- **Volatile (10 s):** metrics, connections, processes
- **Network (30–120 s):** ports, network, arp, mounts
- **System (120 s):** battery, open files, services, users, hardware, containers
- **Inventory (10 min–24 h):** storage, tasks, apps, packages, binaries, sbom
- **Posture (1 h):** security, sysctl, configs — feeds 23 CIS checks
- **Compliance (12 h):** SCA (CIS benchmark scan)
- **Synthetic (60 s):** `agent_health` heartbeat — circuit-breaker snapshot, queue depth, uptime, manager link state, policy versions

**Payload security pipeline (per envelope):** `NDJSON → gzip → AES-256-GCM (random 96-bit nonce) → HMAC-SHA256 → TLS 1.3`. Keys are derived per-agent from the enrollment secret; envelopes are sealed *before* they ever touch the queue or disk spool, so spooled data at rest is already encrypted.

**Resilience & self-healing (the hard part):**
- **launchd `KeepAlive` + `RunAtLoad`** — auto-start at boot, auto-restart on exit, `ThrottleInterval=10` floor.
- **Boot-persistence self-repair** (`boot_persistence.py`) — verifies + repairs the plist (present, `RunAtLoad`/`KeepAlive`, `root:wheel`/`0644`, launchd-*enabled*, loaded) at startup and on every self-heal cycle; defeats tamper/uninstall that would otherwise kill persistence at the next boot.
- **`self_heal` daemon (300 s one-shot)** — re-bootstraps a dropped job and catches *silent non-delivery* (agent alive but shipping nothing: manager down, rogue server on the port, persistent 401) with cause-specific recovery — never a blind restart that would trigger a spool-replay storm.
- **Single-instance guard** (`single_instance.py`) — advisory `flock` so two agent processes can't race on the shared spool.
- **Boot-safe key storage** — file keystore (root can read at boot), with keychain→file mirror migration.
- **Reboot detection** — emits a `system_boot` event with downtime + clean/unexpected verdict.
- **Wake-from-sleep resume** — monotonic-gap detection forces an immediate reprobe + spool drain after the Mac wakes.
- **Clock-skew resilience** — a backward NTP correction after boot re-seeds the schedule instead of stalling collection.

**Zero-loss delivery** (`agent/sender.py`): dedicated sender thread; on any send failure the encrypted envelope is written to an append-only NDJSON spool (50 MB cap, oldest-10% trim, **disk-full-safe** — write never raises), replayed on startup and drained the instant the manager is reachable again. Exponential backoff + jitter; HTTP-status aware (`401`→re-enroll after 3 strikes, `429` transient, `503`→spool, other `4xx`→drop as unrecoverable).

**Dynamic signed config** (`config_engine.py` + `policy.py`): one immutable `RuntimeConfig` merged from `baseline (agent.toml) ◅ verified manager policies ◅ tighten-only env overrides`. Signature verify runs **before** JSON parse; 10-step reject ladder (corrupt/key_unavailable/signature_invalid/schema/audience/expiry/downgrade). Cache-first + non-blocking so the agent runs from last-verified policies even offline; high-water version persists across restarts to block replay.

---

## 5. Manager architecture (deep)

**Async ingest** — `POST /api/v1/ingest` does the minimum on the hot path (agent-exists check → HMAC verify → replay-window/nonce check → AES-GCM decrypt → gunzip → publish to RabbitMQ), returning `202` in `< 5 ms`. Two worker classes consume off-path:
- **TelemetryWorker** (prefetch=20, manual ACK) → three-tier file store, SQLite payload index, WebSocket broadcast, and publish to `jarvis.work`.
- **JarvisWorker** → the detection engine.

**Detection engine** (layered, order matters):
1. **Allowlist** — suppress before any rule fires (Apple system processes, trusted CDN/cloud IPs, dual-use severity caps, benign IDE/shell parents).
2. **Static rules** — 26 process rules, 5 parent-child lineage, 5 obfuscation, 47 malicious ports, suspicious paths, risky packages.
3. **Behavioral** (13 sections) — Welford online z-score (|z|>3), velocity (>2.5× baseline), Shannon entropy (beaconing vs scanning), entity first-seen, privilege-escalation detection.
4. **NVD CVE worker** (async) — package+version → CVE, CVSS≥4 emits findings with EPSS + CISA KEV flags.
5. **Composite scoring** — `CVSS·0.30 + EPSS·0.25 + KEV·0.20 + recency·0.10 + behavioral·0.10 + asset·0.05`, scaled 0–10.
6. **Correlator** (every 3rd payload) — 21 time-gated (6–168 h) cross-section rules producing attack-chain, blast-radius, likely-next-steps.

**Threat intel** — a separate `attacklens-threat-intel` container owns feed ingestion (Feodo, Emerging Threats, URLhaus, ThreatFox, Spamhaus DROP, CISA KEV, ransomware.live, NVD, EPSS); the manager proxies to it with a local-DB fallback.

**AI analysis** (`ai_analyst.py`) — Claude-powered finding analysis + step-by-step remediation plans, cached in `ai_analysis` / `remediation_plans` tables (keyed by finding) so a finding is analyzed once.

**Storage — three-tier file store** (`store.py`): `hot` (<7 d, SQLite-indexed) → `warm` (7–90 d, streamed, promote-on-access) → `cold` (>90 d, gzip-9 archive). Findings/baselines/entity-state/AI-cache live in SQLite (`intel.db`), deduplicated by `agent+category+item_key`.

---

## 6. Security / threat model highlights

- **Transport:** TLS 1.3 min; envelope AES-256-GCM + HMAC-SHA256; per-agent keys.
- **Replay resistance:** timestamp window ±300 s + nonce uniqueness at ingest.
- **Control-plane integrity:** signed policies verified over raw bytes before parse; monotonic version high-water blocks downgrade/replay; response gate fails closed.
- **Secret handling:** boot-safe root-owned `0600` key file; automatic re-enrollment on persistent `401`; keys never loaded from the config file.
- **Persistence integrity:** plist ownership/enable/structure self-repaired; single-instance lock prevents spool corruption.

---

## 7. Technology stack

| Layer | Tech |
|---|---|
| Agent | Python 3.13, PyInstaller (native ARM64 binary), `launchd` (macOS) / SCM (Windows) / `systemd` (Linux), psutil |
| Transport | TLS 1.3, AES-256-GCM, HMAC-SHA256, gzip, NDJSON |
| Manager API | FastAPI + Uvicorn, async workers |
| Messaging | RabbitMQ (`agent.telemetry`, `jarvis.work`) |
| Storage | Three-tier NDJSON+gzip file store, SQLite (payload index, `intel.db`), optional Postgres |
| Detection | Custom rules engine, Welford statistics, MITRE ATT&CK correlator, NVD/EPSS/KEV |
| AI | Claude (Anthropic) — finding analysis + remediation |
| Frontend | React + Vite + Tailwind/shadcn, WebSocket live updates |
| Infra | Docker Compose, Caddy (TLS), separate threat-intel container |

---

## 8. What I've built so far (engineering log)

Focused on **agent reliability and operational trustworthiness** — the edges where EDR agents actually fail in production.

**macOS agent — reboot & persistence hardening**
- Boot-persistence self-repair module (`boot_persistence.py`): verifies + repairs the LaunchDaemon (existence, `RunAtLoad`/`KeepAlive`, `root:wheel`/`0644`, launchd-enabled, loaded) at startup and on each self-heal cycle; added `is_enabled()`/`enable()` to `launchd.py`.
- Reboot-detection telemetry: `system_boot` event with estimated downtime + clean-vs-unexpected verdict (clean only if the agent got a graceful `SIGTERM`).
- Wake-from-sleep resume: monotonic-gap detector in the sender forces an immediate manager reprobe + spool drain after sleep.

**Fixed a real "dead after restart" root cause**
- The agent stored its key in the **login keychain**, which a root LaunchDaemon can't read at boot (no user session) → key lost every reboot → silent non-delivery. Fix: default to a boot-safe root-owned file keystore, always mirror keychain→file, and migrate keychain-only installs on first run. Postinstall now verifies the daemon reached `running` and dumps stderr if not.

**Edge-case resilience sweep (with tests)**
- **Single-instance guard** (`single_instance.py`, `flock`) — prevents two agent processes (the agent LaunchDaemon *and* the watchdog-spawned child) racing on the spool; also surfaced that latent two-daemon topology bug.
- **Config robustness** — `load_config` now raises a clear `ConfigError` (missing file / malformed TOML / missing `[manager].url`) and exits `78` once instead of restart-looping; `--status` uses a raw parse so it works on a broken config.
- **Disk-full safety** — `DiskSpool.write` never raises (ENOSPC/read-only/non-serialisable → counted-dropped, trims to recover); sender send-path fully guarded so no surprise kills the delivery thread.
- **Clock-skew** — backward NTP jump re-seeds the collector schedule instead of stalling.

**Product / repo hygiene**
- Friction audit (`friction.md`): ranked onboarding/trust/scale friction with evidence — placeholder installer values, no golden path, default-insecure config, install fragility, repo bloat.
- Repo hygiene: `.gitignore` + untracked 197 files of build cruft (a recursive repo-in-repo copy + `.pkg` binaries), leaving load-bearing dashboard assets tracked (documented why).
- Doc consolidation: single canonical `docs/INSTALL.md` router + signposts; deprecated the old installer path.

**Testing**
- ~40 new unit tests across boot-persistence, keystore boot-safety, single-instance, config robustness, disk-full spool, and clock-skew; full agent suite green (**476 passing**).
- `CAPABILITIES.md` rewritten to reflect active auto-launch + all new resilience capabilities and a full 23-section telemetry coverage matrix.

---

## 9. Known open items (honest state)

- **Two-daemon topology:** both the agent and watchdog LaunchDaemons start an agent; the single-instance lock prevents damage, but one supervision model should be chosen.
- **Config divergence:** the in-code `_DEFAULT_SECTIONS` and the pkg-generated config disagree (SCA not scheduled on a default pkg install; metrics 10 s vs 60 s; inventory 1 h vs 24 h; binaries enabled vs disabled) — needs reconciling.
- **P0 onboarding:** the one-command installer ships placeholder `REPO_URL`/server-IP values; fresh installs default to plain HTTP + `tls_verify=false`.
- **Dashboard build:** static assets are tracked in git because CI doesn't run `npm run build`; add the build step, then untrack.

---

## 10. Repo map

```
agent/
  agent/            core.py (orchestrator+sender wiring), sender.py, keystore.py,
                    config_engine.py, policy.py, watchdog.py, single_instance.py
  os/macos/         launchd.py, boot_persistence.py, self_heal.py, keystore.py,
                    collectors/ (volatile, network, system, posture, inventory, sca),
                    pkg/ (build_pkg.sh — signed ARM64 .pkg), installer/
manager/
  manager/          FastAPI app, ingest, workers, store.py (3-tier), ai_analyst.py,
                    detection (allowlist, rules, behavioral, correlator, scoring)
  rulepacks/        SBOM/security/services/storage/sysctl/tasks/users rule packs
  dashboard/        React/Vite SOC UI
docs/               INSTALL.md (canonical), architecture.md, deployment/
friction.md         Product/CS friction audit
LEARNINGS.md        Append-only engineering learnings log
```
