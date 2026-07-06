# macOS Agent — Capabilities Manifest

**Module:** `agent/os/macos/` &nbsp;·&nbsp; **Target:** macOS 12+ (Apple Silicon / ARM64, x86_64 compatible)
**Status legend:** ✅ implemented & active · 🟡 implemented but not wired/active · 🔴 gap / to build
**Last updated:** 2026-06-08

> **Why this file exists.** Each OS needs a *different* agent — macOS uses `launchd`,
> Windows uses the SCM (`service.py`), Linux uses `systemd`. The collectors, persistence
> mechanism, and posture sources are OS-specific. This manifest is the single source of
> truth for **what the macOS agent must do**, **how it does it**, and **what is still
> missing**. Windows and Linux carry their own `CAPABILITIES.md` with the same structure.
> Scope of this document and all work it drives is strictly `agent/os/macos/`.


---

## 0. Capability matrix (at a glance)

| # | Capability | Status | Owner module |
|---|---|---|---|
| 1 | **Auto-launch on boot / restart** (survives reboot) | 🟡 loader ready + `activate.sh`; awaiting root bootstrap | `launchd.py`, `installer/activate.sh` |
| 2 | **Always-on background operation** (binaries run behind, headless) | 🟡 configured; activates with #1 | `launchd.py` |
| 3 | **Crash recovery / self-healing** (restart on death) | ✅ via launchd `KeepAlive` (watchdog daemon disabled — see §3) | `launchd.py` |
| 4 | **Continuous data transfer** (never silently drop telemetry) | ✅ active & verified (zero-loss replay test) | `agent/sender.py` |
| 5 | **Connection checking** (probe before send, drain on reconnect) | ✅ active + surfaced in `agent_health` → dashboard | `agent/sender.py`, `manager/api/assets.py` |
| 6 | **CIS benchmark data collection** | ✅ active — 23 checks, pipeline fixed + expanded | `os/macos/collectors/posture.py` (dispatched) |
| 7 | **Health heartbeat** (agent reports its own state) | ✅ active | `agent/core.py` |
| 8 | **Secure enrollment + payload encryption** | ✅ active | `agent/enrollment.py`, `crypto.py` |
| 9 | **Dynamic signed config** (signature-verified manager policies, fail-closed) | ✅ active — `ConfigEngine` + signed-policy verify/cache/reload; heartbeat carries `policy_versions` | `agent/policy.py`, `agent/config_engine.py`, `agent/core.py` |

---

## 1. Auto-launch on boot / restart  🟡

**Requirement:** when the machine reboots, the agent must come back up on its own — no
human login, no manual start.

**Mechanism — two `launchd` daemons** (`launchd.py`):

```
launchd  (OS init, PID 1)
  └── com.attacklens.watchdog   KeepAlive=true, RunAtLoad=true   ← launchd restarts if it dies
        └── com.attacklens.agent   KeepAlive=true, RunAtLoad=true ← watchdog/launchd restart if it dies
```

- Plists live in `/Library/LaunchDaemons/` → **system** daemons, start at boot **before any user logs in**.
- `RunAtLoad=true` → start immediately when loaded / at boot.
- `KeepAlive=true` → `launchd` relaunches the process whenever it exits for any reason.
- `ThrottleInterval=10` → 10 s floor between relaunches (prevents crash-loop spin).
- Runs as `UserName=root` so collectors that need privilege (csrutil, fdesetup, sysctl) work.

**Current deployment (verified 2026-06-08):** the installed daemon runs Python, not a
PyInstaller binary:
`python3.13 /Library/AttackLens/bin/run_agent.py --config /Library/AttackLens/agent.toml`.
Both plists are present; `launchctl list | grep attacklens` is **empty** → not yet loaded.

**Work done this pass:**
- `launchd.py` modernised: `install_plist`/`start`/`stop`/`uninstall_plist` now use
  `launchctl bootstrap|bootout|enable` (macOS 10.10+) with a `load -w` legacy fallback,
  and are idempotent (boot out any stale instance before bootstrapping).
- `installer/activate.sh` added — preflights interpreter/entry/plist/config, loads the
  **agent** daemon, and verifies it is actually running (prints PID).

**Remaining (needs root, one command):**
```
sudo bash agent/os/macos/installer/activate.sh
```
After this the agent auto-starts at every boot (`RunAtLoad`) and auto-restarts on exit
(`KeepAlive`). To-do after activation: confirm survival across a real reboot.

**Helpers available:** `install_plist()`, `uninstall_plist()`, `start()`, `stop()`,
`restart()`, `reload_config()` (SIGHUP — change intervals without a full restart).

---

## 2. Always-on background operation  🟡

**Requirement:** the binaries run silently behind the system, with no UI, no Dock icon,
low resource footprint, surviving user logout.

**Mechanism (plist keys in `launchd.py`):**
- `ProcessType=Background` → scheduler treats it as non-interactive; deprioritised vs UI apps.
- `LowPriorityIO=true` → disk I/O yields to foreground work.
- System-domain LaunchDaemon (not a LaunchAgent) → **not tied to a GUI session**, runs with
  no user logged in.
- `StandardOutPath` / `StandardErrorPath` → `/Library/AttackLens/logs/{agent,watchdog}-std*.log`.
- `WorkingDirectory=/Library/AttackLens`.

**Background PATH fix already in place** (`collectors/base.py:_get_env`): LaunchDaemons start
with a minimal `PATH` (`/usr/bin:/bin:/usr/sbin:/sbin`). The agent injects
`/usr/local/bin:/opt/homebrew/bin` so brew/docker/pip-based collectors still resolve.

**Status:** configured correctly; **inactive** until capability #1 is bootstrapped.

---

## 3. Crash recovery / self-healing  ✅ (launchd) / 🟡 (watchdog layer)

**Requirement:** if the agent crashes, it restarts automatically; if it crash-loops, it backs
off instead of pinning the CPU.

**Primary mechanism — launchd `KeepAlive`:** the agent plist has `KeepAlive=true` +
`ThrottleInterval=10`, so `launchd` itself relaunches the agent on any exit, with a 10 s floor
to prevent crash-loop spin. This alone satisfies the requirement and activates with #1.

**Optional second layer — `agent/watchdog.py`** (standalone supervisor with rate-limited
restarts, `max_restarts`/`restart_window_sec` back-off). **Code fixed (2026-06-09):** the
watchdog now detects a `.py` agent target (the deployed `[binaries].agent =
/Library/AttackLens/bin/run_agent.py`) and launches it via a Python interpreter
(`[binaries].python`, defaulting to the framework `python3` running the watchdog) instead of
exec'ing a non-executable script — the historical FATAL-loop. Native PyInstaller binaries still
launch directly (strict `X_OK`). Verified by `agent/tests/unit/test_watchdog.py::TestInterpreterMode`.
The installed watchdog plist already runs `python3 run_watchdog.py --config …`, so enabling the
layer is now just a launchd switch in `activate.sh` (load `com.attacklens.watchdog` instead of
the bare agent). Left **opt-in** 🟡 because launchd `KeepAlive` already satisfies crash recovery;
the watchdog adds rate-limited back-off on top.

---

## 4. Continuous data transfer  ✅

**Requirement:** telemetry flows to the manager continuously and is **never silently lost**,
even across manager outages, network drops, or reboots.

**Mechanism — `agent/sender.py` (`Sender` + `DiskSpool`):**
- Dedicated daemon thread drains an in-memory queue and POSTs encrypted envelopes to
  `…/api/v1/ingest`.
- **Disk spool** (`/Library/AttackLens/spool/unsent.ndjson`, append-only NDJSON):
  - On any send failure the envelope is written to disk, not dropped.
  - **Replayed on startup** (`Sender.start()` drains the spool from the previous run) → survives reboot.
  - **Auto-drained** back into the queue the moment the manager is reachable again.
  - 50 MB cap; on overflow drops the **oldest** 10 % (newest data preferred) and logs it.
- **Exponential backoff + jitter** (`retry_delay` × 2ⁿ, capped 60 s) on transient errors.
- **HTTP status awareness:** `200` ok · `401` → spool + re-enroll after 3 strikes ·
  `429` honoured as transient · `503` (manager couldn't persist) → spool · other `4xx` → dropped
  as unrecoverable (a bad payload is not retried forever).
- **TLS 1.3 minimum** when manager URL is `https://`; plain `http://` supported for local dev
  (warns).

> Historical bug (fixed): payloads used to be dropped on a 503 instead of spooled — that was
> the "silent data-loss" defect. The 503-spools-and-retries path above is the fix.

**Status:** active and **verified**. Zero-loss replay is proven by an automated offline→online
cycle over a real loopback socket — `agent/tests/integration/test_offline_online_replay.py`
(200 envelopes emitted while offline → all delivered after reconnect, in order, no duplicates,
spool drained to zero; plus a restart-replays-prior-spool case). The `DiskSpool` integrity
primitive is pinned by `agent/tests/unit/test_spool.py`. No change required for the base
capability; see §10 for hardening.

---

## 5. Connection checking  ✅

**Requirement:** know whether the manager is reachable; don't waste the retry budget when it
obviously isn't; resume the instant it returns.

**Mechanism (`agent/sender.py`):**
- `_probe()` → lightweight `GET /health` with a 5 s timeout (endpoint confirmed at
  `manager/server.py:360`).
- While offline, the loop **skips the full 3× retry cycle** and spools directly, re-probing
  every 30 s.
- On a successful probe the spool is drained and normal sending resumes; `"Manager connection
  restored"` is logged on the first 200 after an outage.

**Dashboard surfacing (2026-06-08):** `Sender.link_state()` snapshots manager connectivity
(`manager_online`, `spool_bytes`, `auth_failures`, `last_contact_ts`, `seconds_since_contact`)
and is embedded in the `agent_health` heartbeat (`Orchestrator._emit_health` → `link`). The
manager's assets API (`manager/api/assets.py`, list + detail) condenses it via `_link_summary`
into a per-agent `link.status` of **healthy / degraded / auth_failed**. The dashboard renders
it as a `LinkBadge` in the asset detail header (`AssetRegistry.tsx`), with a tooltip showing
seconds-since-contact, offline spool size, and auth-failure count; rebuilt into
`dashboard/static/` via `make build-dashboard`.
Tests: `agent/tests/unit/test_link_state.py`, `manager/tests/unit/test_link_status_api.py`.

**Status:** active — link state probed, heartbeated, and exposed to the dashboard.

---

## 6. CIS benchmark data collection  ✅

**Requirement:** collect every field the manager needs to score the **CIS macOS Benchmark**.

> **Pipeline fix (2026-06-08):** the live `COLLECTORS` registry now
> platform-dispatches the posture collectors (`security`/`sysctl`/`configs`) to
> the macOS-specific `agent/os/macos/collectors/posture.py` on darwin (see
> `agent/agent/collectors/__init__.py`). Previously the registry always used the
> generic `agent/agent/collectors/posture.py`, which emitted **raw CLI strings**
> (`sip="System Integrity Protection status: enabled."`) that never matched the
> canonical values the scorer compares against — so SIP/FileVault/Gatekeeper/
> Firewall reported FAIL and the rest "unknown" on every Mac. `_norm_security`
> was also corrected to forward the full field set and the `xprotect_version` /
> `dev_tools` keys. Net: a hardened Mac now scores correctly (verified end-to-end).

**Producers (macOS-specific, `collectors/posture.py`, 1 hr cadence):**

| Collector | Section | Supplies |
|---|---|---|
| `SecurityCollector` | `security` | SIP, Gatekeeper, FileVault, Firewall, XProtect, Secure Boot, auto-update, dev-tools, Lockdown Mode, SSH (remote login / password auth / root login), Screen Sharing (VNC), Remote Management (ARD), screensaver lock + idle timeout |
| `ConfigsCollector` | `configs` | shell rc, `~/.ssh/config`, `authorized_keys`, `/etc/hosts`, `sshd_config`, `sudoers` (4 KiB cap each) + download-cradle "suspicious" flag |
| `SysctlCollector` | `sysctl` | security-relevant kernel params (`kern.*`, `net.inet.*`, `security.*`) |

**Consumer:** `manager/api/posture.py` maps these fields → **23 CIS checks** across CIS
Controls **3, 4, 5, 7, 8, 10, 12**. Every check below already has a producing field:

| CIS check | Source field (`security` unless noted) |
|---|---|
| SIP / System Integrity Protection | `sip` |
| FileVault FDE | `filevault` |
| Gatekeeper | `gatekeeper` |
| Application Firewall | `firewall` |
| Secure Boot — Full Security | `secure_boot` |
| Automatic Security Updates | `auto_update` |
| Screensaver requires password | `screensaver_lock` |
| Screensaver idle ≤ 5 min | `screensaver_idle_sec` |
| SSH password auth disabled | `remote_login` + `ssh_password_auth` |
| SSH root login prohibited | `ssh_permit_root_login` |
| Screen Sharing (VNC) off | `screen_sharing` |
| Apple Remote Desktop off | `remote_management` |
| XProtect definitions present | `xprotect_version` |
| No suspicious shell configs | `configs[].suspicious` |
| Developer Tools security | `dev_tools` |
| Lockdown Mode | `lockdown_mode` |

**CIS expansion (✅ implemented 2026-06-08 — 7 new checks):**

| New check (id) | Source field(s) | CIS Control |
|---|---|---|
| Audit Subsystem Enabled (`AUD`) | `audit_enabled` + `audit_flags` (auditd / `/etc/security/audit_control`) | 8 Audit Log Management |
| Password Policy ≥8 (`PWP`) | `pw_policy_configured` + `pw_min_length` (`pwpolicy -getaccountpolicies`) | 5 Account Management |
| Guest Account Disabled (`GST`) | `guest_account` (`com.apple.loginwindow GuestEnabled`) | 5 |
| Automatic Login Disabled (`ALI`) | `auto_login_user` (`com.apple.loginwindow autoLoginUser`) | 5 |
| Automatic Update Install (`AUI`) | `auto_update_install` + `critical_update_install` | 7 Vulnerability Management |
| Network Time Sync (`NTP`) | `network_time` + `time_server` (`systemsetup -getusingnetworktime`) | 8 |
| File / Printer Sharing Off (`SHR`) | `file_sharing` + `printer_sharing` (smbd / `cupsctl`) | 4 Secure Configuration |

A missing field (root-only tools when not yet collected) scores **unknown**, never a
false FAIL — unknowns are excluded from the score denominator.

**Tests:** `manager/tests/unit/test_posture_cis.py` (scorer: regression that canonical
fields PASS + the 7 new checks) and `agent/tests/unit/test_posture_collector_cis.py`
(collector parsing + normalizer passthrough/key-fix).

**Remaining gaps (🔴 — future):** per-user screensaver policy via MDM, Bluetooth sharing,
EFI integrity, and password *age/lockout* (only min-length is scored today).

---

## 7. Health heartbeat  ✅

`agent/core.py` pushes a synthetic `agent_health` section every 60 s containing the
circuit-breaker snapshot (which collectors are CLOSED / OPEN / HALF-OPEN). This is how the
manager distinguishes "agent online but a collector is failing" from "agent gone".

---

## 8. Secure enrollment + payload encryption  ✅

- `agent/enrollment.py` — first-run enrollment against the manager, obtains agent identity.
- `agent/crypto.py` + `keystore.py` (macOS keystore at `os/macos/keystore.py`) — per-agent key
  (`security/agent-001.key`), envelopes encrypted before they ever hit the queue/spool.
- Re-enrollment is triggered automatically after 3 consecutive `401`s (stale key) — see §4.

---

## 9. Dynamic signed config (ConfigEngine & signed-policy control plane)  ✅

**Requirement:** the manager must be able to *tighten or relax* agent behaviour
(security thresholds, active-response actions, telemetry cadence, compliance
baselines) at runtime — but the agent must only ever obey configuration it can
prove came from the manager, unmodified, current, and meant for it. Active
response, in particular, must **fail closed**: absent a perfect proof it stays off.

**Mechanism — one immutable `RuntimeConfig` from three layers** (`config_engine.py`):

```
baseline (agent.toml)  ◅  verified manager policies  ◅  tighten-only runtime overrides
```

- **Baseline** — the existing `agent.toml`, unchanged for non-policy config.
- **Verified policies** — fetched from `GET /api/v1/policies/<type>` for each of
  `security | response | telemetry | compliance`, signature-verified and merged
  over the matching baseline section (policy wins on key conflict).
- **Tighten-only overrides** — env `ATTACKLENS_*` may *disable* response or
  *shrink* `allowed_actions`; they can **never** enable response or add an action
  (explicit allow-list; anything else is logged and ignored).

`response_enabled` is `True` **iff** a `response` policy is present, signature-
valid, audience-valid, unexpired, and version-monotonic — and the wall clock is
sane. Every other state ⇒ `False`. It is **never** derived from baseline or env.

**Snapshots swap atomically** under a lock (`current()`); readers never see a
torn config. Startup `load()` is **cache-first and non-blocking** — the agent
runs from the last verified policies even with the manager offline, and
`refresh()` re-fetches on a monotonic cadence and on reconnect. Durations use
`time.monotonic()`; expiry uses the wall clock; a backward wall jump beyond
`MAX_SKEW_SEC` (300 s) forces `response_enabled=False` (`clock_skew`) until the
next good refresh.

### Signing contract (byte-exact — for the manager team)

The wire object from `GET /api/v1/policies/<type>`:

```json
{ "payload_b64": "<base64 of the exact signed bytes>",
  "signature_b64": "<base64>",
  "sig_alg": "ed25519" | "rsa-pss-sha256",
  "key_id": "<pinned key id>" }
```

`payload_b64` base64-decodes to UTF-8 JSON = the **signed payload**:

```json
{ "schema": 1, "type": "security|response|telemetry|compliance",
  "version": <int>, "issued_at": <int unix s>, "expires_at": <int unix s>,
  "audience": "<agent_id|group_id|fleet>", "content": { } }
```

- **The manager signs the exact bytes it base64-encodes into `payload_b64`.**
  The agent verifies the signature over the **raw decoded bytes** and parses the
  JSON **only after** verification succeeds — it never re-serialises the payload.
  There is no canonical-JSON negotiation: the transmitted bytes are the signed
  bytes. `sig_alg` selects the verify routine (ed25519 preferred, else RSA-PSS
  with MGF1-SHA256 and salt = digest length); `key_id` selects the pinned key.

### Verify order → reject code (`policy.py:load_verified`)

Checks run in this fixed order; each failure raises a `PolicyError` with a stable
`.reason`:

| Step | Check | Reject code |
|---|---|---|
| 1 | `payload_b64` / `signature_b64` decode | `corrupt` |
| 2 | `key_id` resolves to a pinned key | `key_unavailable` |
| 3 | signature verifies over raw bytes (**before any parse**) | `signature_invalid` |
| 4 | payload parses as JSON | `corrupt` |
| 5 | `schema == 1` | `schema_invalid` |
| 6 | `audience ∈ {agent_id, fleet} ∪ group_ids` | `audience_mismatch` |
| 7 | `issued_at ≤ now + MAX_SKEW_SEC` (not future-dated) | `corrupt` |
| 8 | `expires_at > now` | `expired` |
| 9 | `version > high_water[type]` (monotonic) | `downgrade` |
| 10 | per-type `content` schema | `schema_invalid` |

Because the signature covers the raw bytes, flipping **any** signed field
(version / issued_at / expires_at / audience / content) is caught at step 3 as
`signature_invalid` — the later codes fire only for *validly signed* policies
that are genuinely expired / mis-addressed / rolled back.

### Cache, high-water, reload

- Under `policies_dir` (`0o700`): `<type>.policy` (raw verified wire object),
  `<type>.prev` (previous good), `.versions.json` (monotonic high-water, `0o600`).
- High-water advances **only** on a fully successful accept, and **persists
  across restarts** — a replayed older version is rejected `downgrade` even after
  a reboot. Cache files are re-verified on load; a corrupt/tampered cache is
  treated as absent (no crash).
- `SIGHUP` / `reload_config()` triggers `ConfigEngine.refresh()`; the heartbeat
  (`agent/core.py:_emit_health`) carries `policy_versions` + `response_enabled`
  so the manager can confirm fleet-wide policy convergence.

### Rotation & revocation

- **Key rotation:** publish the new public key as `<new_key_id>.pub` under
  `keystore_dir` and start signing with it; policies carry the `key_id` they were
  signed under, so old and new keys can coexist during a rollover. Retire a key
  by deleting its `.pub` — any policy still referencing it then fails closed with
  `key_unavailable` (response off, alert), rather than being silently trusted.
- **Policy revocation:** there is no "unsign" — revoke by **superseding**. Issue a
  higher-`version` policy (monotonic high-water guarantees the old one can never
  be replayed) and/or let the bad policy **expire** (`expires_at`); keep TTLs
  short so a compromised-but-unexpired document self-heals. To kill active
  response fleet-wide immediately, push a `response` policy with
  `enabled=false` / empty `allowed_actions`, or expire it — the gate fails closed.
- **No secrets in policies:** `content` is config, not credentials; values flagged
  sensitive are redacted in logs and reject reasons log only the `.reason` code.

**Tests:** `agent/tests/unit/test_policy.py` (verify-then-parse, every reject
code, parser-never-runs-on-unverified-bytes) and
`agent/tests/unit/test_config_engine.py` (merge, fail-closed matrix, tighten-only
env, downgrade + high-water persistence across restart, offline→reconnect,
atomic hot-reload under concurrent readers, clock-skew). Hermetic via
`agent/tests/fixtures/signing.py` (throwaway keypair; real pinned key never used).

---

## 10. Build / packaging anchors

- `pkg/build_pkg.sh` + `pkg/entitlements.plist` — signed ARM64 `.pkg` that installs to
  `/Library/AttackLens/`, drops both plists, and bootstraps the daemons.
- `installer/install.sh` / `uninstall.sh` — script-based install path.
- `requirements.txt` — runtime deps (PyInstaller target).
- Repo `Makefile`: `make build-binaries` (agent + watchdog), `make build-pkg`.

---

## 11. Work queue (gaps → tasks)

Derived from the status flags above; all scoped to `agent/os/macos/`:

1. **[#1/#2/#3] Activate persistence.** ✅ loader modernised + `installer/activate.sh`
   added. **Run:** `sudo bash agent/os/macos/installer/activate.sh`, then confirm
   RunAtLoad/KeepAlive survive a real reboot (last verification step).
2. **[#3] Self-heal guard.** Optional: re-enable the watchdog layer (fix its exec target,
   see §3) or add a periodic re-bootstrap check.
3. **[#4] Continuous-transfer verification.** ✅ Done — automated offline→online cycle proves
   zero-loss spool replay (`agent/tests/integration/test_offline_online_replay.py`,
   `agent/tests/unit/test_spool.py`). Run: `python3 -m pytest agent/tests/unit/test_spool.py
   agent/tests/integration/test_offline_online_replay.py`.
4. **[#6] CIS coverage expansion.** ✅ Done — fixed the broken pipeline (rich macOS posture
   collectors now dispatched into the registry + `_norm_security` forwards the canonical
   schema) and added 7 checks (audit, password policy, guest, auto-login, update-install,
   network time, sharing) → **23 checks** total. Tests: `manager/tests/unit/test_posture_cis.py`,
   `agent/tests/unit/test_posture_collector_cis.py`.
5. **[#5] Connection-check surfacing.** ✅ Done — `Sender.link_state()` → `agent_health.link`
   heartbeat → `manager/api/assets.py` (`_link_summary`, list + detail) exposes per-agent
   `link.status` (healthy/degraded/auth_failed). Tests: `agent/tests/unit/test_link_state.py`,
   `manager/tests/unit/test_link_status_api.py`.

> Remaining open items: **#1/#2 root bootstrap** (run `activate.sh` + reboot check) and the
> optional **#3 watchdog** re-enable. Everything else in this manifest is implemented + tested.
