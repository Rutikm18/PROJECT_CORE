# AttackLens Windows Agent — DeepMesh Implementation Prompt

**Purpose:** Complete, verified reference prompt for implementing the Windows agent to full
parity with — and beyond — the macOS agent. Includes what was built on macOS, every bug and
design challenge encountered, and an exact task list for the Windows build.

---

## Part 1 — What DeepMesh is and what was implemented on macOS

### What is DeepMesh?

DeepMesh is the full-stack endpoint telemetry + detection platform:

```
[Endpoint agent]  ──HTTPS/TLS──►  [Manager + AttackLens engine]  ──►  [Dashboard]
      │                                        │
  Collects OS                          Detects threats
  state + events                       Correlates signals
  Encrypts payloads                    AI-validates findings
  Spools offline                       Surfaces to analysts
```

The macOS agent is the fully-shipped implementation. The Windows agent exists as a working
scaffold but needs to be brought to parity + native depth.

---

### Implemented architecture (macOS, fully production-hardened)

#### 1. Data collection (24 sections)

Every section is a `BaseCollector` subclass with a `collect()` method that returns a typed
dict or list. The orchestrator schedules, times out, and circuit-breaks each section
independently. Sections and their cadences:

| Cadence | Sections | Source |
|---------|----------|--------|
| 10–60 s | `metrics`, `connections`, `processes` | psutil + macOS VM stat |
| 30–120 s | `ports`, `network`, `arp`, `mounts`, `battery`, `openfiles`, `services`, `users`, `hardware`, `containers` | netstat/lsof/system_profiler |
| 600 s | `storage`, `tasks` | diskutil/launchd |
| 3600 s | `security`, `sysctl`, `configs`, `developer_security`, `sbom`, `apps`, `packages`, `binaries` | system tools |
| 12 h | `sca` | CIS benchmark engine |
| 60 s synthetic | `agent_health` | orchestrator self-report |

#### 2. Data pipeline (collect → encrypt → send)

```
Collector.collect()
    │  raw dict/list
    ▼
normalize(section, raw)          ← macOS-specific parser (CLI strings → canonical schema)
    │  canonical dict/list
    ▼
Orchestrator._run_section()
    │  builds envelope:
    │  { agent_id, section, ts, data, schema_version }
    ▼
encrypt(payload_bytes, enc_key, mac_key)  ← AES-256-GCM + HMAC-SHA256
    │  ciphertext
    ▼
queue.put(envelope)              ← bounded in-memory queue
    │
    ▼  (Sender thread)
DiskSpool.write()  ←── on failure, retry, or queue overflow
    │  NDJSON append (50 MB cap)
    ▼
POST /api/v1/ingest              ← TLS 1.3, agent API key header
    │  200 → advance spool cursor
    │  401 → re-enroll after 3 strikes
    │  429 → honour Retry-After header
    │  503 → spool (not drop)
```

#### 3. Enrollment flow (first run)

```
POST /api/v1/enroll
  body: { agent_id, hostname, os, arch, os_version, agent_version }
  headers: X-Enrollment-Token (if manager requires it)
  response: { api_key: "<64-hex>" }
```

Key stored in macOS Keychain (POSIX) / file keystore (root daemon, boot-safe).
Re-enrollment: automatic after 3 consecutive 401s.

#### 4. Resilience engineering (the hardest part — all on macOS)

Every item below was a real bug or failure mode found in production:

| System | Mechanism | Bug that triggered it |
|--------|-----------|----------------------|
| **Circuit breaker** | CLOSED → OPEN (3 fails) → HALF-OPEN (60s cooldown) → CLOSED | Hung `system_profiler` call stalled pool worker forever |
| **Per-section timeout** | 25s hard deadline via daemon thread; frees pool slot regardless | Slow disk scan hung all section collection |
| **In-flight overlap guard** | Skip section if prior run still running | 10s collector that takes 15s submitted twice, doubled work |
| **Clock-skew detector** | Backward NTP jump > 60s → re-seed all next-fire times | NTP correction after boot stalled collection for hours |
| **Disk-full spool** | ENOSPC → trim oldest 10% + count drop, never raise | Spool write exception killed delivery thread silently |
| **503 spooling** | 503 → write to disk, not drop | Manager restart caused silent data loss on every 503 |
| **Single-instance lock** | `flock` on lockfile, 5s wait | Two launchd daemons (agent + watchdog) raced on spool |
| **Boot-safe keystore** | File keystore mirror (`0600` root-only) | Root LaunchDaemon can't read login Keychain at boot |
| **Wake-from-sleep reprobe** | Monotonic clock jump > 30s → immediate probe | Cached socket dead after sleep; 30s stall on resume |
| **Startup phase stagger** | Deterministic hash → `now - interval + phase` (≤30s) | All sections fire simultaneously at boot → 429 storm |
| **Spool replay cursor** | inode-bound, fsynced offset file; advance only on 2xx ACK | Crash before ACK = re-send (idempotent) not loss |
| **Retry-After honoring** | Parse delta-seconds or HTTP-date, cap at 120s | Pathological Retry-After could park sender for hours |
| **Auth spiral prevention** | Single-flight re-enroll, 5s–300s backoff | Mass 401 → N parallel re-enrollments rotated key N times |
| **Config fail-fast** | `ConfigError` → exit 78 once | Bad TOML crashed into launchd restart loop |
| **Boot-persistence repair** | Self-heal every 5min: verify plist + `RunAtLoad` + enabled | Attacker `launchctl disable` removed agent from next boot |
| **Self-heal delivery probe** | Detect silent non-delivery (agent alive, manager not receiving) | Agent running but shipping zero telemetry for hours |
| **Subprocess budget** | Thread-local budget shared across all `_run()` calls in a section | Cold first-run of `security` section: 50 shell calls × 1s each = 50s |

#### 5. Payload envelope format

```json
{
  "agent_id": "agent-001",
  "section":  "processes",
  "ts":       1723370400.123,
  "data":     [ ... ],
  "schema_version": 1
}
```

Encrypted envelope (wire format):
```
[ nonce (12B) | ciphertext | GCM tag (16B) ]
HMAC-SHA256 over the above → sent as X-Payload-HMAC header
Content-Encoding: gzip (agent compresses before encrypting)
```

#### 6. Signed-policy control plane

Manager can push signed config that overrides agent behaviour:

- `response`, `security`, `telemetry`, `compliance` policy types
- Ed25519 / RSA-PSS-SHA256 signature over exact wire bytes
- Verify-before-parse (never parse unverified bytes)
- Monotonic version counter (downgrade attack prevention)
- Audience checking (agent_id / group / fleet)
- `response_enabled` fails closed — absent a perfectly-verified policy, active response is off
- Atomic config swap under a lock; cached on disk, works offline

---

## Part 2 — Challenges and bugs encountered (complete list)

### Design-level challenges

1. **macOS-specific CLI output vs canonical schema mismatch**
   The generic collector ran shell commands (`sysctl -a`, `vm_stat`) and returned raw strings.
   The manager's detection engine expected canonical typed dicts. This meant a macOS-specific
   normalizer layer had to parse every CLI format (regex-heavy, fragile) and emit clean data.
   **Resolution:** `os/macos/collectors/` replaces the generic collectors entirely;
   `os/macos/normalizer.py` handles the raw-to-canonical mapping.

2. **Root daemon vs login keychain**
   A system LaunchDaemon starts at boot with no user session. The macOS login keychain is locked
   at that point. `keyring` (the original key storage) silently failed — the agent enrolled,
   stored the key, rebooted, and couldn't find it. Zero errors, just silent auth failure.
   **Resolution:** file keystore at `/Library/AttackLens/security/<id>.key` (`0600`, root-only).

3. **CIS scoring pipeline: wrong collectors dispatched**
   The shared `collectors/__init__.py` always loaded the *generic* posture collector even on
   macOS. The generic one emitted raw strings (`sip="System Integrity Protection status: enabled."`).
   The CIS scorer compared against `"enabled"`. Every Mac scored FAIL on every CIS check.
   **Resolution:** platform-dispatch in `collectors/__init__.py` + platform-specific `posture.py`.

4. **Two-supervisor topology**
   Both `com.attacklens.agent` (runs agent directly) and `com.attacklens.watchdog` (spawns agent
   via `subprocess`) had `RunAtLoad`+`KeepAlive`. On every restart, both fired → two agents raced
   on the spool. Fix: single-instance `flock` guard, and the long-term fix is to pick one topology.

5. **Subnet-path CONTAINERS-005 bug**
   `(_as_int(0) or -1) == 0` — Python's `or` short-circuits: `0 or -1 = -1`, so `uid=0`
   (root) never matched. The rule never fired for root-owned containers.
   **Resolution:** `uid = _as_int(...); if uid is not None and uid == 0:`.

6. **`_get_field("tag")` reads `"tags"` key**
   A condition evaluator `_get_field("tag")` was designed to read from a `"tags"` (plural) key
   in the item dict. Tests used `"tag"` as the key → always missed.

7. **AI validator calling non-existent method**
   `ai_validator.py` called `ai_analyst._call_claude(prompt)`. `FindingAnalyzer` has no
   `_call_claude` method — it was always raising `AttributeError`, caught silently by the outer
   `except Exception`, and degrading to deterministic-only scoring. The AI evaluation path was
   broken for the entire AI validation phase.
   **Resolution:** `ai_analyst._get_provider()` → `provider.chat(prompt)` → `provider.parse_json(resp.text)`.

8. **`tokens_used = raw.get("tokens_used")`**
   `raw` was the return of `_call_claude()` (assumed to be a dict). But the correct return from
   `provider.chat()` is an `AIResponse` object. Used `resp.total_tokens` instead.

9. **PowerShell-per-call pattern (Windows)**
   Every Windows collector spawns `powershell.exe` (100–300 ms each, memory spike, AV-noisy).
   This is the single biggest Windows agent architectural problem. A 10s `metrics` section that
   spawns 3 PowerShell processes is a red flag to every AV/EDR on the system.

10. **`_call_with_timeout` doesn't actually stop the hung thread**
    Python can't interrupt a thread from outside. A hung collector gets a daemon thread leak.
    The tradeoff was acceptable (one leaked thread vs permanently frozen pool slot), but it
    means a host with consistently slow collectors accumulates daemon threads.

### Operational edge cases

- **NTP correction after boot** → backward `time.time()` jump → all next-fire times in the future → zero collection.
- **Sleep/wake** → cached HTTP connection dead → sender retries dead socket for up to 30s before timeout.
- **Disk full** → spool write raises `ENOSPC` → delivery thread crashed → no telemetry, no error surfaced.
- **503 treated as client error** → payload dropped, not spooled → silent data loss on every manager restart.
- **Startup stampede** → all collectors fire at t=0 → CPU spike + manager 429 burst.
- **Config parse error** → raw `tomllib.load` exception → launchd restart loop (exits + relaunches forever).
- **Boot `sca` timeout** → CIS benchmark runs 57+ shell probes → cold-start takes >25s default timeout → scored as "not applicable" for every check.
- **Silent non-delivery** → agent alive, launchd happy, spool growing, but manager connection lost → no alert without the self-heal delivery probe.

---

## Part 3 — Windows agent: what needs to be built

### Current Windows state

| Area | State | Detail |
|------|-------|--------|
| 23 collection sections | Partial | Implemented via PowerShell spawns + `winreg` — functional but not optimal |
| Service host | Partial | `pywin32 ServiceFramework` (SCM) — no recovery actions, no pre-shutdown, no delayed-autostart |
| Key storage | Done | DPAPI + Credential Manager (`CRYPTPROTECT_LOCAL_MACHINE`) — boot-safe |
| Transport | Partial | Shared sender works; needs Windows proxy support + cert pinning |
| Resilience | Missing | Supervision, boot-persistence, single-instance, disk-full, clock-skew NOT ported |
| Native telemetry | Missing | No ETW, no Event Log, no WMI events, no Sysmon/Defender ingestion |

### What must be built (prioritized)

#### Phase 0 — Verified data path (do first)

- Prove enroll → encrypt → ingest → dashboard works end-to-end on a real Windows VM
- SCM recovery/failure actions (`sc failure` restart on 1st/2nd/subsequent)
- Named mutex single-instance guard (`Global\AttackLensAgent`)
- Windows proxy support (honor `WinHTTP`/`WinINET` system proxy + PAC scripts)
- TLS hostname verification + cert pinning (parity with macOS)

#### Phase 1 — Reliability parity (port macOS hardening)

- **Supervision + heartbeats**: SCM watchdog via `SERVICE_CONTROL_PRESHUTDOWN` + in-process heartbeat
- **Delayed auto-start** (`SERVICE_CONFIG_DELAYED_AUTO_START`) — start after network/DNS ready
- **Single-instance named mutex** — `CreateMutex("Global\AttackLensAgent")`, check `ERROR_ALREADY_EXISTS`
- **Boot-persistence self-repair** — verify `AUTO_START` + recovery actions on every start; re-assert if drifted
- **Pre-shutdown handler** (`SERVICE_CONTROL_PRESHUTDOWN`) — flush queue, write clean-stop marker
- **Clock-skew re-seed** — port `_maybe_reseed_on_skew` (same logic, works cross-platform)
- **Disk-full spool** — already in shared `sender.py`, verify it works on Windows paths
- **Startup phase stagger** — already in shared `core.py`, verify it works on Windows
- **Wake/sleep reprobe** — `WM_POWERBROADCAST` / `SERVICE_CONTROL_POWEREVENT` → force probe
- **Config fail-fast** — already in shared `core.py`
- **Boot-transition telemetry** — port `boot_persistence.py` using `psutil.boot_time()` (cross-platform)

#### Phase 2 — Native telemetry (the real upgrade)

Replace PowerShell spawns with native Windows APIs:

- **ETW subscriptions** (via `pywintrace` or `krabsetw`):
  - `Microsoft-Windows-Kernel-Process` → process start/stop, image loads, thread creation
  - `Microsoft-Windows-DNS-Client` → DNS queries (C2/beaconing detection)
  - `Microsoft-Windows-Kernel-Network` / TCPIP → connections with PID
  - `Microsoft-Windows-PowerShell` → script-block logging (4104-equivalent at ETW speed)
  - `Microsoft-Windows-WMI-Activity` → WMI-based lateral movement
- **Windows Event Log subscriptions** (`EvtSubscribe`, push not poll):
  - Security channel: 4688 (process + cmdline), 4624/4625 (logon/fail), 4672 (special privs),
    4720/4732 (account/group changes), 4698 (scheduled task), 4697 (service install), 1102 (log cleared)
  - Sysmon/Operational (if present): events 1,3,7,8,11,13,15,17,18...
  - Defender/Operational: 1116/1117 (detections)
  - PowerShell/Operational: 4104 (script block)
  - TerminalServices: RDP sessions
- **WMI via COM** (persistent connection, not one-shot `wmic`):
  - Replace hot-path collectors: process list, services, scheduled tasks
  - WMI event subscriptions for persistence change detection
- **Authenticode signature verification** (`WinVerifyTrust`) on every executing image:
  - Signed / unsigned / revoked / catalog-signed
  - Publisher, EKU, catalog verification
  - Cache by image hash (Authenticode is expensive)
- **Full 4688 command-line capture**:
  - Detect if `ProcessCreationIncludeCmdLine_Enabled` is off
  - Optionally enable it via registry (agent has SYSTEM)

#### Phase 3 — Depth and posture

- **Full persistence surface** (everything an attacker can use on Windows):
  - Run/RunOnce keys (HKLM + HKCU, both WoW64 views)
  - Startup folders (user + all-users)
  - Scheduled tasks (full XML parse, not just names)
  - Services + drivers (kernel mode)
  - WMI permanent event subscriptions (`__EventFilter` / `CommandLineEventConsumer`)
  - IFEO (Image File Execution Options) — debugger hijack
  - COM hijacking (CLSID enumeration)
  - `AppInit_DLLs`, `Winlogon` (Shell/Userinit/Notify)
  - BITS jobs
  - LSA packages/SSP, print monitors, netsh helpers
  - Accessibility tool hijacks (sethc, osk, magnify, narrator)
- **Identity and lateral movement**:
  - Logon sessions + type (interactive/RDP/network/service/batch)
  - Failed-logon bursts (4625 rate)
  - Privileged group membership changes (4728/4732/4756)
  - LSASS handle access detection (Mimikatz-class)
  - Kerberoasting / DCSync signals (domain-joined hosts)
- **Windows CIS benchmark** (parity with macOS's 23 checks):
  - Map Windows-specific checks: BitLocker, Defender exclusions, Tamper Protection state,
    ASR rules, Exploit Protection, NLA for RDP, PowerShell language mode + logging,
    LSA Protection, Credential Guard, WDAC/AppLocker, SMBv1, NTLM restriction level,
    audit policy completeness, pending reboots, TPM state, Secure Boot

#### Phase 4 — Self-defense and enterprise

- **PPL/ELAM eligibility** — sign the agent binary with an AV/anti-malware EV cert
- **ACL hardening** — `SYSTEM + Administrators` only on install dir, config, spool, service registry key
- **Tamper detection** — alert on service stop/disable, binary modification, Defender exclusion of agent path
- **Self-repair** — watch own service config (recovery actions, start type), re-assert if drifted
- **Signed MSI** (WiX) — silent install (`/qn`), proper SCM registration, clean uninstall
- **Enterprise deployment** — GPO / Intune / SCCM / `winget`; per-machine install
- **Auto-update channel** — signed package, version/rollback story, MSI upgrade preserves enrollment keys
- **Self-logging to Windows Event Log** — register as an event source; operators use Event Viewer

---

## Part 4 — Core architecture: how the Windows agent must work

### Directory layout

```
agent/os/windows/
  __init__.py
  agent_win_entry.py          ← Windows-specific main() wrapping core.py
  service.py                  ← SCM ServiceFramework (pywin32)
  watchdog_svc.py             ← Optional watchdog service
  keystore.py                 ← DPAPI + Credential Manager
  normalizer.py               ← Windows-specific raw→canonical mapping
  collectors/
    __init__.py               ← COLLECTORS registry (Windows-specific)
    base.py                   ← WinBaseCollector (winreg helpers, _run_ps, _run)
    volatile.py               ← metrics, connections, processes (psutil — already good)
    network.py                ← ports, network, arp, mounts
    system.py                 ← battery, openfiles, services, users, hardware, containers
    posture.py                ← security, sysctl, configs (already implemented)
    inventory.py              ← storage, tasks, apps, packages, binaries, sbom
  etw/                        ← NEW: ETW subscriber modules
    process_provider.py       ← Kernel-Process provider consumer
    dns_provider.py           ← DNS-Client provider consumer
    network_provider.py       ← TCPIP provider consumer
    ps_provider.py            ← PowerShell script-block provider
  evtlog/                     ← NEW: Event Log subscription modules
    security_channel.py       ← 4688, 4624/4625, 4672, 4720/4732, 4698, 4697, 1102
    sysmon_channel.py         ← Sysmon/Operational events
    defender_channel.py       ← Defender/Operational 1116/1117
  wmi/                        ← NEW: persistent WMI COM connection
    client.py                 ← WMI query helper (persistent connection)
    subscriptions.py          ← WMI event subscriptions (persistence change detection)
  sca/
    policies/
      sca_windows_cis.yml     ← Windows CIS benchmark checks
    engine.py                 ← shared SCA engine (already cross-platform)
  installer/
    build_msi.py              ← WiX/MSI generation
    install.ps1               ← PowerShell installer
    uninstall.ps1             ← already exists
  pkg/
    attacklens_agent.wxs      ← WiX XML source for signed MSI
```

### Core data flow (Windows-specific)

```
SCM start → service.py SvcDoRun()
    │
    ├─ acquire Global\AttackLensAgent mutex  (single-instance)
    │
    ├─ report SERVICE_START_PENDING with checkpoint + wait-hint
    │
    ├─ enrollment check (DPAPI keystore)
    │   └─ if no key → POST /api/v1/enroll
    │
    ├─ load config (agent.toml under %ProgramData%\AttackLens)
    │   └─ ConfigError → log to Event Log, exit 1
    │
    ├─ derive enc_key + mac_key from stored API key
    │
    ├─ start Sender thread (shared sender.py — already works on Windows)
    │
    ├─ start ETW subscriber threads (Phase 2+)
    │   ├─ process_provider → feeds processes section real-time
    │   ├─ dns_provider → feeds connections section real-time
    │   └─ ps_provider → feeds security section script-block events
    │
    ├─ start Event Log subscriber threads (Phase 2+)
    │   ├─ SecurityChannel → 4688, 4624/25, 4672, ...
    │   └─ SysmonChannel → if Sysmon present
    │
    ├─ start Orchestrator (shared core.py — already Windows-aware)
    │   ├─ schedule all collectors on their intervals
    │   ├─ per-section circuit breaker + timeout
    │   ├─ health heartbeat every 60s
    │   └─ phase-stagger startup
    │
    ├─ start boot-persistence self-repair thread (every 300s)
    │   ├─ verify SERVICE_AUTO_START + recovery actions
    │   └─ re-assert if drifted
    │
    ├─ report SERVICE_RUNNING
    │
    └─ wait on stop event (SERVICE_CONTROL_STOP / PRESHUTDOWN)
        ├─ flush send queue + spool
        ├─ write clean-stop marker
        └─ release mutex + exit
```

### Collector design rules (Windows-specific)

1. **Never spawn PowerShell in hot-loop collectors** (metrics, connections, processes — 10–60s cadence).
   Use `psutil` for everything that psutil covers (CPU, memory, processes, network connections, disks).

2. **Use `winreg` directly** for registry reads. Never shell out `reg query` — it spawns a process,
   is locale-dependent, and is detectable by AV.

3. **Use WMI via COM** (`win32com.client`) for data that psutil doesn't cover (services detail,
   installed software, WMI subscriptions). Keep a persistent WMI connection, do not open/close per query.

4. **For ETW**: use `pywintrace` or `pyetw`. Run one ETW session per provider group. Buffer events
   in a thread-safe queue; the collector's `collect()` drains and returns what has accumulated since
   the last call. ETW runs continuously in background threads — `collect()` is a drain, not a trigger.

5. **For Event Log**: use `win32evtlog.EvtSubscribe` with push callback (not pull loop).
   Persist bookmark to `%ProgramData%\AttackLens\evtlog\<channel>.bookmark` — reload on restart
   to resume without re-reading or missing events.

6. **Never parse localized output** — Windows text is locale-dependent. Use API calls, registry
   values, or `ConvertTo-Json` (PowerShell JSON output is locale-independent). Event IDs are
   locale-independent.

7. **Handle both WoW64 registry views** — 32-bit processes see redirected registry. Use
   `KEY_WOW64_64KEY` for the 64-bit view, `KEY_WOW64_32KEY` for the 32-bit view. Enumerate both.

8. **Feature-detect, never crash** — Credential Guard, ASR, WDAC, TPM availability differ across
   Windows 10/11 / Server 2016/2019/2022/2025. Check for feature existence before reading; return
   `None` (scores as `unknown`, never false FAIL) when the feature isn't present.

9. **Session 0 isolation** — the service runs in Session 0. It cannot interact with the user desktop,
   show windows, or read user-profile paths without impersonation. Use `%ProgramData%` for machine-wide
   paths, `%SystemRoot%` for system paths.

10. **`CREATE_NO_WINDOW`** — already in `WinBaseCollector._run()`. Never drop it — a service that
    pops cmd windows trips AV + is visible to users.

### Normalizer design (Windows-specific)

The Windows normalizer (`os/windows/normalizer.py`) maps Windows-specific raw data to the same
canonical schema the manager's detection engine expects. Key mappings:

```python
# security section canonical schema (same fields as macOS, None where not applicable)
{
    "sip":         None,          # macOS-only
    "gatekeeper":  None,          # macOS-only
    "filevault":   None,          # macOS-only (BitLocker → "bitlocker" in _raw)
    "xprotect":    None,          # macOS-only
    "firewall":    "on"|"off",    # Windows Firewall (all profiles)
    "secure_boot": "full"|"none"|None,
    "av_installed": True|False,
    "av_product":  "Windows Defender"|None,
    "os_patched":  True|False,    # last hotfix ≤ 30 days
    "auto_update": True|False,
    "selinux":     None,          # Linux-only
    "apparmor":    None,          # Linux-only
    "ufw":         None,          # Linux-only
    # Windows-specific (in _raw so detection rules can use them):
    "_raw": {
        "uac":              "enabled"|"disabled",
        "bitlocker":        "on"|"off",
        "defender":         "enabled"|"disabled",
        "credential_guard": True|False|None,
        "wdac_enabled":     True|False|None,
        "smb1_enabled":     True|False|None,
        "lsass_ppl":        True|False|None,
        "last_patch_days":  int|None,
    }
}
```

Processes section (Windows-specific additions):
```python
{
    "pid":         int,
    "ppid":        int,
    "name":        str,                      # executable name
    "user":        "DOMAIN\\username",       # Windows format
    "cpu_pct":     float,
    "mem_pct":     float,
    "mem_rss_mb":  int,
    "status":      str,
    "started_at":  int,                      # unix timestamp
    "cmdline":     str,
    # Windows-specific (from ETW / Phase 2):
    "_win": {
        "integrity_level": "low"|"medium"|"high"|"system",
        "signed":          True|False|None,
        "signer":          str|None,
        "parent_chain":    ["ppid_name", ...],
    }
}
```

### Transport (shared, already works)

The shared `agent/agent/sender.py` and `crypto.py` work on Windows unchanged.
- AES-256-GCM + HMAC-SHA256 encryption is pure Python (`cryptography` package)
- `DiskSpool` uses `os.path` and standard file I/O — works on Windows paths
- `urllib.request` for HTTPS — works on Windows
- **What needs adding**: Windows proxy resolution via `WinHTTP`

### Key storage (Windows)

**Already implemented** (`os/windows/keystore.py`):
- DPAPI `CryptProtectData` / `CryptUnprotectData` with `CRYPTPROTECT_LOCAL_MACHINE` flag
  → encrypted to the machine (not user), survives user change, readable by SYSTEM service
- Stored in `%ProgramData%\AttackLens\security\<agent_id>.key.dpapi`
- Fallback: plain file (same as macOS file backend) for non-Windows test runs

### Service lifecycle (Windows SCM)

```python
# service.py — what it must do correctly
class AttackLensAgentSvc(win32serviceutil.ServiceFramework):
    _svc_name_ = "AttackLensAgent"
    _svc_display_name_ = "AttackLens Security Agent"
    _svc_deps_ = ["Dnscache", "Tcpip"]  # wait for network stack

    def SvcDoRun(self):
        # 1. Report start pending with checkpoint
        self.ReportServiceStatus(win32service.SERVICE_START_PENDING,
                                 waitHint=10000, checkPoint=1)
        # 2. Acquire named mutex (single-instance)
        # 3. Run main() from core.py
        # 4. Report running
        # 5. Wait on stop event
        ...

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        # signal orchestrator + sender to drain + exit

    # Register SERVICE_CONTROL_PRESHUTDOWN for graceful flush on OS shutdown
```

SCM recovery actions (set at install time, not in code):
```powershell
sc.exe failure AttackLensAgent reset=86400 actions=restart/5000/restart/10000/restart/30000
```

---

## Part 5 — The verified implementation prompt

Use this prompt verbatim when starting a new session to build the Windows agent.

---

```
You are implementing the Windows agent for AttackLens — an endpoint security telemetry platform.
The macOS agent is already fully production-hardened. Your job is to bring the Windows agent to
the same standard and then exceed it with Windows-native telemetry depth.

## Repository structure (what already exists)

agent/
  agent/              ← SHARED modules (cross-platform, do NOT modify OS-specific behavior)
    core.py           ← Orchestrator: schedules collectors, encrypts, enqueues, health heartbeat
    sender.py         ← Sender: AES-256-GCM encrypt, disk spool (NDJSON), HTTP POST, retry/backoff
    crypto.py         ← AES-256-GCM + HMAC-SHA256 encryption helpers
    enrollment.py     ← First-run enrollment: POST /api/v1/enroll, store API key
    keystore.py       ← Cross-platform keystore dispatcher
    policy.py         ← Signed-policy verification (Ed25519/RSA-PSS)
    config_engine.py  ← Three-layer config merge (toml + signed policies + env overrides)
    circuit_breaker.py← Per-section circuit breaker (CLOSED→OPEN→HALF-OPEN)
    normalizer.py     ← macOS normalizer (reference implementation)
    single_instance.py← flock-based single-instance (POSIX only — needs Windows counterpart)
    supervision.py    ← Supervisor (rate-limited restart, max_restarts, restart_window)
    watchdog.py       ← Watchdog process (optional second supervisor layer)
    obs.py            ← Structured logging + rate-limiting
    manifest.py       ← Binary integrity manifest + SHA-256 checksum validation
    collectors/       ← GENERIC collectors (Windows platform-dispatches to os/windows/collectors/)
  os/windows/         ← WINDOWS-SPECIFIC (your target)
    service.py        ← SCM service host (pywin32) — needs hardening
    watchdog_svc.py   ← Optional watchdog service
    keystore.py       ← DPAPI keystore — already implemented, do not change
    normalizer.py     ← Windows normalizer — partially implemented, needs expansion
    agent_win_entry.py← Windows entry point
    collectors/
      base.py         ← WinBaseCollector (winreg helpers, _run_ps, _run) — needs _run killed
      volatile.py     ← metrics (psutil ✅), connections (psutil ✅), processes (psutil ✅)
      network.py      ← ports, network, arp, mounts — uses PowerShell (needs native)
      system.py       ← battery, openfiles, services, users, hardware, containers — mixed
      posture.py      ← security, sysctl, configs — implemented, needs hardening
      inventory.py    ← storage, tasks, apps, packages, binaries, sbom — uses PowerShell

## What the manager expects (canonical schema)

Every collector returns either:
  - a dict (for single-value sections like metrics, security)
  - a list of dicts (for multi-value sections like processes, connections)

The manager's detection engine in manager/manager/attacklens/ processes these.
The normalizer maps Windows-raw to canonical fields. Where a Windows concept maps
to a macOS field (e.g. firewall="on"), use the same field name. Where it's
Windows-only, put it in the "_raw" subdict. The manager ignores "_raw" for CIS
scoring but detection rules can reference it.

## Enrollment and key storage

Enrollment already works on Windows:
  POST /api/v1/enroll with body { agent_id, hostname, os, arch, os_version, agent_version }
  Response: { api_key: "<64-hex>" }
  Stored via DPAPI (os/windows/keystore.py) — CRYPTPROTECT_LOCAL_MACHINE, machine-scoped.
  Path: %ProgramData%\AttackLens\security\<agent_id>.key.dpapi

## Transport

sender.py works on Windows unchanged. It:
  - Encrypts each envelope: AES-256-GCM(gzip(json)), HMAC-SHA256 header
  - POSTs to /api/v1/ingest with X-Agent-ID + X-Agent-Sig headers
  - On fail: writes to DiskSpool (%ProgramData%\AttackLens\spool\unsent.ndjson, 50MB cap)
  - Handles: 200 (ok), 401 (re-enroll after 3), 429 (Retry-After), 503 (spool)
  - Exponential backoff (2–60s), wake-from-sleep reprobe

What you need to add to transport:
  - Windows proxy resolution: check WinHTTP system proxy settings
    (registry: HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings)
    or call WinHttpGetDefaultProxyConfiguration via ctypes if available
  - TLS cert pinning option (for enterprise managed deployments)

## Phase 0 tasks (start here, verify end-to-end before anything else)

1. Fix service.py to correctly:
   - Report SERVICE_START_PENDING with wait-hint (prevents SCM from marking slow start as hung)
   - Set recovery/failure actions on first install (restart 5s/10s/30s)
   - Register SERVICE_CONTROL_PRESHUTDOWN handler (flush queue before OS shutdown)
   - Handle SERVICE_CONTROL_POWEREVENT (sleep/wake → force reprobe in sender)
   - Delayed auto-start: SERVICE_CONFIG_DELAYED_AUTO_START = True

2. Add named mutex single-instance guard:
   import win32event, win32api, winerror
   mutex = win32event.CreateMutex(None, True, "Global\\AttackLensAgent")
   if win32api.GetLastError() == winerror.ERROR_ALREADY_EXISTS:
       log.warning("Another agent instance is running — exiting")
       sys.exit(0)
   # Hold mutex for process lifetime (don't release it)

3. Verify enrollment works on a clean Windows 10/11 VM:
   - Run as SYSTEM: python -m agent.os.windows.agent_win_entry --enroll-only
   - Confirm key written to DPAPI store
   - Confirm POST /api/v1/enroll reaches manager
   - Confirm subsequent ingest calls succeed (200) and appear in dashboard

4. Verify spool and replay:
   - Kill network → generate 100 section payloads → restore network
   - Confirm all 100 appear in manager, none duplicated
   - Confirm spool file drains to zero

## Phase 1 tasks (reliability parity with macOS)

5. Port boot-persistence self-repair (os/windows/boot_persistence.py):
   - On service start, verify: service start type == AUTO_START
   - Verify recovery actions are set (3× restart with delays)
   - If drifted (attacker ran `sc config AttackLensAgent start=demand`), re-assert and log
   - Run this check in a 300s timer thread during normal operation
   - Write a clean-stop marker on SIGTERM/PRESHUTDOWN: %ProgramData%\AttackLens\boot_state.json
     { "last_seen": <unix_ts>, "clean_stop": true|false, "boot_time": <psutil.boot_time()> }
   - On startup, compare boot_time to persisted value → emit system_boot event if changed

6. Clock-skew detector:
   - Already in core.py (Orchestrator._maybe_reseed_on_skew) — works cross-platform
   - Verify it works on Windows (no macOS-specific calls)

7. Disk-full safety:
   - Already in sender.py (DiskSpool.write()) — works cross-platform
   - Verify on Windows: fill disk, confirm agent keeps running, counts dropped, doesn't crash

8. Subprocess budget for slow-collector sections:
   - Port the thread-local budget from os/macos/collectors/base.py to os/windows/collectors/base.py
   - posture collectors (security, sysctl) can fan out into many calls; they need a budget
   - Budget = section_timeout_sec - 3.0 (headroom for partial-data return)

## Phase 2 tasks (native telemetry — kill PowerShell spawns)

9. Replace hot-path collectors with native APIs:
   - volatile.py: already uses psutil ✅ (no changes needed)
   - network.py PortsCollector: use psutil.net_connections(kind='all') filtered to LISTEN state
   - network.py NetworkCollector: use psutil.net_if_addrs() + psutil.net_if_stats()
   - network.py ArpCollector: use ctypes GetIpNetTable2 (iphlpapi.dll) — no PowerShell
   - system.py ServicesCollector: use win32service.EnumServicesStatusEx (no PowerShell)
   - system.py UsersCollector: use win32net.NetUserEnum + win32security.LookupAccountSid
   - inventory.py TasksCollector: use win32com.client to connect to Schedule.Service COM object
   - inventory.py AppsCollector: enumerate HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall
     and HKCU equivalent (both WoW64 views) — pure winreg, no PowerShell

10. ETW process telemetry (pywintrace or pyetw):
    Create os/windows/etw/process_provider.py:
    - Subscribe to Microsoft-Windows-Kernel-Process (GUID: 22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716)
    - Events of interest: ProcessStart (opcode 1), ProcessStop (opcode 2), ImageLoad (opcode 5)
    - For each ProcessStart emit: pid, ppid, image_path, cmdline, user, integrity_level, timestamp
    - Buffer in a thread-safe deque; ProcessesCollector.collect() drains it
    - This replaces the psutil snapshot with real-time process start/stop events

11. ETW DNS telemetry:
    Create os/windows/etw/dns_provider.py:
    - Subscribe to Microsoft-Windows-DNS-Client (GUID: 1c95126e-7eea-49a9-a3fe-a378b03ddb4d)
    - Events: Query (opcode 0), Response (opcode 1)
    - Emit: query_name, query_type, result, pid, timestamp
    - Buffer in deque; ConnectionsCollector.collect() includes recent DNS queries

12. Event Log security channel:
    Create os/windows/evtlog/security_channel.py:
    - EvtSubscribe to "Security" channel with EvtSubscribeToFutureEvents + bookmark
    - Filter: EventID in (4688, 4624, 4625, 4672, 4720, 4728, 4732, 4698, 4697, 1102)
    - Parse each event's XML for the relevant fields
    - 4688 (ProcessCreate): NewProcessName, CommandLine, SubjectUserName, ParentProcessName
    - 4624/4625 (Logon/Fail): LogonType, TargetUserName, IpAddress, WorkstationName
    - Buffer and emit as structured dicts
    - Persist bookmark to %ProgramData%\AttackLens\evtlog\security.bookmark

## Phase 3 tasks (persistence surface and posture depth)

13. Full persistence surface collector (os/windows/collectors/persistence.py):
    - Run/RunOnce: enumerate HKLM + HKCU, both Wow64 views
    - Startup folders: %APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup
                       %ProgramData%\Microsoft\Windows\Start Menu\Programs\Startup
    - Scheduled tasks: connect to Schedule.Service COM, enumerate all tasks, parse XML
      (Triggers, Actions, Principal/RunLevel, Enabled, LastRunTime, LastTaskResult)
    - Services + drivers: EnumServicesStatusEx, classify kernel/user/SYSTEM
    - WMI subscriptions: query __EventFilter, __EventConsumer, __FilterToConsumerBinding
    - IFEO: enumerate HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
    - AppInit_DLLs: HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs
    - Winlogon: HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon (Shell, Userinit, Notify)
    - Diff each against a first-seen baseline stored in %ProgramData%\AttackLens\baseline\
      → emit a "persistence_change" event for new entries (the finding the manager detects)

14. Windows CIS benchmark (sca/policies/sca_windows_cis.yml):
    Map these checks to agent-collected fields:
    - BitLocker enabled on C: (manage-bde -status or PowerShell)
    - Windows Defender: RTP on, tamper protection on, no exclusions of system paths
    - Windows Firewall: all profiles (domain/private/public) enabled
    - UAC: EnableLUA=1, ConsentPromptBehaviorAdmin >= 2
    - LSA Protection: RunAsPPL=1 or 2
    - Credential Guard: LsaCfgFlags >= 1
    - SMBv1 disabled: LanmanServer\Parameters\SMB1=0 or absent on Win10 1709+
    - NTLM: MSV1_0\NtlmMinClientSec + NtlmMinServerSec >= 537395200
    - Secure Boot: UEFISecureBootEnabled=1
    - PowerShell: ScriptBlockLogging enabled, Constrained Language Mode
    - RDP: NLA required (UserAuthentication=1), disabled if not needed
    - Auto-update: WindowsUpdate\AU\NoAutoUpdate=0 or absent
    - Password policy: MinimumPasswordLength >= 8, PasswordComplexity=1 (net accounts)
    - Audit policy: AuditProcessCreation, AuditLogonEvents, AuditAccountManagement enabled
    - Pending reboots: check HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired

## Critical design rules to enforce throughout

1. NEVER spawn powershell.exe in a hot-loop collector (metrics, connections, processes, ports).
   Use psutil, winreg, win32api, ctypes, win32com.client — in that preference order.

2. NEVER parse localized text output. cmd/PowerShell output is locale-dependent.
   Use: win32api functions, registry values (DWORD/REG_SZ), COM properties, JSON output.
   Exception: when using PowerShell for slow collectors, always use ConvertTo-Json -Compress
   and parse the JSON — locale-independent.

3. ALWAYS handle WoW64 registry views. A 32-bit process sees redirected registry.
   Use KEY_WOW64_64KEY for the 64-bit view, KEY_WOW64_32KEY for the 32-bit view.
   Check both for persistence keys (attackers exploit this split).

4. ALWAYS feature-detect, NEVER assume a feature exists.
   Return None (→ scores as "unknown", not FAIL) when a feature is unavailable.
   This is critical for Windows SKU spread (Home/Pro/Enterprise, 10/11/Server).

5. ALWAYS use CREATE_NO_WINDOW for any subprocess.
   (Already in WinBaseCollector._run() — maintain it everywhere.)

6. NEVER put sensitive values in log lines. Log the key name, not the value.

7. Session 0 — the service runs in isolation. Do not attempt to read user-profile paths
   (%APPDATA%, %USERPROFILE%) without explicit impersonation context.
   Use %ProgramData% for machine-wide agent data.

## Testing requirements

For every Phase 0 task: write a unit test in agent/tests/unit/test_windows_<area>.py
Test patterns from the macOS agent to port:
  - test_windows_collectors.py: mock psutil, winreg, win32api → verify output schema
  - test_windows_normalizer.py: input raw Windows data → verify canonical output
  - test_windows_keystore.py: mock CryptProtectData/CryptUnprotectData → verify store/load
  - test_windows_service.py: mock win32service → verify start/stop/preshutdown handlers
  - test_windows_single_instance.py: verify mutex acquisition + duplicate-instance exit

Existing tests to run against any change to shared modules (sender, crypto, enrollment):
  agent/tests/unit/test_sender_status_handling.py
  agent/tests/unit/test_spool.py
  agent/tests/unit/test_circuit_breaker_recovery.py
  agent/tests/unit/test_clock_skew.py
  agent/tests/unit/test_enrollment.py
  agent/tests/unit/test_keystore.py

## Verification checklist (Phase 0 complete when ALL pass)

□ Fresh Windows 10/11 VM: service installs, starts, registers in dashboard
□ Enrollment: agent_id + API key generated, stored in DPAPI, survives reboot
□ All 23 sections appear in dashboard with non-null data
□ Network kill → spool → restore → all payloads delivered, spool=0, no duplicates
□ Service crash → SCM restarts in ≤5s (recovery actions)
□ System shutdown → clean-stop marker written, boot_state.json present
□ Reboot → agent auto-starts, system_boot telemetry event emitted, dashboard shows last reboot
□ Second agent.exe process → exits immediately (mutex)
□ Bad agent.toml → service logs error to Event Log, exits once (no restart loop)
□ Disk full → agent keeps running, spool trims, drop count visible in agent_health
□ Behind corporate proxy → enrollment and ingest succeed

## Manager-side changes needed (minimal)

The manager already handles Windows agents via the same ingest endpoint and detection engine.
No schema changes are needed for Phase 0/1. For Phase 2+, the manager's detection engine
(rulepack.py, engine.py) will need:
  - New rules for Windows-specific fields (_raw.uac, _raw.bitlocker, _raw.lsass_ppl, etc.)
  - New sections registered in shared/sections.py if you add "persistence" or "etw_events"
  - The existing CIS posture endpoint (manager/api/posture.py) needs Windows check mappings
    added for the 14 Windows CIS checks

## Reference: macOS agent bugs to avoid repeating on Windows

1. Do not use the Windows login-session credential store (Credential Manager user-scoped) 
   for the API key. Use DPAPI with CRYPTPROTECT_LOCAL_MACHINE (already correct in keystore.py).
   
2. Do not assume all sections fire at time=0. Use phase stagger (already in core.py).
   On Windows, the SCM start sequence adds variable delay — the stagger handles this.

3. Do not treat 503 as a client error (drop payload). 503 must spool. This is already
   correct in sender.py — verify it on Windows paths.

4. Do not parse PowerShell output for the security section's localizable fields.
   Use registry values (ConvertTo-Json where needed).

5. Do not forget to check both 32-bit and 64-bit registry views for Run/RunOnce keys.
   Malware specifically uses the WoW64 redirect to hide from 64-bit scanners.

6. The ETW Threat-Intelligence provider (VirtualAlloc RWX, CreateRemoteThread, credential
   access primitives) requires the agent to be PPL or anti-malware signed. Plan for this
   in the signing/packaging step — it cannot be added as an afterthought.

7. The 4688 command-line field is blank unless `ProcessCreationIncludeCmdLine_Enabled`
   is set in policy. The agent should detect this and optionally enable it — but only
   if it has a signed policy from the manager authorizing it (fail-closed principle).
```

---

## Part 6 — Things list (ordered by dependency)

### Must-do first (Phase 0)
1. Fix `service.py`: `START_PENDING` + wait-hint, recovery actions, `PRESHUTDOWN`, `POWEREVENT`
2. Named mutex single-instance guard (`Global\AttackLensAgent`)
3. Delayed auto-start (`SERVICE_CONFIG_DELAYED_AUTO_START`)
4. Windows proxy resolution in sender (WinHTTP registry)
5. End-to-end verification: enroll → ingest → dashboard on real Windows VM
6. Spool replay verification on Windows (offline → online → drain)

### Reliability parity (Phase 1)
7. `boot_persistence.py` Windows port (SERVICE auto-start + recovery action self-repair)
8. `boot_state.json` clean-stop marker + `system_boot` telemetry event
9. Verify clock-skew re-seed works on Windows (pure `time.time()` — should be fine)
10. Subprocess budget for Windows collectors (port from macOS base.py)
11. 300s self-repair timer thread (verify boot persistence + delivery probe)
12. PowerShell language mode detection (for posture section, Phase 3)

### Native telemetry (Phase 2)
13. Replace `ArpCollector` with `ctypes.GetIpNetTable2`
14. Replace `ServicesCollector` with `win32service.EnumServicesStatusEx`
15. Replace `UsersCollector` with `win32net.NetUserEnum`
16. Replace `TasksCollector` with `Schedule.Service` COM object
17. Replace `AppsCollector` with `winreg` UNINSTALL key enumeration (both WoW64 views)
18. ETW process provider (Kernel-Process → real-time process start/stop)
19. ETW DNS provider (DNS-Client → beaconing/C2 detection)
20. Event Log security channel (4688, 4624/4625, 4672, 4698, 4697, 1102)
21. Event Log Sysmon channel (if Sysmon present — detect and subscribe)
22. Event Log Defender channel (1116/1117 — ingest Defender detections as findings)
23. Authenticode `WinVerifyTrust` on process images (with hash-based cache)

### Depth and posture (Phase 3)
24. Full persistence surface collector (Run keys, Startup, Tasks, Services, WMI subs, IFEO, AppInit_DLLs, Winlogon)
25. First-seen baseline diff → emit `persistence_change` events
26. LSASS handle access detection (ETW Threat-Intelligence provider — requires PPL/signing)
27. Logon session analysis (4624/4625 burst detection, logon type classification)
28. Windows CIS benchmark YAML (`sca_windows_cis.yml`) with 14+ checks
29. CIS posture endpoint updates in manager (`manager/api/posture.py`)

### Self-defense and enterprise (Phase 4)
30. ACL hardening on install dir + config + spool + service registry key
31. Tamper detection: alert on service stop/disable, Defender exclusion of agent path
32. Self-repair: re-assert recovery actions if an attacker reset them
33. Authenticode sign the agent binary (EV anti-malware cert)
34. Signed MSI (WiX) with silent install + proper SCM registration
35. Intune/SCCM/GPO deployment testing
36. Auto-update channel (signed package, preserve enrollment keys on upgrade)
37. Windows Event Log event source registration (operators use Event Viewer, not text logs)
38. `agent diagnose` command: service state, recovery config, key backend, spool size, last contact

---

*Created: 2026-08-11. Reference implementation: `agent/os/macos/`. Target: `agent/os/windows/`.*
