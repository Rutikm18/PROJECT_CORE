# Windows Agent — Advanced Capabilities Roadmap

**Goal:** take the Windows agent from a working parity scaffold to a **best-in-class endpoint
agent** — deep native telemetry, Windows-grade resilience, anti-tamper, and clean deployment.
Written from four lenses: **Windows internals expert · security engineer · troubleshooting
expert · developer**.

**Legend:** ✅ exists · 🟡 partial/harden · 🔴 add. Each item lists **What / Why / How / Do it
better**, and factors/edge-cases to respect.

---

## 0. Current baseline (what exists today)

| Area | State | Notes |
|---|---|---|
| Collectors (23 sections) | 🟡 | Parity with macOS, but implemented via **`powershell.exe` + `winreg`** (spawn-per-call) — functional, not optimal (see §12). Some section names are macOS-borrowed (`sysctl`, `mounts`) and need Windows-native meaning. |
| Service host | 🟡 | `pywin32` `ServiceFramework` (SCM) with basic `SvcDoRun`/`SvcStop`. No failure/recovery actions, no pre-shutdown, no delayed-autostart. |
| Key storage | ✅ | DPAPI + Credential Manager (`CRYPTPROTECT_LOCAL_MACHINE`) — boot-safe for a SYSTEM service. |
| Transport | 🟡 | Shared sender (AES-GCM + HMAC + TLS, disk spool). Needs Windows proxy support + cert pinning. |
| Resilience | 🔴 | The macOS reliability program (supervision, boot-persistence, single-instance, disk-full, clock-skew, manifest+checksum) is **not yet ported**. |
| Native security telemetry | 🔴 | **No ETW, no Windows Event Log, no WMI event subscriptions, no Sysmon/Defender ingestion, no AMSI.** This is the biggest gap. |

**Guiding principle:** prefer **native Windows APIs / ETW / Event Log** over shelling out to
PowerShell. PowerShell-per-collection is slow, memory-heavy, trips AV/EDR heuristics, and is
itself a top attack vector — a security agent that spawns `powershell.exe` every 10 s is a smell.

---

## 1. Service lifecycle & auto-recovery (Windows-native)

Parity with the macOS "auto-restart after shutdown / survive tamper" work, done the Windows way.

- **🔴 SCM recovery/failure actions** — configure `sc failure` (restart on 1st/2nd/subsequent
  failure, reset window, optional "run command"/reboot). *Why:* the SCM becomes the single
  lifecycle owner + crash-recovery, the Windows equivalent of launchd `KeepAlive`.
- **🔴 Delayed auto-start + `SERVICE_CONFIG_DELAYED_AUTO_START`** — start after boot-critical
  services so network/DNS are ready; avoids the "started before the stack is up" flaps.
- **🔴 `SERVICE_CONTROL_PRESHUTDOWN`** — handle pre-shutdown to flush the queue/spool and write a
  clean-stop marker (parity with macOS reboot detection). Ordinary `SERVICE_CONTROL_SHUTDOWN` gives
  too little time.
- **🔴 Run as `LocalSystem` with a service SID + least privilege** — use a **restricted/write-
  restricted service SID** and drop unneeded privileges; don't run wide-open SYSTEM if avoidable.
- **🔴 Single-instance guard** — a **named kernel mutex** (`Global\AttackLensAgent`) so two agents
  can't run (Windows analog of the macOS `flock`).
- **🔴 Boot auto-start verification / self-repair** — on start, verify the service is `AUTO_START`
  and recovery actions are set; re-assert if drifted (parity with macOS boot-persistence).
- **Do it better:** report status transitions correctly (`SERVICE_START_PENDING` with checkpoint/
  wait-hint) so the SCM never marks a slow start as hung; add a lightweight **watchdog service** or
  in-process supervision (heartbeats) that escalates a wedged worker to a clean SCM restart.

---

## 2. Native security telemetry — ETW (the #1 upgrade) 🔴

Event Tracing for Windows is *the* real-time, low-overhead kernel/user event stream. This is what
elevates the agent from "polls state" to "sees events as they happen."

- **What / How:** subscribe to real-time ETW sessions via `TraceLogging`/`krabsetw`-style consumers
  (or `pywintrace`). High-value providers:
  - `Microsoft-Windows-Kernel-Process` → process start/stop, **image loads**, thread creation.
  - `Microsoft-Windows-DNS-Client` → DNS queries (beaconing/C2 detection) without a resolver hook.
  - `Microsoft-Windows-Kernel-Network` / TCPIP → connections with PID.
  - `Microsoft-Windows-Threat-Intelligence` (requires PPL/ELAM) → in-memory injection, `VirtualAlloc`
    RWX, credential access primitives.
  - `Microsoft-Windows-WMI-Activity` → WMI-based lateral movement/persistence.
  - `Microsoft-Windows-PowerShell` → script-block/module logging.
- **Why:** command lines, injections, and DNS in **real time** — the events that matter for
  detection — with far less overhead than polling + no PowerShell spawns.
- **Factors:** ETW needs SYSTEM; the Threat-Intelligence provider needs the agent to be **PPL/ELAM
  or anti-malware signed**; buffer sizing + loss handling matter (ETW can drop events under load —
  track drops).
- **Do it better:** run a persistent **autologger** so boot-time events aren't missed before the
  service starts; back-pressure by dropping *lowest-value* providers first, never process events.

---

## 3. Windows Event Log ingestion 🔴

The classic, reliable audit source — complementary to ETW.

- **What / How:** subscribe (push, not poll) via `EvtSubscribe` (`win32evtlog`) to:
  - **Security:** 4688 (process create + command line if GPO enabled), 4624/4625 (logon/failed),
    4672 (special privileges), 4720/4728/4732 (account & privileged-group changes), 4698
    (scheduled task), 4697 (service install), 1102 (log cleared).
  - **System / Application**, **Sysmon/Operational** (if Sysmon present — ingest 1,3,7,8,11,13…),
    **PowerShell/Operational** 4104 (script block), **Windows Defender/Operational** (1116/1117
    detections), **TerminalServices** (RDP), **Windows-WMI-Activity/Operational**.
- **Why:** authoritative, tamper-evident audit trail; Sysmon/Defender give rich detections for free.
- **Factors:** 4688 command-line capture requires a GPO/registry setting — **the agent should detect
  it's off and optionally enable it** (`ProcessCreationIncludeCmdLine_Enabled`). Channels need
  read ACLs. Bookmarks so a restart resumes without re-reading or missing events.
- **Do it better:** ship a **bookmark/checkpoint** per channel (like the macOS replay checkpoint);
  normalize Sysmon + Security + ETW into one canonical process/network schema so detection rules
  don't care about the source.

---

## 4. Process & execution visibility 🟡→🔴

- **🔴 Full command line + parent lineage + integrity level + token** (from ETW/4688), not just a
  process list snapshot.
- **🔴 Authenticode signature verification** (`WinVerifyTrust`) on every executing image — signed /
  unsigned / revoked / catalog-signed, publisher, EKU. *Windows analog of the macOS `codesign`
  trust verdict.*
- **🔴 LOLBin & suspicious-parent detection** (Office/`winword`→`cmd`/`powershell`; `mshta`,
  `rundll32`, `regsvr32`, `wmic`, `certutil`, `bitsadmin`).
- **🔴 Injection & tampering signals** (RWX allocations, `CreateRemoteThread`, process hollowing,
  PPID spoofing) — from the Threat-Intelligence ETW provider.
- **Do it better:** cache signature verdicts by image hash (Authenticode is expensive); verify the
  **catalog** too so OS files aren't flagged unsigned.

---

## 5. Persistence-surface coverage (Windows-specific) 🟡→🔴

Windows has far more persistence real-estate than macOS — cover it explicitly:

- Run/RunOnce keys (HKLM+HKCU, WoW64 views), Startup folders, **Scheduled Tasks** (deep parse, not
  just names), **Services** (incl. drivers/kernel), **WMI permanent event subscriptions**
  (`__EventFilter`/`CommandLineEventConsumer`), **IFEO** (Image File Execution Options), **COM
  hijacking** (CLSID), **AppInit_DLLs**, Winlogon (Shell/Userinit/Notify), **BITS jobs**, LSA
  packages/SSP, print monitors, netsh helpers, screensaver, accessibility-tool hijacks (sethc).
- **Why:** these are the actual ATT&CK persistence techniques on Windows; a "services + run keys"
  agent misses most of them.
- **Do it better:** diff against a **first-seen baseline** (entity tracking, like the macOS
  behavioral store) so you alert on *new* persistence, not the existing benign set.

---

## 6. Identity, credentials & lateral movement 🔴

- Logon sessions & types (interactive/RDP/network/service), failed-logon bursts, **privileged group
  membership changes**, new local admins.
- **LSASS access detection** (handle opens to `lsass.exe` — Mimikatz-class credential theft) via ETW.
- Kerberoasting / DCSync signals (domain-joined), SMB/RDP lateral movement, pass-the-hash indicators.
- **Do it better:** correlate logon + process + network across sections (the manager's MITRE
  correlator) rather than alerting per-event.

---

## 7. Network visibility 🟡→🔴

- **🔴 DNS query telemetry** (ETW DNS-Client) — the single best C2/beaconing signal.
- TCP/UDP connections with owning PID + signer, listening ports, ARP/neighbor, routes, adapters.
- Beaconing detection (periodicity/entropy — the manager's behavioral layer), RDP/SMB exposure.
- **Do it better:** enrich each connection with process signer + whether the remote is
  private/cloud/known-bad (threat-intel join) at the agent edge to cut noise.

---

## 8. Security posture & compliance (Windows CIS/ASR) 🟡→🔴

- **Defender** status (RTP, tamper protection, signature age, exclusions — exclusions are an
  attacker target), **Firewall** profiles, **BitLocker** (per-volume), **UAC**, **SmartScreen**,
  **LSA Protection (RunAsPPL)**, **Credential Guard**, **WDAC/AppLocker** policy, **ASR rules**
  state, **Exploit Protection**, patch level / installed hotfixes / pending reboots, **TPM +
  Secure Boot**, PowerShell language mode & logging config, RDP/NLA settings.
- Map to **CIS Windows Benchmark** (parity with the macOS 23-check CIS work).
- **Do it better:** unknown/undeterminable → score **unknown**, never a false FAIL (same rule as
  macOS); flag **Defender exclusions** and **disabled tamper protection** as high-signal findings.

---

## 9. Integrity & anti-tamper (self-defense) 🔴

A security agent is a target — it must defend itself.

- **Install manifest + SHA-256 checksum** validation of the agent binaries at start (direct port of
  the macOS R1 manifest work).
- **Authenticode-sign the agent binary** (EV cert) — enables trust, PPL eligibility, and fewer AV
  false-positives on the agent itself.
- **Protected Process Light (PPL) / ELAM** where feasible so the agent resists kill/inject.
- **Harden ACLs** on the install dir, config, spool, and the service registry key (SYSTEM +
  Administrators only; deny modify to users).
- **Tamper detection** — alert on service stop/disable, binary/registry modification, config change,
  or Defender-exclusion of the agent path; treat "agent stopped" as a security event reported on
  next start (clean-stop marker like macOS).
- **Do it better:** watch the service's own config (recovery actions, start type) and self-repair if
  an attacker flips it to disabled.

---

## 10. Secure communications (Windows specifics) 🟡

- TLS 1.2+ (1.3 where available), strict cert validation, **hostname verification**, optional
  **certificate pinning / mTLS**.
- **Windows proxy support** — honor WinHTTP/WinINET system proxy, **PAC scripts**, and authenticated
  proxies (enterprise reality); fall back cleanly.
- **Honor `Retry-After`** + network circuit breaker (parity with the macOS sender work).
- **Do it better:** use the OS trust store correctly; support enterprise root CAs; reject plain HTTP
  by default with an explicit dev override.

---

## 11. Reliability engineering (port the macOS program) 🔴

Bring the hardening we already proved on macOS to Windows:

- **Durable spool** (bounded queue + explicit loss policy + drop metrics + health alert).
- **Supervision tree / heartbeats** → clean SCM restart on a wedged worker.
- **Disk-full safety**, **bad-config fail-fast**, **clock-skew re-seed**, **single-instance mutex**,
  **sleep/wake resume** (Windows power events `WM_POWERBROADCAST` / `SERVICE_CONTROL_POWEREVENT`).
- **Adaptive backpressure** + **fair live-vs-replay** delivery.
- **Do it better:** reuse the shared `agent/agent/` modules (`obs`, `supervision`, `manifest`,
  `single_instance`) cross-platform where possible; only the OS glue differs.

---

## 12. Performance & footprint 🟡

- **Kill the PowerShell-per-collection pattern** — replace hot-path collectors with native WinAPI /
  WMI (COM) / ETW. PowerShell spawns are ~100–300 ms each, memory-heavy, and AV-noisy.
- Use **WMI via COM** (persistent connection) instead of `wmic`/PowerShell one-shots.
- ETW push beats polling for volatile data; batch + compress (already gzip); cap CPU/RAM; use
  `CREATE_NO_WINDOW` (already present) and low I/O priority.
- **Do it better:** set a self-imposed CPU/RAM budget and shed low-priority collection under load
  (adaptive backpressure).

---

## 13. Deployment, packaging & management 🟡→🔴

- **Signed MSI** (WiX) with silent install (`/qn`), proper service registration + recovery actions,
  and clean uninstall (there's already `uninstall.ps1`).
- **Enterprise deployment**: GPO / Intune / SCCM / winget; per-machine (not per-user).
- **Auto-update** channel (parity with the macOS git/cron pipeline concept, but signed-package based).
- **Config**: machine-wide under `%ProgramData%\AttackLens` with hardened ACLs; support MDM-pushed
  config + the signed-policy control plane.
- **Do it better:** version + rollback story; MSI upgrade preserves enrollment keys.

---

## 14. Troubleshooting & observability (built-in) 🟡→🔴

- **Self-logging to the Windows Event Log** (registered event source) so operators use Event Viewer.
- `--status` / on-disk health file (parity with macOS), structured + **rate-limited/deduped logs**
  (port `obs.py`), a **connectivity self-test** command (enroll + probe + TLS check), and an
  **`agent diagnose`** that reports service state, recovery config, key backend, spool size, last
  contact, and channel/ETW subscription health.
- **Do it better:** emit the supervision/heartbeat + telemetry-loss counters in `agent_health` so
  the dashboard shows degraded Windows agents exactly like macOS.

---

## 15. Windows-specific edge cases & conditions to handle

These are where Windows agents quietly break — design for them explicitly:

- **WoW64 redirection** — 32-bit process reading 64-bit registry/filesystem: use
  `KEY_WOW64_64KEY` (already done in `base.py`) and `Sysnative`; enumerate *both* registry views.
- **SKU/version spread** — Windows 10/11, Server 2016→2025, **ARM64 Windows**; feature-detect
  (Credential Guard, ASR, WDAC availability differ) → return `unsupported`, never crash.
- **Domain vs workgroup**, non-English locales (don't parse localized command output — use APIs/
  event IDs, not text), **Session 0 isolation** (service can't touch user desktop).
- **Safe Mode / early boot**, offline/air-gapped, roaming laptops (sleep/wake, VPN flaps).
- **UAC / privilege** — some data needs SYSTEM; degrade gracefully when not elevated.
- **AV false-positives on the agent** — signing + reputation + vendor allow-listing.
- **High-EPS hosts** (domain controllers, terminal servers) — ETW/event floods → backpressure +
  sampling for low-value events, never drop security-critical ones.

---

## 16. Prioritized roadmap

| Phase | Focus | Items |
|---|---|---|
| **P0 — Green data path (now)** | Prove enroll → ingest → dashboard | verify enrollment, encrypted ingest, link-health; proxy + TLS validation; single-instance mutex; SCM recovery actions |
| **P1 — Reliability parity** | Port macOS hardening | supervision/heartbeat, manifest+checksum, durable spool + loss policy, disk-full/clock-skew, boot-autostart self-repair, pre-shutdown flush, Retry-After |
| **P2 — Native telemetry (the leap)** | Real detection value | ETW (process/DNS/image-load), Event Log + Sysmon/Defender ingestion, Authenticode verdicts, DNS/beaconing |
| **P3 — Depth & posture** | Best-in-class coverage | full persistence surface, identity/LSASS, Windows CIS/ASR posture, injection detection (Threat-Intel ETW) |
| **P4 — Self-defense & scale** | Harden + enterprise | PPL/ELAM, ACL hardening, tamper alerts, signed MSI + Intune/SCCM, auto-update, high-EPS backpressure |

---

## 17. How to verify (testing hooks per phase)

- **P0:** enroll on a clean VM; confirm encrypted payloads accepted; kill network → spool → reconnect
  drains with no loss/dupes; behind a proxy; SCM restart after crash.
- **P1:** chaos tests — kill/wedge worker → SCM clean restart; disk full; corrupt spool recovery;
  clock jump; reboot/sleep-wake auto-recovery; second-instance blocked by mutex.
- **P2:** generate known events (spawn `powershell -enc`, do a DNS lookup to a canary domain, load an
  unsigned DLL) → confirm ETW/Event Log captures + normalizes them.
- **P3/P4:** run ATT&CK-style scenarios (persistence via Run key + scheduled task + WMI sub; LSASS
  access; Defender exclusion added) → confirm findings + correlation; attempt to stop/disable the
  service → confirm tamper alert + self-repair.

---

*Cross-platform reuse:* wherever possible, Windows should consume the **shared** `agent/agent/`
resilience modules (`obs`, `supervision`, `manifest`, `single_instance`, sender/spool) — only the
OS-specific glue (SCM, ETW, Event Log, DPAPI, registry) is Windows-only. One brain, two bodies.
