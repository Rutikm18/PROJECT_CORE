# Windows MSI Agent — Full Implementation Prompt

## Context & Goal

You are implementing a **Windows MSI agent** for the AttackLens telemetry platform. The macOS agent already exists and is fully working. The Windows agent must have **feature parity** with the macOS agent while using Windows-native APIs, paths, and conventions throughout. The architecture (config format, data format, enrollment flow, encryption, sender, spool queue) is **shared** — only the OS layer changes.

Read the existing macOS implementation thoroughly before writing any Windows code. Every design decision below was made deliberately; match it unless a Windows constraint forces a difference.

---

## Existing codebase to study first

```
agent/
  agent_entry.py            ← main entry point (already cross-platform)
  agent/
    core.py                 ← orchestrator + main()
    config.py               ← AgentConfig dataclass (TOML loader)
    enrollment.py           ← first-run enrollment (POST /api/v1/enroll)
    keystore.py             ← key load/store (dispatch to OS backend)
    crypto.py               ← AES-256-GCM + HMAC-SHA256 + HKDF
    sender.py               ← HTTP sender + spool queue
    watchdog.py             ← watchdog process
    circuit_breaker.py      ← per-collector failure isolation
  os/
    macos/
      keystore.py           ← macOS Keychain backend
      launchd.py            ← macOS service management
      normalizer.py         ← raw → canonical field normalization
      collectors/
        base.py             ← BaseCollector, CollectorResult, _run(), _sp_json()
        volatile.py         ← metrics, connections, processes
        network.py          ← ports, network, arp, mounts
        inventory.py        ← storage, tasks, apps, packages, binaries, sbom
        posture.py          ← security, sysctl, configs
        system.py           ← battery, openfiles, services, users, hardware, containers
  config/
    agent.toml.example      ← full reference config (22 sections)
shared/
  sections.py               ← SectionDef registry (canonical section names + intervals)
```

---

## What to build

```
agent/os/windows/
  keystore.py               ← Windows Credential Manager backend
  service.py                ← Windows Service wrapper (win32service)
  watchdog_svc.py           ← Watchdog as Windows Service
  normalizer.py             ← raw → canonical (mirrors macOS normalizer)
  collectors/
    base.py                 ← BaseCollector (Windows version of _run, registry helpers)
    volatile.py             ← metrics, connections, processes
    network.py              ← ports, network, arp, mounts
    inventory.py            ← storage, tasks, apps, packages, binaries, sbom
    posture.py              ← security, registry, configs
    system.py               ← battery, openfiles, services, users, hardware, containers

agent/os/windows/installer/
  build_msi.ps1             ← MSI builder (WiX v4 + PowerShell)
  attacklens-service.ps1    ← service management CLI (install to PATH)
  attacklens-service.cmd    ← CMD shim wrapper for the PS1 CLI
  generate_config.ps1       ← writes complete agent.toml
  product.wxs               ← WiX product definition
  QUICKSTART.md             ← Windows quick start guide

agent/os/windows/pkg/
  generate_config.ps1       ← (copy of installer version, for standalone use)
```

---

## 1. Repository layout & integration

### 1.1 Entry point

`agent/agent_entry.py` already does:
```python
from agent.agent.core import main
```

`core.py` calls `load_config()`, sets up logging, runs enrollment, then starts the collector orchestrator. **Do not modify `core.py`** — all Windows specifics go in `agent/os/windows/`.

### 1.2 OS detection in core.py

`core.py` already has OS detection. Ensure the Windows import path is:
```python
if sys.platform == "win32":
    from agent.os.windows.keystore import load_key, store_key
```
Match the existing macOS pattern exactly.

---

## 2. Windows Keystore (`agent/os/windows/keystore.py`)

Use the **Windows Credential Manager** via the `keyring` library (which uses `win32cred` internally).

```python
# Backend: keyring with Windows CredentialManager
# Service name: "AttackLens Agent"
# Username: agent_id  (e.g. "win-<machine-guid>")
# Credential type: CRED_TYPE_GENERIC

def store_key(agent_id: str, api_key: str, **kwargs) -> None:
    import keyring
    keyring.set_password("AttackLens Agent", agent_id, api_key)

def load_key(agent_id: str, **kwargs) -> str | None:
    import keyring
    return keyring.get_password("AttackLens Agent", agent_id)

def delete_key(agent_id: str, **kwargs) -> None:
    import keyring
    keyring.delete_password("AttackLens Agent", agent_id)
```

**Fallback**: if `keyring` is unavailable, fall back to a file at `security_dir\agent.key` (AES-256 encrypted with machine GUID as key material). Match the macOS `file` backend interface exactly.

**Agent ID format**: `win-<machine-guid-lowercase>` where machine GUID comes from:
```
HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid
```

---

## 3. Windows Service wrapper (`agent/os/windows/service.py`)

Use **`pywin32`** (`win32service`, `win32serviceutil`, `win32event`).

```python
import win32service, win32serviceutil, win32event, servicemanager
import subprocess, sys, os

class AttackLensAgentService(win32serviceutil.ServiceFramework):
    _svc_name_         = "AttackLensAgent"
    _svc_display_name_ = "AttackLens Agent"
    _svc_description_  = "AttackLens endpoint telemetry agent"

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self._stop_event)

    def SvcDoRun(self):
        # Launch agent as subprocess; restart on crash (watchdog role)
        ...
```

Requirements:
- Service runs as **LocalSystem** (or a dedicated low-privilege service account if configured via `run_as_user` in `agent.toml`)
- Service start type: **Automatic (Delayed Start)**
- Recovery actions: restart after 10 s (first two failures), then restart after 60 s
- Writes to `C:\ProgramData\AttackLens\logs\agent-service.log`
- On `SvcStop`, sends CTRL_BREAK_EVENT to the subprocess and waits up to 10 s before `TerminateProcess`

### 3.1 Watchdog service (`watchdog_svc.py`)

Mirror the agent service but running `run_watchdog.py`. Service name: `AttackLensWatchdog`.

---

## 4. Windows Collectors

### 4.1 Base (`agent/os/windows/collectors/base.py`)

```python
def _run(cmd: list[str], timeout: int = 15) -> str:
    """Run a command, return stdout, swallow errors."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=timeout, creationflags=subprocess.CREATE_NO_WINDOW
        )
        return result.stdout
    except Exception:
        return ""

def _run_json(cmd: list[str], timeout: int = 15) -> Any:
    """Run command and JSON-parse stdout."""

def _wmi(query: str) -> list[dict]:
    """Execute a WMI query via wmi module or PowerShell fallback."""
    try:
        import wmi
        c = wmi.WMI()
        return [dict(obj.properties) for obj in c.query(query)]
    except ImportError:
        # PowerShell fallback
        ps_cmd = f'Get-WmiObject -Query "{query}" | ConvertTo-Json -Depth 3'
        return _run_powershell_json(ps_cmd) or []

def _run_powershell(script: str, timeout: int = 20) -> str:
    return _run(["powershell", "-NoProfile", "-NonInteractive",
                 "-ExecutionPolicy", "Bypass", "-Command", script], timeout)

def _run_powershell_json(script: str, timeout: int = 20) -> Any:
    out = _run_powershell(f"{script} | ConvertTo-Json -Depth 5 -Compress", timeout)
    try:
        return json.loads(out)
    except Exception:
        return None

def _reg_get(hive, path: str, value: str) -> str | None:
    """Read a Windows registry value. Returns None on any error."""
    try:
        import winreg
        key = winreg.OpenKey(hive, path)
        val, _ = winreg.QueryValueEx(key, value)
        return str(val)
    except Exception:
        return None
```

### 4.2 Volatile (`volatile.py`) — 10 s interval

**MetricsCollector** — use `psutil` (fully supported on Windows):
- Same fields as macOS: `cpu_percent`, `mem_percent`, `cpu_per_core`, `cpu_cores`, `cpu_cores_physical`, `cpu_freq_mhz`, `mem_used_mb`, `mem_total_mb`, `mem_available_mb`, `swap_percent`, `swap_used_mb`, `swap_total_mb`, `disk_read_mb_s`, `disk_write_mb_s`, `net_sent_mb_s`, `net_recv_mb_s`, `load_1m` (Windows: use rolling average from CPU history), `load_5m`, `load_15m`, `uptime_sec`
- Delta-based I/O rates using class-level `_prev_disk`, `_prev_net`, `_prev_ts` (identical pattern to macOS)

**ConnectionsCollector** — `psutil.net_connections(kind='inet')`:
- Same fields: `proto`, `local_addr`, `local_port`, `remote_addr`, `remote_port`, `remote_service`, `state`, `pid`, `process`, `user`, `is_private`, `direction`
- Windows adds `TIME_WAIT`, `CLOSE_WAIT` states — include them
- `user`: resolve via `psutil.Process(pid).username()` — returns `DOMAIN\user` on Windows; normalize to lowercase

**ProcessesCollector** — `psutil.process_iter()`:
- Same fields: `pid`, `ppid`, `name`, `user`, `cpu_percent`, `mem_percent`, `mem_rss_mb`, `mem_vms_mb`, `status`, `started_at`, `cmdline` (512 chars), `exe`, `signed`
- `signed`: check Authenticode signature via `subprocess.run(["powershell", "-Command", f"(Get-AuthenticodeSignature '{exe}').Status"])` — returns `Valid`/`NotSigned`/`UnknownError`; cache results (signing check is expensive)
- Top 80 by CPU

### 4.3 Network (`network.py`) — 30 s–2 min

**PortsCollector** (30 s) — LISTEN sockets:
- `psutil.net_connections(kind='inet')` filtered to `LISTEN` state
- Fields: `proto`, `port`, `bind_addr`, `state`, `pid`, `process`

**NetworkCollector** (2 min):
- Interfaces: `psutil.net_if_addrs()` + `psutil.net_if_stats()`
- DNS servers: registry `HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\*\NameServer`
- Default gateway: `ipconfig /all` parsed, or routing table via `psutil`
- Hostname/domain: `socket.getfqdn()`, `os.environ.get('USERDOMAIN')`
- WiFi: `netsh wlan show interfaces` — SSID, BSSID, signal, channel

**ArpCollector** (2 min):
- Parse `arp -a` output (same cross-platform format)
- Fields: `ip`, `mac`, `interface`, `state`

**MountsCollector** (2 min):
- `psutil.disk_partitions(all=False)`
- Fields: `device`, `mountpoint`, `fstype`, `options`
- Include only mounted, real partitions (filter out removable with no media)

### 4.4 System (`system.py`) — 2 min

**BatteryCollector**:
- `psutil.sensors_battery()` — same interface, works on Windows
- WMI fallback: `SELECT * FROM Win32_Battery`
- Fields: `present`, `charging`, `charge_pct`, `cycle_count` (WMI `CycleCount`), `condition`, `capacity_mah`, `design_mah`, `voltage_mv`

**OpenFilesCollector**:
- `psutil.process_iter(['pid', 'name', 'open_files'])` — same as macOS
- Windows note: `open_files()` requires SeDebugPrivilege for some processes; catch `AccessDenied` silently
- Top 60 by fd count

**ServicesCollector** (2 min):
- Primary: `psutil.win_service_iter()` (Windows-only psutil API)
- Fields: `name`, `display_name`, `status` (running/stopped/paused), `start_type` (auto/manual/disabled), `pid`, `description`, `binpath`
- Fallback: `sc query type= all state= all` parsed
- Filter to non-driver services only (`SERVICE_WIN32`)

**UsersCollector** (2 min):
- All local accounts: PowerShell `Get-LocalUser | Select-Object Name,Enabled,LastLogon,PasswordRequired | ConvertTo-Json`
- Admin group members: `Get-LocalGroupMember -Group "Administrators" | ConvertTo-Json`
- Fields: `name`, `sid`, `enabled`, `admin`, `locked`, `password_required`, `last_login`, `home`
- Note: no `uid`/`gid` on Windows; use `sid` instead

**HardwareCollector** (2 min):
- USB: WMI `SELECT * FROM Win32_USBControllerDevice` + `Win32_PnPEntity`
- GPU: WMI `SELECT * FROM Win32_VideoController`
- CPU/System: WMI `Win32_Processor`, `Win32_ComputerSystem`, `Win32_BaseBoard`
- Fields per device: `bus`, `name`, `vendor`, `product_id`, `vendor_id`, `serial`, `revision`
- Normalize field names to match macOS output

**ContainersCollector** (2 min):
- Docker: `docker ps -a --format json` (identical to macOS — Docker Desktop on Windows uses same CLI)
- Fields: identical to macOS

### 4.5 Inventory (`inventory.py`) — 10 min / 24 hr

**StorageCollector** (10 min):
- `psutil.disk_partitions()` + `psutil.disk_usage(mountpoint)`
- Fields: `device`, `mountpoint`, `fstype`, `total_gb`, `used_gb`, `free_gb`, `usage_pct`

**TasksCollector** (10 min) — scheduled tasks:
- `schtasks /query /fo CSV /v` parsed — or PowerShell `Get-ScheduledTask | Get-ScheduledTaskInfo | ConvertTo-Json`
- Fields: `name`, `type` (`scheduled_task`), `schedule`, `command`, `user`, `enabled`, `last_run`, `next_run`, `status`
- Filter: skip disabled Microsoft built-in tasks by default (configurable)

**AppsCollector** (24 hr) — installed software:
- Registry: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*` + `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*` + `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*`
- Fields: `name`, `version`, `vendor` (Publisher), `install_date`, `install_location`, `uninstall_string`, `source` (`registry`)
- Also query Windows Store apps: PowerShell `Get-AppxPackage | Select Name,Version,Publisher,InstallLocation | ConvertTo-Json`

**PackagesCollector** (24 hr):
- winget: `winget list --source winget --accept-source-agreements` (parse tabular output)
- Chocolatey: `choco list --local-only --limit-output` if `choco.exe` exists
- Scoop: `scoop list` if `scoop` exists
- pip3: `python -m pip list --format json`
- npm global: `npm list -g --json --depth 0`
- Fields: `manager`, `name`, `version`, `latest` (if available), `outdated`, `installed_at`

**BinariesCollector** (24 hr, disabled by default):
- SHA-256 of executables in `%SystemRoot%\System32`, `%SystemRoot%\SysWOW64`, `%ProgramFiles%\*\*.exe`, `%SystemRoot%\System32\drivers\*.sys`
- Fields: `path`, `name`, `hash_sha256`, `size_bytes`, `permissions`, `signed`

**SbomCollector** (24 hr):
- pip3, winget, chocolatey, npm packages in PURL format
- Fields: `type`, `name`, `version`, `purl`, `license`, `source`, `cpe`

### 4.6 Posture (`posture.py`) — 1 hr

This is the most Windows-specific collector. All fields must use the **same canonical names** as the macOS `security` section so the dashboard renders them uniformly.

**SecurityCollector** — fields to collect:

| Field | Method | Notes |
|-------|--------|-------|
| `uac` | Registry `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System` key `EnableLUA` | `"enabled"` / `"disabled"` |
| `bitlocker` | PowerShell `Get-BitLockerVolume \| Select MountPoint,VolumeStatus,EncryptionPercentage \| ConvertTo-Json` or `manage-bde -status` | `"on"` / `"off"` / per-volume dict |
| `defender` | PowerShell `Get-MpComputerStatus \| Select AMRunningMode,RealTimeProtectionEnabled,AntivirusEnabled,AntivirusSignatureLastUpdated \| ConvertTo-Json` | dict or `"not_installed"` |
| `firewall` | `netsh advfirewall show allprofiles state` | `"on"` if all profiles on |
| `secure_boot` | PowerShell `Confirm-SecureBootUEFI` | `True`/`False`/`None` if not UEFI |
| `auto_update` | Registry `HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU` key `NoAutoUpdate` (0=enabled) or WMI `Win32_AutoUpdate` | `True`/`False` |
| `remote_login` | Registry `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server` key `fDenyTSConnections` (0=enabled) | `True`/`False` (RDP enabled) |
| `screen_sharing` | Same as `remote_login` on Windows (RDP = screen sharing) | |
| `ssh_password_auth` | Check if OpenSSH Server is running + parse `%ProgramData%\ssh\sshd_config` | `"yes"` / `"no"` / `None` |
| `ssh_permit_root_login` | Parse `sshd_config` — Windows equivalent is "Administrator" login | |
| `screensaver_lock` | Registry `HKCU\Control Panel\Desktop` key `ScreenSaverIsSecure` | `True`/`False` |
| `screensaver_idle_sec` | Registry `HKCU\Control Panel\Desktop` key `ScreenSaveTimeOut` | int seconds |
| `selinux` | Always `None` | |
| `apparmor` | Always `None` | |
| `ufw` | Always `None` | |
| `sip` | Always `None` | |
| `gatekeeper` | Always `None` | |
| `filevault` | Always `None` (use `bitlocker`) | |
| `xprotect_version` | Always `None` | |
| `lockdown_mode` | Always `None` | |
| `dev_tools` | Check if WinDbg, VS, VSCode debugger installed — `"enabled"` / `"disabled"` | optional |
| `av_installed` | WMI `SELECT * FROM AntiVirusProduct` (SecurityCenter2) | `True`/`False` |
| `av_product` | Same WMI query — `displayName` field | e.g. `"Windows Defender"` |
| `os_patched` | WMI `Win32_QuickFixEngineering` last patch date vs today — True if ≤ 30 days | `True`/`False` |
| `remote_management` | Check WinRM service: `sc query WinRM` | `True`/`False` |
| `tpm_version` | WMI `Win32_TPM` — `SpecVersion` | string or `None` |
| `smb_signing` | Registry `HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters` key `RequireSecuritySignature` | `True`/`False` |
| `autorun_disabled` | Registry `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer` key `NoDriveTypeAutoRun` | `True`/`False` |

**RegistryCollector** (replaces macOS `sysctl`) — security-relevant registry keys:
- Query a curated list of 30+ security-relevant registry paths (UAC, audit policy, LSASS protection, credential guard, exploit protection, etc.)
- Fields: `key` (full path), `value`, `value_name`, `security_relevant: true`

**ConfigsCollector** — Windows equivalent of shell/SSH configs:
- `%USERPROFILE%\.ssh\config`, `%USERPROFILE%\.ssh\authorized_keys`
- `%USERPROFILE%\Documents\WindowsPowerShell\profile.ps1`
- `%USERPROFILE%\Documents\PowerShell\profile.ps1`
- `%SystemRoot%\System32\drivers\etc\hosts`
- `%ProgramData%\ssh\sshd_config`
- `C:\Windows\System32\GroupPolicy\Machine\Scripts\*`
- Suspicious pattern detection: `IEX`, `Invoke-Expression`, `DownloadString`, `FromBase64String`, `Start-Process -WindowStyle Hidden`, `certutil -decode`, `bitsadmin /transfer`
- 4 KiB cap per file
- Fields: `path`, `content`, `suspicious: bool`

---

## 5. Normalizer (`agent/os/windows/normalizer.py`)

Mirror `agent/os/macos/normalizer.py` exactly. Handle three paths for `metrics`:
1. **psutil path** — `cpu_percent` already canonical
2. **WMI path** — normalize WMI field names to canonical
3. **CLI text path** — parse `typeperf` or `Get-Counter` output

Implement `normalize_record(section: str, raw: Any) -> Any` with the same interface as the macOS normalizer. The dashboard calls the same normalizer dispatch regardless of OS.

---

## 6. Windows Service installer (`agent/os/windows/service.py` — detail)

### Service registration

```python
if __name__ == "__main__":
    win32serviceutil.HandleCommandLine(AttackLensAgentService)
```

Install via: `python service.py install` / `python service.py start` / `python service.py stop` / `python service.py remove`

### Service recovery configuration

After installing, apply recovery policy via `sc failure`:
```
sc failure AttackLensAgent reset= 86400 actions= restart/10000/restart/10000/restart/60000
```

### Service account

Default: `NT AUTHORITY\SYSTEM`. If `run_as_user` is set in `agent.toml`, configure the service to run as that account (requires `SeServiceLogonRight`).

---

## 7. MSI Installer (WiX v4)

### 7.1 Build script (`build_msi.ps1`)

```powershell
# Requirements check
# - WiX v4 (dotnet tool install --global wix)
# - Python 3.11+ in PATH
# - Running as Administrator (for service registration test)
```

Build steps:
1. **Pre-flight**: check `wix`, `python`, source directory exist
2. **Copy source**: robocopy Python source to `build\src\` (excludes `__pycache__`, `*.pyc`, `.git`, `dist`, `tests`)
3. **Write bootstrap launchers**: `build\bin\run_agent.py` and `build\bin\run_watchdog.py` (identical to macOS — `sys.path = [r'C:\Program Files\AttackLens\src']`)
4. **Write WiX source**: populate `product.wxs` with correct GUIDs and paths
5. **Compile WiX**: `wix build product.wxs -o dist\attacklens-agent-2.0.0-x64.msi`
6. **Output**: `dist\attacklens-agent-2.0.0-x64.msi`

### 7.2 WiX product definition (`product.wxs`)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<Wix xmlns="http://wixtoolset.org/schemas/v4/wxs"
     xmlns:util="http://wixtoolset.org/schemas/v4/wxs/util">
  <Package
    Name="AttackLens Agent"
    Manufacturer="AttackLens"
    Version="2.0.0"
    UpgradeCode="PUT-STABLE-GUID-HERE"
    Scope="perMachine"
    InstallerVersion="500">
```

Required components:
- **ProgramFiles component**: all files under `C:\Program Files\AttackLens\`
  - `src\` (Python source tree)
  - `bin\run_agent.py`, `bin\run_watchdog.py`
  - `bin\generate_config.ps1`
  - `QUICKSTART.md`
- **ProgramData component**: directories under `C:\ProgramData\AttackLens\`
  - `logs\`, `security\`, `spool\`, `data\`
  - `agent.toml` — generated by CustomAction
- **Bin symlink**: install `attacklens-service.ps1` and `attacklens-service.cmd` wrapper to a directory on the system PATH
- **Registry component**: `HKLM\SOFTWARE\AttackLens\Agent` with `Version`, `InstallDir`, `ConfigPath`
- **Windows Service components**: install `AttackLensAgent` and `AttackLensWatchdog` services
- **Environment component**: add `C:\Program Files\AttackLens\bin` to system PATH

Custom actions:
- `CA_DetectPython` — find python.exe, write path to registry for use by services
- `CA_GenerateConfig` — call `generate_config.ps1` to write `agent.toml`
- `CA_InstallDeps` — `python -m pip install --quiet psutil cryptography requests keyring pywin32`
- `CA_StartServices` — start both Windows Services
- `CA_StopServices` (deferred, on uninstall) — stop and remove services
- `CA_RemoveData` (optional, on full uninstall) — remove `C:\ProgramData\AttackLens\`

Upgrade handling:
```xml
<MajorUpgrade DowngradeErrorMessage="A newer version is already installed."
              Schedule="afterInstallInitialize"/>
```

### 7.3 Installer UI

Use WiX Standard Bootstrapper Application (Simple UI):
- Welcome screen with version
- License agreement
- Manager IP input field (text box bound to `MANAGER_URL` property)
- Agent name input field (bound to `AGENT_NAME` property)
- Optional: `RUN_AS_USER` / `RUN_AS_GROUP` fields
- Install progress
- Finish screen with "Open QUICKSTART.md" checkbox

Silent install support:
```
msiexec /i attacklens-agent-2.0.0-x64.msi /qn MANAGER_URL="http://34.224.174.38:8080" AGENT_NAME="myhost"
```

---

## 8. Service Management CLI (`attacklens-service.ps1`)

Install to a directory on the system PATH alongside a `.cmd` shim:
```batch
@echo off
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0attacklens-service.ps1" %*
```

Required commands (match macOS interface exactly):

```
attacklens-service status           — service + config summary
attacklens-service start            — start both services (requires elevation)
attacklens-service stop             — stop both services (requires elevation)
attacklens-service restart          — stop then start
attacklens-service reload           — signal agent to reload config (sends event)
attacklens-service logs             — tail agent.log in real-time (Get-Content -Wait)
attacklens-service config           — print agent.toml
attacklens-service version          — version + python info + OS build
attacklens-service diagnose         — connectivity + install health check
attacklens-service set-manager <IP> — update manager URL, clear key, restart
attacklens-service enroll           — clear Credential Manager key, force re-enrollment
attacklens-service update-config    — regenerate agent.toml (preserve id/name)
attacklens-service help             — usage
```

### 8.1 Elevation check

```powershell
function Require-Admin {
    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
        ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Error "Run as Administrator: Start-Process powershell -Verb RunAs -ArgumentList 'attacklens-service $args'"
        exit 1
    }
}
```

### 8.2 `diagnose` command

Check:
- Windows version (`[System.Environment]::OSVersion`)
- Python 3.11+ found and version
- Required Python packages (`psutil`, `cryptography`, `requests`, `keyring`, `pywin32`)
- Install dir exists (`C:\Program Files\AttackLens`)
- `agent.toml` exists and is parseable
- Manager URL is not a placeholder
- TCP connectivity to manager (`Test-NetConnection -ComputerName $host -Port $port`)
- HTTP `GET /health` response code
- Both Windows Services installed and running (`Get-Service AttackLensAgent`)
- Windows Credential Manager entry exists (enrolled?)
- Windows Firewall not blocking outbound to manager IP
- Event log entries (last 5 errors from AttackLens source)

### 8.3 `set-manager` command

```powershell
# Update agent.toml (same python3 regex approach as macOS)
python -c "
import re, sys
path = r'C:\ProgramData\AttackLens\agent.toml'
url  = sys.argv[1]
tls  = 'false' if url.startswith('http://') else 'true'
with open(path) as f: c = f.read()
c = re.sub(r'^url\s*=\s*\"[^\"]*\"', f'url        = \"{url}\"', c, flags=re.MULTILINE)
c = re.sub(r'^tls_verify\s*=\s*\S+', f'tls_verify = {tls}',    c, flags=re.MULTILINE)
with open(path, 'w') as f: f.write(c)
" $NewUrl

# Clear Credential Manager
cmdkey /delete:"AttackLens Agent"

# Restart services
Restart-Service AttackLensAgent -Force
Restart-Service AttackLensWatchdog -Force
```

---

## 9. Config generator (`generate_config.ps1`)

Write a complete `C:\ProgramData\AttackLens\agent.toml` with all 22 collection sections.

Environment variables (same as macOS `generate_config.sh`):
- `MANAGER_URL` — default `http://YOUR_MANAGER_IP:8080`
- `AGENT_ID` — default derived from `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid` as `win-<guid>`
- `AGENT_NAME` — default from `$env:COMPUTERNAME`
- `AGENT_TAGS` — comma-separated
- `ENROLL_TOKEN` — optional
- `RUN_AS_USER`, `RUN_AS_GROUP`, `RUN_AS_UID` — optional (for service account)

The TOML written must be **byte-for-byte compatible** with the macOS version's format — same section names, same keys, same ordering. The only differences are Windows-specific defaults for `[paths]` and `[binaries]`.

**Paths in Windows agent.toml:**
```toml
[paths]
install_dir  = "C:\\Program Files\\AttackLens"
config_dir   = "C:\\ProgramData\\AttackLens"
log_dir      = "C:\\ProgramData\\AttackLens\\logs"
data_dir     = "C:\\ProgramData\\AttackLens\\data"
security_dir = "C:\\ProgramData\\AttackLens\\security"
spool_dir    = "C:\\ProgramData\\AttackLens\\spool"
pid_file     = "C:\\ProgramData\\AttackLens\\attacklens-agent.pid"

[binaries]
agent    = "C:\\Program Files\\AttackLens\\bin\\run_agent.py"
watchdog = "C:\\Program Files\\AttackLens\\bin\\run_watchdog.py"

[logging]
level   = "INFO"
file    = "C:\\ProgramData\\AttackLens\\logs\\agent.log"
max_mb  = 10
backups = 5
```

All 22 collection sections are identical to the macOS version.

---

## 10. Python dependencies (Windows)

Install at MSI time via CustomAction. All must be available for the detected `python.exe`:

```
psutil>=5.9           # process/network/disk metrics
cryptography>=41      # AES-256-GCM
requests>=2.31        # HTTP transport
keyring>=24           # Windows Credential Manager
pywin32>=306          # win32service, win32security, win32cred
wmi>=1.5.1            # WMI queries (optional, psutil fallback available)
tomli>=2.0            # TOML parser (only needed for Python < 3.11)
```

---

## 11. Failure modes to handle

| Failure | Handling |
|---------|---------|
| Python not found | Pre-flight check in `build_msi.ps1`; MSI CustomAction fails cleanly with message |
| Python < 3.11 | Warning in installer; agent degrades gracefully using `tomli` backport |
| `pywin32` not installed | Service wrapper falls back to `subprocess`-based NSSM approach |
| `wmi` not installed | All WMI queries fall back to PowerShell `Get-WmiObject` |
| `keyring` not installed | Fall back to encrypted file backend in `security_dir` |
| Service already running on upgrade | `MajorUpgrade` WiX element stops old service via `CA_StopServices` before file replacement |
| Manager unreachable | Spool to `spool\` as NDJSON+gzip; drain on reconnect (identical to macOS) |
| Enrollment fails | `sys.exit(1)` with clear log message; service recovery restarts after 10 s |
| UAC prompt blocked | MSI requires elevation at install time; `requireAdministrator` in manifest |
| Antivirus blocks agent | Log warning; add exclusion path in MSI: `%ProgramFiles%\AttackLens` |
| Config file missing | Agent writes defaults to `agent.toml` on first run; logs warning |
| Windows Defender blocking PowerShell | Use `subprocess`/`winreg` fallbacks everywhere PowerShell is used |
| `AccessDenied` on `open_files()` | Catch silently; continue with other processes |
| Registry key doesn't exist | `_reg_get` returns `None`; collector field is `None` |
| `Get-BitLockerVolume` not available | Fall back to `manage-bde -status` parsing |
| `Confirm-SecureBootUEFI` not UEFI system | Returns `None` |

---

## 12. Compatibility matrix

| OS | Architecture | Python | Status |
|----|-------------|--------|--------|
| Windows 10 21H2+ | x64 | 3.11, 3.12, 3.13 | Must work |
| Windows 11 23H2+ | x64 | 3.11, 3.12, 3.13 | Must work |
| Windows Server 2019 | x64 | 3.11+ | Must work |
| Windows Server 2022 | x64 | 3.11+ | Must work |
| Windows 10 ARM64 | arm64 | 3.11+ | Best-effort |
| Older than Windows 10 | any | any | Not supported |

---

## 13. Security requirements

- MSI must be **Authenticode-signed** (or unsigned with a note to sign in production)
- Agent runs as `NT AUTHORITY\SYSTEM` by default — minimize privilege where possible
- `C:\ProgramData\AttackLens\security\` ACL: `SYSTEM:F`, `Administrators:F`, no other access
- `agent.toml` ACL: `SYSTEM:F`, `Administrators:R`, `Users:R` (readable for CLI status commands)
- All outbound HTTP/HTTPS to manager goes through Windows Firewall; add an explicit outbound allow rule during install
- Never write the API key to `agent.toml` — Credential Manager only
- `cmdkey /delete:"AttackLens Agent"` in `attacklens-service enroll` and `set-manager`

---

## 14. Testing checklist (include in QUICKSTART.md)

```powershell
# After install:
attacklens-service version          # confirms CLI works
attacklens-service status           # both services running, manager URL set
attacklens-service diagnose         # all green
attacklens-service logs             # shows agent collecting data

# Functional:
attacklens-service set-manager 34.224.174.38  # update manager
attacklens-service enroll                     # force re-enrollment
attacklens-service restart                    # restart services
attacklens-service config                     # print full agent.toml

# Silent install test:
msiexec /i attacklens-agent-2.0.0-x64.msi /qn `
  MANAGER_URL="http://34.224.174.38:8080" `
  AGENT_NAME="testwin1" `
  /l*v install.log
```

---

## 15. Deliverables

When complete, provide:

1. All files under `agent/os/windows/` (collectors, keystore, service wrapper, normalizer)
2. `agent/os/windows/installer/build_msi.ps1` — MSI build script
3. `agent/os/windows/installer/product.wxs` — WiX v4 product definition
4. `agent/os/windows/installer/attacklens-service.ps1` — service management CLI
5. `agent/os/windows/installer/attacklens-service.cmd` — CMD shim
6. `agent/os/windows/installer/generate_config.ps1` — config generator
7. `agent/os/windows/installer/QUICKSTART.md` — Windows quick start guide
8. `dist/attacklens-agent-2.0.0-x64.msi` — built MSI (or build instructions)
9. `agent/tests/unit/test_windows_normalizer.py` — normalizer unit tests
10. Updated `shared/sections.py` if any new Windows-only sections are needed (prefix with `windows_` if truly OS-specific; otherwise reuse existing section names)

---

*This prompt is self-contained. The referenced macOS code at `agent/os/macos/` is the authoritative reference for all shared interfaces — match it exactly.*
