# Windows Agent Installation Guide

The mac_intel agent installs as two Windows Services (`MacIntelAgent` +
`MacIntelWatchdog`), collecting 22 categories of endpoint telemetry.

---

## Requirements

| | Detail |
|-|--------|
| Windows | 10 / 11 / Server 2019 / Server 2022 |
| Architecture | x64 (AMD64) |
| Privileges | Administrator (Run as Administrator) |
| Network | HTTPS outbound to manager on port 8443 (or 443) |
| .NET | Not required (standalone EXE) |
| Disk | ~80 MB for binaries, ~200 MB spool buffer |

---

## Method A — Installer Script (Recommended)

### Step 1 — Copy Files

Copy these three files to a folder on the target machine:
```
jarvis-agent.exe
jarvis-watchdog.exe
install.ps1
```

### Step 2 — Open Admin PowerShell

Right-click **Windows PowerShell** → **Run as Administrator**

```powershell
# Navigate to the folder containing the files
cd C:\Users\YourUser\Downloads\agent
```

### Step 3 — Run Installer

```powershell
# Minimal — IP-only (self-signed cert)
.\install.ps1 `
    -ManagerUrl "https://54.213.44.12:8443" `
    -AgentName  "Bob Windows Laptop" `
    -TlsVerify  $false

# With domain (Let's Encrypt cert)
.\install.ps1 `
    -ManagerUrl "https://jarvis.company.com" `
    -AgentName  "Bob Windows Laptop" `
    -TlsVerify  $true

# With enrollment token (if manager requires it)
.\install.ps1 `
    -ManagerUrl  "https://54.213.44.12:8443" `
    -AgentName   "Bob Windows Laptop" `
    -EnrollToken "sk-enroll-xxxxxxxx" `
    -TlsVerify   $false
```

### What the installer does

1. Creates directory structure at `C:\Program Files (x86)\Jarvis\`
2. Copies binaries with restricted ACLs (SYSTEM + Admins only)
3. Generates `agent.toml` with auto-derived agent ID (MachineGuid)
4. Registers `MacIntelAgent` + `MacIntelWatchdog` Windows Services
5. Starts both services

### Step 4 — Verify

```powershell
# Check service status
Get-Service MacIntelAgent, MacIntelWatchdog

# Expected output:
# Status   Name              DisplayName
# ------   ----              -----------
# Running  MacIntelAgent     mac_intel Agent
# Running  MacIntelWatchdog  mac_intel Watchdog

# View live logs
Get-Content "C:\Program Files (x86)\Jarvis\logs\agent.log" -Wait -Tail 20
```

Once enrolled, the agent appears in the manager dashboard within 30 seconds.

---

## Method B — Build from Source

Build on a Windows machine with Python installed.

### Prerequisites

```powershell
# Install Python 3.11+ from python.org (add to PATH)
python --version   # should be 3.11+

# Install agent dependencies
cd macbook_data\agent
pip install -r requirements.txt
pip install pyinstaller pywin32
```

### Build EXEs

```powershell
cd agent\os\windows\pkg
.\build_exe.ps1 -Version "2.0.0" -Arch "x64"

# Output:
# dist\jarvis-agent.exe
# dist\jarvis-watchdog.exe
```

Then follow Method A from Step 1, using the files in `dist\`.

---

## Installation Layout

```
C:\Program Files (x86)\Jarvis\
├── bin\
│   ├── jarvis-agent.exe        ← main agent service binary
│   └── jarvis-watchdog.exe     ← watchdog service binary
├── config\
│   └── agent.toml              ← configuration file
├── logs\
│   └── agent.log               ← rotating log (10 MB × 3)
├── data\                       ← agent data store
├── spool\                      ← offline payload buffer
└── security\                   ← DPAPI-encrypted key reference
```

ACL policy:
- `security\` — SYSTEM only (DPAPI-encrypted key)
- `bin\*.exe` — SYSTEM + Admins read+execute (no write)
- `config\` — SYSTEM + Admins read (no write by others)

---

## Configuration Reference

`C:\Program Files (x86)\Jarvis\config\agent.toml`

```toml
# ── Agent identity ──────────────────────────────────────────────────────────
[agent]
# Human-readable name shown in the dashboard
name = "Bob Windows Laptop"

# Agent ID — auto-generated from Windows MachineGuid if omitted
# Format: win-<machineguid-lowercase>
# id = "win-a1b2c3d4-..."

# ── Manager connection ──────────────────────────────────────────────────────
[manager]
url             = "https://YOUR_MANAGER_IP:8443"
tls_verify      = false        # false for self-signed / true for Let's Encrypt
timeout_sec     = 30
retry_attempts  = 3
retry_delay_sec = 5
max_queue_size  = 500

# ── Enrollment ──────────────────────────────────────────────────────────────
[enrollment]
token    = ""          # leave blank if OPEN_ENROLLMENT=true on manager
keystore = "keychain"  # uses Windows Credential Manager (DPAPI)

# ── Watchdog ────────────────────────────────────────────────────────────────
[watchdog]
enabled            = true
check_interval_sec = 30
max_restarts       = 5
restart_window_sec = 300

# ── Paths ────────────────────────────────────────────────────────────────────
[paths]
install_dir  = "C:\\Program Files (x86)\\Jarvis\\bin"
config_dir   = "C:\\Program Files (x86)\\Jarvis\\config"
log_dir      = "C:\\Program Files (x86)\\Jarvis\\logs"
data_dir     = "C:\\Program Files (x86)\\Jarvis\\data"
security_dir = "C:\\Program Files (x86)\\Jarvis\\security"
spool_dir    = "C:\\Program Files (x86)\\Jarvis\\spool"

# ── Logging ─────────────────────────────────────────────────────────────────
[logging]
level   = "INFO"
file    = "C:\\Program Files (x86)\\Jarvis\\logs\\agent.log"
max_mb  = 10
backups = 3
```

---

## Service Management

```powershell
# --- Start services ---
Start-Service MacIntelAgent
Start-Service MacIntelWatchdog

# --- Stop services ---
Stop-Service MacIntelWatchdog -Force
Stop-Service MacIntelAgent    -Force

# --- Restart services ---
Restart-Service MacIntelAgent

# --- Status ---
Get-Service MacIntelAgent, MacIntelWatchdog | Select-Object Name, Status, StartType

# --- Live log tail ---
Get-Content "C:\Program Files (x86)\Jarvis\logs\agent.log" -Wait -Tail 30

# --- Windows Event Log (service start/stop events) ---
Get-EventLog -LogName System -Source "Service Control Manager" -Newest 10 |
    Where-Object {$_.Message -like "*MacIntel*"}
```

---

## Debug Mode (Foreground, No Service)

Useful for troubleshooting. Run in an Admin cmd/PowerShell:

```powershell
cd "C:\Program Files (x86)\Jarvis\bin"

# Stop service first
Stop-Service MacIntelAgent -Force

# Run in debug mode (outputs to console)
.\jarvis-agent.exe debug
```

Press `Ctrl+C` to stop. Check for enrollment + telemetry messages.

---

## Uninstall

```powershell
# Run as Administrator
.\uninstall.ps1
```

Or manually:
```powershell
# 1. Stop and remove services
Stop-Service MacIntelWatchdog -Force -ErrorAction SilentlyContinue
Stop-Service MacIntelAgent    -Force -ErrorAction SilentlyContinue
sc.exe delete MacIntelWatchdog
sc.exe delete MacIntelAgent

# 2. Remove files
Remove-Item "C:\Program Files (x86)\Jarvis" -Recurse -Force

# 3. Remove stored key from Windows Credential Manager
cmdkey /delete:macintel-agent

Write-Host "Agent uninstalled cleanly."
```

---

## Reinstall / Re-enroll

```powershell
# Uninstall first
.\uninstall.ps1

# Reinstall
.\install.ps1 -ManagerUrl "https://..." -AgentName "..." -TlsVerify $false
```

On reinstall the agent generates a new enrollment request and receives
a fresh HMAC key. No manual key management needed.

---

## Upgrade

```powershell
# Stop the agent service
Stop-Service MacIntelAgent -Force

# Replace binaries
Copy-Item .\jarvis-agent-new.exe "C:\Program Files (x86)\Jarvis\bin\jarvis-agent.exe" -Force

# Start the service
Start-Service MacIntelAgent

# Watchdog will restart the main service if it crashes during upgrade
```

---

## Windows Defender / Antivirus Exclusions

If AV is blocking the agent binary, add exclusions:

```powershell
# Add exclusions (run as Admin)
Add-MpPreference -ExclusionPath "C:\Program Files (x86)\Jarvis"
Add-MpPreference -ExclusionProcess "jarvis-agent.exe"
Add-MpPreference -ExclusionProcess "jarvis-watchdog.exe"
```

Or via Group Policy: `Computer Configuration → Administrative Templates →
Windows Defender → Exclusions → Path Exclusions`

---

## Troubleshooting

### Service fails to start

```powershell
# Check Windows Event Viewer
Get-EventLog -LogName Application -Newest 20 | Where-Object {$_.Source -like "*MacIntel*"}

# Or: Event Viewer → Windows Logs → Application → filter by "MacIntelAgent"

# Run in debug mode to see the actual error:
Stop-Service MacIntelAgent -Force
cd "C:\Program Files (x86)\Jarvis\bin"
.\jarvis-agent.exe debug
```

### Agent not appearing in dashboard

```powershell
# Check logs
Get-Content "C:\Program Files (x86)\Jarvis\logs\agent.log" -Tail 50

# Test connectivity to manager
Test-NetConnection -ComputerName YOUR_MANAGER_IP -Port 8443

# Common causes:
# 1. Firewall blocking outbound 8443
# 2. Wrong manager URL or tls_verify setting
# 3. Wrong enrollment token
```

### TOML parse error

All collection section keys must be on **separate lines**:
```toml
# WRONG (semicolons are invalid TOML):
[collection.sections.metrics]
enabled = true; interval_sec = 10; send = true

# CORRECT:
[collection.sections.metrics]
enabled      = true
interval_sec = 10
send         = true
```

### "Access Denied" writing to spool or logs

```powershell
# Fix ACLs on data directories
icacls "C:\Program Files (x86)\Jarvis" /grant "NT AUTHORITY\SYSTEM:(OI)(CI)(F)" /T
icacls "C:\Program Files (x86)\Jarvis\security" /inheritance:r /grant "NT AUTHORITY\SYSTEM:(OI)(CI)(F)"
```

### Check stored key

```powershell
# View stored credential (not the raw key, but presence of it)
cmdkey /list | Select-String "macintel"
```

### Re-enroll without full uninstall

```powershell
# Delete stored credential (forces re-enrollment on next start)
cmdkey /delete:macintel-agent

# Restart agent
Restart-Service MacIntelAgent
```

---

## Security Notes

- `MacIntelAgent` service runs as **NetworkService** by default
  - Can be changed to a dedicated LSAD account via `-ServiceAccount` param
- The HMAC key is stored in **Windows Credential Manager** (DPAPI-encrypted)
  - Bound to the machine — cannot be exported or used on another machine
- Raw key material is **never written to disk** in plaintext
- All traffic is **HTTPS + HMAC-SHA256 signed** (replay-protected with nonce)
- Binary ACLs: read+execute only for service account (no write = tamper-resistant)
- `security\` directory: SYSTEM-only ACL
