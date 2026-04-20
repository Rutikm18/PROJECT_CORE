<#
.SYNOPSIS
    Generate agent.toml from MSI-provided parameters.

.DESCRIPTION
    Called as a PowerShell Custom Action alternative. This script is also
    usable standalone (e.g., to regenerate config after manual changes).

    It writes a complete agent.toml to $DataDir\agent.toml with all
    22 collector sections pre-configured.

.PARAMETER InstallDir
    Root installation directory. Default: C:\Program Files (x86)\Jarvis
    All subdirs (bin, config, data, logs, security, spool) created here.

.PARAMETER DataDir
    Data/config root. Defaults to InstallDir (single-tree install).

.PARAMETER ManagerUrl
    Manager HTTPS endpoint. Required.

.PARAMETER EnrollToken
    Enrollment token (sk-enroll-...). Used for first-run key exchange.

.PARAMETER ManagerApiKey
    64-hex API key. Alternative to EnrollToken (skips enrollment).

.PARAMETER AgentId
    Unique agent identifier. Auto-generated UUID if omitted.

.PARAMETER AgentName
    Human-readable label. Defaults to computer name.

.PARAMETER TlsVerify
    true / false. Default: true.

.EXAMPLE
    # Called by MSI Custom Action (all params from MSI properties)
    .\generate_config.ps1 `
        -ManagerUrl  "https://manager.corp.example:8443" `
        -EnrollToken "sk-enroll-abc123def456" `
        -AgentName   "WORKSTATION-01"

.EXAMPLE
    # Regenerate config with a different manager URL
    .\generate_config.ps1 -ManagerUrl "https://new-manager:8443"
#>

param(
    [string] $InstallDir    = "C:\Program Files (x86)\Jarvis",
    [string] $DataDir       = "",
    [string] $ManagerUrl    = "https://localhost:8443",
    [string] $EnrollToken   = "",
    [string] $ManagerApiKey = "",
    [string] $AgentId       = "",
    [string] $AgentName     = "",
    [string] $TlsVerify     = "true"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Consolidate under $InstallDir when no separate DataDir given
if (-not $DataDir) { $DataDir = $InstallDir }

# ── Derived paths ─────────────────────────────────────────────────────────────
$BinDir      = Join-Path $InstallDir "bin"
$ConfigDir   = Join-Path $DataDir "config"
$LogDir      = Join-Path $DataDir "logs"
$SecurityDir = Join-Path $DataDir "security"
$SpoolDir    = Join-Path $DataDir "spool"
$SubDataDir  = Join-Path $DataDir "data"
$PidFile     = Join-Path $DataDir "jarvis-agent.pid"
$ConfigPath  = Join-Path $ConfigDir "agent.toml"
$AgentExe    = Join-Path $BinDir "jarvis-agent.exe"
$WatchdogExe = Join-Path $BinDir "jarvis-watchdog.exe"

# ── Resolve agent identity ────────────────────────────────────────────────────
# Auto-derive from Windows MachineGuid for stable identity across reinstalls
if (-not $AgentId) {
    try {
        $regKey  = "HKLM:\SOFTWARE\Microsoft\Cryptography"
        $MachineGuid = (Get-ItemProperty -Path $regKey -Name MachineGuid).MachineGuid
        $AgentId = "win-$($MachineGuid.ToLower())"
        Write-Verbose "Agent ID from MachineGuid: $AgentId"
    } catch {
        $AgentId = "win-$([System.Guid]::NewGuid().ToString())"
        Write-Verbose "Agent ID fallback (UUID): $AgentId"
    }
}

if (-not $AgentName) {
    $AgentName = $env:COMPUTERNAME
    Write-Verbose "Using computer name as agent name: $AgentName"
}

# ── Keystore: prefer DPAPI on Windows ────────────────────────────────────────
$Keystore = "dpapi"

# ── Path helper: forward-slash for TOML strings ──────────────────────────────
function ConvertTo-TomlPath([string]$p) {
    return $p.Replace("\", "/")
}

# ── Validation ────────────────────────────────────────────────────────────────
if (-not $ManagerUrl) {
    Write-Error "MANAGER_URL is required."
}

# Ensure data directories exist
foreach ($dir in @($BinDir, $ConfigDir, $LogDir, $SecurityDir, $SpoolDir, $SubDataDir)) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        Write-Verbose "Created: $dir"
    }
}

# ── Write agent.toml ──────────────────────────────────────────────────────────
$timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"

$lines = @(
    "# mac_intel Agent Configuration",
    "# Generated: $timestamp",
    "#",
    "# Only [manager] url is required.",
    "# Agent ID is auto-derived from Windows MachineGuid by the binary.",
    "# All collection schedules, paths, and logging use built-in defaults.",
    "# Restart the MacIntelAgent service to apply changes.",
    "",
    "[agent]",
    "name = `"$AgentName`"",
    "",
    "[manager]",
    "url        = `"$ManagerUrl`"",
    "tls_verify = $($TlsVerify.ToLower())"
)

# Write api_key only if a valid 64-hex key was provided (skips enrollment)
if ($ManagerApiKey -match '^[0-9a-fA-F]{64}$') {
    $lines += "api_key = `"$($ManagerApiKey.ToLower())`""
}

# Write enrollment token only if provided
if ($EnrollToken) {
    $lines += @(
        "",
        "[enrollment]",
        "token = `"$EnrollToken`""
    )
}

# ── Write file ────────────────────────────────────────────────────────────────
$content = $lines -join "`r`n"
[System.IO.File]::WriteAllText($ConfigPath, $content, [System.Text.Encoding]::UTF8)

Write-Host "  agent.toml written to: $ConfigPath" -ForegroundColor Green
Write-Host ""
Write-Host "  Agent ID:   $AgentId"
Write-Host "  Agent Name: $AgentName"
Write-Host "  Manager:    $ManagerUrl"
if ($EnrollToken) {
    Write-Host "  Enrollment: token provided (first-run enrollment will occur)"
} elseif ($ManagerApiKey -match '^[0-9a-fA-F]{64}$') {
    Write-Host "  Enrollment: api_key set directly (enrollment skipped)"
} else {
    Write-Warning "  Neither ENROLL_TOKEN nor MANAGER_API_KEY set — agent will fail to enroll!"
}
Write-Host ""
