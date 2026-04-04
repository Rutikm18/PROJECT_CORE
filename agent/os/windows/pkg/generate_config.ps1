<#
.SYNOPSIS
    Generate agent.toml from MSI-provided parameters.

.DESCRIPTION
    Called as a PowerShell Custom Action alternative. This script is also
    usable standalone (e.g., to regenerate config after manual changes).

    It writes a complete agent.toml to $DataDir\agent.toml with all
    22 collector sections pre-configured.

.PARAMETER InstallDir
    Root installation directory. Default: C:\Program Files\MacIntel

.PARAMETER DataDir
    ProgramData directory for config, logs, keys. Default: C:\ProgramData\MacIntel

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
    [string] $InstallDir    = "C:\Program Files\MacIntel",
    [string] $DataDir       = "C:\ProgramData\MacIntel",
    [string] $ManagerUrl    = "https://localhost:8443",
    [string] $EnrollToken   = "",
    [string] $ManagerApiKey = "",
    [string] $AgentId       = "",
    [string] $AgentName     = "",
    [string] $TlsVerify     = "true"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── Derived paths ─────────────────────────────────────────────────────────────
$LogDir      = Join-Path $DataDir "logs"
$SecurityDir = Join-Path $DataDir "security"
$SubDataDir  = Join-Path $DataDir "data"
$PidFile     = Join-Path $DataDir "agent.pid"
$ConfigPath  = Join-Path $DataDir "agent.toml"
$AgentExe    = Join-Path $InstallDir "bin\macintel-agent.exe"
$WatchdogExe = Join-Path $InstallDir "bin\macintel-watchdog.exe"

# ── Resolve agent identity ────────────────────────────────────────────────────
if (-not $AgentId) {
    $AgentId = [System.Guid]::NewGuid().ToString()
    Write-Verbose "Generated agent ID: $AgentId"
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
foreach ($dir in @($DataDir, $LogDir, $SecurityDir, $SubDataDir)) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        Write-Verbose "Created: $dir"
    }
}

# ── Write agent.toml ──────────────────────────────────────────────────────────
$timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"

$lines = @(
    "# agent.toml — mac_intel Agent Configuration",
    "# Generated: $timestamp",
    "# Edit this file to change agent behaviour; restart the MacIntelAgent service to apply.",
    "",
    "[agent]",
    "id   = `"$AgentId`"",
    "name = `"$AgentName`"",
    "",
    "[manager]",
    "url            = `"$ManagerUrl`"",
    "tls_verify     = $($TlsVerify.ToLower())",
    "timeout_sec    = 30",
    "max_queue_size = 500"
)

# Write api_key only if a valid 64-hex key was provided (skips enrollment)
if ($ManagerApiKey -match '^[0-9a-fA-F]{64}$') {
    $lines += "api_key = `"$($ManagerApiKey.ToLower())`""
}

$lines += @(
    "",
    "[enrollment]",
    "token    = `"$EnrollToken`"",
    "keystore = `"$Keystore`"",
    "",
    "[watchdog]",
    "enabled             = true",
    "check_interval_sec  = 30",
    "max_restarts        = 5",
    "restart_window_sec  = 300",
    "",
    "[paths]",
    "install_dir  = `"$(ConvertTo-TomlPath $InstallDir)`"",
    "config_dir   = `"$(ConvertTo-TomlPath $DataDir)`"",
    "log_dir      = `"$(ConvertTo-TomlPath $LogDir)`"",
    "data_dir     = `"$(ConvertTo-TomlPath $SubDataDir)`"",
    "security_dir = `"$(ConvertTo-TomlPath $SecurityDir)`"",
    "pid_file     = `"$(ConvertTo-TomlPath $PidFile)`"",
    "",
    "[binaries]",
    "agent    = `"$(ConvertTo-TomlPath $AgentExe)`"",
    "watchdog = `"$(ConvertTo-TomlPath $WatchdogExe)`"",
    "",
    "[logging]",
    "level   = `"INFO`"",
    "file    = `"$(ConvertTo-TomlPath (Join-Path $LogDir 'agent.log'))`"",
    "max_mb  = 10",
    "backups = 3",
    "",
    "[collection]",
    "tick_sec = 5",
    ""
)

# ── Collection sections ───────────────────────────────────────────────────────
# Format: name, interval_seconds
$sections = @(
    @{ name = "metrics";     interval = 60    },
    @{ name = "connections"; interval = 60    },
    @{ name = "processes";   interval = 60    },
    @{ name = "ports";       interval = 60    },
    @{ name = "network";     interval = 300   },
    @{ name = "arp";         interval = 300   },
    @{ name = "mounts";      interval = 300   },
    @{ name = "battery";     interval = 300   },
    @{ name = "open_files";  interval = 120   },
    @{ name = "services";    interval = 300   },
    @{ name = "users";       interval = 600   },
    @{ name = "hardware";    interval = 3600  },
    @{ name = "containers";  interval = 120   },
    @{ name = "security";    interval = 600   },
    @{ name = "sysctl";      interval = 3600  },
    @{ name = "configs";     interval = 3600  },
    @{ name = "storage";     interval = 300   },
    @{ name = "tasks";       interval = 3600  },
    @{ name = "apps";        interval = 3600  },
    @{ name = "packages";    interval = 3600  },
    @{ name = "binaries";    interval = 86400 },
    @{ name = "sbom";        interval = 86400 }
)

foreach ($s in $sections) {
    $lines += @(
        "[collection.sections.$($s.name)]",
        "enabled      = true",
        "interval_sec = $($s.interval)",
        "send         = true",
        ""
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
