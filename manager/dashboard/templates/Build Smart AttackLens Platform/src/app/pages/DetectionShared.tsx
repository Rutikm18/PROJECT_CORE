/**
 * DetectionShared — Animated enterprise detection UI.
 *
 * Animations: sonar-ping · heartbeat · slide-panel · stagger-rows
 *             bar-fill · bounce-in KPIs · scan-line · ECG waveform
 * Theme: orange/amber gradient · white cards · rounded-2xl
 */
import { useState, useEffect, useCallback, useRef, useMemo } from "react";
import { createPortal } from "react-dom";
import {
  RefreshCw, X, Search, Filter, AlertTriangle, Shield,
  Zap, Target, BookOpen, Activity, CheckCircle2, XCircle,
  ExternalLink, Copy, Info, Eye, Crosshair, Database,
  GitBranch, Brain, TrendingUp, FileCode, Network,
  Radio, ChevronRight, ChevronDown,
  Plus, Trash2, SlidersHorizontal,
} from "lucide-react";
import { cn } from "../../lib/utils";

// ── Types ─────────────────────────────────────────────────────────────────────

export interface DetectionFinding {
  id:                number;
  external_id?:      string;
  finding_uid?:      string;      // UUIDv4 — globally unique, non-sequential reference
  terrain_id?:       string;      // citadels|vector|origin|identity|posture
  agent_id:          string;
  category:          string;
  severity:          "critical" | "high" | "medium" | "low" | "info";
  score:             number;
  composite_score?:  number;
  title:             string;
  description:       string;
  evidence:          Record<string, unknown> | string;
  source:            string;
  rule_id?:          string;
  cve_ids?:          string[] | string;
  cvss_score?:       number | null;
  cvss_vector?:      string;
  epss_score?:       number | null;
  kev:               boolean;
  exploit_available: boolean;
  exploit_sources?:  string[] | string;
  mitre_technique?:  string;
  mitre_tactic?:     string;
  first_detected_at: number;
  last_detected_at:  number;
  scan_count:        number;
  status:            string;
  // Canonical attack-terrain bucket (server-assigned via terrain_validators) —
  // single source of truth so the same finding lands in the same terrain in
  // All Incidents and the Attack Terrain sub-views.
  terrain?:          string;   // origin | vector | citadels | identity | posture
  // ── Triage lifecycle (server-driven, finding_lifecycle.py) ────────────────
  is_terminal?:      boolean;
  available_actions?: FindingAction[];
  sla_due?:          number;
  sla_status?:       string;
  priority_reason?:  string;
  action_plan?:      unknown[] | string;
  tags?:             string[] | string;
  confidence_pct?:   number;
  impact?:           string;
  cat_meta?:         { label: string; icon: string; group: string };
  // AI Precision Validation (populated when ATTACKLENS_AI_VALIDATION=true)
  precision_score?:       number;        // 0..1 — composite precision
  precision_factors?:     Record<string, number>;
  ai_verdict?:            {
    label?:        "tp" | "fp" | "uncertain";
    confidence?:   number;                // 0..1
    reasoning?:    string;
    key_evidence?: string[];
    risk_factors?: string[];
    tokens_used?:  number;
  } | string;
  ai_validation_used?:    number | boolean;
  confidence?:            number;        // base cluster confidence (0..1)
  signal_cluster_id?:     number | null;
  layers_involved?:       string[] | string;
  validation_gates_passed?: string[] | string;
  host_class?:            string;
  // Terrain-aware validation — per-criterion checklist (kev/ai/exploit/...)
  terrain_validation?: {
    terrain?:     string;
    score?:       number;
    percentage?:  number;
    summary?:     string;
    met_count?:   number;
    total_count?: number;
    criteria?: Array<{
      name:         string;
      label:        string;
      description?: string;
      weight?:      number;
      met?:         number;
      status?:      "met" | "partial" | "not_met" | "n/a";
      contribution?: number;
    }>;
  } | string;
  // Terrain source provenance — why this finding landed in its terrain
  terrain_source?:        string;
  // Validated status — true when precision_score >= resolved threshold
  is_validated?:          boolean;
  effective_threshold?:   number;
  // Agent context (joined from asset_registry on read)
  agent_os?:              string;
  agent_hostname?:        string;
  agent_os_version?:      string;
}

// ── Detection Blueprint (per-category) ───────────────────────────────────────

interface BlueprintSpec {
  telemetry:         string[];
  detection_logic:   string;
  validation:        string[];
  evidence_required: string[];
  fp_reduction:      string;
  attack_chain:      string;
  ai_analytics:      string[];
  threat_intel:      string[];
  hunting_queries:   string[];
  confidence_factors:string[];
  exposure_note:     string;
  sigma_idea:        string;
}

const BLUEPRINT: Record<string, BlueprintSpec> = {
  execution: {
    telemetry: ["processes","binaries","openfiles","connections"],
    detection_logic: "Correlate process ancestry (parent→child), command-line args, binary entropy, file-backed execution, and network callbacks. Flag: interpreter spawning scripting engines (shell→python→curl), LOLBin abuse (osascript, diskutil, launchctl), memory-only execution, process with high-entropy binary from temp path.",
    validation: ["Parent PID + command-line arguments","Binary path + SHA256 + creation time","Is binary signed? codesign -dv","Binary in expected path vs /tmp?","Network connections within 5s of launch","CPU/memory vs 90-day baseline","User account + UID + session type","Process ancestry depth ≥ 4 levels"],
    evidence_required: ["Full process ancestry chain","Command-line with all args (untruncated)","Binary SHA256 at execution time","Open file handles","Network socket state","stdin/stdout file descriptors"],
    fp_reduction: "Compare against known-good process baseline. Whitelist signed Apple + vendor binaries. Suppress if spawned by known MDM tool (Jamf, Mosyle). Require ≥2 of: unsigned binary, temp path, network callback, high entropy.",
    attack_chain: "Execution (TA0002) → commonly follows T1566 Phishing or T1189 Drive-By. Precedes T1543 Persistence, T1548 Privilege Escalation, or T1071 C2 establishment.",
    ai_analytics: ["Process ancestry graph anomaly (GNN model)","Command-line token frequency — rare token = high score","Temporal clustering: burst at unusual hours","UEBA: user never launched this binary before","Kill-chain stage prediction via sequence model"],
    threat_intel: ["VirusTotal (hash lookup)","MalwareBazaar","MITRE ATT&CK T1059","SigmaHQ process_creation rules","YARA community rules"],
    hunting_queries: ["processes WHERE parent='bash' AND name IN ('curl','python3','ruby') AND connections > 0","processes WHERE path LIKE '/tmp/%' AND signed=false","processes WHERE entropy > 7.2 AND size < 512000","processes WHERE cmd LIKE '%base64%' OR cmd LIKE '%python -c%'","processes WHERE parent='launchd' AND name NOT IN (baseline)"],
    confidence_factors: ["+30 unsigned binary from temp path","+25 network callback within 10s","+20 entropy > 7.0","+15 parent is browser or mail","-20 binary on >1000 clean endpoints","-15 process in MDM application list"],
    exposure_note: "Internet-exposed hosts face active scanning within minutes. Cross-correlate with open ports and listening services to assess reachability.",
    sigma_idea: "title: Suspicious Process Spawned From Browser\nlogsource:\n  category: process_creation\ndetection:\n  selection:\n    ParentImage|endswith:\n      - '/Google Chrome'\n      - '/Safari'\n    Image|endswith:\n      - '/bash'\n      - '/python3'\n      - '/curl'\n  condition: selection\nlevel: high",
  },
  network: {
    telemetry: ["connections","ports","network","arp","dns"],
    detection_logic: "Match active connections against threat intel feeds (AbuseIPDB, ThreatFox, GreyNoise). Flag: beaconing (regular intervals), newly-registered domains (<30d WHOIS), DNS tunneling/DoH, large transfers to geo-suspicious destinations, ARP cache poisoning.",
    validation: ["Destination IP + domain + ASN + country","Protocol + port","Connection age + bytes ratio","JA3/JA3S TLS fingerprint","DNS query for dest domain in last 60s?","Threat feed match (which feed, recency)","WHOIS domain age < 30 days?","GreyNoise classification","Beacon interval stddev analysis"],
    evidence_required: ["Full 5-tuple: src_ip:port → dst_ip:port + proto","DNS resolution chain","TLS certificate CN + issuer + validity","Process owning the socket","Bytes sent and received per session","Connection start time + duration"],
    fp_reduction: "Whitelist CDN ranges (Cloudflare, Fastly, Akamai). Exclude Apple update servers. Require ≥2 independent feed matches OR CISA KEV-linked IOC. Suppress connections from signed system processes.",
    attack_chain: "C2 (TA0011): T1071 Application Layer Protocol, T1095 Non-Application Layer. Exfiltration (TA0010) T1048. ARP poisoning → T1557 Man-in-the-Middle.",
    ai_analytics: ["Beacon detection: FFT analysis of inter-connection intervals","DGA detection via n-gram entropy model","Destination clustering: >5 threat-feed hosts = C2 pool","Data volume anomaly: >3σ from 30-day baseline","Graph analysis: lateral movement path detection"],
    threat_intel: ["AbuseIPDB (confidence score)","ThreatFox (malware family + C2 IOC)","GreyNoise (scanner/malicious)","Feodo Tracker (botnet C2)","OTX AlienVault pulses","Spamhaus DROP/EDROP"],
    hunting_queries: ["connections WHERE feed_match=true AND country NOT IN ['US','GB','DE'] AND bytes_out > 1MB","connections WHERE beacon_score > 0.85 AND interval_stddev < 5s","connections WHERE domain_age_days < 30 AND process='bash'","connections WHERE ja3 IN (malicious_ja3_list)","arp WHERE mac_changes > 3 IN 10min FOR same_ip"],
    confidence_factors: ["+40 dest IP in ≥2 threat feeds","+30 beacon score > 0.9","+25 domain registered < 7 days","+20 JA3 matches known C2 framework","-25 destination is CDN range","-20 owning process is signed Apple binary"],
    exposure_note: "Hosts with any port listening on 0.0.0.0 are internet-accessible. Cross-correlate with Shodan/Censys external exposure to quantify real attack surface.",
    sigma_idea: "title: Connection to Recently Registered Domain\nlogsource:\n  category: network_connection\ndetection:\n  selection:\n    dst_domain_age_days|lt: 30\n    protocol: HTTPS\n  filter:\n    Image|startswith:\n      - '/System/'\n      - '/Applications/Safari'\n  condition: selection and not filter\nlevel: high",
  },
  vulnerability: {
    telemetry: ["packages","sbom","apps","binaries","ports"],
    detection_logic: "Match installed packages (name + version) against NVD/CVE.org. Prioritize: CISA KEV (actively exploited), EPSS > 50%, CVSS ≥ 9.0, package reachable from network (running service + listening port), public exploit on ExploitDB/GitHub. SBOM dependency tree for transitive vulns.",
    validation: ["Exact package name (not fuzzy)","Installed vs fixed version","CVE ID + NVD confirmed (not advisory-only)","CVSS v3.1 base score + vector","EPSS score (percentile + probability)","KEV status + CISA due date","Is package running as active process?","Is port open (network-reachable)?","Public exploit confirmed?","SBOM transitive dependency depth"],
    evidence_required: ["Package name + installed + fixed version","Installation source (Homebrew, pip, npm)","Process name if running","Network port if service","CVE list with CVSS + EPSS","Package last updated timestamp"],
    fp_reduction: "Require NVD-published CVE (not advisory-only). Exclude CVEs marked DISPUTED or REJECTED. Suppress if version is in vendor-patched range. Reduce score if package not network-reachable.",
    attack_chain: "Initial Access (TA0001) via T1190 Exploit Public-Facing Application. T1203 Client Execution, T1068 Exploitation for Privilege Escalation. SBOM transitive vulns enable T1195.001 Supply Chain.",
    ai_analytics: ["EPSS trend prediction: exploitation probability growth","Reachability analysis: is vulnerable code path callable?","Patch velocity: how fast does this ecosystem release fixes?","Exposure correlation: CVE + open port + internet = critical","Threat actor profiling: does any APT actively exploit this CVE?"],
    threat_intel: ["NVD (nvd.nist.gov)","CISA KEV catalog","EPSS (api.first.org)","ExploitDB","Metasploit modules","VulnCheck KEV","OSV (open source vulnerabilities)"],
    hunting_queries: ["packages WHERE kev=true AND running=true","packages WHERE epss > 0.5 AND port != null","packages WHERE cvss >= 9.0 AND days_since_fix > 30","sbom WHERE transitive_cve > 5 AND internet_exposed=true","packages WHERE manager='pip' AND name IN (typosquat_list)"],
    confidence_factors: ["+50 KEV listed","+30 EPSS > 70%","+25 public exploit confirmed","+20 process running AND port open","-20 CVE not NVD-confirmed","-15 package not currently running"],
    exposure_note: "Combine CVE data with internet exposure: if Shodan indexes this host's port with this package version, it is actively exploitable by any attacker with internet access.",
    sigma_idea: "title: KEV Vulnerability Running as Active Service\nlogsource:\n  category: package_vulnerability\ndetection:\n  selection:\n    kev: true\n    process_running: true\n    epss_score|gt: 0.1\n  condition: selection\nlevel: critical",
  },
  persistence: {
    telemetry: ["services","tasks","configs","binaries","openfiles","sysctl"],
    detection_logic: "Monitor LaunchAgents/LaunchDaemons plist creation/modification, scheduled tasks (cron/launchd timer), shell config injection (.zshrc, .bashrc), SUID/SGID binary changes, world-writable PATH directories, kernel extension loading. Flag any mechanism pointing to a binary not in a standard install location.",
    validation: ["Persistence type: launchd/cron/shell-config/suid/kext","Binary path referenced","Binary SHA256 + signed status + creation timestamp","User context creating it (UID, username)","Was creator interactive or scripted?","Does entry encode commands (base64)?","Is binary in world-writable path?","RunAtLoad or StartInterval value"],
    evidence_required: ["Full plist content or cron entry text","Binary SHA256 at referenced path","File creation/modification timestamp","Parent process that created the file","codesign result for binary","File path vs expected install paths"],
    fp_reduction: "Whitelist LaunchAgents installed by signed packages. Suppress Apple-signed binaries. Require: unsigned binary OR non-standard path OR recently created (<7d). MDM-managed LaunchDaemons should be baselined.",
    attack_chain: "Persistence (TA0003): T1543.001 Launch Agent, T1543.004 Launch Daemon, T1053.003 Cron, T1546.004 Unix Shell Config. Often follows initial execution and precedes C2.",
    ai_analytics: ["LaunchAgent anomaly: new plist not in MDM baseline","Shell config change rate > 1/hr = suspicious","Binary path clustering: /tmp = high confidence","Temporal correlation: persistence within 60s of malicious exec","Baseline deviation: service not seen in last 30 agent scans"],
    threat_intel: ["MITRE ATT&CK T1543 Create/Modify System Process","MITRE ATT&CK T1053 Scheduled Task/Job","SigmaHQ persistence rules","Objective-See macOS persistence database"],
    hunting_queries: ["services WHERE path LIKE '/tmp/%' OR path LIKE '/var/folders/%'","tasks WHERE cmd LIKE '%base64%' OR cmd LIKE '%curl%|%sh%'","configs WHERE path IN ('.zshrc','.bashrc') AND content LIKE '%curl%sh%'","binaries WHERE suid=true AND path NOT IN (suid_baseline)","services WHERE created_last_24h=true AND signed=false"],
    confidence_factors: ["+35 binary path in /tmp or /var/folders","+30 binary unsigned","+25 persistence created within 5min of suspicious process","+20 command contains download-cradle patterns","-20 created by known package manager","-15 Apple-signed binary"],
    exposure_note: "Persistence mechanisms survive reboots. The longer undetected, the greater the dwell time. Cross-correlate with agent_health gaps — attackers disable telemetry immediately after establishing persistence.",
    sigma_idea: "title: LaunchDaemon Created Outside Package Installer\nlogsource:\n  category: file_event\ndetection:\n  selection:\n    TargetFilename|startswith: '/Library/LaunchDaemons/'\n    TargetFilename|endswith: '.plist'\n  filter:\n    ParentImage|contains:\n      - 'Installer'\n      - 'jamf'\n      - 'munki'\n  condition: selection and not filter\nlevel: high",
  },
  identity: {
    telemetry: ["users","security","configs","processes","connections"],
    detection_logic: "Detect: new UID=0 accounts outside MDM workflow, admin group membership changes after hours, sudo NOPASSWD grants, SSH authorized_keys modification, auth failures exceeding threshold, service account interactive login, login from unexpected geo/device.",
    validation: ["Account name + UID + GID + group membership","Account creation method (dscl, useradd, /etc/passwd)","Login source: terminal, SSH, console, su/sudo","Login time vs user's baseline schedule","MFA enforced? Auth method used","Last password change timestamp","sudoers entry content + creator","Failed auth count + time window"],
    evidence_required: ["Account dump at detection time","sudoers content","Auth log entries around the event","Login source IP if remote","PAM authentication trace","Group membership before and after"],
    fp_reduction: "Suppress accounts created by MDM/identity tools. Whitelist IT admin accounts for after-hours access. Require UID=0 NOT in MDM baseline. For brute force: >20 failures from same source in <5 minutes.",
    attack_chain: "Persistence (T1136 Create Account), Privilege Escalation (T1548 Abuse Elevation), Credential Access (T1110 Brute Force, T1552 Unsecured Credentials), Lateral Movement (T1021 Remote Services).",
    ai_analytics: ["UEBA: login time deviation from 90-day baseline","Impossible travel: 2 geo-locations within 1 hour","Peer group analysis: behavior vs role peers","Privilege escalation graph: who has sudo on how many hosts?","N+1 consecutive failures then success = credential theft"],
    threat_intel: ["HaveIBeenPwned (breach lookup)","MITRE ATT&CK TA0006 Credential Access","CISA advisories on credential-based intrusions"],
    hunting_queries: ["users WHERE uid=0 AND name NOT IN ('root') AND created_last_7d=true","users WHERE shell IN ('/bin/bash','/bin/zsh') AND account_type='service'","configs WHERE path='/etc/sudoers' AND content LIKE '%NOPASSWD%' AND modified_last_24h=true","processes WHERE name='su' AND user IN (service_accounts)","auth_logs WHERE failures > 20 AND window_secs < 300"],
    confidence_factors: ["+40 UID=0 account not in MDM baseline","+35 sudo NOPASSWD for non-admin user","+30 login from known-bad IP or Tor exit node","+25 service account interactive login","-25 account created by enrolled MDM tool","-20 within documented change window"],
    exposure_note: "One compromised UID=0 account = full system compromise. Cross-correlate with all hosts where this account has SSH keys or sudo access to determine lateral blast radius.",
    sigma_idea: "title: UID 0 Account Created Outside Installer\nlogsource:\n  category: user_management\ndetection:\n  selection:\n    action: user_created\n    uid: 0\n  filter:\n    parent_process|contains:\n      - 'Installer'\n      - 'jamf'\n  condition: selection and not filter\nlevel: critical",
  },
  evasion: {
    telemetry: ["security","sysctl","processes","agent_health","configs"],
    detection_logic: "Flag: security control disabled (SIP, FileVault, Gatekeeper, firewall, audit daemon), EDR/AV process killed or binary removed, sysctl security parameters changed (kexts allowed, codesign bypass), agent heartbeat gap > 5min, log file truncation or /var/log clearing.",
    validation: ["Security control state: current vs last known good","Process responsible for state change","sysctl key + old value + new value","Agent heartbeat gap duration","Security binary integrity (hash changed?)","Audit log continuity check"],
    evidence_required: ["Security control snapshot (SIP/FV/GK/FW)","Process list at time of change","sysctl -a output delta from baseline","Agent heartbeat log with gaps","Log file sizes over time (truncation evidence)"],
    fp_reduction: "Cross-reference with authorized maintenance windows. Suppress if MDM push is concurrent. Require: security control change AND process anomaly in same 60s window.",
    attack_chain: "Defense Evasion (TA0005): T1562.001 Disable Tools, T1562.004 Disable Firewall, T1070.003 Clear Command History, T1112 Modify Registry/sysctl.",
    ai_analytics: ["Telemetry gap anomaly: sudden silence after noisy baseline","Security state change frequency: >once/week = suspicious","Correlation: security disabled + new process + new connection = kill chain"],
    threat_intel: ["MITRE ATT&CK T1562 Impair Defenses","Objective-See reports on macOS malware disabling SIP","CIS Benchmark change detection rules"],
    hunting_queries: ["security WHERE sip_status='disabled' AND changed_last_24h=true","agent_health WHERE heartbeat_gap > 300s","processes WHERE name IN ('launchctl','csrutil','spctl') AND parent!='loginwindow'"],
    confidence_factors: ["+50 SIP disabled outside Recovery Mode","+40 EDR process killed","+30 agent heartbeat gap > 10min","-20 change during documented maintenance window"],
    exposure_note: "Security control disablement dramatically increases risk across ALL other categories. Treat as incident-level regardless of other context.",
    sigma_idea: "title: Security Tool Process Terminated\nlogsource:\n  category: process_termination\ndetection:\n  selection:\n    Image|endswith:\n      - '/osquery'\n      - '/crowdstrike-sensor'\n  condition: selection\nlevel: critical",
  },
};

function getBlueprintKey(category: string, source: string, tactic?: string): string {
  const c = (category ?? "").toLowerCase();
  const t = (tactic ?? "").toLowerCase();
  if (c.includes("process") || c.includes("exec") || c.includes("malware") || c.includes("script")) return "execution";
  if (c.includes("network") || c.includes("connection") || c.includes("c2") || source?.startsWith("feed:")) return "network";
  if (c.includes("package") || c.includes("vuln") || c.includes("cve") || c.includes("sbom")) return "vulnerability";
  if (c.includes("persist") || c.includes("service") || c.includes("task") || c.includes("config") || c.includes("backdoor")) return "persistence";
  if (c.includes("user") || c.includes("identity") || c.includes("account") || c.includes("cred") || t.includes("credential")) return "identity";
  if (c.includes("evasion") || c.includes("tamper") || c.includes("defense") || c.includes("security")) return "evasion";
  return "execution";
}

// ── Helpers ───────────────────────────────────────────────────────────────────

export function fmtTs(ts: number | null | undefined): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleDateString("en-US", { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}
export function _parseJson(v: unknown, def: unknown): unknown {
  if (Array.isArray(v) || (v && typeof v === "object")) return v;
  if (typeof v === "string" && (v.startsWith("[") || v.startsWith("{"))) { try { return JSON.parse(v); } catch {} }
  return def;
}
function relTime(ts: number): string {
  const s = Math.floor(Date.now() / 1000 - ts);
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

// ── Animated counter hook ─────────────────────────────────────────────────────

function useCountUp(target: number, duration = 700): number {
  const [val, setVal] = useState(0);
  const prev = useRef(0);
  useEffect(() => {
    if (target === prev.current) return;
    const start = prev.current;
    const diff  = target - start;
    const steps = 24;
    let  i      = 0;
    const t = setInterval(() => {
      i++;
      const eased = 1 - Math.pow(1 - i / steps, 3);
      setVal(Math.round(start + diff * eased));
      if (i >= steps) { clearInterval(t); prev.current = target; }
    }, duration / steps);
    return () => clearInterval(t);
  }, [target, duration]);
  return val;
}

// ── Design tokens ─────────────────────────────────────────────────────────────

const SEV: Record<string, {
  badge: string; dot: string; ring: string; glow: string;
  rowBase: string; rowHover: string; bar: string; kpi: string;
}> = {
  critical: {
    badge:    "bg-red-50 text-red-700 border-red-300",
    dot:      "bg-red-500 text-red-500",
    ring:     "ring-red-400/40",
    glow:     "al-glow-critical",
    rowBase:  "row-critical",
    rowHover: "row-critical-hover",
    bar:      "bg-gradient-to-r from-red-500 to-red-600",
    kpi:      "bg-red-50 border-red-200 text-red-700",
  },
  high: {
    badge:    "bg-amber-50 text-amber-700 border-amber-300",
    dot:      "bg-amber-500 text-amber-500",
    ring:     "ring-amber-400/30",
    glow:     "",
    rowBase:  "row-high",
    rowHover: "row-high-hover",
    bar:      "bg-gradient-to-r from-amber-400 to-amber-500",
    kpi:      "bg-amber-50 border-amber-200 text-amber-700",
  },
  medium: {
    badge:    "bg-blue-50 text-blue-700 border-blue-300",
    dot:      "bg-blue-500 text-blue-500",
    ring:     "ring-blue-400/30",
    glow:     "",
    rowBase:  "row-medium",
    rowHover: "row-medium-hover",
    bar:      "bg-gradient-to-r from-blue-400 to-blue-500",
    kpi:      "bg-blue-50 border-blue-200 text-blue-700",
  },
  low: {
    badge:    "bg-green-50 text-green-700 border-green-300",
    dot:      "bg-green-500 text-green-500",
    ring:     "ring-green-400/30",
    glow:     "",
    rowBase:  "row-low",
    rowHover: "row-low-hover",
    bar:      "bg-gradient-to-r from-green-400 to-green-500",
    kpi:      "bg-green-50 border-green-200 text-green-700",
  },
  info: {
    badge:    "bg-gray-100 text-gray-500 border-gray-200",
    dot:      "bg-gray-300 text-gray-300",
    ring:     "",
    glow:     "",
    rowBase:  "row-info",
    rowHover: "",
    bar:      "bg-gray-300",
    kpi:      "bg-gray-50 border-gray-200 text-gray-500",
  },
};

// ── Exported atoms ────────────────────────────────────────────────────────────

export function SevBadge({ sev }: { sev: string }) {
  const s = SEV[sev] ?? SEV.info;
  return (
    <span className={cn("px-2 py-0.5 text-[9px] font-bold rounded-full border uppercase tracking-wide whitespace-nowrap", s.badge)}>
      {sev}
    </span>
  );
}

export function SlaBadge({ status }: { status: string }) {
  const c: Record<string, string> = {
    breached: "bg-red-50 text-red-700 border-red-200",
    warning:  "bg-amber-50 text-amber-700 border-amber-200",
    ok:       "bg-green-50 text-green-700 border-green-200",
    closed:   "bg-gray-100 text-gray-500 border-gray-200",
  };
  return <span className={cn("px-1.5 py-0.5 text-[9px] font-bold rounded-full border uppercase", c[status] ?? c.ok)}>SLA {status}</span>;
}

// ── Triage lifecycle: status chip + action buttons ─────────────────────────────

export interface FindingAction {
  action:        string;   // open | investigate | close | accept_risk | false_positive | reopen
  label:         string;
  kind:          string;   // primary | resolve | dismiss
  needs_reason:  boolean;
  target_status: string;
}

const _STATUS_CHIP: Record<string, string> = {
  new:            "bg-blue-50 text-blue-700 border-blue-200",
  triaging:       "bg-indigo-50 text-indigo-700 border-indigo-200",
  investigating:  "bg-violet-50 text-violet-700 border-violet-200",
  in_remediation: "bg-amber-50 text-amber-700 border-amber-200",
  remediated:     "bg-teal-50 text-teal-700 border-teal-200",
  verified:       "bg-emerald-50 text-emerald-700 border-emerald-200",
  closed:         "bg-gray-100 text-gray-600 border-gray-200",
  false_positive: "bg-slate-100 text-slate-500 border-slate-200",
  accepted_risk:  "bg-orange-50 text-orange-600 border-orange-200",
  duplicate:      "bg-gray-100 text-gray-500 border-gray-200",
};

export function StatusChip({ status }: { status: string }) {
  const cls = _STATUS_CHIP[status] ?? _STATUS_CHIP.new;
  return (
    <span className={cn("px-2 py-0.5 text-[9px] font-bold rounded-full border uppercase tracking-wide whitespace-nowrap", cls)}>
      {(status ?? "new").replace(/_/g, " ")}
    </span>
  );
}

// Canonical attack-terrain → label + colour. Keyed on the SERVER-assigned
// `terrain` field (origin/vector/citadels/identity/posture), never on a
// client-side category guess — so a finding shows the same terrain in All
// Incidents and the Attack Terrain sub-views.
const _TERRAIN_CHIP: Record<string, { label: string; cls: string }> = {
  origin:   { label: "Origin",   cls: "bg-amber-50 text-amber-700 border-amber-200" },
  vector:   { label: "Vector",   cls: "bg-blue-50 text-blue-700 border-blue-200" },
  citadels: { label: "Citadels", cls: "bg-red-50 text-red-700 border-red-200" },
  identity: { label: "Identity", cls: "bg-purple-50 text-purple-700 border-purple-200" },
  posture:  { label: "Posture",  cls: "bg-teal-50 text-teal-700 border-teal-200" },
};

export function TerrainChip({ terrain }: { terrain?: string }) {
  const t = _TERRAIN_CHIP[(terrain ?? "origin").toLowerCase()] ?? { label: terrain ?? "Other", cls: "bg-gray-100 text-gray-600 border-gray-200" };
  return (
    <span className={cn("text-[9px] font-bold px-2 py-0.5 rounded-full border whitespace-nowrap", t.cls)}>
      {t.label}
    </span>
  );
}

// The stable unique incident id (AL-F-00000042) with UUID tooltip.
// Click the primary ID to copy; hover to see the full UUIDv4.
export function IdChip({ f }: { f: DetectionFinding }) {
  const id = f.external_id ?? `#${f.id}`;
  const uid = f.finding_uid || "";
  return (
    <div className="flex items-center gap-1">
      <button
        onClick={(e) => { e.stopPropagation(); navigator.clipboard?.writeText(id).catch(() => {}); }}
        title={uid ? `Click to copy "${id}"\nUUID: ${uid}` : `Click to copy "${id}"`}
        className="text-[9px] font-mono font-semibold px-1.5 py-0.5 rounded border border-gray-200 bg-gray-50 text-gray-600 hover:bg-orange-50 hover:text-orange-700 hover:border-orange-200 transition-colors whitespace-nowrap"
      >
        {id}
      </button>
      {uid && (
        <button
          onClick={(e) => { e.stopPropagation(); navigator.clipboard?.writeText(uid).catch(() => {}); }}
          title={`UUID: ${uid} (click to copy)`}
          className="text-[8px] font-mono px-1 py-0.5 rounded border border-gray-100 bg-gray-50/50 text-gray-400 hover:bg-purple-50 hover:text-purple-600 hover:border-purple-200 transition-colors whitespace-nowrap"
        >
          {uid.slice(0, 8)}&hellip;
        </button>
      )}
    </div>
  );
}

// Button styling per action intent.
const _ACTION_BTN: Record<string, string> = {
  primary: "bg-white hover:bg-blue-50 border-gray-200 hover:border-blue-300 text-gray-700 hover:text-blue-700",
  resolve: "bg-white hover:bg-emerald-50 border-gray-200 hover:border-emerald-300 text-gray-700 hover:text-emerald-700",
  dismiss: "bg-white hover:bg-slate-100 border-gray-200 hover:border-slate-300 text-gray-600 hover:text-slate-700",
};

/**
 * Renders the triage action buttons the SERVER says are valid for this finding's
 * current state (finding.available_actions), POSTs the chosen action to the
 * unified lifecycle endpoint, prompts for a justification when the action
 * requires one, surfaces a 409 (illegal transition) inline, and calls onChanged
 * so the parent list/drawer can refresh. The state machine lives server-side —
 * the UI just renders what it's told.
 */
export function FindingActions({
  finding, onChanged, compact = false,
}: {
  finding: DetectionFinding;
  onChanged?: (updated?: DetectionFinding) => void;
  compact?: boolean;
}) {
  const [busy, setBusy] = useState<string | null>(null);
  const [err, setErr]   = useState<string | null>(null);
  const actions = finding.available_actions ?? [];

  async function run(a: FindingAction) {
    setErr(null);
    let reason: string | undefined;
    if (a.needs_reason) {
      const r = window.prompt(`${a.label}: enter a short justification`, "");
      if (r === null) return;                 // cancelled
      if (!r.trim()) { setErr("A justification is required."); return; }
      reason = r.trim();
    }
    setBusy(a.action);
    try {
      const res = await fetch(`/api/v1/soc/findings/${finding.id}/action`, {
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body:    JSON.stringify({ action: a.action, actor: "analyst", reason }),
      });
      if (res.status === 409) {
        const body = await res.json().catch(() => ({}));
        setErr(body?.detail?.error ?? "Action no longer valid — refresh.");
        onChanged?.();
        return;
      }
      if (!res.ok) { setErr(`Failed (${res.status})`); return; }
      const updated = await res.json().catch(() => undefined);
      onChanged?.(updated as DetectionFinding | undefined);
    } catch {
      setErr("Network error — try again.");
    } finally {
      setBusy(null);
    }
  }

  if (!actions.length) return null;

  return (
    <div className={cn("flex flex-col gap-1.5", compact ? "" : "w-full")}>
      <div className="flex items-center gap-1.5 flex-wrap">
        {actions.map(a => (
          <button
            key={a.action}
            onClick={(e) => { e.stopPropagation(); run(a); }}
            disabled={busy !== null}
            title={a.needs_reason ? `${a.label} (requires a reason)` : a.label}
            className={cn(
              "px-2.5 py-1 text-[10px] font-semibold rounded-lg border transition-all disabled:opacity-50 disabled:cursor-not-allowed whitespace-nowrap",
              _ACTION_BTN[a.kind] ?? _ACTION_BTN.primary,
            )}
          >
            {busy === a.action ? "…" : a.label}
          </button>
        ))}
      </div>
      {err && <span className="text-[10px] text-red-600">{err}</span>}
    </div>
  );
}

// ── Hook ──────────────────────────────────────────────────────────────────────

export function useDetectionData(url: string, refreshMs = 30_000) {
  const [findings, setFindings] = useState<DetectionFinding[]>([]);
  const [loading,  setLoading]  = useState(true);
  const [error,    setError]    = useState<string | null>(null);
  const [rev,      setRev]      = useState(0);
  const load = useCallback(async () => {
    try {
      const r = await fetch(url);
      if (!r.ok) throw new Error(`${r.status} ${r.statusText}`);
      const body = await r.json();
      setFindings(body.findings ?? body ?? []);
      setError(null);
    } catch (e) { setError(String(e)); }
    finally { setLoading(false); }
  }, [url, rev]);
  useEffect(() => { load(); }, [load]);
  useEffect(() => { const t = setInterval(() => setRev(v => v + 1), refreshMs); return () => clearInterval(t); }, [refreshMs]);
  return { findings, loading, error, refetch: () => setRev(v => v + 1) };
}

// ── ECG Waveform SVG ─────────────────────────────────────────────────────────

function ECGWave({ color = "#f97316" }: { color?: string }) {
  return (
    <svg viewBox="0 0 200 32" className="h-8 w-40 opacity-60" fill="none">
      <polyline
        className="ecg-path"
        points="0,16 20,16 28,4 36,28 44,8 52,24 60,16 80,16 88,2 96,30 104,10 112,22 120,16 200,16"
        stroke={color} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"
        style={{ strokeDasharray: 400, strokeDashoffset: 400, animation: "ecg-line 2s ease-out forwards" }}
      />
    </svg>
  );
}

// ── Animated KPI tile ─────────────────────────────────────────────────────────

function KpiTile({ label, value, color, delay = 0, icon }: {
  label: string; value: number; color: string; delay?: number; icon?: React.ReactNode;
}) {
  const count = useCountUp(value, 700);
  const s = SEV[color] ?? { kpi: "bg-gray-50 border-gray-200 text-gray-600" };
  return (
    <div className={cn("rounded-xl border p-3 text-center al-bounce-in", s.kpi)}
      style={{ animationDelay: `${delay}ms` }}>
      {icon && <div className="flex justify-center mb-1 opacity-60">{icon}</div>}
      <div className="text-xl font-black tabular-nums leading-none al-num">{count}</div>
      <div className="text-[9px] font-semibold text-gray-500 mt-1">{label}</div>
    </div>
  );
}

// ── Severity dot with sonar ───────────────────────────────────────────────────

function SevDot({ sev }: { sev: string }) {
  const s = SEV[sev] ?? SEV.info;
  const isCrit = sev === "critical";
  return (
    <div className={cn("relative flex items-center justify-center flex-shrink-0", isCrit && "al-sonar-dot")}>
      <div className={cn("w-2.5 h-2.5 rounded-full flex-shrink-0", s.dot,
        isCrit && "ring-2 ring-red-500/30")} />
    </div>
  );
}

// ── Animated confidence bar ───────────────────────────────────────────────────

function ConfBar({ pct, sev }: { pct: number; sev: string }) {
  const s = SEV[sev] ?? SEV.info;
  return (
    <div className="flex items-center gap-1.5">
      <div className="w-14 h-1.5 bg-gray-100 rounded-full overflow-hidden">
        <div
          className={cn("h-full rounded-full al-bar-fill", s.bar)}
          style={{ width: `${pct}%` }}
        />
      </div>
      <span className="text-[9px] text-gray-500 tabular-nums w-7">{pct}%</span>
    </div>
  );
}

// ── KEV / Exploit / MITRE chips ───────────────────────────────────────────────

function KevChip() {
  return (
    <span className="px-1.5 py-0.5 bg-red-600 text-white rounded text-[8px] font-black badge-kev-pulse">
      KEV
    </span>
  );
}
function ExploitChip() {
  return (
    <span className="px-1.5 py-0.5 bg-amber-100 text-amber-800 border border-amber-300 rounded text-[8px] font-bold">
      EXPLOIT
    </span>
  );
}
function MitreChip({ t }: { t: string }) {
  return (
    <span className="px-1.5 py-0.5 bg-indigo-50 text-indigo-700 border border-indigo-200 rounded text-[8px] font-mono font-semibold">
      {t}
    </span>
  );
}

function ValidatedBadge({ f }: { f: DetectionFinding }) {
  if (!f.is_validated) return null;
  return (
    <span
      className="px-1.5 py-0.5 rounded text-[8px] font-black border bg-emerald-100 text-emerald-800 border-emerald-300"
      title="Validated Finding — precision score meets or exceeds the configured detection threshold"
    >
      ✓ VALIDATED
    </span>
  );
}

function PrecisionChip({ score }: { score?: number | null }) {
  if (score == null || isNaN(score) || score <= 0) return null;
  const pct = Math.round(score * 100);
  const cls =
    pct >= 90 ? "bg-emerald-600 text-white border-emerald-700"
    : pct >= 75 ? "bg-amber-100 text-amber-800 border-amber-300"
    : "bg-red-50 text-red-700 border-red-200";
  return (
    <span
      className={cn("px-1.5 py-0.5 rounded text-[8px] font-black border tabular-nums", cls)}
      title="Detection Confidence — terrain-scored against KEV / EPSS / exploit / AI verdict / posture"
    >
      {pct}% ✓
    </span>
  );
}

// ── Exploitability column ─────────────────────────────────────────────────────

interface PriorityInfo {
  grade: string;
  shortLabel: string;
  color: string;
  bg: string;
  border: string;
}

function priorityGrade(f: DetectionFinding): PriorityInfo {
  const cvss    = f.cvss_score ?? 0;
  const epss    = f.epss_score ?? 0;
  const kev     = f.kev;
  const exploit = f.exploit_available;
  const srcs: string[] = _parseJson(f.exploit_sources, []) as string[];
  const hasMsf      = srcs.some(s => s.toLowerCase().includes("metasploit"));
  const hasVerified = srcs.some(s => s.toLowerCase().includes("verified"));

  if (kev && exploit && (hasMsf || hasVerified) && epss > 0.5 && cvss >= 9.0)
    return { grade: "P0", shortLabel: "Immediate", color: "#dc2626", bg: "#fff1f2", border: "#fca5a5" };
  if (kev && exploit)
    return { grade: "P0", shortLabel: "Immediate", color: "#dc2626", bg: "#fff1f2", border: "#fca5a5" };
  if (kev)
    return { grade: "P1", shortLabel: "Urgent",    color: "#ea580c", bg: "#fff7ed", border: "#fdba74" };
  if (cvss >= 9.0 && exploit)
    return { grade: "P1", shortLabel: "Urgent",    color: "#ea580c", bg: "#fff7ed", border: "#fdba74" };
  if (epss > 0.5 && cvss >= 8.0)
    return { grade: "P1", shortLabel: "Urgent",    color: "#ea580c", bg: "#fff7ed", border: "#fdba74" };
  if (exploit && cvss >= 7.0)
    return { grade: "P2", shortLabel: "High",      color: "#d97706", bg: "#fffbeb", border: "#fcd34d" };
  if (cvss >= 9.0)
    return { grade: "P2", shortLabel: "High",      color: "#d97706", bg: "#fffbeb", border: "#fcd34d" };
  if (epss > 0.2)
    return { grade: "P2", shortLabel: "High",      color: "#d97706", bg: "#fffbeb", border: "#fcd34d" };
  if (exploit || cvss >= 7.0 || epss > 0.05)
    return { grade: "P3", shortLabel: "Scheduled", color: "#2563eb", bg: "#eff6ff", border: "#93c5fd" };
  if (cvss >= 4.0)
    return { grade: "P3", shortLabel: "Scheduled", color: "#2563eb", bg: "#eff6ff", border: "#93c5fd" };
  return { grade: "P4", shortLabel: "Defer",     color: "#6b7280", bg: "#f9fafb", border: "#d1d5db" };
}

interface LiveIntelData {
  priority_grade:  string;
  priority_label:  string;
  is_kev:          boolean;
  exploit_available: boolean;
  exploit_signals: { source: string; label: string; verified?: number; count?: number; max_stars?: number }[];
  cvss_score:      number | null;
  epss_score:      number | null;
  intel_confidence: number | null;
  sources_used:    string[];
  rationale:       string[];
  pipeline_available: boolean;
}

function ExploitabilityDetail({ findingId, onClose }: { findingId: number; onClose: () => void }) {
  const [data, setData]   = useState<LiveIntelData | null>(null);
  const [err,  setErr]    = useState<string | null>(null);
  const [load, setLoad]   = useState(true);

  useEffect(() => {
    let dead = false;
    fetch(`/api/v1/soc/findings/${findingId}/exploitability`)
      .then(r => r.ok ? r.json() : Promise.reject(`${r.status}`))
      .then(d  => { if (!dead) { setData(d); setLoad(false); } })
      .catch(e => { if (!dead) { setErr(String(e)); setLoad(false); } });
    return () => { dead = true; };
  }, [findingId]);

  const SOURCE_ICON: Record<string, string> = {
    exploitdb: "🔴", metasploit: "⚡", poc_github: "📦",
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40" onClick={onClose}>
      <div className="w-[480px] max-h-[85vh] bg-white rounded-2xl shadow-2xl border border-gray-200 overflow-hidden flex flex-col"
        onClick={e => e.stopPropagation()}>
        {/* Header */}
        <div className="flex items-center justify-between px-4 py-3 border-b border-gray-100 bg-gray-50/60">
          <div className="flex items-center gap-2">
            <Target className="w-4 h-4 text-orange-500" />
            <span className="text-[12px] font-bold text-gray-900">Live Exploitability Intel</span>
            {data && !data.pipeline_available && (
              <span className="text-[9px] bg-amber-50 text-amber-700 border border-amber-200 px-2 py-0.5 rounded-full font-semibold">cached data</span>
            )}
          </div>
          <button onClick={onClose} className="p-1 hover:bg-gray-200 rounded-lg transition-colors">
            <X className="w-3.5 h-3.5 text-gray-400" />
          </button>
        </div>

        <div className="overflow-y-auto flex-1 p-4 space-y-4 text-xs">
          {load && (
            <div className="flex flex-col items-center justify-center py-12 gap-2 text-gray-400">
              <RefreshCw className="w-5 h-5 animate-spin text-orange-400" />
              <span className="text-[11px]">Querying intel sources…</span>
            </div>
          )}

          {err && (
            <div className="px-3 py-3 bg-red-50 border border-red-200 rounded-xl text-red-700 text-[11px] flex items-center gap-2">
              <AlertTriangle className="w-3.5 h-3.5 flex-shrink-0" />{err}
            </div>
          )}

          {data && (
            <>
              {/* Priority badge */}
              <div className="flex items-center gap-3 p-3 rounded-xl border" style={{ background: "#fafafa" }}>
                <div className="text-[28px] font-black tabular-nums leading-none" style={{
                  color: data.priority_grade === "P0" ? "#dc2626"
                       : data.priority_grade === "P1" ? "#ea580c"
                       : data.priority_grade === "P2" ? "#d97706"
                       : data.priority_grade === "P3" ? "#2563eb" : "#6b7280"
                }}>{data.priority_grade}</div>
                <div>
                  <div className="text-[11px] font-bold text-gray-800">{data.priority_label}</div>
                  <div className="flex items-center gap-2 mt-1">
                    {data.is_kev && <span className="px-1.5 py-0.5 bg-red-600 text-white rounded text-[8px] font-black">KEV</span>}
                    {data.exploit_available && <span className="px-1.5 py-0.5 bg-amber-100 text-amber-800 border border-amber-300 rounded text-[8px] font-bold">EXPLOIT</span>}
                    {data.cvss_score != null && <span className="px-1.5 py-0.5 bg-gray-100 text-gray-700 rounded text-[8px] font-mono">CVSS {data.cvss_score.toFixed(1)}</span>}
                    {data.epss_score != null && <span className="px-1.5 py-0.5 bg-gray-100 text-gray-700 rounded text-[8px] font-mono">EPSS {Math.round(data.epss_score*100)}%</span>}
                  </div>
                </div>
              </div>

              {/* Exploit signals */}
              {data.exploit_signals.length > 0 && (
                <div>
                  <div className="text-[9px] font-bold text-gray-400 uppercase tracking-widest mb-2">Exploit Evidence</div>
                  <div className="space-y-1.5">
                    {data.exploit_signals.map((s, i) => (
                      <div key={i} className="flex items-center gap-2 px-3 py-2 bg-amber-50 border border-amber-100 rounded-xl">
                        <span className="text-base leading-none">{SOURCE_ICON[s.source] ?? "🔍"}</span>
                        <span className="text-[10px] font-semibold text-amber-900">{s.label}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Rationale */}
              <div>
                <div className="text-[9px] font-bold text-gray-400 uppercase tracking-widest mb-2">Assessment Rationale</div>
                <ol className="space-y-1.5">
                  {data.rationale.map((r, i) => (
                    <li key={i} className="flex items-start gap-2 al-row-in" style={{ animationDelay: `${i*40}ms` }}>
                      <span className="w-4 h-4 rounded-full bg-orange-100 text-orange-600 text-[7px] font-black flex items-center justify-center flex-shrink-0 mt-0.5">{i+1}</span>
                      <span className="text-[10px] text-gray-700">{r}</span>
                    </li>
                  ))}
                </ol>
              </div>

              {/* Intel confidence */}
              {data.intel_confidence != null && (
                <div>
                  <div className="text-[9px] font-bold text-gray-400 uppercase tracking-widest mb-1.5">Intel Confidence</div>
                  <div className="flex items-center gap-2">
                    <div className="flex-1 h-2 bg-gray-100 rounded-full overflow-hidden">
                      <div className="h-full rounded-full al-bar-fill bg-gradient-to-r from-orange-400 to-amber-500"
                        style={{ width: `${Math.round(data.intel_confidence * 100)}%` }} />
                    </div>
                    <span className="text-[10px] font-bold text-gray-700 w-8 tabular-nums">{Math.round(data.intel_confidence*100)}%</span>
                  </div>
                  {data.sources_used.length > 0 && (
                    <div className="flex flex-wrap gap-1 mt-1.5">
                      {data.sources_used.map(s => (
                        <span key={s} className="px-1.5 py-0.5 bg-indigo-50 text-indigo-700 border border-indigo-200 rounded text-[8px] font-mono">{s}</span>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
}

export function ExploitabilityCell({ f }: { f: DetectionFinding }) {
  const [showDetail, setShowDetail] = useState(false);
  const p    = priorityGrade(f);
  const epss = f.epss_score != null ? Math.round(f.epss_score * 100) : null;

  return (
    <div className="flex flex-col gap-1 min-w-[100px]" onClick={e => e.stopPropagation()}>
      {/* Priority badge */}
      <div className="flex items-center gap-1">
        <span
          className="px-1.5 py-0.5 text-[10px] font-black rounded border tabular-nums"
          style={{ color: p.color, background: p.bg, borderColor: p.border }}
        >{p.grade}</span>
        <span className="text-[9px] font-semibold" style={{ color: p.color }}>{p.shortLabel}</span>
      </div>

      {/* Signal micro-row */}
      <div className="flex items-center gap-0.5 flex-wrap">
        {f.kev && (
          <span className="px-1 py-0.5 bg-red-600 text-white rounded text-[7px] font-black leading-none">KEV</span>
        )}
        {f.exploit_available && (
          <span className="px-1 py-0.5 bg-amber-100 text-amber-700 border border-amber-300 rounded text-[7px] font-bold leading-none">EXP</span>
        )}
        {epss != null && epss > 0 && (
          <span className={cn("px-1 py-0.5 rounded text-[7px] font-bold leading-none tabular-nums",
            epss >= 50 ? "bg-red-50 text-red-700 border border-red-200"
                       : epss >= 20 ? "bg-amber-50 text-amber-700 border border-amber-200"
                       : "bg-gray-100 text-gray-500"
          )}>E{epss}%</span>
        )}
        {f.cvss_score != null && (
          <span className={cn("px-1 py-0.5 rounded text-[7px] font-mono font-semibold leading-none",
            f.cvss_score >= 9 ? "bg-red-50 text-red-700"
                              : f.cvss_score >= 7 ? "bg-amber-50 text-amber-700" : "bg-gray-100 text-gray-500"
          )}>{f.cvss_score.toFixed(1)}</span>
        )}
      </div>

      {/* Live intel button */}
      <button
        onClick={() => setShowDetail(true)}
        className="inline-flex items-center gap-0.5 text-[9px] font-semibold text-indigo-600 hover:text-indigo-800 transition-colors"
      >
        <Zap className="w-2.5 h-2.5" />Live Intel
      </button>

      {showDetail && <ExploitabilityDetail findingId={f.id} onClose={() => setShowDetail(false)} />}
    </div>
  );
}

// ── AI Precision Validator panel ────────────────────────────────────────────

const FACTOR_LABELS: Record<string, { label: string; hint: string }> = {
  ai_verdict:         { label: "AI Verdict",          hint: "LLM senior-analyst review (weight 35%)" },
  ti_corroboration:   { label: "TI Corroboration",    hint: "KEV + malicious hash/IP + EPSS (weight 25%)" },
  cross_layer:        { label: "Cross-Layer Coverage", hint: "Signals across surface/exposure/execution (weight 15%)" },
  baseline_anomaly:   { label: "Baseline Anomaly",    hint: "Novelty vs prior rejections (weight 10%)" },
  asset_criticality:  { label: "Asset Criticality",   hint: "Crown-jewel vs endpoint (weight 8%)" },
  fp_history_damping: { label: "FP-History Damping",  hint: "Inverse of recent FP rate (weight 7%)" },
};

function _parseAiVerdict(raw: unknown): {
  label?:        string;
  confidence?:   number;
  reasoning?:    string;
  key_evidence?: string[];
  risk_factors?: string[];
  tokens_used?:  number;
} | null {
  if (raw == null) return null;
  if (typeof raw === "string") {
    if (!raw.trim() || raw.trim() === "{}") return null;
    try { return JSON.parse(raw); } catch { return null; }
  }
  if (typeof raw === "object") return raw as any;
  return null;
}

export function AIPrecisionPanel({ f }: { f: DetectionFinding }) {
  const score = typeof f.precision_score === "number" ? f.precision_score : null;
  const factors: Record<string, number> | null =
    f.precision_factors && typeof f.precision_factors === "object"
      ? (f.precision_factors as Record<string, number>)
      : null;
  const ai = _parseAiVerdict(f.ai_verdict);

  // Three distinct states:
  //   1. validator_active  — full pipeline ran (LLM + deterministic)
  //   2. deterministic_only — legacy path / LLM unavailable → only the
  //                          deterministic factors produced a score
  //   3. not_run            — no score at all
  const validatorRan       = Boolean(f.ai_validation_used);
  const hasDeterministic   = factors != null || (score != null && score > 0);
  const llmRan             = !!ai?.label;

  // Pull the threshold this finding was actually filtered against (set by
  // /findings?validated_only=true). Fall back to 90 % if absent.
  const effectiveThr = typeof (f as any).effective_threshold === "number"
    ? (f as any).effective_threshold as number
    : 0.90;

  if (!validatorRan && !hasDeterministic) {
    return (
      <div className="px-4 py-3 bg-amber-50/60 border-l-2 border-amber-300">
        <div className="text-[9px] font-bold text-amber-700 uppercase tracking-wide mb-1 flex items-center gap-1.5">
          <Brain className="w-3 h-3 text-amber-600" />Detection Confidence — Validator Not Active
        </div>
        <p className="text-[10px] text-amber-900 leading-relaxed">
          The validation pipeline was not running when this finding was emitted.
          Enable <span className="font-mono">ATTACKLENS_VALIDATION=true</span> and
          <span className="font-mono"> ATTACKLENS_AI_VALIDATION=true</span>, restart the manager, and re-ingest telemetry for new findings to be scored.
        </p>
      </div>
    );
  }

  const pct        = score != null ? Math.round(score * 100) : null;
  const thrPct     = Math.round(effectiveThr * 100);
  const promoted   = pct != null && pct >= thrPct;
  const ringColor  = pct == null
    ? "text-gray-300"
    : pct >= thrPct ? "text-emerald-500"
    : pct >= 75 ? "text-amber-500"
    : "text-red-500";
  const ringBg     = pct == null
    ? "bg-gray-50 border-gray-200"
    : pct >= thrPct ? "bg-emerald-50 border-emerald-200"
    : pct >= 75 ? "bg-amber-50 border-amber-200"
    : "bg-red-50 border-red-200";

  // LLM verdict tile — colour-coded only when the LLM actually responded.
  const verdictColor = !llmRan
    ? "bg-gray-50 text-gray-500 border-gray-200"
    : ai?.label === "tp"        ? "bg-emerald-50 text-emerald-700 border-emerald-200"
    : ai?.label === "fp"        ? "bg-red-50 text-red-700 border-red-200"
    : ai?.label === "uncertain" ? "bg-amber-50 text-amber-700 border-amber-200"
    :                              "bg-gray-50 text-gray-500 border-gray-200";
  const verdictText = !llmRan
    ? "LLM NOT RUN"
    : ai?.label === "tp" ? "TRUE POSITIVE"
    : ai?.label === "fp" ? "FALSE POSITIVE"
    : ai?.label === "uncertain" ? "UNCERTAIN"
    : "NO VERDICT";

  // Top-right status pill mirrors the panel state honestly.
  let statusLabel = "PROMOTED";
  let statusCls   = "bg-emerald-50 text-emerald-700 border-emerald-200";
  if (!validatorRan) {
    statusLabel = "DETERMINISTIC ONLY";
    statusCls   = "bg-blue-50 text-blue-700 border-blue-200";
  } else if (!promoted) {
    statusLabel = "BELOW THRESHOLD";
    statusCls   = "bg-amber-50 text-amber-700 border-amber-200";
  }

  return (
    <div className="px-4 py-3 bg-gradient-to-br from-indigo-50/50 to-white">
      <div className="flex items-center justify-between mb-2">
        <div className="text-[9px] font-bold text-indigo-700 uppercase tracking-wide flex items-center gap-1.5">
          <Brain className="w-3 h-3 text-indigo-500" />Detection Confidence — AI Validator
        </div>
        <span className={cn("px-2 py-0.5 rounded-full text-[8px] font-bold border", statusCls)}>
          {statusLabel}
        </span>
      </div>

      {!validatorRan && hasDeterministic && (
        <div className="mb-2 px-3 py-2 rounded-lg bg-blue-50 border border-blue-200 text-[9px] text-blue-800">
          <strong>Heads-up:</strong> the LLM verdict step did not run for this finding (validation pipeline was OFF or no Anthropic key). The score below uses deterministic factors only.
        </div>
      )}

      {/* Composite score + verdict row */}
      <div className="flex gap-2 mb-3">
        <div className={cn("flex-1 rounded-xl border p-3 text-center", ringBg)}>
          <div className={cn("text-2xl font-black leading-none", ringColor)}>
            {pct != null ? `${pct}%` : "—"}
          </div>
          <div className="text-[8px] text-gray-500 mt-1 uppercase tracking-wide font-semibold">Detection Confidence</div>
          <div className="text-[8px] text-gray-400 mt-0.5">Threshold ≥ {thrPct}%</div>
        </div>
        <div className={cn("flex-1 rounded-xl border p-3 text-center flex flex-col items-center justify-center", verdictColor)}>
          <div className="text-[10px] font-black leading-tight">{verdictText}</div>
          {ai?.confidence != null && (
            <div className="text-[8px] mt-1 opacity-80">
              {Math.round(ai.confidence * 100)}% AI confidence
            </div>
          )}
        </div>
      </div>

      {/* Per-factor breakdown */}
      {factors && Object.keys(factors).length > 0 && (
        <div className="space-y-1.5 mb-3">
          {Object.entries(factors).map(([key, value]) => {
            const meta = FACTOR_LABELS[key] || { label: key, hint: "" };
            const v = typeof value === "number" ? value : 0;
            const v_pct = Math.round(v * 100);
            const barColor =
              v >= 0.85 ? "bg-emerald-500"
              : v >= 0.65 ? "bg-amber-400"
              : "bg-red-400";
            return (
              <div key={key} className="space-y-0.5" title={meta.hint}>
                <div className="flex items-center justify-between text-[9px]">
                  <span className="text-gray-600 font-semibold">{meta.label}</span>
                  <span className="font-mono font-bold text-gray-700">{v_pct}%</span>
                </div>
                <div className="h-1.5 bg-gray-100 rounded-full overflow-hidden">
                  <div className={cn("h-full rounded-full transition-all", barColor)}
                       style={{ width: `${v_pct}%` }} />
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* AI reasoning + evidence */}
      {ai?.reasoning && (
        <div className="mt-2 px-3 py-2 rounded-lg bg-white border border-indigo-100">
          <div className="text-[8px] font-bold text-indigo-600 uppercase tracking-wide mb-1">
            Senior-Analyst Reasoning
          </div>
          <p className="text-[10px] text-gray-700 leading-snug">{ai.reasoning}</p>
        </div>
      )}

      {(ai?.key_evidence?.length || ai?.risk_factors?.length) && (
        <div className="grid grid-cols-2 gap-2 mt-2">
          {ai?.key_evidence?.length ? (
            <div className="px-2.5 py-2 rounded-lg bg-blue-50 border border-blue-100">
              <div className="text-[8px] font-bold text-blue-700 uppercase tracking-wide mb-1">Key Evidence</div>
              <ul className="space-y-0.5">
                {ai.key_evidence.slice(0, 6).map((e, i) => (
                  <li key={i} className="text-[9px] text-blue-900 flex gap-1">
                    <span className="text-blue-400">›</span><span>{e}</span>
                  </li>
                ))}
              </ul>
            </div>
          ) : null}
          {ai?.risk_factors?.length ? (
            <div className="px-2.5 py-2 rounded-lg bg-red-50 border border-red-100">
              <div className="text-[8px] font-bold text-red-700 uppercase tracking-wide mb-1">Risk Factors</div>
              <ul className="space-y-0.5">
                {ai.risk_factors.slice(0, 6).map((r, i) => (
                  <li key={i} className="text-[9px] text-red-900 flex gap-1">
                    <span className="text-red-400">!</span><span>{r}</span>
                  </li>
                ))}
              </ul>
            </div>
          ) : null}
        </div>
      )}

      {ai?.tokens_used != null && ai.tokens_used > 0 && (
        <div className="mt-2 text-[8px] text-gray-400 text-right">
          LLM used {ai.tokens_used} tokens
        </div>
      )}
    </div>
  );
}


// ── Terrain Validation Checklist ────────────────────────────────────────────
// Renders the per-criterion result computed by attacklens/terrain_validators.py.
// Each finding belongs to one terrain (Citadels/Vector/Origin/Identity/Posture)
// and is scored against 6-7 named criteria specific to that terrain.

const TERRAIN_META: Record<string, { label: string; color: string; bg: string; border: string }> = {
  origin:   { label: "Origin (Vulnerability)", color: "text-amber-700",  bg: "bg-amber-50",  border: "border-amber-200" },
  vector:   { label: "Vector (Network)",       color: "text-blue-700",   bg: "bg-blue-50",   border: "border-blue-200" },
  citadels: { label: "Citadels (Execution)",   color: "text-red-700",    bg: "bg-red-50",    border: "border-red-200" },
  identity: { label: "Identity (Accounts)",    color: "text-indigo-700", bg: "bg-indigo-50", border: "border-indigo-200" },
  posture:  { label: "Posture (Controls)",     color: "text-emerald-700",bg: "bg-emerald-50",border: "border-emerald-200" },
};

function _parseTerrainValidation(raw: unknown):
  DetectionFinding["terrain_validation"] extends infer T ? Exclude<T, string> : never {
  if (!raw) return null as any;
  if (typeof raw === "string") {
    try { return JSON.parse(raw); } catch { return null as any; }
  }
  return raw as any;
}

export function TerrainValidationPanel({ f }: { f: DetectionFinding }) {
  const tv = _parseTerrainValidation(f.terrain_validation);
  if (!tv || !tv.terrain) {
    return (
      <div className="px-4 py-3 bg-gray-50/60 border-l-2 border-gray-200">
        <div className="text-[9px] font-bold text-gray-400 uppercase tracking-wide mb-1 flex items-center gap-1.5">
          <CheckCircle2 className="w-3 h-3 text-gray-300" />Detection Confidence — Terrain Scoring
        </div>
        <p className="text-[10px] text-gray-500">
          No terrain validation data for this finding. Re-emit findings after enabling the validator to populate the per-criterion checklist.
        </p>
      </div>
    );
  }

  const meta = TERRAIN_META[tv.terrain ?? ""] ?? TERRAIN_META.origin;
  const pct  = Math.round((tv.percentage ?? (tv.score ?? 0) * 100));
  const thr  = typeof (f as any).effective_threshold === "number"
    ? Math.round(((f as any).effective_threshold as number) * 100)
    : 90;
  const passes = pct >= thr;

  const ringCls = passes
    ? "text-emerald-600 bg-emerald-50 border-emerald-200"
    : pct >= 70 ? "text-amber-600 bg-amber-50 border-amber-200"
    : "text-red-600 bg-red-50 border-red-200";

  const statusIcon = (s?: string) =>
    s === "met"     ? <CheckCircle2 className="w-3.5 h-3.5 text-emerald-500" />
    : s === "partial" ? <Info        className="w-3.5 h-3.5 text-amber-500" />
    :                   <XCircle     className="w-3.5 h-3.5 text-red-400" />;

  return (
    <div className={cn("px-4 py-3 border-l-2", meta.border, meta.bg + "/30")}>
      <div className="flex items-center justify-between mb-2 flex-wrap gap-2">
        <div className={cn("text-[9px] font-bold uppercase tracking-wide flex items-center gap-1.5", meta.color)}>
          <CheckCircle2 className="w-3 h-3" />Detection Confidence — Terrain Scoring
          <span className={cn("ml-1 px-1.5 py-0.5 rounded-md border text-[8px] font-bold uppercase",
                               meta.color, meta.bg, meta.border)}>
            {meta.label}
          </span>
        </div>
        <span className={cn("px-2 py-0.5 rounded-full text-[8px] font-bold border",
                             passes ? "bg-emerald-50 text-emerald-700 border-emerald-200"
                                    : "bg-amber-50 text-amber-700 border-amber-200")}>
          {passes ? "VALIDATED" : "BELOW THRESHOLD"}
        </span>
      </div>

      {/* Big score tile */}
      <div className="flex gap-2 mb-3">
        <div className={cn("flex-1 rounded-xl border p-3 text-center", ringCls)}>
          <div className="text-2xl font-black leading-none">{pct}%</div>
          <div className="text-[8px] mt-1 uppercase tracking-wide opacity-80 font-semibold">Detection Confidence</div>
          <div className="text-[8px] mt-0.5 opacity-60">
            Threshold ≥ {thr}% · {tv.summary || `${tv.met_count ?? 0} of ${tv.total_count ?? 0} criteria met`}
          </div>
        </div>
      </div>

      {/* Criteria checklist */}
      <div className="space-y-1.5">
        {(tv.criteria || []).map(c => {
          const cPct  = Math.round((c.met ?? 0) * 100);
          const wPct  = Math.round((c.weight ?? 0) * 100);
          const barCls =
            c.status === "met"     ? "bg-emerald-500"
            : c.status === "partial" ? "bg-amber-400"
            : "bg-gray-200";
          return (
            <div key={c.name} className="rounded-lg border border-gray-100 bg-white px-3 py-2">
              <div className="flex items-start justify-between gap-2">
                <div className="flex items-start gap-2 flex-1 min-w-0">
                  <div className="mt-0.5 flex-shrink-0">{statusIcon(c.status)}</div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-baseline gap-2 flex-wrap">
                      <span className="text-[10px] font-bold text-gray-800">{c.label}</span>
                      <span className="text-[8px] text-gray-400 font-mono">weight {wPct}%</span>
                    </div>
                    {c.description && (
                      <p className="text-[9px] text-gray-500 mt-0.5 leading-snug">{c.description}</p>
                    )}
                  </div>
                </div>
                <span className={cn("text-[10px] font-mono font-black flex-shrink-0",
                                     c.status === "met" ? "text-emerald-600"
                                     : c.status === "partial" ? "text-amber-600"
                                     : "text-gray-400")}>
                  {cPct}%
                </span>
              </div>
              <div className="h-1 bg-gray-100 rounded-full overflow-hidden mt-1.5">
                <div className={cn("h-full rounded-full", barCls)} style={{ width: `${cPct}%` }} />
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}


// ── OS-aware Remediation panel (uses /api/v1/remediation/{id}/recipe) ───────

type OS = "macos" | "linux" | "windows";

interface RemediationStep {
  n:                number;
  title:            string;
  detail:           string;
  verify?:          string;
  commands?:        Record<string, string[]>;
  commands_for_os?: string[];
}

interface RemediationRecipe {
  recipe_id?:             string;
  summary?:               string;
  applies_to?:            string;
  risk_level?:            "low" | "medium" | "high";
  estimated_time?:        string;
  steps?:                 RemediationStep[];
  validation?:            string;
  compensating_controls?: string;
  references?:            string[];
  os_type?:               OS;
  agent_os?:              string;
  agent_os_locked?:       boolean;
  kev?:                   boolean;
  cve_ids?:               string[];
  precision_score?:       number;
  source?:                string;
}

function _normalizeAgentOS(raw?: string | null): OS | null {
  if (!raw) return null;
  const s = raw.toLowerCase();
  if (s.includes("darwin") || s.includes("mac") || s.includes("osx")) return "macos";
  if (s.includes("win")) return "windows";
  if (s.includes("linux") || s.includes("ubuntu") || s.includes("debian")
      || s.includes("rhel") || s.includes("centos") || s.includes("fedora")
      || s.includes("arch") || s.includes("alpine") || s.includes("suse")) return "linux";
  if (s === "macos" || s === "linux" || s === "windows") return s as OS;
  return null;
}

export function OSRemediationPanel({
  findingId,
  agentOs,
  allowOverride = true,
}: {
  findingId: number;
  /** Pin the panel to the agent's OS — when set, no fetch override is sent. */
  agentOs?: string | null;
  /** When true (default), the analyst can switch OS even if pinned. */
  allowOverride?: boolean;
}) {
  // Initial OS: prefer the agent's OS when supplied, otherwise let backend decide.
  const initialOS = _normalizeAgentOS(agentOs);
  const [os, setOS]       = useState<OS | null>(initialOS);
  const [override, setOverride] = useState(false);
  const [data, setData]   = useState<RemediationRecipe | null>(null);
  const [load, setLoad]   = useState(true);
  const [err,  setErr]    = useState<string | null>(null);
  const [copied, setCopied] = useState<string | null>(null);

  // Re-pin to the agent's OS when the parent supplies a new value.
  useEffect(() => {
    const detected = _normalizeAgentOS(agentOs);
    if (detected && !override) setOS(detected);
  }, [agentOs, override]);

  useEffect(() => {
    let dead = false;
    setLoad(true); setErr(null);
    // When the OS is locked to the agent's OS, omit os_type so the backend
    // auto-detects (and the response reports agent_os_locked=true).
    const qs = override && os ? `?os_type=${os}` : "";
    fetch(`/api/v1/remediation/${findingId}/recipe${qs}`)
      .then(r => r.ok ? r.json() : Promise.reject(`${r.status}`))
      .then(d => {
        if (dead) return;
        setData(d); setLoad(false);
        // Backend echoes os_type — sync state when not in override mode.
        if (!override && d?.os_type) setOS(d.os_type as OS);
      })
      .catch(e => { if (!dead) { setErr(String(e)); setLoad(false); } });
    return () => { dead = true; };
  }, [findingId, os, override]);

  const onCopy = useCallback((cmd: string) => {
    navigator.clipboard?.writeText(cmd);
    setCopied(cmd);
    setTimeout(() => setCopied(null), 1200);
  }, []);

  const riskClass =
    data?.risk_level === "high"   ? "bg-red-50 text-red-700 border-red-200"
    : data?.risk_level === "medium" ? "bg-amber-50 text-amber-700 border-amber-200"
    : "bg-emerald-50 text-emerald-700 border-emerald-200";

  return (
    <div className="px-4 py-3">
      <div className="flex items-center justify-between mb-2">
        <div className="text-[9px] font-bold text-emerald-700 uppercase tracking-wide flex items-center gap-1.5 flex-wrap">
          <Shield className="w-3 h-3" />Remediation
          {data?.source && (
            <span className="ml-0.5 text-[7px] font-mono font-normal text-gray-400">
              {data.source === "ai_cached" ? "AI plan" : "knowledge base"}
            </span>
          )}
          {/* Agent OS pin — visible when we are locked to the agent's actual OS */}
          {data && !override && (data.agent_os_locked || _normalizeAgentOS(agentOs)) && (
            <span className="ml-1 inline-flex items-center gap-1 px-1.5 py-0.5 rounded-md bg-emerald-50 text-emerald-700 border border-emerald-200 text-[8px] font-bold uppercase tracking-wide">
              {(data.os_type || _normalizeAgentOS(agentOs) || "macos") === "macos" ? "macOS"
                : (data.os_type || _normalizeAgentOS(agentOs))}
              <span className="font-normal opacity-60">agent OS</span>
            </span>
          )}
        </div>
        {/* OS override — hidden by default when locked; click to opt in */}
        {allowOverride && (
          override ? (
            <div className="inline-flex bg-gray-100 rounded-lg p-0.5 gap-0.5">
              {(["macos","linux","windows"] as OS[]).map(o => (
                <button key={o}
                  onClick={() => setOS(o)}
                  className={cn(
                    "px-2 py-0.5 rounded-md text-[9px] font-bold uppercase tracking-wide transition-all",
                    os === o ? "bg-white text-orange-600 shadow-sm" : "text-gray-500 hover:text-gray-700"
                  )}>
                  {o === "macos" ? "macOS" : o}
                </button>
              ))}
              <button onClick={() => setOverride(false)}
                title="Pin back to agent OS"
                className="px-2 py-0.5 rounded-md text-[9px] font-bold uppercase tracking-wide text-gray-400 hover:text-gray-700">
                ×
              </button>
            </div>
          ) : (
            <button onClick={() => setOverride(true)}
              title="Show commands for a different OS"
              className="text-[9px] text-gray-400 hover:text-orange-600 font-semibold uppercase tracking-wide">
              switch OS
            </button>
          )
        )}
      </div>

      {load && (
        <div className="flex items-center gap-2 text-[10px] text-gray-400 py-3">
          <RefreshCw className="w-3 h-3 animate-spin" /> Loading remediation…
        </div>
      )}

      {err && (
        <div className="text-[10px] text-red-600 bg-red-50 border border-red-200 rounded-lg px-3 py-2">
          Failed to load remediation: {err}
        </div>
      )}

      {data && !load && (
        <div className="space-y-3">
          {/* Summary header */}
          <div className="rounded-xl border border-gray-200 bg-white p-2.5">
            <p className="text-[10px] text-gray-800 leading-snug font-semibold">{data.summary}</p>
            <div className="flex items-center gap-2 mt-1.5 flex-wrap">
              {data.risk_level && (
                <span className={cn("text-[8px] font-bold px-1.5 py-0.5 rounded border uppercase tracking-wide", riskClass)}>
                  {data.risk_level} risk
                </span>
              )}
              {data.estimated_time && (
                <span className="text-[8px] font-bold px-1.5 py-0.5 rounded border bg-gray-50 text-gray-600 border-gray-200">
                  ~ {data.estimated_time}
                </span>
              )}
              {data.kev && (
                <span className="text-[8px] font-black px-1.5 py-0.5 rounded bg-red-600 text-white">
                  KEV — actively exploited
                </span>
              )}
              {data.applies_to && (
                <span className="text-[8px] text-gray-500 italic">{data.applies_to}</span>
              )}
            </div>
          </div>

          {/* Steps */}
          <ol className="space-y-2.5">
            {(data.steps || []).map((step, i) => {
              const cmds = step.commands_for_os
                || (step.commands?.[os])
                || [];
              return (
                <li key={i} className="rounded-xl border border-gray-200 bg-white p-2.5 al-row-in"
                    style={{ animationDelay: `${i * 40}ms` }}>
                  <div className="flex items-start gap-2 mb-1.5">
                    <span className="w-5 h-5 rounded-full bg-orange-500 text-white flex items-center justify-center text-[10px] font-bold flex-shrink-0">{step.n}</span>
                    <div className="flex-1">
                      <p className="text-[11px] font-bold text-gray-900 leading-tight">{step.title}</p>
                      <p className="text-[10px] text-gray-600 mt-0.5 leading-snug">{step.detail}</p>
                    </div>
                  </div>
                  {cmds.length > 0 && (
                    <div className="space-y-1 ml-7">
                      {cmds.map((cmd, j) => (
                        <div key={j} className="group flex items-center gap-1.5 bg-gray-900 rounded-md px-2 py-1.5">
                          <span className="text-emerald-300 text-[9px] font-mono select-none">$</span>
                          <code className="text-[10px] font-mono text-emerald-100 break-all flex-1">{cmd}</code>
                          <button
                            onClick={() => onCopy(cmd)}
                            className="opacity-0 group-hover:opacity-100 transition-opacity p-0.5 hover:bg-gray-700 rounded"
                            title="Copy">
                            {copied === cmd
                              ? <CheckCircle2 className="w-3 h-3 text-emerald-400" />
                              : <Copy className="w-3 h-3 text-gray-400" />}
                          </button>
                        </div>
                      ))}
                    </div>
                  )}
                  {step.verify && (
                    <div className="ml-7 mt-1.5 flex items-start gap-1">
                      <CheckCircle2 className="w-3 h-3 text-emerald-500 flex-shrink-0 mt-0.5" />
                      <span className="text-[9px] text-emerald-700 leading-snug">{step.verify}</span>
                    </div>
                  )}
                </li>
              );
            })}
          </ol>

          {/* Validation */}
          {data.validation && (
            <div className="rounded-lg border border-emerald-200 bg-emerald-50 px-3 py-2">
              <div className="text-[8px] font-bold text-emerald-700 uppercase tracking-wide mb-0.5">Validation</div>
              <p className="text-[10px] text-emerald-900">{data.validation}</p>
            </div>
          )}

          {/* Compensating controls */}
          {data.compensating_controls && (
            <div className="rounded-lg border border-amber-200 bg-amber-50 px-3 py-2">
              <div className="text-[8px] font-bold text-amber-700 uppercase tracking-wide mb-0.5">If immediate fix isn't possible</div>
              <p className="text-[10px] text-amber-900">{data.compensating_controls}</p>
            </div>
          )}

          {/* References */}
          {data.references && data.references.length > 0 && (
            <div className="flex flex-wrap gap-1">
              {data.references.map((r, i) => (
                <a key={i} href={r} target="_blank" rel="noopener noreferrer"
                   className="inline-flex items-center gap-0.5 text-[9px] text-blue-600 hover:text-blue-800 font-mono border-b border-blue-200 hover:border-blue-500">
                  <ExternalLink className="w-2.5 h-2.5" />ref {i+1}
                </a>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}


// ── Detail panel — 4-tab ─────────────────────────────────────────────────────

type DTab = "overview" | "validation" | "blueprint" | "hunt";

// One-line "why this matters" caption shown under each field group, so the
// analyst understands the purpose of every value (customer-POV curation).
function Why({ children }: { children: React.ReactNode }) {
  return <p className="text-[9px] text-gray-400 italic leading-snug mt-1">Why: {children}</p>;
}

export function FindingDetail({ finding: f, onClose, onChanged }: { finding: DetectionFinding; onClose: () => void; onChanged?: () => void }) {
  const [tab, setTab] = useState<DTab>("overview");
  const evidence    = _parseJson(f.evidence, {}) as Record<string, unknown>;
  // action_plan no longer rendered inline — replaced by <OSRemediationPanel />.
  const cveIds      = _parseJson(f.cve_ids, []) as string[];
  const exploitSrcs = _parseJson(f.exploit_sources, []) as string[];
  const tags        = _parseJson(f.tags, []) as string[];
  const score       = f.composite_score ?? f.score;
  const bp          = BLUEPRINT[getBlueprintKey(f.category, f.source, f.mitre_tactic)];
  const s           = SEV[f.severity] ?? SEV.info;

  // Escape key to close
  useEffect(() => {
    const h = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    document.addEventListener("keydown", h);
    return () => document.removeEventListener("keydown", h);
  }, [onClose]);

  // Freeze background scroll while drawer is open
  useEffect(() => {
    const prev = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => { document.body.style.overflow = prev; };
  }, []);

  const TABS: { id: DTab; label: string; icon: React.ReactNode }[] = [
    { id: "overview",   label: "Overview",   icon: <Eye className="w-3 h-3" /> },
    { id: "validation", label: "Validate",   icon: <CheckCircle2 className="w-3 h-3" /> },
    { id: "blueprint",  label: "Blueprint",  icon: <BookOpen className="w-3 h-3" /> },
    { id: "hunt",       label: "Hunt",       icon: <Crosshair className="w-3 h-3" /> },
  ];

  return createPortal(
    <>
      {/* Backdrop — portaled to body, always viewport-fixed */}
      <div
        className="al-backdrop-in"
        style={{ position: "fixed", top: 44, left: 0, right: 0, bottom: 0, zIndex: 40, background: "rgba(0,0,0,0.35)", backdropFilter: "blur(2px)" }}
        onClick={onClose}
        onWheel={e => e.stopPropagation()}
        onTouchMove={e => e.stopPropagation()}
      />
      {/* Sliding drawer */}
      <div
        className="al-drawer-in flex flex-col overflow-hidden"
        style={{ position: "fixed", top: 44, right: 0, bottom: 0, width: "min(520px, 100vw)", zIndex: 50, background: "#fff", boxShadow: "-4px 0 32px 0 rgba(0,0,0,0.15)" }}
      >
      {/* Dynamic top stripe */}
      <div className={cn("h-1.5 w-full flex-shrink-0", f.severity === "critical" ? "bg-gradient-to-r from-red-500 via-red-400 to-orange-500" : f.severity === "high" ? "bg-gradient-to-r from-amber-500 via-amber-400 to-orange-400" : "bg-gradient-to-r from-orange-400 via-amber-400 to-orange-500")} />

      {/* Header */}
      <div className="flex items-center justify-between px-4 py-2.5 border-b border-gray-100 bg-gray-50/60 flex-shrink-0">
        <div className="flex items-center gap-1.5 flex-wrap min-w-0">
          <SevBadge sev={f.severity} />
          <StatusChip status={f.status} />
          {f.kev && <KevChip />}
          {f.exploit_available && <ExploitChip />}
          {f.mitre_technique && <MitreChip t={f.mitre_technique} />}
          <span className="text-[9px] font-mono text-gray-400 select-all">{f.external_id ?? `#${f.id}`}</span>
        </div>
        <button onClick={onClose} className="p-1.5 hover:bg-gray-200 rounded-lg transition-colors flex-shrink-0 ml-2">
          <X className="w-3.5 h-3.5 text-gray-400" />
        </button>
      </div>

      {/* Triage action bar — server-driven valid actions for this finding's state.
          On success we refresh the parent list and close the drawer (the finding
          may have left the current view, e.g. closed → drops off active). */}
      {(f.available_actions?.length ?? 0) > 0 && (
        <div className="px-4 py-2 border-b border-gray-100 bg-white flex-shrink-0">
          <FindingActions
            finding={f}
            onChanged={() => { onChanged?.(); onClose(); }}
          />
        </div>
      )}

      {/* Tabs */}
      <div className="flex border-b border-gray-100 flex-shrink-0 bg-white">
        {TABS.map((t, i) => (
          <button key={t.id} onClick={() => setTab(t.id)}
            className={cn(
              "flex-1 flex items-center justify-center gap-1 py-2.5 text-[10px] font-bold transition-all relative",
              tab === t.id ? "text-orange-600" : "text-gray-400 hover:text-gray-600"
            )}
            style={{ animationDelay: `${i * 40}ms` }}>
            {t.icon}{t.label}
            {tab === t.id && (
              <span className="absolute bottom-0 left-2 right-2 h-0.5 bg-orange-500 rounded-t-full"
                style={{ animation: "tab-slide 0.2s ease both", transformOrigin: "left" }} />
            )}
          </button>
        ))}
      </div>

      <div className="overflow-y-auto flex-1 text-sm">

        {/* ── OVERVIEW — the minimal set an analyst needs to triage ────────── */}
        {tab === "overview" && (
          <div className="divide-y divide-gray-50">
            {/* What is it + how bad */}
            <div className="px-4 py-3">
              <p className="text-[12px] font-bold text-gray-900 leading-snug">{f.title}</p>
              <div className="flex flex-wrap gap-1 mt-2">
                <SevBadge sev={f.severity} />
                {f.sla_status && <SlaBadge status={f.sla_status} />}
                {f.mitre_tactic && <span className="px-2 py-0.5 bg-purple-50 text-purple-700 border border-purple-200 rounded-full text-[9px] font-semibold">{f.mitre_tactic}</span>}
              </div>
              <Why>Title + severity tell you, at a glance, what was found and how urgently it needs attention.</Why>
            </div>

            {/* How urgent — the three scores that drive prioritisation */}
            <div className="px-4 py-3">
              <div className="grid grid-cols-3 gap-2">
                {[
                  { l: "Risk", v: `${score.toFixed(1)}`, c: score >= 8 ? "text-red-600" : score >= 6 ? "text-amber-600" : "text-blue-600", bg: score >= 8 ? "bg-red-50 border-red-100" : "bg-gray-50 border-gray-100" },
                  { l: "CVSS", v: f.cvss_score != null ? f.cvss_score.toFixed(1) : "—", c: f.cvss_score != null && f.cvss_score >= 9 ? "text-red-600" : "text-gray-600", bg: "bg-gray-50 border-gray-100" },
                  { l: "EPSS", v: f.epss_score != null ? `${Math.round(f.epss_score * 100)}%` : "—", c: f.epss_score != null && f.epss_score >= 0.5 ? "text-red-600" : "text-gray-600", bg: "bg-gray-50 border-gray-100" },
                ].map(t => (
                  <div key={t.l} className={cn("rounded-xl border py-2.5 text-center al-bounce-in", t.bg)}>
                    <div className={cn("text-sm font-black leading-none", t.c)}>{t.v}</div>
                    <div className="text-[9px] text-gray-500 mt-1">{t.l}</div>
                  </div>
                ))}
              </div>
              <Why>Risk = blended priority · CVSS = base technical severity · EPSS = probability it'll be exploited in the next 30 days.</Why>
            </div>

            {/* Is it actively exploited — the single biggest prioritisation signal */}
            <div className="px-4 py-3 space-y-1.5">
              {([
                ["KEV",     f.kev ? "Listed — actively exploited in the wild (CISA)" : "Not on CISA KEV list", f.kev],
                ["Exploit", f.exploit_available ? `Public exploit available (${exploitSrcs.join(", ") || "Exploit-DB"})` : "No public exploit found", f.exploit_available],
              ] as [string, string, boolean][]).map(([l, v, hi]) => (
                <div key={l} className="flex items-start gap-2">
                  <span className="w-16 text-[9px] text-gray-400 font-semibold uppercase tracking-wide flex-shrink-0 mt-0.5">{l}</span>
                  <span className={cn("text-[10px] flex-1", hi ? "font-bold text-red-600" : "text-gray-600")}>{v}</span>
                </div>
              ))}
              {cveIds.length > 0 && (
                <div className="flex flex-wrap gap-1 pt-1">
                  {cveIds.map(c => (
                    <a key={c} href={`https://nvd.nist.gov/vuln/detail/${c}`} target="_blank" rel="noopener noreferrer"
                      className="font-mono text-[8px] px-1.5 py-0.5 bg-blue-50 text-blue-700 border border-blue-200 rounded hover:bg-blue-100">{c}</a>
                  ))}
                </div>
              )}
              <Why>KEV (CISA) and a public exploit mean attackers can act now — these outrank a high CVSS with no real-world exploitation.</Why>
            </div>

            {/* What it is, in plain language */}
            <div className="px-4 py-3">
              <div className="text-[9px] font-bold text-gray-400 uppercase tracking-wide mb-1.5">Description</div>
              <p className="text-[11px] text-gray-700 leading-relaxed">{f.description}</p>
              <Why>Plain-language explanation of what was detected, so you don't have to decode the raw evidence.</Why>
            </div>

            {/* What happens if ignored */}
            {f.impact && (
              <div className="px-4 py-3">
                <div className="text-[9px] font-bold text-amber-600 uppercase tracking-wide mb-1.5 flex items-center gap-1">
                  <AlertTriangle className="w-3 h-3" />Business Impact
                </div>
                <p className="text-[10px] text-amber-900 bg-amber-50 border border-amber-200 rounded-xl px-3 py-2 leading-relaxed">{f.impact}</p>
                <Why>The consequence if this is left unresolved — used to justify priority to stakeholders.</Why>
              </div>
            )}

            {/* What to do about it — OS-aware fix steps */}
            <OSRemediationPanel findingId={f.id} agentOs={f.agent_os} />

            {/* Which host + how long present */}
            <div className="px-4 py-3">
              <div className="text-[9px] font-bold text-gray-400 uppercase tracking-wide mb-1.5">Affected Host</div>
              {[["Agent", f.agent_id],["First detected", fmtTs(f.first_detected_at)],["Last detected", fmtTs(f.last_detected_at)]].map(([l,v]) => (
                <div key={l} className="flex items-center gap-2 py-0.5">
                  <span className="w-24 text-[9px] text-gray-400 font-medium">{l}</span>
                  <span className="text-[10px] text-gray-700 font-mono">{v}</span>
                </div>
              ))}
              <Why>Which machine to act on, and whether this is brand-new or a long-standing exposure.</Why>
            </div>
          </div>
        )}

        {/* ── VALIDATE — is this real? The proof and the verdict ───────────── */}
        {tab === "validation" && (
          <div className="divide-y divide-gray-50">

            {/* Terrain validation checklist — per-criterion checks actually run */}
            <div>
              <TerrainValidationPanel f={f} />
              <div className="px-4 pb-3 -mt-1"><Why>The concrete checks that were run (KEV / exploit / exposure / AI) — each ✓ is a real reason to believe this is a true positive.</Why></div>
            </div>

            {/* AI Precision Validator — composite score + LLM verdict */}
            <div>
              <AIPrecisionPanel f={f} />
              <div className="px-4 pb-3 -mt-1"><Why>The model's true/false-positive verdict and confidence — your second opinion before you act.</Why></div>
            </div>

            {/* Raw evidence — the actual telemetry this finding was built from */}
            {Object.keys(evidence).length > 0 ? (
              <div className="px-4 py-3">
                <div className="text-[9px] font-bold text-gray-400 uppercase tracking-wide mb-2 flex items-center gap-1.5"><Database className="w-3 h-3 text-blue-500" />Raw Evidence</div>
                <pre className="text-[9px] font-mono text-green-400 bg-gray-900 rounded-xl p-3 overflow-auto max-h-48 whitespace-pre-wrap break-words border border-gray-700">{JSON.stringify(evidence, null, 2)}</pre>
                <Why>The exact telemetry captured from the host — your ground-truth proof to confirm or dismiss the finding.</Why>
              </div>
            ) : (
              <div className="px-4 py-3">
                <p className="text-[10px] text-gray-400">No raw evidence captured for this finding.</p>
              </div>
            )}
          </div>
        )}

        {/* ── BLUEPRINT — how we detected it + where it sits in ATT&CK ─────── */}
        {tab === "blueprint" && bp && (
          <div className="divide-y divide-gray-50">
            <div className="px-4 py-3">
              <div className="text-[9px] font-bold text-gray-400 uppercase tracking-wide mb-2 flex items-center gap-1.5"><Brain className="w-3 h-3 text-indigo-500" />Detection Logic</div>
              <p className="text-[10px] text-gray-700 leading-relaxed">{bp.detection_logic}</p>
              {bp.telemetry?.length > 0 && (
                <div className="flex flex-wrap gap-1 mt-2">
                  {bp.telemetry.map(t => <span key={t} className="px-2 py-0.5 bg-orange-50 border border-orange-200 text-orange-700 rounded text-[9px] font-mono font-semibold">{t}</span>)}
                </div>
              )}
              <Why>How AttackLens decided this is a finding, and which agent telemetry it used — so you can trust (or challenge) the detection.</Why>
            </div>
            <div className="px-4 py-3">
              <div className="text-[9px] font-bold text-gray-400 uppercase tracking-wide mb-2 flex items-center gap-1.5"><Target className="w-3 h-3 text-red-500" />MITRE ATT&CK</div>
              <p className="text-[10px] text-gray-700 bg-indigo-50 border border-indigo-100 rounded-xl px-3 py-2">{bp.attack_chain}</p>
              {f.mitre_technique && (
                <a href={`https://attack.mitre.org/techniques/${f.mitre_technique.replace(".","/")}`} target="_blank" rel="noopener noreferrer"
                  className="inline-flex items-center gap-1 mt-2 text-[9px] text-indigo-600 hover:text-indigo-800 font-semibold">
                  <ExternalLink className="w-2.5 h-2.5" />View {f.mitre_technique} on MITRE ATT&CK
                </a>
              )}
              <Why>The adversary technique this maps to — gives you the standard playbook for what the attacker is trying to achieve.</Why>
            </div>
          </div>
        )}

        {/* ── HUNT — find the same activity elsewhere + what comes next ────── */}
        {tab === "hunt" && bp && (
          <div className="divide-y divide-gray-50">
            <div className="px-4 py-3">
              <div className="text-[9px] font-bold text-gray-400 uppercase tracking-wide mb-3 flex items-center gap-1.5"><Crosshair className="w-3 h-3 text-orange-500" />Threat Hunting Queries</div>
              <div className="space-y-2">
                {bp.hunting_queries.map((q, i) => (
                  <div key={i} className="group relative al-row-in" style={{ animationDelay: `${i*60}ms` }}>
                    <pre className="text-[9px] font-mono text-green-400 bg-gray-900 rounded-xl px-3 py-2.5 overflow-x-auto whitespace-pre-wrap border border-gray-700">{q}</pre>
                    <button onClick={() => navigator.clipboard?.writeText(q)}
                      className="absolute top-1.5 right-2 opacity-0 group-hover:opacity-100 transition-opacity p-0.5 rounded bg-gray-700 hover:bg-gray-600">
                      <Copy className="w-2.5 h-2.5 text-gray-300" />
                    </button>
                  </div>
                ))}
              </div>
              <Why>Copy-paste queries to check whether the same activity is present on other hosts — turns one finding into a fleet-wide sweep.</Why>
            </div>
            <div className="px-4 py-3">
              <div className="text-[9px] font-bold text-gray-400 uppercase tracking-wide mb-2 flex items-center gap-1.5"><GitBranch className="w-3 h-3 text-red-500" />What Comes Next</div>
              <div className="bg-gradient-to-r from-red-50 to-amber-50 border border-amber-200 rounded-xl px-3 py-2.5">
                <p className="text-[10px] text-gray-800 font-medium">{bp.attack_chain}</p>
              </div>
              <Why>The likely next step in the attack — tells you what follow-on activity to hunt for before the attacker gets there.</Why>
            </div>
          </div>
        )}

        {(tab === "blueprint" || tab === "hunt") && !bp && (
          <div className="px-4 py-16 text-center">
            <Info className="w-6 h-6 text-gray-200 mx-auto mb-2" />
            <p className="text-[11px] text-gray-400">Detection blueprint not yet mapped for this category.</p>
          </div>
        )}
      </div>
      </div>
    </>,
    document.body
  );
}

// ── Filter bar ────────────────────────────────────────────────────────────────

export function DetectionFilters({
  agentId, onAgent, severity, onSeverity, search, onSearch, count, loading, refetch,
}: {
  agentId: string; onAgent: (v: string) => void;
  severity: string; onSeverity: (v: string) => void;
  search: string; onSearch: (v: string) => void;
  count: number; loading: boolean; refetch?: () => void;
}) {
  const debRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const [raw, setRaw] = useState(search);
  const handle = (v: string) => {
    setRaw(v);
    if (debRef.current) clearTimeout(debRef.current);
    debRef.current = setTimeout(() => onSearch(v), 280);
  };

  return (
    <div className="flex items-center gap-2 flex-wrap px-5 py-3 border-b border-gray-100 bg-gray-50/60">
      <Filter className="w-3.5 h-3.5 text-gray-400 flex-shrink-0" />
      <div className="relative">
        <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3 h-3 text-gray-400 pointer-events-none" />
        <input value={raw} onChange={e => handle(e.target.value)} placeholder="Search or type ID (AL-F-…)"
          className="pl-7 pr-3 py-1.5 text-[11px] border border-gray-200 rounded-xl bg-white text-gray-800 placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-orange-200 focus:border-orange-300 w-44 transition-all" />
      </div>
      <select value={severity} onChange={e => onSeverity(e.target.value)}
        className="px-2 py-1.5 text-[10px] border border-gray-200 rounded-xl bg-white text-gray-700 focus:outline-none focus:ring-1 focus:ring-orange-200 cursor-pointer">
        <option value="">All Severities</option>
        {["critical","high","medium","low","info"].map(s => (
          <option key={s} value={s}>{s[0].toUpperCase() + s.slice(1)}</option>
        ))}
      </select>
      <div className="ml-auto flex items-center gap-2">
        <div className="flex items-center gap-1.5 text-[10px] text-gray-400">
          <span className={cn("w-1.5 h-1.5 rounded-full", loading ? "bg-amber-400 animate-pulse" : "bg-green-500 al-heartbeat")} />
          {loading ? "Loading…" : `${count} finding${count !== 1 ? "s" : ""} · live`}
        </div>
        {refetch && (
          <button onClick={refetch} className="flex items-center gap-1 px-2.5 py-1.5 text-[10px] font-semibold rounded-xl bg-white hover:bg-orange-50 border border-gray-200 hover:border-orange-200 text-gray-600 hover:text-orange-600 transition-all">
            <RefreshCw className={cn("w-3 h-3", loading && "animate-spin")} />Refresh
          </button>
        )}
      </div>
    </div>
  );
}

// ── Generic detection page ────────────────────────────────────────────────────

interface GenericPageProps {
  title:    string;
  subtitle: string;
  apiUrl:   string;
  accent:   string;
  icon:     React.ReactNode;
  emptyMsg: string;
  columns:  { key: string; label: string; render?: (f: DetectionFinding) => React.ReactNode }[];
}

export function GenericDetectionPage({ title, subtitle, apiUrl, accent, icon, emptyMsg, columns }: GenericPageProps) {
  const [agentId,  setAgentId]  = useState("");
  const [severity, setSeverity] = useState("");
  const [search,   setSearch]   = useState("");
  const [selected, setSelected] = useState<DetectionFinding | null>(null);

  // ID Search detection: when the analyst types an ID (AL-F-00000515, 00000515,
  // or a bare number), switch to direct indexed external_id lookup instead of
  // full-text search.  The backend uses the UNIQUE index on external_id — O(log n).
  const isIdSearch = (q: string): boolean => {
    const t = q.trim();
    if (!t) return false;
    // Pattern: starts with AL-F-, or is purely numeric (internal id / external suffix)
    return /^AL-F-/i.test(t) || /^\d+$/.test(t);
  };

  const params: Record<string, string> = { limit: "200" };
  if (agentId)  params.agent_id = agentId;
  if (severity) params.severity = severity;
  if (search) {
    if (isIdSearch(search)) {
      params.id_search = search.trim();
    } else {
      params.search = search.trim();
    }
  }
  const url = `${apiUrl}?${new URLSearchParams(params)}`;

  const { findings, loading, error, refetch } = useDetectionData(url);

  const total    = findings.length;
  const critical = findings.filter(f => f.severity === "critical").length;
  const high     = findings.filter(f => f.severity === "high").length;
  const kev      = findings.filter(f => f.kev).length;
  const mitres   = [...new Set(findings.map(f => f.mitre_technique).filter(Boolean))].length;

  return (
    <div className="space-y-4 pb-6">
      {/* ── Header card ─────────────────────────────────────────────────── */}
      <div className="bg-white border border-gray-200 rounded-2xl shadow-sm overflow-hidden">
        {/* Orange pulse stripe */}
        <div className="h-1 bg-gradient-to-r from-orange-400 via-amber-400 to-orange-500 relative overflow-hidden">
          <div className="absolute inset-0 al-scan"
            style={{ background: "linear-gradient(90deg, transparent, rgba(255,255,255,0.6), transparent)", width: "40%" }} />
        </div>

        <div className="p-5">
          <div className="flex items-start justify-between gap-4">
            <div className="flex items-start gap-3">
              {/* Icon box with subtle glow */}
              <div className={cn("w-10 h-10 rounded-xl bg-orange-50 border border-orange-100 flex items-center justify-center flex-shrink-0 transition-shadow hover:shadow-md hover:shadow-orange-100")}>
                {icon}
              </div>
              <div>
                <h1 className="text-base font-bold text-gray-900">{title}</h1>
                <p className="text-xs text-gray-500 mt-0.5">{subtitle}</p>
              </div>
            </div>

            {/* Live indicator + refresh */}
            <div className="flex items-center gap-2 flex-shrink-0">
              <div className="flex items-center gap-1.5 px-3 py-1.5 bg-gray-50 border border-gray-200 rounded-xl">
                <span className="w-1.5 h-1.5 rounded-full bg-green-500 al-heartbeat flex-shrink-0" />
                <ECGWave />
                <span className="text-[9px] text-gray-500 font-semibold uppercase tracking-wide">LIVE</span>
              </div>
              <button onClick={refetch}
                className="flex items-center gap-1.5 px-3 py-2 rounded-xl bg-gray-100 hover:bg-orange-50 hover:border-orange-200 border border-gray-200 text-gray-600 hover:text-orange-600 text-xs font-semibold transition-all">
                <RefreshCw className={cn("w-3.5 h-3.5", loading && "animate-spin")} />
              </button>
            </div>
          </div>

          {/* KPI tiles — animated count-up */}
          <div className="grid grid-cols-5 gap-2.5 mt-4 pt-4 border-t border-gray-100">
            <KpiTile label="Total Findings"   value={total}    color="info"     delay={0}   icon={<Activity className="w-3 h-3" />} />
            <KpiTile label="Critical"         value={critical} color="critical" delay={60}  icon={<AlertTriangle className="w-3 h-3" />} />
            <KpiTile label="High"             value={high}     color="high"     delay={120} icon={<Zap className="w-3 h-3" />} />
            <KpiTile label="KEV Listed"       value={kev}      color={kev > 0 ? "critical" : "info"} delay={180} icon={<Radio className="w-3 h-3" />} />
            <KpiTile label="MITRE Techniques" value={mitres}   color="medium"   delay={240} icon={<Target className="w-3 h-3" />} />
          </div>
        </div>
      </div>

      {error && (
        <div className="px-4 py-3 bg-red-50 border border-red-200 rounded-2xl text-xs text-red-700 flex items-center gap-2 al-row-in">
          <AlertTriangle className="w-3.5 h-3.5 flex-shrink-0" />{error}
        </div>
      )}

      {/* ── Table card ──────────────────────────────────────────────────────── */}
      <div className="bg-white border border-gray-200 rounded-2xl shadow-sm overflow-hidden">
          <div className="h-0.5 bg-gradient-to-r from-orange-400 via-amber-400 to-orange-500" />

          <DetectionFilters
            agentId={agentId} onAgent={setAgentId}
            severity={severity} onSeverity={setSeverity}
            search={search} onSearch={setSearch}
            count={total} loading={loading}
            refetch={refetch}
          />

          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="bg-gray-50/80 border-b border-gray-100">
                  <th className="pl-4 pr-2 py-2.5 w-10" />
                  <th className="px-2 py-2.5 text-left text-[9px] font-black text-gray-400 uppercase tracking-wider">ID</th>
                  <th className="px-3 py-2.5 text-left text-[9px] font-black text-gray-400 uppercase tracking-wider">Finding</th>
                  {columns.map(c => (
                    <th key={c.key} className="px-3 py-2.5 text-left text-[9px] font-black text-gray-400 uppercase tracking-wider whitespace-nowrap">{c.label}</th>
                  ))}
                  <th className="px-3 py-2.5 text-left text-[9px] font-black text-gray-400 uppercase tracking-wider whitespace-nowrap">Exploitability</th>
                  <th className="px-3 py-2.5 text-left text-[9px] font-black text-gray-400 uppercase tracking-wider">Confidence</th>
                  <th className="px-3 py-2.5 text-left text-[9px] font-black text-gray-400 uppercase tracking-wider">Agent</th>
                  <th className="px-3 py-2.5 text-left text-[9px] font-black text-gray-400 uppercase tracking-wider">Last Seen</th>
                  <th className="pr-3 py-2.5 w-6" />
                </tr>
              </thead>
              <tbody>
                {loading && findings.length === 0 ? (
                  /* Skeleton rows */
                  Array.from({ length: 5 }).map((_, i) => (
                    <tr key={i} className="border-b border-gray-50">
                      {Array.from({ length: columns.length + 6 }).map((_, j) => (
                        <td key={j} className="px-3 py-3">
                          <div className="h-3 bg-gray-100 rounded-full animate-pulse" style={{ width: j === 1 ? "70%" : "40%", animationDelay: `${i * 80 + j * 40}ms` }} />
                        </td>
                      ))}
                    </tr>
                  ))
                ) : findings.length === 0 ? (
                  <tr>
                    <td colSpan={columns.length + 7} className="py-20 text-center">
                      <Shield className="w-10 h-10 text-gray-200 mx-auto mb-3" />
                      <p className="text-[11px] text-gray-400 font-semibold">{emptyMsg}</p>
                    </td>
                  </tr>
                ) : (
                  findings.map((f, idx) => {
                    const s    = SEV[f.severity] ?? SEV.info;
                    const isSel = selected?.id === f.id;
                    const isCrit = f.severity === "critical";

                    return (
                      <tr key={f.id}
                        onClick={() => setSelected(isSel ? null : f)}
                        className={cn(
                          "border-b border-gray-100/80 cursor-pointer transition-all duration-150 al-row-in",
                          isSel ? "row-selected" : [s.rowBase, s.rowHover],
                          isCrit && !isSel && "al-glow-critical",
                        )}
                        style={{ animationDelay: `${Math.min(idx * 30, 400)}ms` }}
                      >
                        {/* Severity dot — sonar for critical */}
                        <td className="pl-4 pr-2 py-3 w-10">
                          <SevDot sev={f.severity} />
                        </td>

                        {/* ID column — unique incident identifier */}
                        <td className="px-2 py-3">
                          <IdChip f={f} />
                        </td>

                        {/* Title + badge chips */}
                        <td className="px-3 py-3 max-w-[260px]">
                          <div className="flex items-center gap-1.5 mb-1">
                            <div className="text-[11px] font-semibold text-gray-800 leading-tight truncate">{f.title}</div>
                          </div>
                          <div className="flex items-center gap-1 flex-wrap">
                            <SevBadge sev={f.severity} />
                            <StatusChip status={f.status} />
                            {f.kev && <KevChip />}
                            <PrecisionChip score={f.precision_score} />
                            <ValidatedBadge f={f} />
                            {f.exploit_available && <ExploitChip />}
                            {f.mitre_technique && <MitreChip t={f.mitre_technique} />}
                          </div>
                        </td>

                        {columns.map(c => (
                          <td key={c.key} className="px-3 py-3">
                            {c.render ? c.render(f) : <span className="text-[10px] text-gray-600">{String((f as Record<string, unknown>)[c.key] ?? "—")}</span>}
                          </td>
                        ))}

                        {/* Exploitability + prioritization */}
                        <td className="px-3 py-3">
                          <ExploitabilityCell f={f} />
                        </td>

                        {/* Animated confidence bar */}
                        <td className="px-3 py-3 w-28">
                          <ConfBar pct={f.confidence_pct ?? 70} sev={f.severity} />
                        </td>

                        <td className="px-3 py-3 text-[10px] font-mono text-gray-400">{f.agent_id?.slice(0, 12)}</td>
                        <td className="px-3 py-3 text-[10px] text-gray-400 whitespace-nowrap">{fmtTs(f.last_detected_at)}</td>
                        <td className="pr-3 py-3 text-gray-300">
                          {isSel
                            ? <ChevronDown className="w-3.5 h-3.5 text-orange-400" />
                            : <ChevronRight className="w-3.5 h-3.5 opacity-0 group-hover:opacity-100 transition-opacity" />}
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>

          {/* Footer */}
          {findings.length > 0 && (
            <div className="px-5 py-2.5 border-t border-gray-100 bg-gray-50/60 flex items-center justify-between">
              <div className="flex items-center gap-3 text-[10px]">
                <span className="font-bold text-gray-700">{total} findings</span>
                {critical > 0 && <span className="text-red-600 font-bold flex items-center gap-1"><span className="w-1.5 h-1.5 rounded-full bg-red-500 animate-pulse inline-block" />{critical} critical</span>}
                {high > 0     && <span className="text-amber-600 font-semibold">{high} high</span>}
                {kev > 0      && <span className="text-red-700 font-black bg-red-50 px-2 py-0.5 rounded-full border border-red-200">{kev} KEV</span>}
              </div>
              <span className="text-[10px] text-gray-400">Click row → detection detail</span>
            </div>
          )}
      </div>

      {/* Fixed right-side drawer — portaled to body */}
      {selected && <FindingDetail finding={selected} onClose={() => setSelected(null)} onChanged={refetch} />}
    </div>
  );
}

// ── Advanced field filter (operators) ─────────────────────────────────────────
// Reusable across every findings view (Origin / Vector / Citadel / Incidents /
// Validated Findings). Lets an analyst build precise field+operator conditions,
// ANDed together, on top of the quick filters.

export type FilterOp =
  | "is" | "is_not" | "contains" | "not_contains" | "exists" | "not_exists";

export interface FilterCondition {
  id:    string;
  field: string;
  op:    FilterOp;
  value: string;
}

export const FILTER_OPS: { op: FilterOp; label: string; needsValue: boolean }[] = [
  { op: "is",           label: "is",           needsValue: true  },
  { op: "is_not",       label: "is not",       needsValue: true  },
  { op: "contains",     label: "contains",     needsValue: true  },
  { op: "not_contains", label: "not contains", needsValue: true  },
  { op: "exists",       label: "exists",       needsValue: false },
  { op: "not_exists",   label: "not exists",   needsValue: false },
];

// Fields an analyst can build conditions on (keys map to DetectionFinding props).
export const FILTER_FIELDS: { key: string; label: string }[] = [
  { key: "title",            label: "Title" },
  { key: "description",      label: "Description" },
  { key: "severity",         label: "Severity" },
  { key: "category",         label: "Category" },
  { key: "status",           label: "Status" },
  { key: "agent_id",         label: "Agent" },
  { key: "source",           label: "Source" },
  { key: "mitre_technique",  label: "MITRE Technique" },
  { key: "mitre_tactic",     label: "MITRE Tactic" },
  { key: "cve_ids",          label: "CVE" },
  { key: "composite_score",  label: "Risk Score" },
  { key: "cvss_score",       label: "CVSS" },
  { key: "epss_score",       label: "EPSS" },
  { key: "confidence_pct",   label: "Confidence %" },
  { key: "kev",              label: "KEV" },
  { key: "exploit_available",label: "Exploit Available" },
];

export function newCondition(): FilterCondition {
  return { id: Math.random().toString(36).slice(2), field: "title", op: "contains", value: "" };
}

function opNeedsValue(op: FilterOp): boolean {
  return FILTER_OPS.find(o => o.op === op)?.needsValue ?? true;
}

// A condition is "active" (worth applying) once it has a field and either a
// value-less operator or a non-empty value.
function condActive(c: FilterCondition): boolean {
  return !!c.field && (!opNeedsValue(c.op) || c.value.trim() !== "");
}

function matchCondition(f: DetectionFinding, c: FilterCondition): boolean {
  const raw = (f as Record<string, unknown>)[c.field];

  const present =
    raw !== null && raw !== undefined && raw !== "" &&
    !(Array.isArray(raw) && raw.length === 0);

  if (c.op === "exists")     return present;
  if (c.op === "not_exists") return !present;

  // Normalise the candidate to a list of lowercased strings (handles arrays
  // like cve_ids, numbers, booleans).
  const hay: string[] = Array.isArray(raw)
    ? raw.map(x => String(x).toLowerCase())
    : raw === null || raw === undefined ? [] : [String(raw).toLowerCase()];

  const needle = c.value.trim().toLowerCase();
  if (needle === "") return true;   // nothing typed yet → don't constrain

  switch (c.op) {
    case "is":           return hay.some(h => h === needle);
    case "is_not":       return !hay.some(h => h === needle);   // absent ⇒ true
    case "contains":     return hay.some(h => h.includes(needle));
    case "not_contains": return !hay.some(h => h.includes(needle));
    default:             return true;
  }
}

// Pure: apply all active conditions with AND semantics.
export function applyAdvancedConditions<T extends DetectionFinding>(
  items: T[], conditions: FilterCondition[],
): T[] {
  const active = conditions.filter(condActive);
  if (active.length === 0) return items;
  return items.filter(f => active.every(c => matchCondition(f, c)));
}

export function activeConditionCount(conditions: FilterCondition[]): number {
  return conditions.filter(condActive).length;
}

// Collapsible builder UI. Controlled via conditions / setConditions.
export function AdvancedFilter({
  conditions, setConditions,
}: {
  conditions:    FilterCondition[];
  setConditions: React.Dispatch<React.SetStateAction<FilterCondition[]>>;
}) {
  const [open, setOpen] = useState(false);
  const activeCount = activeConditionCount(conditions);

  const update = (id: string, patch: Partial<FilterCondition>) =>
    setConditions(prev => prev.map(c => (c.id === id ? { ...c, ...patch } : c)));
  const remove = (id: string) =>
    setConditions(prev => prev.filter(c => c.id !== id));
  const add = () => setConditions(prev => [...prev, newCondition()]);

  return (
    <div className="relative">
      <button
        onClick={() => { if (!open && conditions.length === 0) add(); setOpen(o => !o); }}
        className={cn(
          "flex items-center gap-1 px-2.5 py-1.5 text-[10px] font-bold rounded-xl border transition-all",
          activeCount > 0
            ? "bg-orange-600 text-white border-orange-600 shadow-sm"
            : "bg-white text-gray-600 border-gray-200 hover:border-orange-300 hover:text-orange-600",
        )}
      >
        <SlidersHorizontal className="w-3 h-3" />
        Advanced
        {activeCount > 0 && (
          <span className="ml-0.5 px-1.5 py-px rounded-full bg-white/25 text-[9px] tabular-nums">{activeCount}</span>
        )}
      </button>

      {open && (
        <div className="absolute z-30 mt-1.5 left-0 w-[420px] max-w-[88vw] bg-white border border-gray-200 rounded-2xl shadow-xl p-3">
          <div className="flex items-center justify-between mb-2">
            <span className="text-[10px] font-black text-gray-500 uppercase tracking-wider">Advanced filter · all conditions match</span>
            <button onClick={() => setOpen(false)} className="text-gray-400 hover:text-gray-700"><X className="w-3.5 h-3.5" /></button>
          </div>

          <div className="space-y-1.5 max-h-[40vh] overflow-y-auto">
            {conditions.length === 0 && (
              <p className="text-[10px] text-gray-400 py-2 text-center">No conditions. Add one to filter precisely.</p>
            )}
            {conditions.map(c => {
              const needsValue = opNeedsValue(c.op);
              return (
                <div key={c.id} className="flex items-center gap-1.5">
                  <select value={c.field} onChange={e => update(c.id, { field: e.target.value })}
                    className="px-2 py-1.5 text-[10px] border border-gray-200 rounded-lg bg-white text-gray-700 focus:outline-none focus:ring-1 focus:ring-orange-200 cursor-pointer w-[34%]">
                    {FILTER_FIELDS.map(f => <option key={f.key} value={f.key}>{f.label}</option>)}
                  </select>
                  <select value={c.op} onChange={e => update(c.id, { op: e.target.value as FilterOp })}
                    className="px-2 py-1.5 text-[10px] border border-gray-200 rounded-lg bg-white text-gray-700 focus:outline-none focus:ring-1 focus:ring-orange-200 cursor-pointer w-[30%]">
                    {FILTER_OPS.map(o => <option key={o.op} value={o.op}>{o.label}</option>)}
                  </select>
                  <input
                    value={needsValue ? c.value : ""}
                    onChange={e => update(c.id, { value: e.target.value })}
                    disabled={!needsValue}
                    placeholder={needsValue ? "value…" : "—"}
                    className="flex-1 min-w-0 px-2 py-1.5 text-[10px] border border-gray-200 rounded-lg bg-white text-gray-800 placeholder-gray-300 focus:outline-none focus:ring-1 focus:ring-orange-200 disabled:bg-gray-50 disabled:text-gray-300" />
                  <button onClick={() => remove(c.id)} className="p-1 text-gray-300 hover:text-red-500 transition-colors flex-shrink-0">
                    <Trash2 className="w-3.5 h-3.5" />
                  </button>
                </div>
              );
            })}
          </div>

          <div className="flex items-center justify-between mt-2 pt-2 border-t border-gray-100">
            <button onClick={add} className="flex items-center gap-1 text-[10px] font-semibold text-orange-600 hover:text-orange-700">
              <Plus className="w-3 h-3" /> Add condition
            </button>
            {conditions.length > 0 && (
              <button onClick={() => setConditions([])} className="text-[10px] font-semibold text-gray-400 hover:text-red-500">
                Clear all
              </button>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

// ── Terrain filter types ──────────────────────────────────────────────────────

type SortKey = "risk" | "cvss" | "epss" | "first_seen" | "last_seen";

interface TerrainFilterState {
  severity:       string;
  search:         string;
  agentId:        string;
  mitreFilter:    string;
  categoryFilter: string;
  statusFilter:   string;
  kevOnly:        boolean;
  exploitOnly:    boolean;
  sortBy:         SortKey;
  sortDir:        "asc" | "desc";
}

const DEFAULT_TERRAIN_FILTERS: TerrainFilterState = {
  severity: "", search: "", agentId: "", mitreFilter: "",
  categoryFilter: "", statusFilter: "", kevOnly: false, exploitOnly: false,
  sortBy: "risk", sortDir: "desc",
};

// ── Terrain rich filter bar ───────────────────────────────────────────────────

function TerrainFilterBar({
  filters, setFilters, adv, setAdv, mitreTactics, categories, count, filtered, loading, refetch,
}: {
  filters:      TerrainFilterState;
  setFilters:   React.Dispatch<React.SetStateAction<TerrainFilterState>>;
  adv:          FilterCondition[];
  setAdv:       React.Dispatch<React.SetStateAction<FilterCondition[]>>;
  mitreTactics: string[];
  categories:   string[];
  count:        number;
  filtered:     number;
  loading:      boolean;
  refetch:      () => void;
}) {
  const debRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const [rawSearch, setRawSearch] = useState(filters.search);

  const set = <K extends keyof TerrainFilterState>(key: K, value: TerrainFilterState[K]) =>
    setFilters(prev => ({ ...prev, [key]: value }));

  const handleSearch = (v: string) => {
    setRawSearch(v);
    if (debRef.current) clearTimeout(debRef.current);
    debRef.current = setTimeout(() => set("search", v), 280);
  };

  const clearAll = () => {
    setFilters(DEFAULT_TERRAIN_FILTERS);
    setAdv([]);
    setRawSearch("");
  };

  const chips: { label: string; onRemove: () => void }[] = [
    ...(filters.severity       ? [{ label: `Sev: ${filters.severity}`,        onRemove: () => set("severity",       "") }] : []),
    ...(filters.mitreFilter    ? [{ label: `MITRE: ${filters.mitreFilter}`,    onRemove: () => set("mitreFilter",    "") }] : []),
    ...(filters.categoryFilter ? [{ label: `Cat: ${filters.categoryFilter}`,   onRemove: () => set("categoryFilter", "") }] : []),
    ...(filters.statusFilter   ? [{ label: `Status: ${filters.statusFilter}`,  onRemove: () => set("statusFilter",   "") }] : []),
    ...(filters.agentId        ? [{ label: `Agent: ${filters.agentId}`,        onRemove: () => set("agentId",        "") }] : []),
    ...(filters.kevOnly        ? [{ label: "KEV Only",    onRemove: () => set("kevOnly",     false) }] : []),
    ...(filters.exploitOnly    ? [{ label: "Exploit Only",onRemove: () => set("exploitOnly", false) }] : []),
  ];

  return (
    <div className="border-b border-gray-100 bg-gray-50/60">
      <div className="flex items-center gap-2 flex-wrap px-4 py-2.5">
        <Filter className="w-3.5 h-3.5 text-gray-400 flex-shrink-0" />

        {/* Search */}
        <div className="relative">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3 h-3 text-gray-400 pointer-events-none" />
          <input value={rawSearch} onChange={e => handleSearch(e.target.value)} placeholder="Search or type ID (AL-F-…)"
            className="pl-7 pr-3 py-1.5 text-[11px] border border-gray-200 rounded-xl bg-white text-gray-800 placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-orange-200 focus:border-orange-300 w-40 transition-all" />
        </div>

        {/* Severity */}
        <select value={filters.severity} onChange={e => set("severity", e.target.value)}
          className="px-2 py-1.5 text-[10px] border border-gray-200 rounded-xl bg-white text-gray-700 focus:outline-none focus:ring-1 focus:ring-orange-200 cursor-pointer">
          <option value="">All Severities</option>
          {["critical","high","medium","low","info"].map(s => (
            <option key={s} value={s}>{s[0].toUpperCase() + s.slice(1)}</option>
          ))}
        </select>

        {/* MITRE Tactic */}
        {mitreTactics.length > 0 && (
          <select value={filters.mitreFilter} onChange={e => set("mitreFilter", e.target.value)}
            className="px-2 py-1.5 text-[10px] border border-gray-200 rounded-xl bg-white text-gray-700 focus:outline-none focus:ring-1 focus:ring-orange-200 cursor-pointer max-w-[130px] truncate">
            <option value="">All Tactics</option>
            {mitreTactics.map(t => <option key={t} value={t}>{t}</option>)}
          </select>
        )}

        {/* Category */}
        {categories.length > 0 && (
          <select value={filters.categoryFilter} onChange={e => set("categoryFilter", e.target.value)}
            className="px-2 py-1.5 text-[10px] border border-gray-200 rounded-xl bg-white text-gray-700 focus:outline-none focus:ring-1 focus:ring-orange-200 cursor-pointer max-w-[120px] truncate">
            <option value="">All Categories</option>
            {categories.map(c => <option key={c} value={c}>{c}</option>)}
          </select>
        )}

        {/* KEV Only */}
        <button onClick={() => set("kevOnly", !filters.kevOnly)}
          className={cn(
            "flex items-center gap-1 px-2.5 py-1.5 text-[10px] font-bold rounded-xl border transition-all",
            filters.kevOnly
              ? "bg-red-600 text-white border-red-600 shadow-sm"
              : "bg-white text-gray-600 border-gray-200 hover:border-red-300 hover:text-red-600"
          )}>
          <Radio className="w-3 h-3" />KEV
        </button>

        {/* Exploit Only */}
        <button onClick={() => set("exploitOnly", !filters.exploitOnly)}
          className={cn(
            "flex items-center gap-1 px-2.5 py-1.5 text-[10px] font-bold rounded-xl border transition-all",
            filters.exploitOnly
              ? "bg-amber-500 text-white border-amber-500 shadow-sm"
              : "bg-white text-gray-600 border-gray-200 hover:border-amber-300 hover:text-amber-600"
          )}>
          <Zap className="w-3 h-3" />Exploit
        </button>

        {/* Advanced field+operator filter */}
        <AdvancedFilter conditions={adv} setConditions={setAdv} />

        {/* Sort */}
        <div className="flex items-center gap-1">
          <select value={filters.sortBy} onChange={e => set("sortBy", e.target.value as SortKey)}
            className="px-2 py-1.5 text-[10px] border border-gray-200 rounded-xl bg-white text-gray-700 focus:outline-none focus:ring-1 focus:ring-orange-200 cursor-pointer">
            <option value="risk">Risk Score</option>
            <option value="cvss">CVSS</option>
            <option value="epss">EPSS</option>
            <option value="first_seen">First Seen</option>
            <option value="last_seen">Last Seen</option>
          </select>
          <button onClick={() => set("sortDir", filters.sortDir === "desc" ? "asc" : "desc")}
            title={filters.sortDir === "desc" ? "Descending" : "Ascending"}
            className="p-1.5 rounded-xl border border-gray-200 bg-white hover:bg-orange-50 text-gray-500 hover:text-orange-600 transition-all">
            <TrendingUp className={cn("w-3 h-3 transition-transform", filters.sortDir === "asc" && "rotate-180")} />
          </button>
        </div>

        {/* Right: live count + refresh */}
        <div className="ml-auto flex items-center gap-2">
          <div className="flex items-center gap-1.5 text-[10px] text-gray-400">
            <span className={cn("w-1.5 h-1.5 rounded-full", loading ? "bg-amber-400 animate-pulse" : "bg-green-500 al-heartbeat")} />
            {loading ? "Loading…" : `${filtered} of ${count} findings`}
          </div>
          <button onClick={refetch} className="flex items-center gap-1 px-2.5 py-1.5 text-[10px] font-semibold rounded-xl bg-white hover:bg-orange-50 border border-gray-200 hover:border-orange-200 text-gray-600 hover:text-orange-600 transition-all">
            <RefreshCw className={cn("w-3 h-3", loading && "animate-spin")} />Refresh
          </button>
        </div>
      </div>

      {/* Active filter chips */}
      {chips.length > 0 && (
        <div className="flex items-center gap-1.5 flex-wrap px-4 pb-2">
          {chips.map((chip, i) => (
            <span key={i} className="inline-flex items-center gap-1 px-2 py-0.5 bg-orange-50 border border-orange-200 text-orange-700 rounded-full text-[9px] font-semibold">
              {chip.label}
              <button onClick={chip.onRemove} className="ml-0.5 hover:text-red-600 transition-colors">
                <X className="w-2.5 h-2.5" />
              </button>
            </span>
          ))}
          <button onClick={clearAll} className="text-[9px] text-gray-400 hover:text-red-500 font-semibold transition-colors px-1">
            Clear all
          </button>
        </div>
      )}
    </div>
  );
}

// ── Terrain detection page (replaces GenericDetectionPage for terrain views) ──

export interface TerrainPageProps {
  title:    string;
  subtitle: string;
  apiUrl:   string;
  accent:   string;
  icon:     React.ReactNode;
  emptyMsg: string;
  columns:  { key: string; label: string; render?: (f: DetectionFinding) => React.ReactNode }[];
}

export function TerrainDetectionPage({ title, subtitle, apiUrl, accent, icon, emptyMsg, columns }: TerrainPageProps) {
  const PAGE_SIZE = 25;

  const [filters, setFilters] = useState<TerrainFilterState>(DEFAULT_TERRAIN_FILTERS);
  const [adv, setAdv] = useState<FilterCondition[]>([]);
  const [selected, setSelected] = useState<DetectionFinding | null>(null);
  const [page, setPage] = useState(1);

  const qs = apiUrl.includes("?") ? `&limit=500` : `?limit=500`;
  const { findings: raw, loading, error, refetch } = useDetectionData(`${apiUrl}${qs}`);

  // Dynamic dropdown options built from live data
  const mitreTactics = useMemo(() =>
    [...new Set(raw.map(f => f.mitre_tactic).filter((t): t is string => !!t))].sort(),
  [raw]);

  const categories = useMemo(() =>
    [...new Set(raw.map(f => f.category).filter((c): c is string => !!c))].sort(),
  [raw]);

  // Client-side filter + sort
  const filtered = useMemo(() => {
    let r = raw;
    if (filters.severity)       r = r.filter(f => f.severity === filters.severity);
    if (filters.kevOnly)        r = r.filter(f => f.kev);
    if (filters.exploitOnly)    r = r.filter(f => f.exploit_available);
    if (filters.mitreFilter)    r = r.filter(f => f.mitre_tactic === filters.mitreFilter || f.mitre_technique?.includes(filters.mitreFilter));
    if (filters.categoryFilter) r = r.filter(f => f.category === filters.categoryFilter);
    if (filters.statusFilter)   r = r.filter(f => f.status === filters.statusFilter);
    if (filters.agentId)        r = r.filter(f => f.agent_id?.toLowerCase().includes(filters.agentId.toLowerCase()));
    if (filters.search) {
      const q = filters.search.toLowerCase().trim();
      // ID Search: when the analyst types an ID pattern (AL-F-00000515 or 00000515),
      // match against external_id / display_id first for instant indexed lookup feel.
      const isId = /^al-f-|^\d+$/.test(q);
      const cveArr = (f: DetectionFinding) => Array.isArray(f.cve_ids) ? f.cve_ids : [];
      r = r.filter(f => {
        // ID search: prefix-match external_id for fast narrowing as the user types
        if (isId) {
          const ext = (f.external_id || "").toLowerCase();
          if (ext.startsWith(q) || ext.includes(q)) return true;
        }
        return (
          f.title?.toLowerCase().includes(q) ||
          f.description?.toLowerCase().includes(q) ||
          f.category?.toLowerCase().includes(q) ||
          f.source?.toLowerCase().includes(q) ||
          (f.external_id || "").toLowerCase().includes(q) ||
          cveArr(f).some(c => c.toLowerCase().includes(q))
        );
      });
      // ID search: sort exact matches first
      if (isId) {
        r = [...r].sort((a, b) => {
          const ae = (a.external_id || "").toLowerCase();
          const be = (b.external_id || "").toLowerCase();
          if (ae === q && be !== q) return -1;
          if (be === q && ae !== q) return 1;
          return ae.length - be.length;
        });
      }
    }

    // Advanced field+operator conditions (ANDed on top of quick filters)
    r = applyAdvancedConditions(r, adv);

    return [...r].sort((a, b) => {
      let av = 0, bv = 0;
      switch (filters.sortBy) {
        case "risk":       av = a.composite_score ?? a.score; bv = b.composite_score ?? b.score; break;
        case "cvss":       av = a.cvss_score  ?? 0;           bv = b.cvss_score  ?? 0;           break;
        case "epss":       av = a.epss_score  ?? 0;           bv = b.epss_score  ?? 0;           break;
        case "first_seen": av = a.first_detected_at;          bv = b.first_detected_at;          break;
        case "last_seen":  av = a.last_detected_at;           bv = b.last_detected_at;           break;
      }
      return filters.sortDir === "desc" ? bv - av : av - bv;
    });
  }, [raw, filters, adv]);

  // Reset page when filters change
  useEffect(() => setPage(1), [
    filters.severity, filters.search, filters.mitreFilter,
    filters.categoryFilter, filters.kevOnly, filters.exploitOnly,
    filters.statusFilter, filters.agentId, adv,
  ]);

  const totalPages = Math.ceil(filtered.length / PAGE_SIZE);
  const paginated  = filtered.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);

  // KPIs always from full raw set
  const kpiTotal    = raw.length;
  const kpiCritical = raw.filter(f => f.severity === "critical").length;
  const kpiHigh     = raw.filter(f => f.severity === "high").length;
  const kpiKev      = raw.filter(f => f.kev).length;
  const kpiMitres   = [...new Set(raw.map(f => f.mitre_technique).filter(Boolean))].length;

  return (
    <div className="space-y-4 pb-6">
      {/* Header card */}
      <div className="bg-white border border-gray-200 rounded-2xl shadow-sm overflow-hidden">
        <div className="h-1 bg-gradient-to-r from-orange-400 via-amber-400 to-orange-500 relative overflow-hidden">
          <div className="absolute inset-0 al-scan"
            style={{ background: "linear-gradient(90deg, transparent, rgba(255,255,255,0.6), transparent)", width: "40%" }} />
        </div>
        <div className="p-5">
          <div className="flex items-start justify-between gap-4">
            <div className="flex items-start gap-3">
              <div className="w-10 h-10 rounded-xl bg-orange-50 border border-orange-100 flex items-center justify-center flex-shrink-0">
                {icon}
              </div>
              <div>
                <h1 className="text-base font-bold text-gray-900">{title}</h1>
                <p className="text-xs text-gray-500 mt-0.5">{subtitle}</p>
              </div>
            </div>
            <div className="flex items-center gap-2 flex-shrink-0">
              <div className="flex items-center gap-1.5 px-3 py-1.5 bg-gray-50 border border-gray-200 rounded-xl">
                <span className="w-1.5 h-1.5 rounded-full bg-green-500 al-heartbeat flex-shrink-0" />
                <ECGWave />
                <span className="text-[9px] text-gray-500 font-semibold uppercase tracking-wide">LIVE</span>
              </div>
              <button onClick={refetch}
                className="flex items-center gap-1.5 px-3 py-2 rounded-xl bg-gray-100 hover:bg-orange-50 hover:border-orange-200 border border-gray-200 text-gray-600 hover:text-orange-600 text-xs font-semibold transition-all">
                <RefreshCw className={cn("w-3.5 h-3.5", loading && "animate-spin")} />
              </button>
            </div>
          </div>
          <div className="grid grid-cols-5 gap-2.5 mt-4 pt-4 border-t border-gray-100">
            <KpiTile label="Total Findings"   value={kpiTotal}    color="info"                      delay={0}   icon={<Activity className="w-3 h-3" />} />
            <KpiTile label="Critical"         value={kpiCritical} color="critical"                  delay={60}  icon={<AlertTriangle className="w-3 h-3" />} />
            <KpiTile label="High"             value={kpiHigh}     color="high"                      delay={120} icon={<Zap className="w-3 h-3" />} />
            <KpiTile label="KEV Listed"       value={kpiKev}      color={kpiKev > 0 ? "critical" : "info"} delay={180} icon={<Radio className="w-3 h-3" />} />
            <KpiTile label="MITRE Techniques" value={kpiMitres}   color="medium"                    delay={240} icon={<Target className="w-3 h-3" />} />
          </div>
        </div>
      </div>

      {error && (
        <div className="px-4 py-3 bg-red-50 border border-red-200 rounded-2xl text-xs text-red-700 flex items-center gap-2 al-row-in">
          <AlertTriangle className="w-3.5 h-3.5 flex-shrink-0" />{error}
        </div>
      )}

      <div className="bg-white border border-gray-200 rounded-2xl shadow-sm overflow-hidden">
          <div className="h-0.5 bg-gradient-to-r from-orange-400 via-amber-400 to-orange-500" />

          <TerrainFilterBar
            filters={filters} setFilters={setFilters}
            adv={adv} setAdv={setAdv}
            mitreTactics={mitreTactics} categories={categories}
            count={kpiTotal} filtered={filtered.length}
            loading={loading} refetch={refetch}
          />

          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="bg-gray-50/80 border-b border-gray-100">
                  <th className="pl-4 pr-2 py-2.5 w-10" />
                  <th className="px-2 py-2.5 text-left text-[9px] font-black text-gray-400 uppercase tracking-wider">ID</th>
                  <th className="px-3 py-2.5 text-left text-[9px] font-black text-gray-400 uppercase tracking-wider">Finding</th>
                  {columns.map(c => (
                    <th key={c.key} className="px-3 py-2.5 text-left text-[9px] font-black text-gray-400 uppercase tracking-wider whitespace-nowrap">{c.label}</th>
                  ))}
                  <th className="px-3 py-2.5 text-left text-[9px] font-black text-gray-400 uppercase tracking-wider whitespace-nowrap">Exploitability</th>
                  <th className="px-3 py-2.5 text-left text-[9px] font-black text-gray-400 uppercase tracking-wider">Confidence</th>
                  <th className="px-3 py-2.5 text-left text-[9px] font-black text-gray-400 uppercase tracking-wider">Agent</th>
                  <th className="px-3 py-2.5 text-left text-[9px] font-black text-gray-400 uppercase tracking-wider">Last Seen</th>
                  <th className="pr-3 py-2.5 w-6" />
                </tr>
              </thead>
              <tbody>
                {loading && paginated.length === 0 ? (
                  Array.from({ length: 5 }).map((_, i) => (
                    <tr key={i} className="border-b border-gray-50">
                      {Array.from({ length: columns.length + 6 }).map((_, j) => (
                        <td key={j} className="px-3 py-3">
                          <div className="h-3 bg-gray-100 rounded-full animate-pulse" style={{ width: j === 1 ? "70%" : "40%", animationDelay: `${i * 80 + j * 40}ms` }} />
                        </td>
                      ))}
                    </tr>
                  ))
                ) : paginated.length === 0 ? (
                  <tr>
                    <td colSpan={columns.length + 7} className="py-20 text-center">
                      <Shield className="w-10 h-10 text-gray-200 mx-auto mb-3" />
                      <p className="text-[11px] text-gray-400 font-semibold">
                        {raw.length === 0 ? emptyMsg : "No findings match the current filters."}
                      </p>
                      {raw.length > 0 && (
                        <button onClick={() => setFilters(DEFAULT_TERRAIN_FILTERS)}
                          className="mt-2 text-[10px] text-orange-500 hover:text-orange-700 font-semibold transition-colors">
                          Clear all filters
                        </button>
                      )}
                    </td>
                  </tr>
                ) : (
                  paginated.map((f, idx) => {
                    const s     = SEV[f.severity] ?? SEV.info;
                    const isSel = selected?.id === f.id;
                    const isCrit = f.severity === "critical";
                    return (
                      <tr key={f.id}
                        onClick={() => setSelected(isSel ? null : f)}
                        className={cn(
                          "border-b border-gray-100/80 cursor-pointer transition-all duration-150 al-row-in",
                          isSel ? "row-selected" : [s.rowBase, s.rowHover],
                          isCrit && !isSel && "al-glow-critical",
                        )}
                        style={{ animationDelay: `${Math.min(idx * 30, 400)}ms` }}
                      >
                        <td className="pl-4 pr-2 py-3 w-10"><SevDot sev={f.severity} /></td>
                        <td className="px-3 py-3 max-w-[260px]">
                          <div className="text-[11px] font-semibold text-gray-800 leading-tight truncate mb-1">{f.title}</div>
                          <div className="flex items-center gap-1 flex-wrap">
                            <SevBadge sev={f.severity} />
                            {f.kev && <KevChip />}
                            <PrecisionChip score={f.precision_score} />
                            <ValidatedBadge f={f} />
                            {f.exploit_available && <ExploitChip />}
                            {f.mitre_technique && <MitreChip t={f.mitre_technique} />}
                          </div>
                        </td>
                        {columns.map(c => (
                          <td key={c.key} className="px-3 py-3">
                            {c.render ? c.render(f) : <span className="text-[10px] text-gray-600">{String((f as Record<string, unknown>)[c.key] ?? "—")}</span>}
                          </td>
                        ))}
                        {/* Exploitability + prioritization */}
                        <td className="px-3 py-3">
                          <ExploitabilityCell f={f} />
                        </td>
                        <td className="px-3 py-3 w-28"><ConfBar pct={f.confidence_pct ?? 70} sev={f.severity} /></td>
                        <td className="px-3 py-3 text-[10px] font-mono text-gray-400">{f.agent_id?.slice(0, 12)}</td>
                        <td className="px-3 py-3 text-[10px] text-gray-400 whitespace-nowrap">{fmtTs(f.last_detected_at)}</td>
                        <td className="pr-3 py-3 text-gray-300">
                          {isSel
                            ? <ChevronDown className="w-3.5 h-3.5 text-orange-400" />
                            : <ChevronRight className="w-3.5 h-3.5 opacity-0 group-hover:opacity-100 transition-opacity" />}
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>

          {/* Footer with pagination */}
          {(filtered.length > 0 || raw.length > 0) && (
            <div className="px-5 py-2.5 border-t border-gray-100 bg-gray-50/60 flex items-center justify-between gap-4 flex-wrap">
              <div className="flex items-center gap-3 text-[10px]">
                <span className="font-bold text-gray-700">{filtered.length} results</span>
                {kpiCritical > 0 && <span className="text-red-600 font-bold flex items-center gap-1"><span className="w-1.5 h-1.5 rounded-full bg-red-500 animate-pulse inline-block" />{kpiCritical} critical</span>}
                {kpiHigh > 0     && <span className="text-amber-600 font-semibold">{kpiHigh} high</span>}
                {kpiKev  > 0     && <span className="text-red-700 font-black bg-red-50 px-2 py-0.5 rounded-full border border-red-200">{kpiKev} KEV</span>}
              </div>
              {totalPages > 1 && (
                <div className="flex items-center gap-1.5">
                  <button onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page === 1}
                    className="px-2.5 py-1 text-[10px] font-semibold rounded-lg border border-gray-200 bg-white hover:bg-orange-50 hover:border-orange-200 text-gray-600 hover:text-orange-600 disabled:opacity-40 disabled:cursor-not-allowed transition-all">
                    ← Prev
                  </button>
                  <span className="text-[10px] text-gray-500 font-medium px-1">Page {page} / {totalPages}</span>
                  <button onClick={() => setPage(p => Math.min(totalPages, p + 1))} disabled={page === totalPages}
                    className="px-2.5 py-1 text-[10px] font-semibold rounded-lg border border-gray-200 bg-white hover:bg-orange-50 hover:border-orange-200 text-gray-600 hover:text-orange-600 disabled:opacity-40 disabled:cursor-not-allowed transition-all">
                    Next →
                  </button>
                </div>
              )}
              <span className="text-[10px] text-gray-400">Click row → detection detail</span>
            </div>
          )}
      </div>

      {/* Fixed right-side drawer — portaled to body */}
      {selected && <FindingDetail finding={selected} onClose={() => setSelected(null)} onChanged={refetch} />}
    </div>
  );
}
