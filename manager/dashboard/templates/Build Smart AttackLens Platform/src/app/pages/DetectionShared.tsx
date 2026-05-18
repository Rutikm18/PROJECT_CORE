/**
 * DetectionShared — Animated enterprise detection UI.
 *
 * Animations: sonar-ping · heartbeat · slide-panel · stagger-rows
 *             bar-fill · bounce-in KPIs · scan-line · ECG waveform
 * Theme: orange/amber gradient · white cards · rounded-2xl
 */
import { useState, useEffect, useCallback, useRef } from "react";
import {
  RefreshCw, X, Search, Filter, AlertTriangle, Shield,
  Zap, Target, BookOpen, Activity, CheckCircle2, XCircle,
  ExternalLink, Copy, Info, Eye, Crosshair, Database,
  GitBranch, Brain, TrendingUp, FileCode, Network,
  Radio, ChevronRight, ChevronDown,
} from "lucide-react";
import { cn } from "../../lib/utils";

// ── Types ─────────────────────────────────────────────────────────────────────

export interface DetectionFinding {
  id:                number;
  external_id?:      string;
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
  sla_due?:          number;
  sla_status?:       string;
  priority_reason?:  string;
  action_plan?:      unknown[] | string;
  tags?:             string[] | string;
  confidence_pct?:   number;
  impact?:           string;
  cat_meta?:         { label: string; icon: string; group: string };
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

// ── Detail panel — 4-tab ─────────────────────────────────────────────────────

type DTab = "overview" | "validation" | "blueprint" | "hunt";

export function FindingDetail({ finding: f, onClose }: { finding: DetectionFinding; onClose: () => void }) {
  const [tab, setTab] = useState<DTab>("overview");
  const evidence    = _parseJson(f.evidence, {}) as Record<string, unknown>;
  const actionPlan  = _parseJson(f.action_plan, []) as { type: string; title: string; detail: string }[];
  const cveIds      = _parseJson(f.cve_ids, []) as string[];
  const exploitSrcs = _parseJson(f.exploit_sources, []) as string[];
  const tags        = _parseJson(f.tags, []) as string[];
  const score       = f.composite_score ?? f.score;
  const bp          = BLUEPRINT[getBlueprintKey(f.category, f.source, f.mitre_tactic)];
  const s           = SEV[f.severity] ?? SEV.info;

  const TABS: { id: DTab; label: string; icon: React.ReactNode }[] = [
    { id: "overview",   label: "Overview",   icon: <Eye className="w-3 h-3" /> },
    { id: "validation", label: "Validate",   icon: <CheckCircle2 className="w-3 h-3" /> },
    { id: "blueprint",  label: "Blueprint",  icon: <BookOpen className="w-3 h-3" /> },
    { id: "hunt",       label: "Hunt",       icon: <Crosshair className="w-3 h-3" /> },
  ];

  return (
    <div className="w-[460px] flex-shrink-0 bg-white border border-gray-200 rounded-2xl shadow-lg overflow-hidden self-start sticky top-0 max-h-[calc(100vh-120px)] flex flex-col al-panel-in">
      {/* Dynamic top stripe */}
      <div className={cn("h-1 w-full", f.severity === "critical" ? "bg-gradient-to-r from-red-500 via-red-400 to-orange-500" : f.severity === "high" ? "bg-gradient-to-r from-amber-500 via-amber-400 to-orange-400" : "bg-gradient-to-r from-orange-400 via-amber-400 to-orange-500")} />

      {/* Header */}
      <div className="flex items-center justify-between px-4 py-2.5 border-b border-gray-100 bg-gray-50/60 flex-shrink-0">
        <div className="flex items-center gap-1.5 flex-wrap min-w-0">
          <SevBadge sev={f.severity} />
          {f.kev && <KevChip />}
          {f.exploit_available && <ExploitChip />}
          {f.mitre_technique && <MitreChip t={f.mitre_technique} />}
          <span className="text-[9px] font-mono text-gray-400">{f.external_id ?? `#${f.id}`}</span>
        </div>
        <button onClick={onClose} className="p-1.5 hover:bg-gray-200 rounded-lg transition-colors flex-shrink-0 ml-2">
          <X className="w-3.5 h-3.5 text-gray-400" />
        </button>
      </div>

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

        {/* ── OVERVIEW ────────────────────────────────────────────────────── */}
        {tab === "overview" && (
          <div className="divide-y divide-gray-50">
            <div className="px-4 py-3">
              <p className="text-[12px] font-bold text-gray-900 leading-snug">{f.title}</p>
              <div className="flex flex-wrap gap-1 mt-2">
                {f.sla_status && <SlaBadge status={f.sla_status} />}
                {f.mitre_tactic && <span className="px-2 py-0.5 bg-purple-50 text-purple-700 border border-purple-200 rounded-full text-[9px] font-semibold">{f.mitre_tactic}</span>}
                {tags.slice(0,3).map(t => <span key={t} className="px-2 py-0.5 bg-gray-100 text-gray-500 rounded-full text-[9px]">{t}</span>)}
              </div>
            </div>

            {/* Score tiles */}
            <div className="px-4 py-3 grid grid-cols-3 gap-2">
              {[
                { l: "Risk Score", v: `${score.toFixed(1)}/10`, c: score >= 8 ? "text-red-600" : score >= 6 ? "text-amber-600" : "text-blue-600", bg: score >= 8 ? "bg-red-50 border-red-100" : "bg-gray-50 border-gray-100" },
                { l: "CVSS",       v: f.cvss_score != null ? f.cvss_score.toFixed(1) : "—", c: f.cvss_score != null && f.cvss_score >= 9 ? "text-red-600" : "text-gray-600", bg: "bg-gray-50 border-gray-100" },
                { l: "EPSS",       v: f.epss_score != null ? `${Math.round(f.epss_score * 100)}%` : "—", c: f.epss_score != null && f.epss_score >= 0.5 ? "text-red-600" : "text-gray-600", bg: "bg-gray-50 border-gray-100" },
              ].map(s => (
                <div key={s.l} className={cn("rounded-xl border py-2.5 text-center al-bounce-in", s.bg)}>
                  <div className={cn("text-sm font-black leading-none", s.c)}>{s.v}</div>
                  <div className="text-[9px] text-gray-500 mt-1">{s.l}</div>
                </div>
              ))}
            </div>

            {/* Confidence */}
            <div className="px-4 py-2.5">
              <div className="flex items-center justify-between text-[9px] text-gray-500 mb-1.5">
                <span className="font-bold uppercase tracking-wide">Detection Confidence</span>
                <span className="font-black text-gray-700">{f.confidence_pct ?? 70}%</span>
              </div>
              <div className="h-2 bg-gray-100 rounded-full overflow-hidden">
                <div className={cn("h-full rounded-full al-bar-fill", SEV[f.severity]?.bar ?? "bg-orange-400")}
                  style={{ width: `${f.confidence_pct ?? 70}%` }} />
              </div>
            </div>

            {/* Quick facts */}
            <div className="px-4 py-3 space-y-1.5">
              {([
                ["KEV",        f.kev ? "Yes — actively exploited in the wild" : "Not listed",  f.kev],
                ["Exploit",    f.exploit_available ? `Confirmed (${exploitSrcs.join(", ") || "public"})` : "Not confirmed", f.exploit_available],
                ["Source",     f.source ?? "—", false],
                ["Confidence", `${f.confidence_pct ?? 70}%`, false],
                ["Priority",   f.priority_reason ?? "Standard scoring", false],
              ] as [string, string, boolean][]).map(([l, v, hi]) => (
                <div key={l} className="flex items-start gap-2">
                  <span className="w-20 text-[9px] text-gray-400 font-semibold uppercase tracking-wide flex-shrink-0 mt-0.5">{l}</span>
                  <span className={cn("text-[10px] flex-1", hi ? "font-bold text-red-600" : "text-gray-700")}>{v}</span>
                </div>
              ))}
              {cveIds.length > 0 && (
                <div className="flex flex-wrap gap-1 pt-1">
                  {cveIds.map(c => <span key={c} className="font-mono text-[8px] px-1.5 py-0.5 bg-blue-50 text-blue-700 border border-blue-200 rounded">{c}</span>)}
                </div>
              )}
            </div>

            {/* Description */}
            <div className="px-4 py-3">
              <div className="text-[9px] font-bold text-gray-400 uppercase tracking-wide mb-1.5">Description</div>
              <p className="text-[11px] text-gray-700 leading-relaxed">{f.description}</p>
            </div>

            {/* Impact */}
            {f.impact && (
              <div className="px-4 py-3">
                <div className="text-[9px] font-bold text-amber-600 uppercase tracking-wide mb-1.5 flex items-center gap-1">
                  <AlertTriangle className="w-3 h-3" />Business Impact
                </div>
                <p className="text-[10px] text-amber-900 bg-amber-50 border border-amber-200 rounded-xl px-3 py-2 leading-relaxed">{f.impact}</p>
              </div>
            )}

            {/* Remediation */}
            {actionPlan.length > 0 && (
              <div className="px-4 py-3">
                <div className="text-[9px] font-bold text-green-700 uppercase tracking-wide mb-2 flex items-center gap-1">
                  <Shield className="w-3 h-3" />Remediation
                </div>
                <ol className="space-y-2">
                  {actionPlan.map((step, i) => (
                    <li key={i} className="flex items-start gap-2">
                      <span className="w-4 h-4 rounded-full bg-orange-500 text-white flex items-center justify-center text-[8px] font-bold flex-shrink-0 mt-0.5">{i+1}</span>
                      <div><p className="text-[10px] font-semibold text-gray-800">{step.title}</p><p className="text-[10px] text-gray-600">{step.detail}</p></div>
                    </li>
                  ))}
                </ol>
              </div>
            )}

            {/* Timeline */}
            <div className="px-4 py-3">
              <div className="text-[9px] font-bold text-gray-400 uppercase tracking-wide mb-1.5">Timeline</div>
              {[["First detected", fmtTs(f.first_detected_at)],["Last detected", fmtTs(f.last_detected_at)],["Scan count", String(f.scan_count)],["Agent", f.agent_id]].map(([l,v]) => (
                <div key={l} className="flex items-center gap-2 py-0.5">
                  <span className="w-24 text-[9px] text-gray-400 font-medium">{l}</span>
                  <span className="text-[10px] text-gray-700 font-mono">{v}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* ── VALIDATION ──────────────────────────────────────────────────── */}
        {tab === "validation" && bp && (
          <div className="divide-y divide-gray-50">
            <div className="px-4 py-3">
              <div className="text-[9px] font-bold text-gray-400 uppercase tracking-wide mb-2 flex items-center gap-1.5"><CheckCircle2 className="w-3 h-3 text-green-500" />Validation Criteria</div>
              <ol className="space-y-1.5">
                {bp.validation.map((v, i) => (
                  <li key={i} className="flex items-start gap-2 al-row-in" style={{ animationDelay: `${i * 40}ms` }}>
                    <span className="w-4 h-4 rounded-full bg-orange-100 text-orange-600 flex items-center justify-center text-[7px] font-black flex-shrink-0 mt-0.5">{i+1}</span>
                    <span className="text-[10px] text-gray-700">{v}</span>
                  </li>
                ))}
              </ol>
            </div>
            <div className="px-4 py-3">
              <div className="text-[9px] font-bold text-gray-400 uppercase tracking-wide mb-2 flex items-center gap-1.5"><Database className="w-3 h-3 text-blue-500" />Evidence Required</div>
              {bp.evidence_required.map((e, i) => (
                <div key={i} className="flex items-start gap-2 py-0.5 al-row-in" style={{ animationDelay: `${i * 35}ms` }}>
                  <span className="w-1 h-1 rounded-full bg-orange-400 flex-shrink-0 mt-1.5" />
                  <span className="text-[10px] text-gray-700">{e}</span>
                </div>
              ))}
            </div>
            {Object.keys(evidence).length > 0 && (
              <div className="px-4 py-3">
                <div className="text-[9px] font-bold text-gray-400 uppercase tracking-wide mb-2">Raw Evidence (JSON)</div>
                <pre className="text-[9px] font-mono text-green-400 bg-gray-900 rounded-xl p-3 overflow-auto max-h-36 whitespace-pre-wrap break-words border border-gray-700">{JSON.stringify(evidence, null, 2)}</pre>
              </div>
            )}
            <div className="px-4 py-3">
              <div className="text-[9px] font-bold text-gray-400 uppercase tracking-wide mb-2 flex items-center gap-1.5"><XCircle className="w-3 h-3 text-purple-500" />False Positive Reduction</div>
              <p className="text-[10px] text-gray-700 bg-purple-50 border border-purple-100 rounded-xl px-3 py-2">{bp.fp_reduction}</p>
            </div>
            <div className="px-4 py-3">
              <div className="text-[9px] font-bold text-gray-400 uppercase tracking-wide mb-2 flex items-center gap-1.5"><TrendingUp className="w-3 h-3 text-amber-500" />Confidence Score Factors</div>
              <div className="space-y-1">
                {bp.confidence_factors.map((c, i) => {
                  const pos = c.startsWith("+");
                  return (
                    <div key={i} className={cn("flex items-start gap-2 px-2 py-1 rounded-lg text-[10px] al-row-in", pos ? "bg-green-50 text-green-800" : "bg-red-50 text-red-800")} style={{ animationDelay: `${i*40}ms` }}>
                      <span className={cn("font-black flex-shrink-0", pos ? "text-green-600" : "text-red-500")}>{pos ? "+" : "−"}</span>
                      <span>{c.replace(/^[+-]\d+\s/, "")}</span>
                    </div>
                  );
                })}
              </div>
            </div>
            <div className="px-4 py-3">
              <div className="text-[9px] font-bold text-gray-400 uppercase tracking-wide mb-2 flex items-center gap-1.5"><Network className="w-3 h-3 text-red-500" />Exposure Analytics</div>
              <p className="text-[10px] text-gray-700 bg-red-50 border border-red-100 rounded-xl px-3 py-2">{bp.exposure_note}</p>
            </div>
          </div>
        )}

        {/* ── BLUEPRINT ───────────────────────────────────────────────────── */}
        {tab === "blueprint" && bp && (
          <div className="divide-y divide-gray-50">
            <div className="px-4 py-3">
              <div className="text-[9px] font-bold text-gray-400 uppercase tracking-wide mb-2 flex items-center gap-1.5"><Activity className="w-3 h-3 text-orange-500" />Telemetry Sections</div>
              <div className="flex flex-wrap gap-1">
                {bp.telemetry.map(t => <span key={t} className="px-2 py-0.5 bg-orange-50 border border-orange-200 text-orange-700 rounded text-[9px] font-mono font-semibold">{t}</span>)}
              </div>
            </div>
            <div className="px-4 py-3">
              <div className="text-[9px] font-bold text-gray-400 uppercase tracking-wide mb-2 flex items-center gap-1.5"><Brain className="w-3 h-3 text-indigo-500" />Detection Logic</div>
              <p className="text-[10px] text-gray-700 leading-relaxed">{bp.detection_logic}</p>
            </div>
            <div className="px-4 py-3">
              <div className="text-[9px] font-bold text-gray-400 uppercase tracking-wide mb-2 flex items-center gap-1.5"><Target className="w-3 h-3 text-red-500" />MITRE ATT&CK Mapping</div>
              <p className="text-[10px] text-gray-700 bg-indigo-50 border border-indigo-100 rounded-xl px-3 py-2">{bp.attack_chain}</p>
              {f.mitre_technique && (
                <a href={`https://attack.mitre.org/techniques/${f.mitre_technique.replace(".","/")}`} target="_blank" rel="noopener noreferrer"
                  className="inline-flex items-center gap-1 mt-2 text-[9px] text-indigo-600 hover:text-indigo-800 font-semibold">
                  <ExternalLink className="w-2.5 h-2.5" />View {f.mitre_technique} on MITRE ATT&CK
                </a>
              )}
            </div>
            <div className="px-4 py-3">
              <div className="text-[9px] font-bold text-gray-400 uppercase tracking-wide mb-2 flex items-center gap-1.5"><Brain className="w-3 h-3 text-purple-500" />AI / Behavioral Analytics</div>
              <div className="space-y-1.5">
                {bp.ai_analytics.map((a, i) => (
                  <div key={i} className="flex items-start gap-2 al-row-in" style={{ animationDelay: `${i*50}ms` }}>
                    <span className="w-5 h-4 rounded bg-purple-100 text-purple-600 flex items-center justify-center text-[7px] font-black flex-shrink-0 mt-0.5">AI</span>
                    <span className="text-[10px] text-gray-700">{a}</span>
                  </div>
                ))}
              </div>
            </div>
            <div className="px-4 py-3">
              <div className="text-[9px] font-bold text-gray-400 uppercase tracking-wide mb-2 flex items-center gap-1.5"><Zap className="w-3 h-3 text-amber-500" />Threat Intelligence</div>
              <div className="flex flex-wrap gap-1">
                {bp.threat_intel.map(t => <span key={t} className="px-2 py-0.5 bg-amber-50 border border-amber-200 text-amber-800 rounded text-[9px] font-semibold">{t}</span>)}
              </div>
            </div>
            <div className="px-4 py-3">
              <div className="text-[9px] font-bold text-gray-400 uppercase tracking-wide mb-2 flex items-center gap-1.5"><FileCode className="w-3 h-3 text-green-500" />Sigma Rule Concept</div>
              <pre className="text-[9px] font-mono text-green-400 bg-gray-900 rounded-xl p-3 overflow-x-auto whitespace-pre leading-relaxed border border-gray-700">{bp.sigma_idea}</pre>
            </div>
          </div>
        )}

        {/* ── HUNT ────────────────────────────────────────────────────────── */}
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
            </div>
            <div className="px-4 py-3">
              <div className="text-[9px] font-bold text-gray-400 uppercase tracking-wide mb-2 flex items-center gap-1.5"><GitBranch className="w-3 h-3 text-blue-500" />Correlation Opportunities</div>
              {["Cross-ref agent_health gaps — attacker may disable telemetry","Check connections from same host ±5 min of this event","Look for persistence mechanisms created near this event","Compare against same check 7d ago (baseline drift)","Check if same finding exists on peer hosts (lateral movement)"].map((c,i) => (
                <div key={i} className="flex items-start gap-2 py-0.5 al-row-in" style={{ animationDelay: `${i*40}ms` }}>
                  <span className="w-1 h-1 rounded-full bg-blue-400 flex-shrink-0 mt-1.5" />
                  <span className="text-[10px] text-gray-700">{c}</span>
                </div>
              ))}
            </div>
            <div className="px-4 py-3">
              <div className="text-[9px] font-bold text-gray-400 uppercase tracking-wide mb-2 flex items-center gap-1.5"><GitBranch className="w-3 h-3 text-red-500" />Attack Chain Position</div>
              <div className="bg-gradient-to-r from-red-50 to-amber-50 border border-amber-200 rounded-xl px-3 py-2.5">
                <p className="text-[10px] text-gray-800 font-medium">{bp.attack_chain}</p>
              </div>
            </div>
            <div className="px-4 py-3">
              <div className="text-[9px] font-bold text-gray-400 uppercase tracking-wide mb-2 flex items-center gap-1.5"><TrendingUp className="w-3 h-3 text-green-500" />Risk Scoring Formula</div>
              <div className="bg-gray-50 border border-gray-100 rounded-xl px-3 py-2.5">
                <p className="text-[10px] font-mono text-gray-700"><span className="text-orange-600 font-bold">composite_score</span> =</p>
                <p className="text-[10px] font-mono text-gray-600 pl-3 leading-relaxed">
                  (cvss_base × 0.25)<br/>+ (epss_pct × 0.20)<br/>+ (kev_flag × 2.0)<br/>+ (exploit_flag × 1.5)<br/>+ (internet_exposed × 1.0)<br/>+ (ai_anomaly_score × 0.15)<br/>+ (asset_criticality × 0.10)
                </p>
                <p className="text-[9px] text-gray-400 pt-1">Normalized 0–10 · capped at 10.0</p>
              </div>
            </div>
            <div className="px-4 py-3">
              <div className="text-[9px] font-bold text-gray-400 uppercase tracking-wide mb-2 flex items-center gap-1.5"><Zap className="w-3 h-3 text-amber-500" />SOAR Automation</div>
              {["Auto-enrich: VirusTotal hash/IP lookup on creation","Auto-tag: KEV + EPSS score from FIRST.org API","Alert: critical → PagerDuty + Slack #soc-critical","Playbook: isolate host if score ≥ 9.0 AND kev=true","Collect: snapshot process tree + memory on creation"].map((s,i) => (
                <div key={i} className="flex items-start gap-2 py-0.5 al-row-in" style={{ animationDelay: `${i*40}ms` }}>
                  <span className="text-[9px] font-black text-amber-500">→</span>
                  <span className="text-[10px] text-gray-700">{s}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {(tab !== "overview") && !bp && (
          <div className="px-4 py-16 text-center">
            <Info className="w-6 h-6 text-gray-200 mx-auto mb-2" />
            <p className="text-[11px] text-gray-400">Blueprint not yet mapped for this category.</p>
          </div>
        )}
      </div>
    </div>
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
        <input value={raw} onChange={e => handle(e.target.value)} placeholder="Search findings…"
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

  const url = `${apiUrl}?${new URLSearchParams({
    ...(agentId  ? { agent_id: agentId } : {}),
    ...(severity ? { severity }           : {}),
    ...(search   ? { search }             : {}),
    limit: "200",
  })}`;

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

      {/* ── Main content ─────────────────────────────────────────────────── */}
      <div className="flex gap-4 items-start">
        {/* Table card */}
        <div className="flex-1 min-w-0 bg-white border border-gray-200 rounded-2xl shadow-sm overflow-hidden">
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
                  <th className="px-3 py-2.5 text-left text-[9px] font-black text-gray-400 uppercase tracking-wider">Finding</th>
                  {columns.map(c => (
                    <th key={c.key} className="px-3 py-2.5 text-left text-[9px] font-black text-gray-400 uppercase tracking-wider whitespace-nowrap">{c.label}</th>
                  ))}
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
                      {Array.from({ length: columns.length + 5 }).map((_, j) => (
                        <td key={j} className="px-3 py-3">
                          <div className="h-3 bg-gray-100 rounded-full animate-pulse" style={{ width: j === 1 ? "70%" : "40%", animationDelay: `${i * 80 + j * 40}ms` }} />
                        </td>
                      ))}
                    </tr>
                  ))
                ) : findings.length === 0 ? (
                  <tr>
                    <td colSpan={columns.length + 6} className="py-20 text-center">
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

                        {/* Title + badge chips */}
                        <td className="px-3 py-3 max-w-[260px]">
                          <div className="text-[11px] font-semibold text-gray-800 leading-tight truncate mb-1">{f.title}</div>
                          <div className="flex items-center gap-1 flex-wrap">
                            <SevBadge sev={f.severity} />
                            {f.kev && <KevChip />}
                            {f.exploit_available && <ExploitChip />}
                            {f.mitre_technique && <MitreChip t={f.mitre_technique} />}
                          </div>
                        </td>

                        {columns.map(c => (
                          <td key={c.key} className="px-3 py-3">
                            {c.render ? c.render(f) : <span className="text-[10px] text-gray-600">{String((f as Record<string, unknown>)[c.key] ?? "—")}</span>}
                          </td>
                        ))}

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

        {/* Animated detail panel */}
        {selected && <FindingDetail finding={selected} onClose={() => setSelected(null)} />}
      </div>
    </div>
  );
}
