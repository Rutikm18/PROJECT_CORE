/**
 * ThreatIntelligence — Expert SOC / TI analyst workspace.
 *
 * Five operational tabs:
 *   IOC Triage     — ranked action queue, detail slide-out, bulk ops, multi-format export
 *   CVE Intel       — NVD/EPSS/KEV enriched CVE list with hunt pivot
 *   KEV Mandates    — CISA patch-deadline tracker with SLA countdown
 *   Hunt Queries    — pre-built Splunk/KQL/Suricata/Sigma queries per active IOC
 *   Feed Status     — live health, last-sync, entry counts
 *
 * Design principles (expert SOC UX):
 *   • Priority-first — critical unblocked items surfaced before the fold
 *   • Context-dense — every row answers What / Why / How to block / Where to hunt
 *   • Actionable — no dead-end views; every card has a next action
 *   • Copy-ready — one click to clipboard for every value a responder would type
 */

import { useState, useEffect, useCallback, useMemo, useRef } from "react";
import { useParams, useNavigate } from "react-router";
import {
  RefreshCw, ExternalLink, Shield, AlertTriangle, Zap,
  Search, Copy, CheckCircle2, Clock, Eye, X, Download,
  ChevronDown, ChevronUp, Server, Globe, Hash, Link2,
  Wifi, Database, Flame, ShieldAlert, ShieldCheck,
  Activity, Crosshair, Star, Radio, Terminal, BookOpen,
  ArrowRight, TriangleAlert, Target, Lock, Unlock,
  Filter, ChevronRight, Info, Layers,
} from "lucide-react";
import { cn } from "../../lib/utils";

// ─────────────────────────────────────────────────────────────────────────────
// API
// ─────────────────────────────────────────────────────────────────────────────

const THREAT = "/api/v1/threat";

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

interface IOC {
  ioc_type: string; ioc_value: string; source: string;
  severity: string; confidence: number; description: string | null;
  tags: string | null; cached_at: number; expires_at: number;
}
type IOCStatus = "pending" | "blocked" | "watching" | "fp";

interface CVE {
  cve_id: string; description: string; cvss_score: number | null;
  severity: string; published_at: string; is_kev: boolean;
  epss: number | null; priority: string;
}
interface KEVEntry {
  cve_id: string; vendor: string; product: string; vuln_name: string;
  date_added: string; required_action: string; due_date: string;
}
interface NewsItem {
  title: string; url: string; summary: string; source: string;
  severity: string; cve_refs: string; published_at: number;
}
interface FeedHealth {
  source: string; status: string; last_success: number;
  entry_count: number; error_count: number; last_error: string;
}
interface DashStats {
  kev_count: number; actor_count: number; nvd_total: number;
  nvd_critical: number; nvd_high: number; ioc_count: number;
  active_feeds: number; total_feeds: number; last_nvd_sync: number;
}
interface DashData {
  stats: DashStats; feeds: FeedHealth[];
  top_cves: CVE[]; kev_recent: KEVEntry[]; news: NewsItem[];
}

// ─────────────────────────────────────────────────────────────────────────────
// Threat category intelligence
// ─────────────────────────────────────────────────────────────────────────────

interface ThreatCat {
  label: string; short: string;
  bg: string; text: string; border: string;
  what: string; why: string; mitre: string; mitreTech: string;
  playbook: { step: string; tool: string; priority: "critical" | "high" | "medium" }[];
}

const CATS: Record<string, ThreatCat> = {
  feodo: {
    label: "Feodo Botnet C2", short: "Feodo C2",
    bg: "bg-red-50", text: "text-red-700", border: "border-red-200",
    what: "Feodo Tracker–listed C2 for Emotet, TrickBot, or Dridex banking trojans.",
    why: "Trojans steal credentials and serve as initial access for ransomware groups.",
    mitre: "TA0011", mitreTech: "T1071.001",
    playbook: [
      { step: "Block IP at perimeter firewall (ingress + egress)", tool: "Firewall ACL / NGFW", priority: "critical" },
      { step: "Search SIEM for any prior outbound connections", tool: "SIEM / EDR", priority: "critical" },
      { step: "Isolate any host that touched this IP", tool: "EDR", priority: "critical" },
      { step: "Add to threat intel platform watchlist", tool: "TIP / MISP", priority: "high" },
      { step: "Check lateral movement from affected hosts", tool: "SIEM", priority: "high" },
    ],
  },
  urlhaus: {
    label: "Malware Distribution URL", short: "URLhaus",
    bg: "bg-purple-50", text: "text-purple-700", border: "border-purple-200",
    what: "Active malware-hosting URL tracked by abuse.ch URLhaus.",
    why: "Employees clicking these deliver malware payloads directly.",
    mitre: "TA0001", mitreTech: "T1566.002",
    playbook: [
      { step: "Block URL at web proxy (exact match + domain)", tool: "Proxy / Secure Web Gateway", priority: "critical" },
      { step: "Block domain at DNS resolver / sinkhole", tool: "DNS Sinkhole / Pi-hole", priority: "critical" },
      { step: "Hunt for DNS queries to this domain in last 7 days", tool: "DNS logs / SIEM", priority: "high" },
      { step: "Deploy email gateway rule for URL in phishing context", tool: "Email Gateway", priority: "medium" },
    ],
  },
  ransomware: {
    label: "Ransomware C2", short: "Ransomware",
    bg: "bg-red-50", text: "text-red-700", border: "border-red-200",
    what: "Infrastructure used by ransomware groups for exfiltration and key exchange.",
    why: "Active contact = encryption may already be in progress. Highest urgency.",
    mitre: "TA0040", mitreTech: "T1486",
    playbook: [
      { step: "Immediately isolate all hosts with outbound connections to this IP", tool: "EDR / NAC", priority: "critical" },
      { step: "Block IP at all network egress points (no exceptions)", tool: "Firewall / NGFW", priority: "critical" },
      { step: "Initiate IR process — declare potential ransomware incident", tool: "IR Runbook", priority: "critical" },
      { step: "Capture memory image of affected hosts before shutdown", tool: "Volatility / EDR", priority: "critical" },
      { step: "Preserve logs: netflow, proxy, endpoint for forensics", tool: "SIEM / EDR", priority: "high" },
      { step: "Notify legal, CISO, backup team per IR plan", tool: "IR Runbook", priority: "high" },
    ],
  },
  c2: {
    label: "C2 Infrastructure", short: "C2",
    bg: "bg-red-50", text: "text-red-700", border: "border-red-200",
    what: "Command & Control server used to remotely issue commands to implanted malware.",
    why: "Blocking C2 severs attacker remote control, containing damage even post-compromise.",
    mitre: "TA0011", mitreTech: "T1071",
    playbook: [
      { step: "Block IP/domain at firewall (bidirectional)", tool: "Firewall ACL", priority: "critical" },
      { step: "Hunt for beaconing patterns (periodic outbound intervals)", tool: "SIEM / NetFlow", priority: "critical" },
      { step: "Search EDR telemetry for process making connection", tool: "EDR", priority: "high" },
      { step: "Add to SIEM detection rule for ongoing alerting", tool: "SIEM", priority: "high" },
    ],
  },
  phishing: {
    label: "Phishing Infrastructure", short: "Phishing",
    bg: "bg-amber-50", text: "text-amber-700", border: "border-amber-200",
    what: "Domain or IP hosting a credential-harvesting phishing page.",
    why: "One harvested credential provides full network access via VPN or cloud SSO.",
    mitre: "TA0001", mitreTech: "T1566.002",
    playbook: [
      { step: "Block domain at DNS and web proxy immediately", tool: "DNS / Proxy", priority: "critical" },
      { step: "Search email logs for messages linking to this domain", tool: "Email Gateway / SIEM", priority: "critical" },
      { step: "Force password reset for any user who visited the URL", tool: "IAM / Active Directory", priority: "critical" },
      { step: "Check for MFA bypass / new device registrations post-visit", tool: "IdP / SIEM", priority: "high" },
    ],
  },
  malware: {
    label: "Malware Distribution", short: "Malware",
    bg: "bg-purple-50", text: "text-purple-700", border: "border-purple-200",
    what: "Server distributing malware payloads — dropper sites, exploit kits, or RAT installers.",
    why: "Single download deploys ransomware, keyloggers, or lateral-movement tools.",
    mitre: "TA0001", mitreTech: "T1105",
    playbook: [
      { step: "Block URL and domain at web proxy and DNS", tool: "Proxy / DNS", priority: "critical" },
      { step: "Scan endpoint AV/EDR for known associated hashes", tool: "EDR / AV", priority: "high" },
      { step: "Check proxy logs for downloads from this host", tool: "Proxy / SIEM", priority: "high" },
    ],
  },
  scanner: {
    label: "Mass Scanner", short: "Scanner",
    bg: "bg-blue-50", text: "text-blue-700", border: "border-blue-200",
    what: "IP conducting automated internet-wide port and vulnerability scanning.",
    why: "Scanners map exposed services for later targeted exploitation.",
    mitre: "TA0043", mitreTech: "T1595",
    playbook: [
      { step: "Add IP to firewall blocklist (inbound only)", tool: "Firewall ACL", priority: "high" },
      { step: "Review WAF logs for scan patterns from this source", tool: "WAF / SIEM", priority: "medium" },
      { step: "Ensure no services are unnecessarily exposed to internet", tool: "Firewall review", priority: "medium" },
    ],
  },
  emerging: {
    label: "Emerging Threat", short: "ET Rule",
    bg: "bg-amber-50", text: "text-amber-700", border: "border-amber-200",
    what: "IOC from Proofpoint Emerging Threats ruleset — known-bad infrastructure updated daily.",
    why: "High signal-to-noise based on observed live attacks. Prioritise immediate blocking.",
    mitre: "TA0040", mitreTech: "T1071",
    playbook: [
      { step: "Deploy matching ET Suricata/Snort rule on IDS/IPS", tool: "IDS/IPS / Suricata", priority: "high" },
      { step: "Block IP/domain at perimeter", tool: "Firewall / NGFW", priority: "high" },
      { step: "Review SIEM for historical hits against this ET rule", tool: "SIEM", priority: "medium" },
    ],
  },
  unknown: {
    label: "Threat Actor IOC", short: "IOC",
    bg: "bg-gray-100", text: "text-gray-600", border: "border-gray-200",
    what: "Indicator of Compromise from a threat intelligence feed.",
    why: "Validate via external references before applying blocks in production.",
    mitre: "TA0043", mitreTech: "T1589",
    playbook: [
      { step: "Validate IOC across VirusTotal / AbuseIPDB / Shodan", tool: "External TI", priority: "high" },
      { step: "If confirmed malicious, add to watchlist and block", tool: "Firewall / EDR", priority: "medium" },
    ],
  },
};

function deriveCat(ioc: IOC): ThreatCat {
  const src  = ioc.source?.toLowerCase() ?? "";
  const desc = (ioc.description ?? "").toLowerCase();
  if (src === "feodo")                                       return CATS.feodo;
  if (src === "urlhaus")                                     return CATS.urlhaus;
  if (src.startsWith("emerging"))                            return CATS.emerging;
  if (desc.includes("ransomware"))                           return CATS.ransomware;
  if (desc.includes("c2") || desc.includes("command"))      return CATS.c2;
  if (desc.includes("phish"))                               return CATS.phishing;
  if (desc.includes("malware") || desc.includes("dropper")) return CATS.malware;
  if (desc.includes("scan"))                                 return CATS.scanner;
  return CATS.unknown;
}

// ─────────────────────────────────────────────────────────────────────────────
// Validation refs + block-in targets
// ─────────────────────────────────────────────────────────────────────────────

const BLOCK_IN: Record<string, string[]> = {
  ip:     ["Perimeter Firewall", "NGFW Egress Policy", "SIEM Alert Rule", "EDR Network Block"],
  domain: ["DNS Sinkhole", "Secure Web Gateway", "EDR DNS Block", "Email Gateway"],
  hash:   ["EDR File Block Policy", "AV Endpoint Policy", "Email Gateway", "DLP"],
  url:    ["Secure Web Gateway", "WAF Rule", "Browser Extension Policy", "Email Gateway"],
};

function validationRefs(type: string, value: string) {
  const m: Record<string, { label: string; url: string }[]> = {
    ip: [
      { label: "AbuseIPDB",  url: `https://www.abuseipdb.com/check/${value}` },
      { label: "VirusTotal", url: `https://www.virustotal.com/gui/ip-address/${value}` },
      { label: "Shodan",     url: `https://www.shodan.io/host/${value}` },
      { label: "GreyNoise",  url: `https://viz.greynoise.io/ip/${value}` },
      { label: "IPInfo",     url: `https://ipinfo.io/${value}` },
    ],
    domain: [
      { label: "VirusTotal", url: `https://www.virustotal.com/gui/domain/${value}` },
      { label: "urlscan.io", url: `https://urlscan.io/search/#domain:${value}` },
      { label: "WHOIS",      url: `https://www.whois.com/whois/${value}` },
      { label: "PassiveDNS", url: `https://www.virustotal.com/gui/domain/${value}/relations` },
    ],
    hash: [
      { label: "VirusTotal",    url: `https://www.virustotal.com/gui/file/${value}` },
      { label: "MalwareBazaar", url: `https://bazaar.abuse.ch/browse.php?search=${value}` },
      { label: "Hybrid Analy.", url: `https://www.hybrid-analysis.com/search?query=${value}` },
    ],
    url: [
      { label: "VirusTotal", url: `https://www.virustotal.com/gui/url/${encodeURIComponent(value)}` },
      { label: "urlscan.io", url: `https://urlscan.io/search/#page.url:${encodeURIComponent(value)}` },
      { label: "URLhaus",    url: `https://urlhaus.abuse.ch/browse.php?search=${encodeURIComponent(value)}` },
    ],
  };
  return m[type] ?? m.ip;
}

function cveRefs(id: string) {
  return [
    { label: "NVD",       url: `https://nvd.nist.gov/vuln/detail/${id}` },
    { label: "MITRE",     url: `https://cve.mitre.org/cgi-bin/cvename.cgi?name=${id}` },
    { label: "EPSS",      url: `https://api.first.org/data/v1/epss?cve=${id}` },
    { label: "CISA KEV",  url: `https://www.cisa.gov/known-exploited-vulnerabilities-catalog` },
    { label: "ExploitDB", url: `https://www.exploit-db.com/search?cve=${id.replace("CVE-","")}` },
  ];
}

// ─────────────────────────────────────────────────────────────────────────────
// Hunt query builder
// ─────────────────────────────────────────────────────────────────────────────

function buildHuntQueries(ioc: IOC): { label: string; lang: string; query: string }[] {
  const v = ioc.ioc_value;
  const t = ioc.ioc_type;
  if (t === "ip") return [
    { label: "Splunk SPL",    lang: "splunk",   query: `index=* (dest_ip="${v}" OR src_ip="${v}") | stats count by src_ip, dest_ip, dest_port, _time | sort -count` },
    { label: "KQL (Sentinel)",lang: "kql",      query: `union DeviceNetworkEvents, CommonSecurityLog\n| where RemoteIP == "${v}" or DestinationIP == "${v}"\n| project TimeGenerated, DeviceName, InitiatingProcessFileName, RemoteIP, RemotePort` },
    { label: "Suricata",      lang: "suricata",  query: `alert ip any any -> ${v} any (msg:"AttackLens - C2 IP ${v}"; sid:9000001; rev:1; classtype:trojan-activity;)` },
    { label: "Sigma (YAML)",  lang: "yaml",      query: `title: AttackLens IOC - IP ${v}\nstatus: experimental\nlogsource:\n  category: network_connection\ndetection:\n  selection:\n    DestinationIp: '${v}'\n  condition: selection\nlevel: high` },
    { label: "iptables",      lang: "bash",      query: `iptables -A OUTPUT -d ${v} -j DROP -m comment --comment "AttackLens IOC"\niptables -A INPUT -s ${v} -j DROP -m comment --comment "AttackLens IOC"` },
  ];
  if (t === "domain") return [
    { label: "Splunk SPL",    lang: "splunk",   query: `index=* (query="${v}" OR dest_host="${v}" OR url="*${v}*") | stats count by src_ip, dest_host, _time | sort -count` },
    { label: "KQL (Sentinel)",lang: "kql",      query: `union DnsEvents, DeviceNetworkEvents\n| where Name == "${v}" or RemoteUrl has "${v}"\n| project TimeGenerated, Computer, Name, IPAddresses, InitiatingProcessFileName` },
    { label: "Suricata",      lang: "suricata",  query: `alert dns any any -> any any (msg:"AttackLens - Malicious Domain ${v}"; dns.query; content:"${v}"; nocase; sid:9000002; rev:1; classtype:trojan-activity;)` },
    { label: "Sigma (YAML)",  lang: "yaml",      query: `title: AttackLens IOC - Domain ${v}\nstatus: experimental\nlogsource:\n  category: dns\ndetection:\n  selection:\n    QueryName|contains: '${v}'\n  condition: selection\nlevel: high` },
    { label: "DNS Block",     lang: "bash",      query: `# Bind RPZ sinkhole\nzone "rpz.local" IN { type master; file "rpz.local.zone"; };\n# Add: ${v} IN CNAME .` },
  ];
  if (t === "hash") return [
    { label: "Splunk SPL",    lang: "splunk",   query: `index=* (FileHash="${v}" OR Hashes="*${v}*") | stats count by host, user, file_path, _time` },
    { label: "KQL (Sentinel)",lang: "kql",      query: `DeviceFileEvents\n| where MD5 == "${v}" or SHA1 == "${v}" or SHA256 == "${v}"\n| project TimeGenerated, DeviceName, ActionType, FileName, FolderPath, InitiatingProcessFileName` },
    { label: "Sigma (YAML)",  lang: "yaml",      query: `title: AttackLens IOC - Hash ${v.slice(0,12)}...\nstatus: experimental\nlogsource:\n  category: file_event\ndetection:\n  selection:\n    Hashes|contains: '${v}'\n  condition: selection\nlevel: critical` },
  ];
  return [
    { label: "Splunk SPL",    lang: "splunk",   query: `index=* url="*${encodeURIComponent(v)}*" | stats count by src_ip, url, _time` },
    { label: "KQL (Sentinel)",lang: "kql",      query: `DeviceNetworkEvents\n| where RemoteUrl has "${v}"\n| project TimeGenerated, DeviceName, RemoteUrl, InitiatingProcessFileName` },
  ];
}

// ─────────────────────────────────────────────────────────────────────────────
// Export helpers
// ─────────────────────────────────────────────────────────────────────────────

function downloadBlob(content: string, filename: string, mime = "text/plain") {
  const a = Object.assign(document.createElement("a"), {
    href: URL.createObjectURL(new Blob([content], { type: mime })),
    download: filename,
  });
  a.click(); URL.revokeObjectURL(a.href);
}

function exportCSV(iocs: IOC[]) {
  const rows = [
    "ioc_value,ioc_type,source,severity,confidence,category,description,cached_at",
    ...iocs.map(i => [
      `"${i.ioc_value}"`, i.ioc_type, i.source, i.severity,
      i.confidence ?? "", `"${deriveCat(i).label}"`,
      `"${(i.description ?? "").replace(/"/g, "'")}"`,
      i.cached_at ? new Date(i.cached_at * 1000).toISOString() : "",
    ].join(",")),
  ].join("\n");
  downloadBlob(rows, `attacklens-iocs-${Date.now()}.csv`, "text/csv");
}

function exportFirewall(iocs: IOC[]) {
  const ts  = new Date().toISOString();
  const ips = iocs.filter(i => i.ioc_type === "ip");
  const dom = iocs.filter(i => i.ioc_type === "domain");
  downloadBlob([
    `! AttackLens Threat IOC Block List — ${ts}`,
    `! ${ips.length} IPs · ${dom.length} domains`,
    `!`, `! === Cisco IOS Extended ACL ===`,
    ...ips.map(i => `deny ip any host ${i.ioc_value}  ! ${i.source} | ${deriveCat(i).label} | conf:${i.confidence}%`),
    `!`, `! === iptables (Linux) ===`,
    ...ips.map(i => `iptables -A OUTPUT -d ${i.ioc_value} -j DROP  # ${i.source} | ${deriveCat(i).short}`),
    `!`, `! === DNS Sinkhole (BIND RPZ) ===`,
    ...dom.map(i => `${i.ioc_value} IN CNAME .  ; ${i.source} | ${deriveCat(i).label}`),
    `!`, `! === Palo Alto EDL-ready (IPs) ===`,
    ...ips.map(i => i.ioc_value),
  ].join("\n"), `attacklens-firewall-rules-${Date.now()}.txt`);
}

function exportSuricata(iocs: IOC[]) {
  const ts  = new Date().toISOString();
  const rules = iocs.flatMap((ioc, idx) => {
    const sid  = 9001000 + idx;
    const cat  = deriveCat(ioc);
    if (ioc.ioc_type === "ip")
      return [`alert ip any any -> ${ioc.ioc_value} any (msg:"AttackLens - ${cat.label} ${ioc.ioc_value}"; sid:${sid}; rev:1; classtype:trojan-activity; reference:url,attacklens;)`];
    if (ioc.ioc_type === "domain")
      return [`alert dns any any -> any any (msg:"AttackLens - ${cat.label} ${ioc.ioc_value}"; dns.query; content:"${ioc.ioc_value}"; nocase; sid:${sid}; rev:1; classtype:trojan-activity;)`];
    return [];
  });
  downloadBlob(`# AttackLens Suricata Rules — ${ts}\n# ${rules.length} rules\n\n` + rules.join("\n"),
    `attacklens-suricata-${Date.now()}.rules`);
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

function lsGet<T>(key: string, def: T): T {
  try { return JSON.parse(localStorage.getItem(key) ?? "") ?? def; } catch { return def; }
}
function lsSet(key: string, v: unknown) {
  try { localStorage.setItem(key, JSON.stringify(v)); } catch {}
}
function relTime(ts: number): string {
  if (!ts) return "—";
  const s = Math.floor(Date.now() / 1000 - ts);
  if (s < 60)    return `${s}s ago`;
  if (s < 3600)  return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}
function shortDate(ts: number | string): string {
  if (!ts) return "—";
  const d = typeof ts === "number" ? new Date(ts * 1000) : new Date(ts);
  return d.toLocaleDateString("en-US", { month: "short", day: "numeric", year: "2-digit" });
}
function daysUntil(dateStr: string): number | null {
  if (!dateStr) return null;
  const ms = new Date(dateStr).getTime();
  if (isNaN(ms)) return null;
  return Math.ceil((ms - Date.now()) / 86400000);
}
function parseArr(v: unknown): string[] {
  if (Array.isArray(v)) return v as string[];
  if (typeof v === "string" && v.startsWith("[")) { try { return JSON.parse(v); } catch {} }
  return [];
}
function riskScore(ioc: IOC): number {
  let s = ioc.severity === "critical" ? 9 : ioc.severity === "high" ? 7 : ioc.severity === "medium" ? 5 : 3;
  const cat = deriveCat(ioc);
  if ([CATS.ransomware, CATS.c2, CATS.feodo].includes(cat)) s = Math.min(10, s + 1);
  if ((ioc.confidence ?? 0) >= 90) s = Math.min(10, s + 1);
  return s;
}

// ─────────────────────────────────────────────────────────────────────────────
// Design atoms
// ─────────────────────────────────────────────────────────────────────────────

function SevBadge({ sev }: { sev: string }) {
  const c: Record<string, string> = {
    critical: "bg-red-50 text-red-700 border-red-200",
    high:     "bg-amber-50 text-amber-700 border-amber-200",
    medium:   "bg-blue-50 text-blue-700 border-blue-200",
    low:      "bg-green-50 text-green-700 border-green-200",
    info:     "bg-gray-100 text-gray-500 border-gray-200",
  };
  return (
    <span className={cn("px-2 py-0.5 text-[9px] font-bold rounded-full border uppercase tracking-wide", c[sev] ?? c.info)}>
      {sev}
    </span>
  );
}

function KevBadge() {
  return <span className="px-1.5 py-0.5 bg-red-600 text-white rounded text-[9px] font-black tracking-wider">KEV</span>;
}

function Card({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <div className={cn("bg-white border border-gray-200 rounded-2xl shadow-sm overflow-hidden", className)}>
      {children}
    </div>
  );
}

function Skeleton({ h = "h-12" }: { h?: string }) {
  return <div className={cn("bg-gray-100 rounded-2xl animate-pulse", h)} />;
}

function CopyBtn({ value, small }: { value: string; small?: boolean }) {
  const [ok, setOk] = useState(false);
  return (
    <button
      onClick={e => { e.stopPropagation(); navigator.clipboard?.writeText(value); setOk(true); setTimeout(() => setOk(false), 1400); }}
      className={cn("flex-shrink-0 rounded hover:bg-gray-100 text-gray-400 hover:text-gray-600 transition-colors", small ? "p-0.5" : "p-1")}
      title="Copy to clipboard"
    >
      {ok ? <CheckCircle2 className={cn(small ? "w-3 h-3" : "w-3.5 h-3.5", "text-green-500")} />
           : <Copy className={cn(small ? "w-3 h-3" : "w-3.5 h-3.5")} />}
    </button>
  );
}

function RefChip({ label, url }: { label: string; url: string }) {
  return (
    <a href={url} target="_blank" rel="noopener noreferrer" onClick={e => e.stopPropagation()}
      className="inline-flex items-center gap-0.5 px-2 py-0.5 rounded-full bg-gray-100 hover:bg-blue-50 text-gray-500 hover:text-blue-600 border border-gray-200 hover:border-blue-200 text-[9px] font-semibold transition-all whitespace-nowrap">
      {label}<ExternalLink className="w-2.5 h-2.5 ml-0.5" />
    </a>
  );
}

const STATUS_CFG: Record<IOCStatus, { label: string; icon: React.ReactNode; cls: string }> = {
  pending:  { label: "Pending",    icon: <Clock className="w-3 h-3" />,       cls: "bg-amber-50 text-amber-700 border-amber-200" },
  blocked:  { label: "Blocked",    icon: <Lock className="w-3 h-3" />,        cls: "bg-green-50 text-green-700 border-green-200" },
  watching: { label: "Watching",   icon: <Eye className="w-3 h-3" />,         cls: "bg-blue-50 text-blue-700 border-blue-200" },
  fp:       { label: "False Pos.", icon: <Unlock className="w-3 h-3" />,      cls: "bg-gray-100 text-gray-400 border-gray-200" },
};

function StatusPill({ status, onChange }: { status: IOCStatus; onChange: (s: IOCStatus) => void }) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  const cfg = STATUS_CFG[status];
  useEffect(() => {
    const h = (e: MouseEvent) => { if (!ref.current?.contains(e.target as Node)) setOpen(false); };
    document.addEventListener("mousedown", h);
    return () => document.removeEventListener("mousedown", h);
  }, []);
  return (
    <div ref={ref} className="relative" onClick={e => e.stopPropagation()}>
      <button onClick={() => setOpen(o => !o)}
        className={cn("flex items-center gap-1 px-2 py-0.5 rounded-full border text-[9px] font-semibold whitespace-nowrap transition-all hover:shadow-sm", cfg.cls)}>
        {cfg.icon}{cfg.label}<ChevronDown className={cn("w-2.5 h-2.5 transition-transform", open && "rotate-180")} />
      </button>
      {open && (
        <div className="absolute right-0 top-full mt-1 z-40 bg-white border border-gray-200 rounded-xl shadow-xl overflow-hidden min-w-[148px]">
          {(Object.entries(STATUS_CFG) as [IOCStatus, typeof STATUS_CFG[IOCStatus]][]).map(([k, c]) => (
            <button key={k} onClick={() => { onChange(k); setOpen(false); }}
              className="w-full flex items-center gap-2 px-3 py-2 text-[10px] font-semibold hover:bg-gray-50 transition-colors text-gray-700">
              {c.icon}{c.label}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// IOC Detail Slide-Out Panel
// ─────────────────────────────────────────────────────────────────────────────

function IOCDetailPanel({ ioc, status, onClose, onStatus }: {
  ioc: IOC; status: IOCStatus; onClose: () => void; onStatus: (s: IOCStatus) => void;
}) {
  const cat    = deriveCat(ioc);
  const refs   = validationRefs(ioc.ioc_type, ioc.ioc_value);
  const blocks = BLOCK_IN[ioc.ioc_type] ?? BLOCK_IN.ip;
  const hunts  = buildHuntQueries(ioc);
  const risk   = riskScore(ioc);
  const [activeHunt, setActiveHunt] = useState(0);
  const [copiedHunt, setCopiedHunt] = useState(false);

  const copyHunt = () => {
    navigator.clipboard?.writeText(hunts[activeHunt].query);
    setCopiedHunt(true); setTimeout(() => setCopiedHunt(false), 1400);
  };

  const typeIcon: Record<string, React.ReactNode> = {
    ip:     <Server className="w-4 h-4 text-gray-500" />,
    domain: <Globe className="w-4 h-4 text-gray-500" />,
    hash:   <Hash className="w-4 h-4 text-gray-500" />,
    url:    <Link2 className="w-4 h-4 text-gray-500" />,
  };

  return (
    <div className="fixed inset-0 z-50 flex">
      {/* Backdrop */}
      <div className="flex-1 bg-black/30 backdrop-blur-sm" onClick={onClose} />

      {/* Panel */}
      <div className="w-[540px] bg-white shadow-2xl flex flex-col overflow-hidden border-l border-gray-200">
        {/* Header */}
        <div className={cn("px-5 py-4 border-b border-gray-100", cat.bg)}>
          <div className="flex items-start gap-3">
            <div className="p-2 bg-white rounded-xl shadow-sm flex-shrink-0">
              {typeIcon[ioc.ioc_type] ?? typeIcon.ip}
            </div>
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 mb-1 flex-wrap">
                <span className={cn("px-2 py-0.5 text-[9px] font-bold rounded-full border", cat.bg, cat.text, cat.border)}>
                  {cat.label}
                </span>
                <SevBadge sev={ioc.severity} />
                <span className={cn("text-[10px] font-black tabular-nums", risk >= 9 ? "text-red-600" : risk >= 7 ? "text-amber-600" : "text-gray-500")}>
                  Risk {risk}/10
                </span>
              </div>
              <div className="flex items-center gap-1.5">
                <span className="font-mono text-sm font-bold text-gray-900 break-all">{ioc.ioc_value}</span>
                <CopyBtn value={ioc.ioc_value} />
              </div>
              <p className="text-[10px] text-gray-500 mt-0.5">
                {ioc.source} · Added {shortDate(ioc.cached_at)} · Expires {shortDate(ioc.expires_at)}
              </p>
            </div>
            <button onClick={onClose} className="p-1.5 rounded-lg hover:bg-white/60 text-gray-500 transition-colors flex-shrink-0">
              <X className="w-4 h-4" />
            </button>
          </div>
          {/* Status row */}
          <div className="flex items-center gap-2 mt-3">
            <StatusPill status={status} onChange={onStatus} />
            <span className="text-[9px] text-gray-500">· Confidence {ioc.confidence}%</span>
            <div className="w-20 h-1.5 bg-gray-200 rounded-full overflow-hidden">
              <div className="h-full rounded-full bg-orange-400" style={{ width: `${ioc.confidence}%` }} />
            </div>
          </div>
        </div>

        <div className="flex-1 overflow-y-auto space-y-0 divide-y divide-gray-100">

          {/* Intelligence summary */}
          <div className="px-5 py-4 space-y-2">
            <p className="text-[9px] font-bold text-gray-400 uppercase tracking-widest flex items-center gap-1.5">
              <Info className="w-3 h-3" />Intelligence Summary
            </p>
            <p className="text-[12px] text-gray-700 leading-relaxed font-medium">{cat.what}</p>
            {ioc.description && (
              <p className="text-[11px] text-gray-500 italic bg-gray-50 px-3 py-2 rounded-xl border border-gray-100">
                "{ioc.description}"
              </p>
            )}
            <div className="flex items-center gap-2 pt-1">
              <span className="px-2 py-0.5 bg-blue-50 text-blue-700 border border-blue-200 text-[9px] font-semibold rounded-full">
                MITRE {cat.mitre}
              </span>
              <span className="px-2 py-0.5 bg-blue-50 text-blue-700 border border-blue-200 text-[9px] font-semibold rounded-full">
                {cat.mitreTech}
              </span>
            </div>
          </div>

          {/* Why it matters */}
          <div className="px-5 py-4 space-y-2 bg-red-50/40">
            <p className="text-[9px] font-bold text-gray-400 uppercase tracking-widest flex items-center gap-1.5">
              <TriangleAlert className="w-3 h-3 text-red-400" />Why It Matters
            </p>
            <p className="text-[12px] text-red-800 leading-relaxed">{cat.why}</p>
          </div>

          {/* Incident response playbook */}
          <div className="px-5 py-4 space-y-3">
            <p className="text-[9px] font-bold text-gray-400 uppercase tracking-widest flex items-center gap-1.5">
              <BookOpen className="w-3 h-3 text-orange-400" />Response Playbook
            </p>
            <div className="space-y-2">
              {cat.playbook.map((step, i) => (
                <div key={i} className={cn(
                  "flex items-start gap-3 px-3 py-2.5 rounded-xl border",
                  step.priority === "critical" ? "bg-red-50 border-red-100" :
                  step.priority === "high"     ? "bg-amber-50 border-amber-100" :
                  "bg-gray-50 border-gray-100"
                )}>
                  <span className={cn(
                    "w-5 h-5 rounded-full flex items-center justify-center text-[9px] font-black flex-shrink-0 mt-0.5",
                    step.priority === "critical" ? "bg-red-500 text-white" :
                    step.priority === "high"     ? "bg-amber-500 text-white" :
                    "bg-gray-300 text-gray-700"
                  )}>{i + 1}</span>
                  <div className="flex-1 min-w-0">
                    <p className="text-[11px] text-gray-800 font-semibold leading-snug">{step.step}</p>
                    <p className="text-[9px] text-gray-500 mt-0.5 flex items-center gap-1">
                      <Terminal className="w-2.5 h-2.5" />{step.tool}
                    </p>
                  </div>
                  <span className={cn(
                    "text-[8px] font-black uppercase px-1.5 py-0.5 rounded flex-shrink-0",
                    step.priority === "critical" ? "bg-red-100 text-red-600" :
                    step.priority === "high"     ? "bg-amber-100 text-amber-700" :
                    "bg-gray-100 text-gray-500"
                  )}>{step.priority}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Block in */}
          <div className="px-5 py-4 space-y-2">
            <p className="text-[9px] font-bold text-gray-400 uppercase tracking-widest flex items-center gap-1.5">
              <Lock className="w-3 h-3 text-gray-400" />Block In
            </p>
            <div className="grid grid-cols-2 gap-1.5">
              {blocks.map(b => (
                <div key={b} className="flex items-center gap-2 px-3 py-2 bg-gray-50 rounded-xl border border-gray-100">
                  <span className="w-1.5 h-1.5 rounded-full bg-orange-400 flex-shrink-0" />
                  <span className="text-[11px] text-gray-800 font-semibold">{b}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Hunt queries */}
          <div className="px-5 py-4 space-y-3">
            <p className="text-[9px] font-bold text-gray-400 uppercase tracking-widest flex items-center gap-1.5">
              <Terminal className="w-3 h-3 text-green-500" />Hunt Queries
            </p>
            {/* Tab selector */}
            <div className="flex gap-1 flex-wrap">
              {hunts.map((h, i) => (
                <button key={i} onClick={() => setActiveHunt(i)}
                  className={cn(
                    "px-2.5 py-1 text-[9px] font-bold rounded-lg border transition-all",
                    activeHunt === i
                      ? "bg-gray-900 text-white border-gray-900"
                      : "bg-white text-gray-500 border-gray-200 hover:border-gray-400"
                  )}>
                  {h.label}
                </button>
              ))}
            </div>
            {/* Query box */}
            <div className="relative">
              <pre className="bg-gray-950 text-green-400 text-[10px] font-mono p-4 rounded-xl overflow-x-auto leading-relaxed whitespace-pre-wrap break-all">
                {hunts[activeHunt].query}
              </pre>
              <button onClick={copyHunt}
                className="absolute top-2 right-2 p-1.5 bg-gray-800 hover:bg-gray-700 text-gray-400 hover:text-white rounded-lg transition-colors">
                {copiedHunt
                  ? <CheckCircle2 className="w-3.5 h-3.5 text-green-400" />
                  : <Copy className="w-3.5 h-3.5" />}
              </button>
            </div>
          </div>

          {/* Validate */}
          <div className="px-5 py-4 space-y-2">
            <p className="text-[9px] font-bold text-gray-400 uppercase tracking-widest flex items-center gap-1.5">
              <ExternalLink className="w-3 h-3 text-gray-400" />External Validation
            </p>
            <div className="flex flex-wrap gap-1.5">
              {validationRefs(ioc.ioc_type, ioc.ioc_value).map(r => <RefChip key={r.label} label={r.label} url={r.url} />)}
            </div>
          </div>

          {/* Metadata */}
          <div className="px-5 py-4">
            <p className="text-[9px] font-bold text-gray-400 uppercase tracking-widest mb-2 flex items-center gap-1.5">
              <Database className="w-3 h-3 text-gray-400" />Metadata
            </p>
            <div className="grid grid-cols-3 gap-x-4 gap-y-2">
              {[
                ["Feed source", ioc.source], ["IOC type", ioc.ioc_type],
                ["Severity",   ioc.severity], ["Confidence", `${ioc.confidence}%`],
                ["Risk score", `${riskScore(ioc)} / 10`], ["Added", shortDate(ioc.cached_at)],
                ["Expires",    shortDate(ioc.expires_at)], ["MITRE TA", cat.mitre],
                ["Technique",  cat.mitreTech],
              ].map(([l, v]) => (
                <div key={l}>
                  <p className="text-[9px] text-gray-400 font-medium">{l}</p>
                  <p className="text-[10px] text-gray-800 font-semibold">{v}</p>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// IOC Triage Tab
// ─────────────────────────────────────────────────────────────────────────────

type SortKey = "risk" | "severity" | "confidence" | "cached_at";

function IOCTriageTab({ iocs }: { iocs: IOC[] }) {
  const [statuses,  setStatuses]  = useState<Record<string, IOCStatus>>(() => lsGet("al_ioc_status4", {}));
  const [stars,     setStars]     = useState<Record<string, boolean>>(() => lsGet("al_ioc_stars4", {}));
  const [selected,  setSelected]  = useState<Set<string>>(new Set());
  const [search,    setSearch]    = useState("");
  const [typeF,     setTypeF]     = useState<"all" | "ip" | "domain" | "hash">("all");
  const [statusF,   setStatusF]   = useState<"all" | "pending" | "blocked" | "watching">("all");
  const [sortKey,   setSortKey]   = useState<SortKey>("risk");
  const [sortAsc,   setSortAsc]   = useState(false);
  const [showAll,   setShowAll]   = useState(false);
  const [alertDismissed, setAlertDismissed] = useState(false);
  const [detailIOC, setDetailIOC] = useState<IOC | null>(null);

  const SEV_ORDER: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

  const setStatus = (key: string, s: IOCStatus) => {
    const n = { ...statuses, [key]: s }; setStatuses(n); lsSet("al_ioc_status4", n);
  };
  const toggleStar = (key: string) => {
    const n = { ...stars, [key]: !stars[key] }; setStars(n); lsSet("al_ioc_stars4", n);
  };
  const toggleSel = (v: string) =>
    setSelected(prev => { const n = new Set(prev); n.has(v) ? n.delete(v) : n.add(v); return n; });
  const bulkStatus = (s: IOCStatus) => {
    const n = { ...statuses }; selected.forEach(v => { n[v] = s; });
    setStatuses(n); lsSet("al_ioc_status4", n); setSelected(new Set());
  };
  const toggleSort = (k: SortKey) => {
    sortKey === k ? setSortAsc(a => !a) : (setSortKey(k), setSortAsc(false));
  };

  const typeCounts: Record<string, number> = {};
  iocs.forEach(i => { typeCounts[i.ioc_type] = (typeCounts[i.ioc_type] ?? 0) + 1; });

  const filtered = useMemo(() => iocs
    .filter(i => typeF === "all" || i.ioc_type === typeF)
    .filter(i => statusF === "all" || (statuses[i.ioc_value] ?? "pending") === statusF)
    .filter(i => !search || i.ioc_value.toLowerCase().includes(search.toLowerCase()) ||
                 i.source?.toLowerCase().includes(search.toLowerCase()) ||
                 (i.description ?? "").toLowerCase().includes(search.toLowerCase()))
    .sort((a, b) => {
      const sa = stars[a.ioc_value] ? 1 : 0, sb = stars[b.ioc_value] ? 1 : 0;
      if (sa !== sb) return sb - sa;
      let d = 0;
      if (sortKey === "risk")       d = riskScore(b) - riskScore(a);
      if (sortKey === "severity")   d = (SEV_ORDER[b.severity] ?? 0) - (SEV_ORDER[a.severity] ?? 0);
      if (sortKey === "confidence") d = (b.confidence ?? 0) - (a.confidence ?? 0);
      if (sortKey === "cached_at")  d = (b.cached_at ?? 0) - (a.cached_at ?? 0);
      return sortAsc ? -d : d;
    }), [iocs, typeF, statusF, search, statuses, stars, sortKey, sortAsc]);

  const visible = showAll ? filtered : filtered.slice(0, 20);
  const pendingCritical = iocs.filter(i => i.severity === "critical" && (statuses[i.ioc_value] ?? "pending") === "pending").length;

  const typeIcon: Record<string, React.ReactNode> = {
    ip:     <Server className="w-3 h-3 text-gray-400" />,
    domain: <Globe className="w-3 h-3 text-gray-400" />,
    hash:   <Hash className="w-3 h-3 text-gray-400" />,
    url:    <Link2 className="w-3 h-3 text-gray-400" />,
  };

  const SortTh = ({ label, k }: { label: string; k: SortKey }) => (
    <th onClick={() => toggleSort(k)}
      className="px-3 py-2.5 text-left text-[9px] font-bold text-gray-400 uppercase tracking-wider cursor-pointer hover:text-gray-600 select-none">
      <span className="flex items-center gap-1">
        {label}
        {sortKey === k && (sortAsc ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />)}
      </span>
    </th>
  );

  const blocked  = Object.values(statuses).filter(s => s === "blocked").length;
  const watching = Object.values(statuses).filter(s => s === "watching").length;
  const pending  = iocs.filter(i => (statuses[i.ioc_value] ?? "pending") === "pending").length;

  return (
    <>
      {/* Critical unblocked alert bar */}
      {pendingCritical > 0 && !alertDismissed && (
        <div className="flex items-center gap-3 px-4 py-3 bg-red-600 text-white rounded-xl mb-3">
          <Flame className="w-4 h-4 flex-shrink-0 animate-pulse" />
          <div className="flex-1">
            <span className="text-[12px] font-bold">
              {pendingCritical} critical IOC{pendingCritical > 1 ? "s" : ""} unblocked
            </span>
            <span className="text-[11px] text-red-200 ml-2">
              — Block immediately in firewall / EDR / DNS sinkhole
            </span>
          </div>
          <button onClick={() => setAlertDismissed(true)} className="text-red-200 hover:text-white">
            <X className="w-4 h-4" />
          </button>
        </div>
      )}

      <Card>
        <div className="h-0.5 bg-gradient-to-r from-orange-400 via-amber-400 to-orange-500" />

        {/* Toolbar */}
        <div className="flex items-center gap-2.5 px-4 py-3 border-b border-gray-100 bg-gray-50 flex-wrap">
          {/* Search */}
          <div className="relative">
            <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-gray-400 pointer-events-none" />
            <input type="text" placeholder="Search IOC value, source, description…" value={search}
              onChange={e => setSearch(e.target.value)}
              className="pl-8 pr-3 py-1.5 text-[11px] border border-gray-200 rounded-xl bg-white text-gray-800 placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-orange-200 focus:border-orange-300 w-64" />
          </div>

          {/* Type tabs */}
          <div className="flex items-center border border-gray-200 rounded-xl overflow-hidden bg-white">
            {(["all","ip","domain","hash"] as const).map(t => (
              <button key={t} onClick={() => setTypeF(t)}
                className={cn("px-3 py-1.5 text-[10px] font-semibold capitalize transition-all",
                  typeF === t ? "bg-orange-500 text-white" : "text-gray-500 hover:text-gray-700 hover:bg-gray-50")}>
                {t}{t !== "all" && typeCounts[t] ? ` (${typeCounts[t]})` : ""}
              </button>
            ))}
          </div>

          {/* Status filter */}
          <select value={statusF} onChange={e => setStatusF(e.target.value as typeof statusF)}
            className="px-2.5 py-1.5 text-[10px] border border-gray-200 rounded-xl bg-white text-gray-600 focus:outline-none focus:ring-1 focus:ring-orange-200">
            <option value="all">All statuses</option>
            <option value="pending">Pending</option>
            <option value="blocked">Blocked</option>
            <option value="watching">Watching</option>
          </select>

          {/* Export */}
          <div className="ml-auto flex items-center gap-1.5">
            {selected.size > 0 && (
              <div className="flex items-center gap-1.5">
                <span className="text-[10px] text-orange-600 font-bold">{selected.size} selected</span>
                <button onClick={() => bulkStatus("blocked")}
                  className="flex items-center gap-1 px-2.5 py-1 bg-green-50 hover:bg-green-100 text-green-700 text-[10px] font-semibold rounded-lg border border-green-200 transition-colors">
                  <Lock className="w-3 h-3" />Block All
                </button>
                <button onClick={() => bulkStatus("watching")}
                  className="flex items-center gap-1 px-2.5 py-1 bg-blue-50 hover:bg-blue-100 text-blue-700 text-[10px] font-semibold rounded-lg border border-blue-200 transition-colors">
                  <Eye className="w-3 h-3" />Watch All
                </button>
                <button onClick={() => setSelected(new Set())} className="p-1 text-gray-400 hover:text-gray-600">
                  <X className="w-3.5 h-3.5" />
                </button>
              </div>
            )}
            <button onClick={() => exportCSV(filtered)}
              className="flex items-center gap-1 px-2.5 py-1.5 bg-white hover:bg-gray-50 border border-gray-200 text-gray-600 text-[10px] font-semibold rounded-xl transition-colors">
              <Download className="w-3 h-3" />CSV
            </button>
            <button onClick={() => exportFirewall(filtered)}
              className="flex items-center gap-1 px-2.5 py-1.5 bg-white hover:bg-gray-50 border border-gray-200 text-gray-600 text-[10px] font-semibold rounded-xl transition-colors">
              <Shield className="w-3 h-3" />Firewall
            </button>
            <button onClick={() => exportSuricata(filtered)}
              className="flex items-center gap-1 px-2.5 py-1.5 bg-white hover:bg-gray-50 border border-gray-200 text-gray-600 text-[10px] font-semibold rounded-xl transition-colors">
              <Terminal className="w-3 h-3" />Suricata
            </button>
          </div>
        </div>

        {/* Table */}
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="bg-gray-50 border-b border-gray-100">
                <th className="pl-3 pr-1 py-2.5 w-8">
                  <div onClick={() => setSelected(
                    selected.size === filtered.length
                      ? new Set()
                      : new Set(filtered.map(i => i.ioc_value))
                  )} className={cn("w-3.5 h-3.5 rounded border cursor-pointer transition-all flex items-center justify-center",
                    selected.size === filtered.length && filtered.length > 0
                      ? "bg-orange-500 border-orange-500"
                      : "border-gray-300 hover:border-orange-400")}>
                    {selected.size === filtered.length && filtered.length > 0 && <CheckCircle2 className="w-2.5 h-2.5 text-white" />}
                  </div>
                </th>
                <th className="px-2 py-2.5 w-5" />
                <th className="px-3 py-2.5 text-left text-[9px] font-bold text-gray-400 uppercase tracking-wider">IOC / Type</th>
                <th className="px-3 py-2.5 text-left text-[9px] font-bold text-gray-400 uppercase tracking-wider">Category</th>
                <th className="px-3 py-2.5 text-left text-[9px] font-bold text-gray-400 uppercase tracking-wider">Feed</th>
                <SortTh label="Confidence" k="confidence" />
                <SortTh label="Risk" k="risk" />
                <SortTh label="Added" k="cached_at" />
                <th className="px-3 py-2.5 text-left text-[9px] font-bold text-gray-400 uppercase tracking-wider">Status</th>
                <th className="px-3 py-2.5 w-16" />
              </tr>
            </thead>
            <tbody>
              {iocs.length === 0 ? (
                <tr><td colSpan={10} className="py-16 text-center">
                  <ShieldAlert className="w-8 h-8 text-gray-200 mx-auto mb-2" />
                  <p className="text-[11px] text-gray-400 font-medium">No IOCs cached — feeds populate after first sync</p>
                </td></tr>
              ) : filtered.length === 0 ? (
                <tr><td colSpan={10} className="py-10 text-center text-[11px] text-gray-400">No IOCs match this filter</td></tr>
              ) : visible.map(ioc => {
                const cat  = deriveCat(ioc);
                const risk = riskScore(ioc);
                const st   = statuses[ioc.ioc_value] ?? "pending";
                const isFP = st === "fp";
                const isNew = !!ioc.cached_at && (Date.now() / 1000 - ioc.cached_at) < 86400;
                return (
                  <tr key={ioc.ioc_value}
                    onClick={() => setDetailIOC(ioc)}
                    className={cn(
                      "border-b border-gray-100 cursor-pointer transition-all group hover:bg-orange-50/40",
                      selected.has(ioc.ioc_value) && "bg-orange-50",
                      isFP && "opacity-40",
                    )}>
                    <td className="pl-3 pr-1 py-2.5 w-8" onClick={e => { e.stopPropagation(); toggleSel(ioc.ioc_value); }}>
                      <div className={cn("w-3.5 h-3.5 rounded border transition-all flex items-center justify-center",
                        selected.has(ioc.ioc_value) ? "bg-orange-500 border-orange-500" : "border-gray-300 hover:border-orange-400")}>
                        {selected.has(ioc.ioc_value) && <CheckCircle2 className="w-2.5 h-2.5 text-white" />}
                      </div>
                    </td>
                    <td className="px-2 py-2.5 w-5">
                      <span className={cn("w-2 h-2 rounded-full inline-block",
                        ioc.severity === "critical" ? "bg-red-500 animate-pulse" :
                        ioc.severity === "high"     ? "bg-amber-500" :
                        ioc.severity === "medium"   ? "bg-blue-400" : "bg-gray-300")} />
                    </td>
                    <td className="px-3 py-2.5 max-w-[220px]">
                      <div className="flex items-center gap-1.5">
                        {typeIcon[ioc.ioc_type] ?? typeIcon.ip}
                        <span className="font-mono text-[11px] text-gray-800 font-semibold truncate">{ioc.ioc_value}</span>
                        <CopyBtn value={ioc.ioc_value} small />
                        {isNew && <span className="px-1.5 py-0.5 bg-orange-500 text-white text-[8px] font-black rounded-full">NEW</span>}
                      </div>
                      <p className="text-[9px] text-gray-400 mt-0.5 ml-5 truncate">{ioc.ioc_type.toUpperCase()}</p>
                    </td>
                    <td className="px-3 py-2.5">
                      <span className={cn("px-2 py-0.5 text-[9px] font-bold rounded-full border whitespace-nowrap", cat.bg, cat.text, cat.border)}>
                        {cat.short}
                      </span>
                    </td>
                    <td className="px-3 py-2.5">
                      <span className="text-[10px] text-gray-500 font-medium">{ioc.source}</span>
                    </td>
                    <td className="px-3 py-2.5 w-20">
                      <div className="flex items-center gap-1.5">
                        <div className="w-10 h-1.5 bg-gray-100 rounded-full overflow-hidden">
                          <div className="h-full rounded-full bg-orange-400" style={{ width: `${ioc.confidence}%` }} />
                        </div>
                        <span className="text-[9px] text-gray-500 tabular-nums">{ioc.confidence}%</span>
                      </div>
                    </td>
                    <td className="px-3 py-2.5 w-14">
                      <span className={cn("text-[12px] font-black tabular-nums",
                        risk >= 9 ? "text-red-600" : risk >= 7 ? "text-amber-600" : "text-gray-500")}>
                        {risk}<span className="text-[9px] font-normal text-gray-400">/10</span>
                      </span>
                    </td>
                    <td className="px-3 py-2.5 w-20">
                      <span className="text-[10px] text-gray-400">{relTime(ioc.cached_at)}</span>
                    </td>
                    <td className="px-3 py-2.5" onClick={e => e.stopPropagation()}>
                      <StatusPill status={st as IOCStatus} onChange={s => setStatus(ioc.ioc_value, s)} />
                    </td>
                    <td className="px-3 py-2.5 w-16">
                      <div className="flex items-center gap-1">
                        <button onClick={e => { e.stopPropagation(); toggleStar(ioc.ioc_value); }}
                          className={cn("p-0.5 rounded transition-colors", stars[ioc.ioc_value] ? "text-amber-400" : "text-gray-300 hover:text-amber-400")}>
                          <Star className={cn("w-3.5 h-3.5", stars[ioc.ioc_value] && "fill-current")} />
                        </button>
                        <ChevronRight className="w-3.5 h-3.5 text-gray-300 opacity-0 group-hover:opacity-100 transition-opacity" />
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>

        {/* Footer */}
        <div className="flex items-center justify-between px-4 py-2.5 border-t border-gray-100 bg-gray-50">
          <div className="flex items-center gap-3 text-[10px]">
            <span className="text-gray-500">{filtered.length} IOCs</span>
            <span className="text-red-600 font-semibold">{pending} pending</span>
            <span className="text-green-600 font-semibold">{blocked} blocked</span>
            <span className="text-blue-600 font-semibold">{watching} watching</span>
          </div>
          {!showAll && filtered.length > 20 && (
            <button onClick={() => setShowAll(true)}
              className="text-[10px] text-orange-500 hover:text-orange-600 font-semibold flex items-center gap-1">
              Show all {filtered.length} <ChevronDown className="w-3 h-3" />
            </button>
          )}
        </div>
      </Card>

      {/* Detail panel */}
      {detailIOC && (
        <IOCDetailPanel
          ioc={detailIOC}
          status={(statuses[detailIOC.ioc_value] ?? "pending") as IOCStatus}
          onClose={() => setDetailIOC(null)}
          onStatus={s => setStatus(detailIOC.ioc_value, s)}
        />
      )}
    </>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// CVE Intelligence Tab
// ─────────────────────────────────────────────────────────────────────────────

function CVEIntelTab({ cves }: { cves: CVE[] }) {
  const [search, setSearch] = useState("");
  const [kevOnly, setKevOnly] = useState(false);
  const [expanded, setExpanded] = useState<string | null>(null);

  const filtered = cves.filter(c =>
    (!kevOnly || c.is_kev) &&
    (!search || c.cve_id.toLowerCase().includes(search.toLowerCase()) ||
                c.description?.toLowerCase().includes(search.toLowerCase()))
  );

  return (
    <div className="space-y-3">
      {/* Filters */}
      <div className="flex items-center gap-2.5">
        <div className="relative">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-gray-400 pointer-events-none" />
          <input placeholder="Search CVE ID or description…" value={search}
            onChange={e => setSearch(e.target.value)}
            className="pl-8 pr-3 py-1.5 text-[11px] border border-gray-200 rounded-xl bg-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-orange-200 w-64" />
        </div>
        <button onClick={() => setKevOnly(k => !k)}
          className={cn("flex items-center gap-1.5 px-3 py-1.5 rounded-xl border text-[10px] font-semibold transition-all",
            kevOnly ? "bg-red-600 text-white border-red-600" : "bg-white text-gray-600 border-gray-200 hover:border-red-200")}>
          <Zap className="w-3 h-3" />KEV Only
        </button>
        <span className="text-[10px] text-gray-400 ml-auto">{filtered.length} CVEs</span>
      </div>

      <Card>
        <div className="h-0.5 bg-gradient-to-r from-red-400 via-amber-400 to-red-500" />
        {/* Header row */}
        <div className="grid grid-cols-[2fr_5fr_1fr_1fr_1fr_1fr] gap-0 px-4 py-2 border-b border-gray-100 bg-gray-50">
          {["CVE ID", "Description", "CVSS", "EPSS", "Priority", ""].map(h => (
            <span key={h} className="text-[9px] font-bold text-gray-400 uppercase tracking-wider">{h}</span>
          ))}
        </div>
        <div className="divide-y divide-gray-50">
          {filtered.length === 0 ? (
            <div className="py-14 text-center text-[11px] text-gray-400">No CVEs match</div>
          ) : filtered.map(c => (
            <div key={c.cve_id}>
              <div onClick={() => setExpanded(expanded === c.cve_id ? null : c.cve_id)}
                className="grid grid-cols-[2fr_5fr_1fr_1fr_1fr_1fr] gap-0 px-4 py-3 hover:bg-gray-50 cursor-pointer transition-colors group items-center">
                <div className="flex items-center gap-1.5">
                  <span className={cn("w-2 h-2 rounded-full flex-shrink-0",
                    c.severity === "critical" ? "bg-red-500 animate-pulse" :
                    c.severity === "high"     ? "bg-amber-500" : "bg-blue-400")} />
                  <span className="font-mono text-[10px] text-blue-600 font-bold">{c.cve_id}</span>
                  {c.is_kev && <KevBadge />}
                </div>
                <span className="text-[11px] text-gray-700 truncate pr-4">{c.description?.slice(0, 80)}…</span>
                <span className={cn("text-[12px] font-black tabular-nums",
                  (c.cvss_score ?? 0) >= 9 ? "text-red-600" : (c.cvss_score ?? 0) >= 7 ? "text-amber-600" : "text-gray-600")}>
                  {c.cvss_score?.toFixed(1) ?? "—"}
                </span>
                <span className={cn("text-[11px] font-bold tabular-nums",
                  (c.epss ?? 0) >= 0.5 ? "text-red-600" : (c.epss ?? 0) >= 0.1 ? "text-amber-600" : "text-gray-500")}>
                  {c.epss != null ? `${(c.epss * 100).toFixed(1)}%` : "—"}
                </span>
                <SevBadge sev={c.severity} />
                <ChevronRight className={cn("w-3.5 h-3.5 text-gray-300 transition-transform group-hover:text-gray-500",
                  expanded === c.cve_id && "rotate-90")} />
              </div>
              {expanded === c.cve_id && (
                <div className="px-4 pb-4 pt-1 bg-gray-50 border-t border-gray-100">
                  <p className="text-[11px] text-gray-700 leading-relaxed mb-3">{c.description}</p>
                  <div className="flex items-center gap-3 mb-3">
                    {c.is_kev && (
                      <div className="flex items-center gap-1.5 px-2.5 py-1.5 bg-red-50 rounded-xl border border-red-200">
                        <Zap className="w-3 h-3 text-red-500" />
                        <span className="text-[10px] font-bold text-red-700">CISA Known Exploited — patch required</span>
                      </div>
                    )}
                    {(c.epss ?? 0) >= 0.5 && (
                      <div className="flex items-center gap-1.5 px-2.5 py-1.5 bg-amber-50 rounded-xl border border-amber-200">
                        <Activity className="w-3 h-3 text-amber-600" />
                        <span className="text-[10px] font-bold text-amber-700">High EPSS — exploitation likely within 30 days</span>
                      </div>
                    )}
                  </div>
                  <div className="flex gap-1.5 flex-wrap">
                    {cveRefs(c.cve_id).map(r => <RefChip key={r.label} label={r.label} url={r.url} />)}
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// KEV Mandates Tab
// ─────────────────────────────────────────────────────────────────────────────

function KEVMandatesTab({ kev }: { kev: KEVEntry[] }) {
  const [patchStatus, setPatch] = useState<Record<string, IOCStatus>>(() => lsGet("al_kev_status4", {}));
  const [search, setSearch] = useState("");
  const [filter, setFilter] = useState<"all" | "overdue" | "due_soon" | "pending">("all");

  const set = (id: string, s: IOCStatus) => {
    const n = { ...patchStatus, [id]: s }; setPatch(n); lsSet("al_kev_status4", n);
  };

  const enriched = kev.map(k => ({ ...k, days: daysUntil(k.due_date) }));
  const overdue   = enriched.filter(k => (k.days ?? 1) < 0 && (patchStatus[k.cve_id] ?? "pending") === "pending").length;
  const dueSoon   = enriched.filter(k => k.days !== null && k.days >= 0 && k.days <= 7 && (patchStatus[k.cve_id] ?? "pending") === "pending").length;

  const filtered = enriched.filter(k =>
    (!search || k.cve_id.toLowerCase().includes(search.toLowerCase()) ||
                k.vendor.toLowerCase().includes(search.toLowerCase()) ||
                k.product.toLowerCase().includes(search.toLowerCase()) ||
                k.vuln_name.toLowerCase().includes(search.toLowerCase())) &&
    (filter === "all" ||
     (filter === "overdue"  && (k.days ?? 1) < 0) ||
     (filter === "due_soon" && k.days !== null && k.days >= 0 && k.days <= 7) ||
     (filter === "pending"  && (patchStatus[k.cve_id] ?? "pending") === "pending"))
  );

  return (
    <div className="space-y-3">
      {/* Summary strip */}
      {(overdue > 0 || dueSoon > 0) && (
        <div className="grid grid-cols-2 gap-2">
          {overdue > 0 && (
            <div className="flex items-center gap-3 px-4 py-3 bg-red-600 text-white rounded-xl">
              <TriangleAlert className="w-5 h-5 flex-shrink-0 animate-pulse" />
              <div>
                <p className="text-[13px] font-black">{overdue} overdue CISA mandates</p>
                <p className="text-[10px] text-red-200">Patch deadline has passed — remediate immediately</p>
              </div>
            </div>
          )}
          {dueSoon > 0 && (
            <div className="flex items-center gap-3 px-4 py-3 bg-amber-50 border border-amber-200 rounded-xl">
              <Clock className="w-5 h-5 text-amber-600 flex-shrink-0" />
              <div>
                <p className="text-[13px] font-black text-amber-800">{dueSoon} due within 7 days</p>
                <p className="text-[10px] text-amber-600">Schedule patching this sprint</p>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Filters */}
      <div className="flex items-center gap-2.5">
        <div className="relative">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-gray-400 pointer-events-none" />
          <input placeholder="Search CVE, vendor, product…" value={search}
            onChange={e => setSearch(e.target.value)}
            className="pl-8 pr-3 py-1.5 text-[11px] border border-gray-200 rounded-xl bg-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-orange-200 w-56" />
        </div>
        <div className="flex border border-gray-200 rounded-xl overflow-hidden bg-white">
          {(["all","overdue","due_soon","pending"] as const).map(f => (
            <button key={f} onClick={() => setFilter(f)}
              className={cn("px-3 py-1.5 text-[10px] font-semibold capitalize transition-all",
                filter === f ? "bg-orange-500 text-white" : "text-gray-500 hover:bg-gray-50")}>
              {f === "due_soon" ? "Due ≤7d" : f === "all" ? "All" : f.charAt(0).toUpperCase() + f.slice(1)}
            </button>
          ))}
        </div>
        <span className="text-[10px] text-gray-400 ml-auto">{filtered.length} entries</span>
      </div>

      <Card>
        <div className="h-0.5 bg-gradient-to-r from-red-500 via-red-400 to-amber-500" />
        <div className="divide-y divide-gray-50">
          {filtered.length === 0 ? (
            <div className="py-14 text-center">
              <ShieldCheck className="w-8 h-8 text-green-300 mx-auto mb-2" />
              <p className="text-[11px] text-gray-400">No KEV entries match this filter</p>
            </div>
          ) : filtered.map(k => {
            const st   = patchStatus[k.cve_id] ?? "pending";
            const done = st === "blocked";
            return (
              <div key={k.cve_id} className={cn("px-5 py-4 hover:bg-gray-50 transition-colors", done && "opacity-50")}>
                <div className="flex items-start gap-3">
                  <div className="flex-1 min-w-0">
                    {/* Top row */}
                    <div className="flex items-center gap-2 flex-wrap mb-2">
                      <span className="font-mono text-[11px] text-red-600 font-bold">{k.cve_id}</span>
                      <KevBadge />
                      {k.days !== null && (
                        <span className={cn("text-[9px] font-black px-2 py-0.5 rounded-full border",
                          k.days < 0   ? "bg-red-600 text-white border-red-600" :
                          k.days <= 7  ? "bg-amber-50 text-amber-700 border-amber-300" :
                          k.days <= 30 ? "bg-yellow-50 text-yellow-700 border-yellow-200" :
                          "bg-gray-100 text-gray-500 border-gray-200")}>
                          {k.days < 0 ? `${Math.abs(k.days)}d OVERDUE` :
                           k.days === 0 ? "DUE TODAY" : `${k.days}d remaining`}
                        </span>
                      )}
                      {done && (
                        <span className="flex items-center gap-1 px-2 py-0.5 bg-green-50 text-green-700 border border-green-200 rounded-full text-[9px] font-bold">
                          <CheckCircle2 className="w-3 h-3" />Patched
                        </span>
                      )}
                    </div>
                    {/* Vuln name */}
                    <p className="text-[12px] text-gray-800 font-bold leading-snug mb-1">{k.vuln_name}</p>
                    <p className="text-[10px] text-gray-500 mb-2">{k.vendor} · {k.product} · Added {shortDate(k.date_added)}</p>
                    {/* Required action */}
                    {k.required_action && (
                      <div className="flex items-start gap-2 bg-red-50 border border-red-100 rounded-xl px-3 py-2.5 mb-2">
                        <ArrowRight className="w-3.5 h-3.5 text-red-500 flex-shrink-0 mt-0.5" />
                        <p className="text-[11px] text-red-800 leading-relaxed">
                          <span className="font-bold">CISA Required Action: </span>{k.required_action}
                        </p>
                      </div>
                    )}
                    <div className="flex gap-1.5 flex-wrap">
                      {cveRefs(k.cve_id).slice(0, 3).map(r => <RefChip key={r.label} label={r.label} url={r.url} />)}
                    </div>
                  </div>
                  <div className="flex-shrink-0 flex flex-col items-end gap-2">
                    <StatusPill status={st as IOCStatus} onChange={s => set(k.cve_id, s)} />
                    {!done && k.days !== null && k.days <= 14 && (
                      <button onClick={() => set(k.cve_id, "blocked")}
                        className="flex items-center gap-1 px-2.5 py-1.5 bg-green-600 hover:bg-green-700 text-white text-[10px] font-bold rounded-xl transition-colors">
                        <CheckCircle2 className="w-3 h-3" />Mark Patched
                      </button>
                    )}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </Card>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Hunt Queries Tab
// ─────────────────────────────────────────────────────────────────────────────

function HuntQueriesTab({ iocs }: { iocs: IOC[] }) {
  const [platform, setPlatform] = useState<"splunk" | "kql" | "suricata" | "sigma" | "bash">("splunk");
  const [search, setSearch] = useState("");
  const [copied, setCopied] = useState<string | null>(null);

  const highPriority = iocs.filter(i =>
    i.severity === "critical" || i.severity === "high" ||
    (deriveCat(i) === CATS.ransomware) || (deriveCat(i) === CATS.c2) || (deriveCat(i) === CATS.feodo)
  ).slice(0, 30);

  const visible = highPriority.filter(i =>
    !search || i.ioc_value.toLowerCase().includes(search.toLowerCase())
  );

  const copy = (id: string, q: string) => {
    navigator.clipboard?.writeText(q);
    setCopied(id); setTimeout(() => setCopied(null), 1400);
  };

  const platformLabels: Record<string, string> = {
    splunk: "Splunk SPL", kql: "KQL (Sentinel)", suricata: "Suricata IDS",
    sigma: "Sigma YAML", bash: "Shell / ACL",
  };

  return (
    <div className="space-y-3">
      {/* Platform selector */}
      <div className="flex items-center gap-2.5">
        <div className="flex border border-gray-200 rounded-xl overflow-hidden bg-white">
          {(["splunk","kql","suricata","sigma","bash"] as const).map(p => (
            <button key={p} onClick={() => setPlatform(p)}
              className={cn("px-3 py-1.5 text-[10px] font-bold transition-all",
                platform === p ? "bg-gray-900 text-white" : "text-gray-500 hover:bg-gray-50")}>
              {platformLabels[p]}
            </button>
          ))}
        </div>
        <div className="relative ml-auto">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-gray-400 pointer-events-none" />
          <input placeholder="Filter by IOC value…" value={search}
            onChange={e => setSearch(e.target.value)}
            className="pl-8 pr-3 py-1.5 text-[11px] border border-gray-200 rounded-xl bg-white w-48 placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-orange-200" />
        </div>
      </div>

      <div className="space-y-2">
        {visible.length === 0 ? (
          <Card>
            <div className="py-14 text-center">
              <Terminal className="w-8 h-8 text-gray-200 mx-auto mb-2" />
              <p className="text-[11px] text-gray-400">No high-priority IOCs for hunt queries — load threat feeds first</p>
            </div>
          </Card>
        ) : visible.map(ioc => {
          const cat    = deriveCat(ioc);
          const hunts  = buildHuntQueries(ioc);
          const hit    = hunts.find(h => h.lang === platform) ?? hunts[0];
          const id     = `${ioc.ioc_value}-${platform}`;
          return (
            <Card key={ioc.ioc_value}>
              <div className="px-4 py-3 border-b border-gray-100 flex items-center gap-2.5">
                <span className={cn("w-2 h-2 rounded-full flex-shrink-0",
                  ioc.severity === "critical" ? "bg-red-500 animate-pulse" : "bg-amber-500")} />
                <span className="font-mono text-[11px] text-gray-800 font-bold">{ioc.ioc_value}</span>
                <CopyBtn value={ioc.ioc_value} small />
                <span className={cn("px-2 py-0.5 text-[9px] font-bold rounded-full border ml-1", cat.bg, cat.text, cat.border)}>
                  {cat.short}
                </span>
                <span className="text-[9px] text-gray-400 ml-auto">{ioc.source} · {relTime(ioc.cached_at)}</span>
                <SevBadge sev={ioc.severity} />
              </div>
              <div className="relative">
                <pre className="bg-gray-950 text-green-400 text-[10px] font-mono px-4 py-3 overflow-x-auto leading-relaxed whitespace-pre-wrap break-all max-h-28">
                  {hit.query}
                </pre>
                <button onClick={() => copy(id, hit.query)}
                  className="absolute top-2 right-2 p-1.5 bg-gray-800 hover:bg-gray-700 text-gray-400 hover:text-white rounded-lg transition-colors">
                  {copied === id
                    ? <CheckCircle2 className="w-3.5 h-3.5 text-green-400" />
                    : <Copy className="w-3.5 h-3.5" />}
                </button>
              </div>
            </Card>
          );
        })}
      </div>

      {visible.length > 0 && (
        <div className="text-[10px] text-gray-400 text-center pt-1">
          Showing top {visible.length} high-priority IOCs · Click an IOC in the Triage tab for full query set
        </div>
      )}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Feed Status Tab
// ─────────────────────────────────────────────────────────────────────────────

function FeedStatusTab({ feeds, stats }: { feeds: FeedHealth[]; stats: DashStats | undefined }) {
  const dot: Record<string, string> = {
    ok:      "bg-green-500", live: "bg-green-500 animate-pulse",
    error:   "bg-red-500",   degraded: "bg-amber-500", unknown: "bg-gray-300",
  };
  const liveCount  = feeds.filter(f => ["ok","live"].includes(f.status)).length;
  const errorCount = feeds.filter(f => f.status === "error").length;

  return (
    <div className="space-y-3">
      {/* Summary strip */}
      <div className="grid grid-cols-4 gap-2">
        {[
          { label: "Live Feeds",   val: liveCount,                    color: "text-green-700", bg: "bg-green-50 border-green-100" },
          { label: "Error Feeds",  val: errorCount,                   color: errorCount > 0 ? "text-red-600" : "text-gray-500", bg: errorCount > 0 ? "bg-red-50 border-red-100" : "bg-gray-50 border-gray-100" },
          { label: "NVD CVEs",     val: stats?.nvd_total?.toLocaleString() ?? "—", color: "text-gray-700", bg: "bg-gray-50 border-gray-100" },
          { label: "Last NVD Sync",val: stats?.last_nvd_sync ? relTime(stats.last_nvd_sync) : "—", color: "text-gray-600", bg: "bg-gray-50 border-gray-100" },
        ].map(k => (
          <div key={k.label} className={cn("rounded-xl p-3 border text-center", k.bg)}>
            <div className={cn("text-xl font-black leading-none", k.color)}>{k.val}</div>
            <div className="text-[10px] text-gray-500 mt-1 font-semibold">{k.label}</div>
          </div>
        ))}
      </div>

      <Card>
        <div className="h-0.5 bg-gradient-to-r from-green-400 via-blue-400 to-green-500" />
        {/* Header */}
        <div className="grid grid-cols-[2fr_1fr_1fr_1fr_1fr_2fr] px-4 py-2 border-b border-gray-100 bg-gray-50">
          {["Feed", "Status", "Entries", "Errors", "Last Sync", "Last Error"].map(h => (
            <span key={h} className="text-[9px] font-bold text-gray-400 uppercase tracking-wider">{h}</span>
          ))}
        </div>
        <div className="divide-y divide-gray-50">
          {feeds.length === 0 ? (
            <div className="py-14 text-center text-[11px] text-gray-400">No feeds configured</div>
          ) : feeds.map(f => (
            <div key={f.source}
              className={cn("grid grid-cols-[2fr_1fr_1fr_1fr_1fr_2fr] px-4 py-3 items-center hover:bg-gray-50 transition-colors",
                f.status === "error" && "bg-red-50/40")}>
              <div className="flex items-center gap-2">
                <div className={cn("w-2 h-2 rounded-full flex-shrink-0", dot[f.status] ?? dot.unknown)} />
                <span className="text-[11px] text-gray-800 font-semibold">{f.source}</span>
              </div>
              <span className={cn("text-[10px] font-semibold capitalize",
                f.status === "ok" || f.status === "live" ? "text-green-600" :
                f.status === "error" ? "text-red-600" : "text-amber-600")}>
                {f.status}
              </span>
              <span className="text-[11px] text-gray-700 font-semibold tabular-nums">
                {f.entry_count > 0 ? f.entry_count.toLocaleString() : "0"}
              </span>
              <span className={cn("text-[11px] tabular-nums font-semibold",
                f.error_count > 0 ? "text-red-600" : "text-gray-400")}>
                {f.error_count}
              </span>
              <span className="text-[10px] text-gray-500">{f.last_success ? relTime(f.last_success) : "never"}</span>
              <span className="text-[10px] text-gray-400 truncate pr-2">
                {f.last_error || "—"}
              </span>
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Main page
// ─────────────────────────────────────────────────────────────────────────────

type Tab = "ioc" | "cve" | "kev" | "hunt"; // | "feeds"
const VALID_TABS: Tab[] = ["ioc", "cve", "kev", "hunt"]; // "feeds" hidden

export default function ThreatIntelligence() {
  const { tab: tabParam } = useParams<{ tab?: string }>();
  const navigate = useNavigate();
  const [data,    setData]    = useState<DashData | null>(null);
  const [ipIocs,  setIpIocs]  = useState<IOC[]>([]);
  const [domIocs, setDomIocs] = useState<IOC[]>([]);
  const [loading, setLoading] = useState(true);
  const [lastFetch, setLastFetch] = useState(0);

  const tab: Tab = VALID_TABS.includes(tabParam as Tab) ? (tabParam as Tab) : "ioc";
  const setTab = (t: Tab) => navigate(`/intelligence/${t}`);

  const load = useCallback(async () => {
    try {
      const [d, ip, dom] = await Promise.allSettled([
        fetch(`${THREAT}/intel/dashboard?cve_limit=30&news_limit=20&kev_limit=30`).then(r => r.ok ? r.json() : null),
        fetch(`${THREAT}/iocs?ioc_type=ip&limit=500`).then(r => r.ok ? r.json() : null),
        fetch(`${THREAT}/iocs?ioc_type=domain&limit=500`).then(r => r.ok ? r.json() : null),
      ]);
      if (d.status   === "fulfilled" && d.value)         setData(d.value);
      if (ip.status  === "fulfilled" && ip.value?.iocs)  setIpIocs(ip.value.iocs);
      if (dom.status === "fulfilled" && dom.value?.iocs) setDomIocs(dom.value.iocs);
      setLastFetch(Math.floor(Date.now() / 1000));
    } finally { setLoading(false); }
  }, []);

  useEffect(() => { load(); const t = setInterval(load, 60_000); return () => clearInterval(t); }, [load]);

  const allIocs   = useMemo(() => [...ipIocs, ...domIocs], [ipIocs, domIocs]);
  const stats     = data?.stats;
  const kevList   = data?.kev_recent ?? [];
  const cveList   = data?.top_cves ?? [];

  // Derived alert counts for tab badges
  const critPending = allIocs.filter(i => i.severity === "critical").length;
  const kevOverdue  = kevList.filter(k => (daysUntil(k.due_date) ?? 1) < 0).length;

  const TABS: { id: Tab; label: string; icon: React.ReactNode; badge?: number; badgeColor?: string }[] = [
    { id: "ioc",  label: "IOC Triage",    icon: <ShieldAlert className="w-3.5 h-3.5" />,
      badge: critPending > 0 ? critPending : undefined, badgeColor: "bg-red-500" },
    { id: "cve",    label: "CVE Intel",     icon: <AlertTriangle className="w-3.5 h-3.5" />,
      badge: stats?.nvd_critical, badgeColor: "bg-amber-500" },
    { id: "kev",    label: "KEV Mandates",  icon: <Zap className="w-3.5 h-3.5" />,
      badge: kevOverdue > 0 ? kevOverdue : undefined, badgeColor: "bg-red-600" },
    { id: "hunt",   label: "Hunt Queries",  icon: <Target className="w-3.5 h-3.5" /> },
    // { id: "feeds",  label: "Feed Status",   icon: <Radio className="w-3.5 h-3.5" /> },
  ];

  return (
    <div className="space-y-4 pb-6">

      {/* ── Page header ───────────────────────────────────────────────────── */}
      <div className="bg-white border border-gray-200 rounded-2xl shadow-sm overflow-hidden">
        <div className="h-1 bg-gradient-to-r from-orange-400 via-red-400 to-amber-400" />
        <div className="p-5">
          <div className="flex items-start justify-between gap-4">
            <div className="flex items-start gap-3">
              <div className="w-10 h-10 rounded-xl bg-orange-50 border border-orange-100 flex items-center justify-center flex-shrink-0">
                <Crosshair className="w-5 h-5 text-orange-500" />
              </div>
              <div>
                <h1 className="text-base font-bold text-gray-900">Threat Intelligence</h1>
                <p className="text-xs text-gray-500 mt-0.5">
                  IOC triage · CVE enrichment · CISA KEV mandates · SIEM hunt queries · feed health
                </p>
              </div>
            </div>
            <button onClick={load}
              className="flex items-center gap-1.5 px-3 py-2 rounded-xl bg-gray-100 hover:bg-gray-200 text-gray-600 text-xs font-semibold transition-colors">
              <RefreshCw className={cn("w-3.5 h-3.5", loading && "animate-spin")} />
              {lastFetch ? relTime(lastFetch) : "Loading…"}
            </button>
          </div>

          {/* KPI strip */}
          <div className="grid grid-cols-6 gap-2 mt-4 pt-4 border-t border-gray-100">
            {[
              { label: "IOCs Cached",    val: allIocs.length,                       sub: "IPs + domains",     color: "text-red-700",   bg: "bg-red-50 border-red-100" },
              { label: "Critical IOCs",  val: critPending,                          sub: "severity = critical",color: "text-red-600",  bg: critPending > 0 ? "bg-red-50 border-red-100" : "bg-gray-50 border-gray-100" },
              { label: "CISA KEV",       val: stats?.kev_count ?? "—",              sub: "actively exploited", color: "text-red-600",  bg: "bg-red-50 border-red-100" },
              { label: "KEV Overdue",    val: kevOverdue || "—",                    sub: "past patch deadline", color: kevOverdue > 0 ? "text-red-600" : "text-gray-500", bg: kevOverdue > 0 ? "bg-red-50 border-red-100" : "bg-gray-50 border-gray-100" },
              { label: "Critical CVEs",  val: stats?.nvd_critical ?? "—",           sub: "CVSS ≥ 9.0",        color: "text-amber-700", bg: "bg-amber-50 border-amber-100" },
              { label: "Active Feeds",   val: stats ? `${stats.active_feeds}/${stats.total_feeds}` : "—", sub: "live intel feeds", color: "text-green-700", bg: "bg-green-50 border-green-100" },
            ].map(k => (
              <div key={k.label} className={cn("rounded-xl p-3 border text-center", k.bg)}>
                <div className={cn("text-xl font-black tabular-nums leading-none", k.color)}>{k.val}</div>
                <div className="text-[11px] font-semibold text-gray-600 mt-1">{k.label}</div>
                <div className="text-[9px] text-gray-400 mt-0.5">{k.sub}</div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* ── Tab navigation ────────────────────────────────────────────────── */}
      <div className="flex items-center gap-1 bg-white border border-gray-200 rounded-2xl shadow-sm p-1.5">
        {TABS.map(t => (
          <button key={t.id} onClick={() => setTab(t.id)}
            className={cn(
              "flex items-center gap-2 px-4 py-2.5 rounded-xl text-[11px] font-bold transition-all relative flex-1 justify-center",
              tab === t.id
                ? "bg-orange-500 text-white shadow-sm"
                : "text-gray-500 hover:text-gray-700 hover:bg-gray-100"
            )}>
            {t.icon}
            {t.label}
            {t.badge !== undefined && t.badge > 0 && (
              <span className={cn(
                "absolute -top-1 -right-1 w-4 h-4 rounded-full text-white text-[8px] font-black flex items-center justify-center",
                t.badgeColor ?? "bg-orange-500",
              )}>
                {t.badge > 9 ? "9+" : t.badge}
              </span>
            )}
          </button>
        ))}
      </div>

      {/* ── Tab content ───────────────────────────────────────────────────── */}
      {loading && !allIocs.length ? (
        <div className="space-y-2">
          <Skeleton h="h-16" /><Skeleton h="h-64" /><Skeleton h="h-48" />
        </div>
      ) : (
        <>
          {tab === "ioc"    && <IOCTriageTab iocs={allIocs} />}
          {tab === "cve"    && <CVEIntelTab  cves={cveList} />}
          {tab === "kev"    && <KEVMandatesTab kev={kevList} />}
          {tab === "hunt"   && <HuntQueriesTab iocs={allIocs} />}
          {/* {tab === "feeds"  && <FeedStatusTab feeds={data?.feeds ?? []} stats={stats} />} */}
        </>
      )}
    </div>
  );
}
