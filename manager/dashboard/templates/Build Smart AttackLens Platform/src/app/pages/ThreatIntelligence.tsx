/**
 * ThreatIntelligence — Operational analyst dashboard.
 * Design: matches platform theme (Asset Registry / Timeline).
 * White cards · orange accent · rounded-2xl · shadow-sm · light badges.
 */
import { useState, useEffect, useCallback, useMemo, useRef } from "react";
import {
  RefreshCw, ExternalLink, Zap, Shield, Star, AlertTriangle,
  Rss, Search, Copy, CheckCircle2, Clock, Eye, X, Download,
  ChevronDown, ChevronUp, Server, Globe, Hash, Link2, Bell,
  Wifi, Database, FileText, Flame, ShieldAlert, ShieldCheck,
  Radio, Activity, Users, Crosshair,
} from "lucide-react";
import { cn } from "../../lib/utils";

// ── API ───────────────────────────────────────────────────────────────────────

const THREAT = "/api/v1/threat";

// ── Types ─────────────────────────────────────────────────────────────────────

interface IOC {
  ioc_type:    string;
  ioc_value:   string;
  source:      string;
  severity:    string;
  confidence:  number;
  description: string | null;
  tags:        string | null;
  cached_at:   number;
  expires_at:  number;
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
  top_cves: CVE[]; kev_recent: KEVEntry[];
  news: NewsItem[];
}

// ── Threat category engine ────────────────────────────────────────────────────

interface ThreatCat {
  label: string; short: string;
  bg: string; text: string; border: string;
  what: string; why: string;
}

const CATS: Record<string, ThreatCat> = {
  feodo:     { label: "Feodo Botnet C2",      short: "Feodo C2",   bg: "bg-red-50",    text: "text-red-700",    border: "border-red-200",    what: "Feodo Tracker–listed C2 for Emotet, TrickBot, or Dridex banking trojans.",               why: "These trojans steal banking credentials and serve as initial access for ransomware groups. Block immediately." },
  urlhaus:   { label: "Malware URL",           short: "URLhaus",    bg: "bg-purple-50", text: "text-purple-700", border: "border-purple-200", what: "Active malware-hosting URL tracked by abuse.ch URLhaus.",                               why: "Employees clicking these links result in immediate malware execution. Block at web proxy and DNS." },
  emerging:  { label: "Emerging Threat",       short: "ET Rule",    bg: "bg-amber-50",  text: "text-amber-700",  border: "border-amber-200",  what: "IOC from Proofpoint Emerging Threats ruleset — known-bad infrastructure updated daily.", why: "High signal-to-noise ratio based on observed live attacks. Prioritise blocking." },
  c2:        { label: "C2 Infrastructure",     short: "C2",         bg: "bg-red-50",    text: "text-red-700",    border: "border-red-200",    what: "Command & Control server used to remotely issue commands to malware on victim machines.", why: "Blocking C2 severs attacker remote control — contains damage even if host is already compromised." },
  ransomware:{ label: "Ransomware C2",         short: "Ransomware", bg: "bg-red-50",    text: "text-red-700",    border: "border-red-200",    what: "Infrastructure used by ransomware groups for data exfiltration and encryption key exchange.", why: "Highest priority. Active contact with ransomware C2 means encryption may already be in progress." },
  phishing:  { label: "Phishing",              short: "Phishing",   bg: "bg-amber-50",  text: "text-amber-700",  border: "border-amber-200",  what: "Domain or IP hosting a credential-harvesting phishing page.",                           why: "One harvested credential provides full network access via VPN or cloud SSO." },
  malware:   { label: "Malware Distribution",  short: "Malware",    bg: "bg-purple-50", text: "text-purple-700", border: "border-purple-200", what: "Server distributing malware payloads — dropper sites, exploit kits, or RAT installers.",  why: "A single download can deploy ransomware, keyloggers, or lateral-movement tools." },
  scanner:   { label: "Mass Scanner",          short: "Scanner",    bg: "bg-blue-50",   text: "text-blue-700",   border: "border-blue-200",   what: "IP conducting automated internet-wide port and vulnerability scanning.",                  why: "Scanners identify exposed services for later exploitation. Block to reduce your external visibility." },
  unknown:   { label: "Threat Actor IOC",      short: "IOC",        bg: "bg-gray-100",  text: "text-gray-600",   border: "border-gray-200",   what: "Indicator of Compromise from a threat intelligence feed.",                              why: "Validate via reference links before blocking in production." },
};

function deriveCat(ioc: IOC): ThreatCat {
  const src  = ioc.source?.toLowerCase() ?? "";
  const desc = (ioc.description ?? "").toLowerCase();
  if (src === "feodo")                                     return CATS.feodo;
  if (src === "urlhaus")                                   return CATS.urlhaus;
  if (src.startsWith("emerging"))                          return CATS.emerging;
  if (desc.includes("ransomware"))                         return CATS.ransomware;
  if (desc.includes("c2") || desc.includes("command"))    return CATS.c2;
  if (desc.includes("phish"))                             return CATS.phishing;
  if (desc.includes("malware") || desc.includes("dropper")) return CATS.malware;
  if (desc.includes("scan"))                              return CATS.scanner;
  return CATS.unknown;
}

// ── Block-in & validation refs ────────────────────────────────────────────────

const BLOCK_IN: Record<string, string[]> = {
  ip:     ["Firewall ACL", "NGFW Policy", "SIEM Alert"],
  domain: ["DNS Sinkhole",  "Web Proxy",  "EDR Block"],
  hash:   ["EDR Policy",    "AV Endpoint","Email Gateway"],
  url:    ["Web Proxy",     "WAF Rule",   "Browser Policy"],
};

function validationRefs(type: string, value: string) {
  const m: Record<string, { label: string; url: string }[]> = {
    ip: [
      { label: "AbuseIPDB",  url: `https://www.abuseipdb.com/check/${value}` },
      { label: "VirusTotal", url: `https://www.virustotal.com/gui/ip-address/${value}` },
      { label: "Shodan",     url: `https://www.shodan.io/host/${value}` },
      { label: "GreyNoise",  url: `https://viz.greynoise.io/ip/${value}` },
    ],
    domain: [
      { label: "VirusTotal", url: `https://www.virustotal.com/gui/domain/${value}` },
      { label: "urlscan.io", url: `https://urlscan.io/search/#domain:${value}` },
      { label: "WHOIS",      url: `https://www.whois.com/whois/${value}` },
    ],
    hash: [
      { label: "VirusTotal",    url: `https://www.virustotal.com/gui/file/${value}` },
      { label: "MalwareBazaar", url: `https://bazaar.abuse.ch/browse.php?search=${value}` },
    ],
    url: [
      { label: "VirusTotal", url: `https://www.virustotal.com/gui/url/${encodeURIComponent(value)}` },
      { label: "urlscan.io", url: `https://urlscan.io/search/#page.url:${encodeURIComponent(value)}` },
    ],
  };
  return m[type] ?? m.ip;
}

function cveRefs(id: string) {
  return [
    { label: "NVD",   url: `https://nvd.nist.gov/vuln/detail/${id}` },
    { label: "MITRE", url: `https://cve.mitre.org/cgi-bin/cvename.cgi?name=${id}` },
    { label: "EPSS",  url: `https://api.first.org/data/v1/epss?cve=${id}` },
  ];
}

// ── localStorage ──────────────────────────────────────────────────────────────

function lsGet<T>(key: string, def: T): T {
  try { return JSON.parse(localStorage.getItem(key) ?? "") ?? def; } catch { return def; }
}
function lsSet(key: string, v: unknown) {
  try { localStorage.setItem(key, JSON.stringify(v)); } catch {}
}

// ── Export helpers ────────────────────────────────────────────────────────────

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
      `"${i.ioc_value}"`, i.ioc_type, i.source, i.severity, i.confidence ?? "",
      `"${deriveCat(i).label}"`,
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
    `!`, `! === Cisco IOS ACL ===`,
    ...ips.map(i => `deny ip any host ${i.ioc_value}  ! ${i.source} | ${i.description ?? deriveCat(i).label} | conf:${i.confidence}%`),
    `!`, `! === DNS / Proxy Block ===`,
    ...dom.map(i => `# ${i.ioc_value}  ! ${i.source} | ${i.description ?? deriveCat(i).label}`),
    `!`, `! === iptables (Linux) ===`,
    ...ips.map(i => `iptables -A INPUT -s ${i.ioc_value} -j DROP  # ${i.source}`),
  ].join("\n"), `attacklens-firewall-rules-${Date.now()}.txt`);
}

// ── Helpers ───────────────────────────────────────────────────────────────────

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
  return Math.ceil((new Date(dateStr).getTime() - Date.now()) / 86400000);
}
function parseArr(v: unknown): string[] {
  if (Array.isArray(v)) return v as string[];
  if (typeof v === "string" && v.startsWith("[")) { try { return JSON.parse(v); } catch {} }
  return [];
}
function iocIsNew(ioc: IOC) {
  return !!ioc.cached_at && (Date.now() / 1000 - ioc.cached_at) < 86400;
}
function riskScore(ioc: IOC): number {
  let s = ioc.severity === "critical" ? 9 : ioc.severity === "high" ? 7 : 5;
  const cat = deriveCat(ioc);
  if (cat === CATS.ransomware || cat === CATS.c2 || cat === CATS.feodo) s = Math.min(10, s + 1);
  if (ioc.confidence >= 90) s = Math.min(10, s + 1);
  return s;
}

// ── Design-system atoms ───────────────────────────────────────────────────────

function SevBadge({ sev }: { sev: string }) {
  const c: Record<string, string> = {
    critical: "bg-red-50 text-red-700 border-red-200",
    high:     "bg-amber-50 text-amber-700 border-amber-200",
    medium:   "bg-blue-50 text-blue-700 border-blue-200",
    low:      "bg-green-50 text-green-700 border-green-200",
    info:     "bg-gray-100 text-gray-600 border-gray-200",
  };
  return (
    <span className={cn("px-2 py-0.5 text-[9px] font-bold rounded-full border uppercase tracking-wide", c[sev] ?? c.info)}>
      {sev}
    </span>
  );
}

function KevBadge() {
  return <span className="px-1.5 py-0.5 bg-red-600 text-white rounded text-[9px] font-black">KEV</span>;
}

function SectionHeader({ title, icon, count, color = "orange", action }: {
  title: string; icon: React.ReactNode; count?: number;
  color?: "orange" | "red" | "blue" | "green" | "amber" | "gray";
  action?: React.ReactNode;
}) {
  const cfg: Record<string, string> = {
    orange: "bg-orange-50 text-orange-500",
    red:    "bg-red-50 text-red-500",
    blue:   "bg-blue-50 text-blue-500",
    green:  "bg-green-50 text-green-600",
    amber:  "bg-amber-50 text-amber-600",
    gray:   "bg-gray-100 text-gray-500",
  };
  return (
    <div className="flex items-center gap-2.5 px-4 py-3 border-b border-gray-100">
      <div className={cn("p-1.5 rounded-lg flex-shrink-0", cfg[color])}>{icon}</div>
      <span className="text-[11px] font-black text-gray-800 uppercase tracking-wide">{title}</span>
      {count !== undefined && (
        <span className="px-2 py-0.5 bg-gray-100 text-gray-500 rounded-full text-[10px] font-bold">{count}</span>
      )}
      {action && <div className="ml-auto">{action}</div>}
    </div>
  );
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

function CopyBtn({ value }: { value: string }) {
  const [ok, setOk] = useState(false);
  return (
    <button
      onClick={e => { e.stopPropagation(); navigator.clipboard?.writeText(value); setOk(true); setTimeout(() => setOk(false), 1400); }}
      className="flex-shrink-0 p-0.5 rounded hover:bg-gray-100 text-gray-400 hover:text-gray-600 transition-colors"
      title="Copy"
    >
      {ok ? <CheckCircle2 className="w-3 h-3 text-green-500" /> : <Copy className="w-3 h-3" />}
    </button>
  );
}

function RefChip({ label, url }: { label: string; url: string }) {
  return (
    <a href={url} target="_blank" rel="noopener noreferrer" onClick={e => e.stopPropagation()}
      className="inline-flex items-center gap-0.5 px-2 py-0.5 rounded-full bg-gray-100 hover:bg-blue-50 text-gray-500 hover:text-blue-600 border border-gray-200 hover:border-blue-200 text-[9px] font-semibold transition-all whitespace-nowrap">
      {label}<ExternalLink className="w-2 h-2" />
    </a>
  );
}

// ── IOC Status selector ───────────────────────────────────────────────────────

const STATUS_CFG: Record<IOCStatus, { label: string; icon: React.ReactNode; cls: string }> = {
  pending:  { label: "Pending",      icon: <Clock className="w-3 h-3" />,       cls: "bg-gray-100 text-gray-600 border-gray-200" },
  blocked:  { label: "Blocked",      icon: <ShieldCheck className="w-3 h-3" />, cls: "bg-green-50 text-green-700 border-green-200" },
  watching: { label: "Watching",     icon: <Eye className="w-3 h-3" />,         cls: "bg-blue-50 text-blue-700 border-blue-200" },
  fp:       { label: "False Pos.",   icon: <X className="w-3 h-3" />,           cls: "bg-gray-100 text-gray-400 border-gray-200" },
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
      <button
        onClick={() => setOpen(o => !o)}
        className={cn("flex items-center gap-1 px-2 py-0.5 rounded-full border text-[9px] font-semibold whitespace-nowrap transition-all hover:shadow-sm", cfg.cls)}
      >
        {cfg.icon}{cfg.label}
        <ChevronDown className={cn("w-2.5 h-2.5 transition-transform", open && "rotate-180")} />
      </button>
      {open && (
        <div className="absolute right-0 top-full mt-1 z-30 bg-white border border-gray-200 rounded-xl shadow-xl overflow-hidden min-w-[148px]">
          {(Object.entries(STATUS_CFG) as [IOCStatus, typeof STATUS_CFG[IOCStatus]][]).map(([k, c]) => (
            <button key={k} onClick={() => { onChange(k); setOpen(false); }}
              className={cn("w-full flex items-center gap-2 px-3 py-2 text-[10px] font-semibold hover:bg-gray-50 transition-colors",
                c.cls.includes("green") ? "text-green-700" : c.cls.includes("blue") ? "text-blue-700" : "text-gray-600")}>
              {c.icon}{c.label}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

// ── IOC Table row ─────────────────────────────────────────────────────────────

function IOCRow({
  ioc, status, starred, selected, onStatus, onStar, onSelect,
}: {
  ioc: IOC; status: IOCStatus; starred: boolean; selected: boolean;
  onStatus: (s: IOCStatus) => void; onStar: () => void; onSelect: () => void;
}) {
  const [expanded, setExpanded] = useState(false);
  const cat   = deriveCat(ioc);
  const risk  = riskScore(ioc);
  const isNew = iocIsNew(ioc);
  const refs  = validationRefs(ioc.ioc_type, ioc.ioc_value);
  const blocks = BLOCK_IN[ioc.ioc_type] ?? BLOCK_IN.ip;

  const typeIcon: Record<string, React.ReactNode> = {
    ip: <Server className="w-3 h-3 text-gray-400" />,
    domain: <Globe className="w-3 h-3 text-gray-400" />,
    hash: <Hash className="w-3 h-3 text-gray-400" />,
    url: <Link2 className="w-3 h-3 text-gray-400" />,
  };

  const isFP = status === "fp";

  return (
    <>
      <tr
        onClick={() => setExpanded(e => !e)}
        className={cn(
          "border-b border-gray-100 cursor-pointer transition-all group",
          selected
            ? "bg-orange-50 shadow-[inset_3px_0_0_#f97316]"
            : "hover:bg-orange-50/40 hover:shadow-[inset_3px_0_0_#f97316]",
          isFP && "opacity-40",
        )}
      >
        {/* Checkbox */}
        <td className="pl-3 pr-1 py-2.5 w-8" onClick={e => { e.stopPropagation(); onSelect(); }}>
          <div className={cn("w-3.5 h-3.5 rounded border transition-all flex items-center justify-center flex-shrink-0",
            selected ? "bg-orange-500 border-orange-500" : "border-gray-300 hover:border-orange-400")}>
            {selected && <CheckCircle2 className="w-2.5 h-2.5 text-white" />}
          </div>
        </td>

        {/* Severity dot */}
        <td className="px-2 py-2.5 w-6">
          <span className={cn("w-2 h-2 rounded-full inline-block flex-shrink-0",
            ioc.severity === "critical" ? "bg-red-500 animate-pulse" :
            ioc.severity === "high"     ? "bg-amber-500" :
            ioc.severity === "medium"   ? "bg-blue-400" : "bg-gray-300"
          )} />
        </td>

        {/* IOC value */}
        <td className="px-2 py-2.5 max-w-[200px]">
          <div className="flex items-center gap-1.5">
            {typeIcon[ioc.ioc_type] ?? typeIcon.ip}
            <span className="font-mono text-[11px] text-gray-800 font-semibold truncate">{ioc.ioc_value}</span>
            <CopyBtn value={ioc.ioc_value} />
            {isNew && (
              <span className="px-1.5 py-0.5 bg-orange-500 text-white text-[8px] font-black rounded-full">NEW</span>
            )}
          </div>
        </td>

        {/* Category */}
        <td className="px-2 py-2.5">
          <span className={cn("px-2 py-0.5 text-[9px] font-bold rounded-full border whitespace-nowrap", cat.bg, cat.text, cat.border)}>
            {cat.short}
          </span>
        </td>

        {/* Source */}
        <td className="px-2 py-2.5">
          <span className="text-[10px] text-gray-500 font-medium">{ioc.source}</span>
        </td>

        {/* Confidence */}
        <td className="px-2 py-2.5 w-20">
          <div className="flex items-center gap-1.5">
            <div className="w-10 h-1.5 bg-gray-100 rounded-full overflow-hidden">
              <div className="h-full rounded-full bg-orange-400 transition-all" style={{ width: `${ioc.confidence}%` }} />
            </div>
            <span className="text-[9px] text-gray-500 tabular-nums">{ioc.confidence}%</span>
          </div>
        </td>

        {/* Risk */}
        <td className="px-2 py-2.5 w-16">
          <span className={cn("text-[11px] font-black tabular-nums",
            risk >= 9 ? "text-red-600" : risk >= 7 ? "text-amber-600" : "text-gray-500")}>
            {risk}<span className="text-[9px] font-normal text-gray-400">/10</span>
          </span>
        </td>

        {/* Added */}
        <td className="px-2 py-2.5 w-20">
          <span className="text-[10px] text-gray-400">{relTime(ioc.cached_at)}</span>
        </td>

        {/* Status */}
        <td className="px-2 py-2.5">
          <StatusPill status={status} onChange={onStatus} />
        </td>

        {/* Star + expand chevron */}
        <td className="px-3 py-2.5 w-14">
          <div className="flex items-center gap-1">
            <button onClick={e => { e.stopPropagation(); onStar(); }}
              className={cn("p-0.5 rounded transition-colors flex-shrink-0",
                starred ? "text-amber-400" : "text-gray-300 hover:text-amber-400")}>
              <Star className={cn("w-3.5 h-3.5", starred && "fill-current")} />
            </button>
            {expanded
              ? <ChevronUp className="w-3.5 h-3.5 text-gray-400" />
              : <ChevronDown className="w-3.5 h-3.5 text-gray-300 opacity-0 group-hover:opacity-100 transition-opacity" />
            }
          </div>
        </td>
      </tr>

      {/* Expanded detail */}
      {expanded && (
        <tr className="border-b border-gray-100 bg-gray-50">
          <td colSpan={10} className="px-5 py-4">
            <div className="grid grid-cols-3 gap-5">

              {/* What this is */}
              <div className="bg-white rounded-xl border border-gray-100 p-3.5 space-y-2">
                <p className="text-[9px] font-bold text-gray-400 uppercase tracking-wider flex items-center gap-1.5">
                  <Shield className="w-3 h-3 text-blue-400" />What this is
                </p>
                <p className="text-[11px] text-gray-700 leading-relaxed">{cat.what}</p>
                {ioc.description && (
                  <p className="text-[10px] text-gray-500 italic bg-gray-50 px-2 py-1.5 rounded-lg border border-gray-100">
                    "{ioc.description}"
                  </p>
                )}
              </div>

              {/* Block in + why it matters */}
              <div className="bg-white rounded-xl border border-red-100 p-3.5 space-y-2">
                <p className="text-[9px] font-bold text-gray-400 uppercase tracking-wider flex items-center gap-1.5">
                  <ShieldAlert className="w-3 h-3 text-red-400" />Block in
                </p>
                <div className="space-y-1.5">
                  {blocks.map(b => (
                    <div key={b} className="flex items-center gap-2">
                      <span className="w-1.5 h-1.5 rounded-full bg-orange-400 flex-shrink-0" />
                      <span className="text-[11px] text-gray-800 font-semibold">{b}</span>
                    </div>
                  ))}
                </div>
                <p className="text-[10px] text-gray-500 leading-relaxed border-t border-gray-100 pt-2 mt-2">{cat.why}</p>
              </div>

              {/* Validate + metadata */}
              <div className="bg-white rounded-xl border border-gray-100 p-3.5 space-y-2">
                <p className="text-[9px] font-bold text-gray-400 uppercase tracking-wider flex items-center gap-1.5">
                  <ExternalLink className="w-3 h-3 text-gray-400" />Validate
                </p>
                <div className="flex flex-wrap gap-1">
                  {refs.map(r => <RefChip key={r.label} label={r.label} url={r.url} />)}
                </div>
                <div className="grid grid-cols-2 gap-x-3 gap-y-1 pt-2 border-t border-gray-100">
                  {[
                    ["Feed",      ioc.source],
                    ["Type",      ioc.ioc_type],
                    ["Severity",  ioc.severity],
                    ["Confidence",`${ioc.confidence}%`],
                    ["Risk",      `${risk} / 10`],
                    ["Added",     shortDate(ioc.cached_at)],
                    ["Expires",   shortDate(ioc.expires_at)],
                  ].map(([l, v]) => (
                    <div key={l} className="flex items-center gap-1">
                      <span className="text-[9px] text-gray-400 font-medium">{l}:</span>
                      <span className="text-[9px] text-gray-700 font-semibold">{v}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </td>
        </tr>
      )}
    </>
  );
}

// ── IOC Table ─────────────────────────────────────────────────────────────────

type SortKey = "risk" | "severity" | "confidence" | "cached_at";

function IOCTable({ iocs }: { iocs: IOC[] }) {
  const [statuses, setStatuses] = useState<Record<string, IOCStatus>>(() => lsGet("al_ioc_status3", {}));
  const [stars,    setStars]    = useState<Record<string, boolean>>(() => lsGet("al_ioc_stars3",   {}));
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [search,   setSearch]   = useState("");
  const [typeF,    setTypeF]    = useState<"all"|"ip"|"domain"|"hash">("all");
  const [statusF,  setStatusF]  = useState<"all"|"pending"|"blocked"|"watching">("all");
  const [sortKey,  setSortKey]  = useState<SortKey>("risk");
  const [sortAsc,  setSortAsc]  = useState(false);
  const [showAll,  setShowAll]  = useState(false);
  const [dismissed,setDismissed]= useState(false);

  const setStatus = (key: string, s: IOCStatus) => {
    const n = { ...statuses, [key]: s }; setStatuses(n); lsSet("al_ioc_status3", n);
  };
  const toggleStar = (key: string) => {
    const n = { ...stars, [key]: !stars[key] }; setStars(n); lsSet("al_ioc_stars3", n);
  };
  const toggleSelect = (v: string) =>
    setSelected(prev => { const n = new Set(prev); n.has(v) ? n.delete(v) : n.add(v); return n; });
  const bulkStatus = (s: IOCStatus) => {
    const n = { ...statuses }; selected.forEach(v => { n[v] = s; });
    setStatuses(n); lsSet("al_ioc_status3", n); setSelected(new Set());
  };
  const toggleSort = (key: SortKey) => {
    sortKey === key ? setSortAsc(a => !a) : (setSortKey(key), setSortAsc(false));
  };

  const SEV_ORDER: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

  const sortedFiltered = useMemo(() => iocs
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

  const visible = showAll ? sortedFiltered : sortedFiltered.slice(0, 15);
  const pendingCritical = iocs.filter(i =>
    i.severity === "critical" && (statuses[i.ioc_value] ?? "pending") === "pending"
  ).length;
  const typeCounts: Record<string, number> = {};
  iocs.forEach(i => { typeCounts[i.ioc_type] = (typeCounts[i.ioc_type] ?? 0) + 1; });

  const SortTh = ({ label, k }: { label: string; k: SortKey }) => (
    <th onClick={() => toggleSort(k)}
      className="px-2 py-2.5 text-left text-[9px] font-bold text-gray-400 uppercase tracking-wider cursor-pointer hover:text-gray-600 transition-colors select-none">
      <span className="flex items-center gap-1">
        {label}
        {sortKey === k && (sortAsc ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />)}
      </span>
    </th>
  );

  return (
    <Card>
      {/* Orange top stripe */}
      <div className="h-0.5 bg-gradient-to-r from-orange-400 via-amber-400 to-orange-500" />

      {/* Priority banner */}
      {pendingCritical > 0 && !dismissed && (
        <div className="flex items-center gap-3 px-4 py-2.5 bg-red-50 border-b border-red-100">
          <Flame className="w-4 h-4 text-red-500 flex-shrink-0 animate-pulse" />
          <span className="text-[11px] font-bold text-red-700 flex-1">
            {pendingCritical} critical IOC{pendingCritical > 1 ? "s" : ""} still unblocked — block in firewall / EDR immediately
          </span>
          <button onClick={() => setDismissed(true)} className="text-red-400 hover:text-red-600 transition-colors">
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      )}

      {/* Section header */}
      <SectionHeader
        title="IOC Action Center"
        icon={<ShieldAlert className="w-4 h-4" />}
        color="orange"
        count={iocs.length}
        action={
          <div className="flex items-center gap-1.5">
            <button onClick={() => exportCSV(sortedFiltered)}
              className="flex items-center gap-1.5 px-2.5 py-1.5 bg-white hover:bg-gray-50 border border-gray-200 text-gray-600 text-[10px] font-semibold rounded-xl transition-colors">
              <Download className="w-3 h-3" />CSV
            </button>
            <button onClick={() => exportFirewall(sortedFiltered)}
              className="flex items-center gap-1.5 px-2.5 py-1.5 bg-white hover:bg-gray-50 border border-gray-200 text-gray-600 text-[10px] font-semibold rounded-xl transition-colors">
              <FileText className="w-3 h-3" />Firewall Rules
            </button>
          </div>
        }
      />

      {/* Toolbar */}
      <div className="flex items-center gap-2 px-4 py-3 border-b border-gray-100 bg-gray-50 flex-wrap">
        {/* Search */}
        <div className="relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-gray-400 pointer-events-none" />
          <input type="text" placeholder="Search IOCs, sources…" value={search}
            onChange={e => setSearch(e.target.value)}
            className="pl-9 pr-3 py-1.5 text-[11px] border border-gray-200 rounded-xl bg-white text-gray-800 placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-orange-200 focus:border-orange-300 w-52" />
        </div>

        {/* Type filter tabs */}
        <div className="flex items-center border border-gray-200 rounded-xl bg-white overflow-hidden">
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
          className="px-2 py-1.5 text-[10px] border border-gray-200 rounded-xl bg-white text-gray-600 focus:outline-none focus:ring-1 focus:ring-orange-200">
          <option value="all">All statuses</option>
          <option value="pending">Pending</option>
          <option value="blocked">Blocked</option>
          <option value="watching">Watching</option>
        </select>

        {/* Bulk actions */}
        {selected.size > 0 && (
          <div className="flex items-center gap-1.5 ml-1">
            <span className="text-[10px] text-orange-600 font-bold">{selected.size} selected</span>
            <button onClick={() => bulkStatus("blocked")}
              className="flex items-center gap-1 px-2.5 py-1 bg-green-50 hover:bg-green-100 text-green-700 text-[10px] font-semibold rounded-lg border border-green-200 transition-colors">
              <ShieldCheck className="w-3 h-3" />Mark Blocked
            </button>
            <button onClick={() => bulkStatus("watching")}
              className="flex items-center gap-1 px-2.5 py-1 bg-blue-50 hover:bg-blue-100 text-blue-700 text-[10px] font-semibold rounded-lg border border-blue-200 transition-colors">
              <Eye className="w-3 h-3" />Watch
            </button>
            <button onClick={() => setSelected(new Set())} className="p-1 text-gray-400 hover:text-gray-600">
              <X className="w-3.5 h-3.5" />
            </button>
          </div>
        )}
      </div>

      {/* Table */}
      <div className="overflow-x-auto">
        <table className="w-full text-xs">
          <thead>
            <tr className="bg-gray-50 border-b border-gray-100">
              <th className="pl-3 pr-1 w-8">
                <div
                  onClick={() => setSelected(
                    selected.size === sortedFiltered.length
                      ? new Set()
                      : new Set(sortedFiltered.map(i => i.ioc_value))
                  )}
                  className={cn("w-3.5 h-3.5 rounded border cursor-pointer transition-all flex items-center justify-center",
                    selected.size === sortedFiltered.length && sortedFiltered.length > 0
                      ? "bg-orange-500 border-orange-500"
                      : "border-gray-300 hover:border-orange-400")}>
                  {selected.size === sortedFiltered.length && sortedFiltered.length > 0 && (
                    <CheckCircle2 className="w-2.5 h-2.5 text-white" />
                  )}
                </div>
              </th>
              <th className="px-2 py-2.5 w-6" />
              <th className="px-2 py-2.5 text-left text-[9px] font-bold text-gray-400 uppercase tracking-wider">IOC Value</th>
              <th className="px-2 py-2.5 text-left text-[9px] font-bold text-gray-400 uppercase tracking-wider">Category</th>
              <th className="px-2 py-2.5 text-left text-[9px] font-bold text-gray-400 uppercase tracking-wider">Feed</th>
              <SortTh label="Conf." k="confidence" />
              <SortTh label="Risk"  k="risk" />
              <SortTh label="Added" k="cached_at" />
              <th className="px-2 py-2.5 text-left text-[9px] font-bold text-gray-400 uppercase tracking-wider">Status</th>
              <th className="px-2 py-2.5 w-14" />
            </tr>
          </thead>
          <tbody>
            {iocs.length === 0 ? (
              <tr><td colSpan={10} className="py-14 text-center">
                <Shield className="w-7 h-7 text-gray-300 mx-auto mb-2" />
                <p className="text-[11px] text-gray-400 font-medium">No IOCs cached yet — feeds populate after first sync</p>
              </td></tr>
            ) : sortedFiltered.length === 0 ? (
              <tr><td colSpan={10} className="py-8 text-center text-[11px] text-gray-400">No IOCs match this filter</td></tr>
            ) : (
              visible.map(ioc => (
                <IOCRow key={ioc.ioc_value} ioc={ioc}
                  status={statuses[ioc.ioc_value] ?? "pending"}
                  starred={!!stars[ioc.ioc_value]}
                  selected={selected.has(ioc.ioc_value)}
                  onStatus={s => setStatus(ioc.ioc_value, s)}
                  onStar={() => toggleStar(ioc.ioc_value)}
                  onSelect={() => toggleSelect(ioc.ioc_value)}
                />
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Footer */}
      <div className="flex items-center justify-between px-4 py-2.5 border-t border-gray-100 bg-gray-50">
        <span className="text-[10px] text-gray-400 font-medium">
          {sortedFiltered.length} IOC{sortedFiltered.length !== 1 ? "s" : ""}
          {selected.size > 0 && ` · ${selected.size} selected`}
          {" · "}
          <span className="text-green-600 font-semibold">{Object.values(statuses).filter(s => s === "blocked").length} blocked</span>
          {" · "}
          <span className="text-amber-600">{iocs.filter(i => (statuses[i.ioc_value] ?? "pending") === "pending").length} pending</span>
        </span>
        {!showAll && sortedFiltered.length > 15 && (
          <button onClick={() => setShowAll(true)}
            className="text-[10px] text-orange-500 hover:text-orange-600 font-semibold transition-colors flex items-center gap-1">
            Show all {sortedFiltered.length} <ChevronDown className="w-3 h-3" />
          </button>
        )}
      </div>
    </Card>
  );
}

// ── Right sidebar ─────────────────────────────────────────────────────────────

function ActionSummary({ iocs, stats }: { iocs: IOC[]; stats: DashStats | undefined }) {
  const statuses: Record<string, IOCStatus> = lsGet("al_ioc_status3", {});
  const pending   = iocs.filter(i => (statuses[i.ioc_value] ?? "pending") === "pending").length;
  const blocked   = iocs.filter(i => statuses[i.ioc_value] === "blocked").length;
  const critPend  = iocs.filter(i => i.severity === "critical" && (statuses[i.ioc_value] ?? "pending") === "pending").length;

  return (
    <Card>
      <SectionHeader title="Status" icon={<Radio className="w-4 h-4" />} color="green" />
      <div className="p-3 grid grid-cols-2 gap-2">
        {[
          { label: "Pending Block", val: pending,   color: pending   > 0 ? "text-red-600"   : "text-gray-600", bg: pending   > 0 ? "bg-red-50 border-red-100"    : "bg-gray-50 border-gray-100" },
          { label: "Blocked",       val: blocked,   color: "text-green-700", bg: "bg-green-50 border-green-100" },
          { label: "Critical Open", val: critPend,  color: critPend > 0 ? "text-red-600" : "text-gray-500", bg: critPend > 0 ? "bg-red-50 border-red-100" : "bg-gray-50 border-gray-100" },
          { label: "NVD Critical",  val: stats?.nvd_critical ?? "—", color: "text-amber-700", bg: "bg-amber-50 border-amber-100" },
        ].map(k => (
          <div key={k.label} className={cn("rounded-xl p-2.5 border text-center", k.bg)}>
            <div className={cn("text-xl font-black tabular-nums leading-none", k.color)}>{k.val}</div>
            <div className="text-[9px] text-gray-500 mt-1 font-semibold">{k.label}</div>
          </div>
        ))}
      </div>
    </Card>
  );
}

function CVEList({ cves }: { cves: CVE[] }) {
  const [expanded, setExpanded] = useState<string | null>(null);
  return (
    <Card>
      <SectionHeader title="Top CVEs" icon={<AlertTriangle className="w-4 h-4" />} color="red" count={cves.length} />
      <div className="divide-y divide-gray-50 max-h-72 overflow-y-auto">
        {cves.length === 0 ? (
          <div className="py-8 text-center text-[10px] text-gray-400">NVD sync pending</div>
        ) : cves.map(c => (
          <div key={c.cve_id}>
            <div onClick={() => setExpanded(expanded === c.cve_id ? null : c.cve_id)}
              className="flex items-center gap-2 px-4 py-2.5 hover:bg-gray-50 cursor-pointer transition-colors group">
              <span className={cn("w-2 h-2 rounded-full flex-shrink-0",
                c.severity === "critical" ? "bg-red-500" : c.severity === "high" ? "bg-amber-500" : "bg-blue-400")} />
              <span className="font-mono text-[10px] text-blue-600 font-bold flex-shrink-0">{c.cve_id}</span>
              {c.is_kev && <KevBadge />}
              <span className="text-[10px] text-gray-500 truncate flex-1">{c.description?.slice(0, 50)}…</span>
              <span className={cn("text-[11px] font-black tabular-nums flex-shrink-0",
                (c.cvss_score ?? 0) >= 9 ? "text-red-600" : (c.cvss_score ?? 0) >= 7 ? "text-amber-600" : "text-gray-500")}>
                {c.cvss_score?.toFixed(1) ?? "—"}
              </span>
            </div>
            {expanded === c.cve_id && (
              <div className="px-4 pb-3 bg-gray-50 border-t border-gray-100">
                <p className="text-[10px] text-gray-600 leading-relaxed mb-2 mt-2">{c.description}</p>
                <div className="flex gap-1 flex-wrap">
                  {cveRefs(c.cve_id).map(r => <RefChip key={r.label} label={r.label} url={r.url} />)}
                </div>
              </div>
            )}
          </div>
        ))}
      </div>
    </Card>
  );
}

function KEVList({ kev }: { kev: KEVEntry[] }) {
  const [patchStatus, setPatch] = useState<Record<string, IOCStatus>>(() => lsGet("al_kev_status3", {}));
  const set = (id: string, s: IOCStatus) => {
    const n = { ...patchStatus, [id]: s }; setPatch(n); lsSet("al_kev_status3", n);
  };

  return (
    <Card>
      <SectionHeader title="CISA KEV" icon={<Zap className="w-4 h-4" />} color="red"
        action={<span className="px-2 py-0.5 bg-red-600 text-white rounded-full text-[9px] font-black">{kev.length} exploited</span>}
      />
      <div className="divide-y divide-gray-50 max-h-80 overflow-y-auto">
        {kev.length === 0 ? (
          <div className="py-8 text-center text-[10px] text-gray-400">KEV catalog loading…</div>
        ) : kev.map(k => {
          const days = daysUntil(k.due_date);
          const st   = patchStatus[k.cve_id] ?? "pending";
          return (
            <div key={k.cve_id} className={cn("px-4 py-3 hover:bg-gray-50 transition-colors", st === "blocked" && "opacity-50")}>
              <div className="flex items-start gap-2">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-1.5 flex-wrap mb-1">
                    <span className="font-mono text-[10px] text-red-600 font-bold">{k.cve_id}</span>
                    <KevBadge />
                    {days !== null && (
                      <span className={cn("text-[9px] font-bold px-1.5 py-0.5 rounded-full",
                        days < 0  ? "bg-red-50 text-red-600 border border-red-200" :
                        days <= 7 ? "bg-amber-50 text-amber-700 border border-amber-200" :
                        "bg-gray-100 text-gray-500")}>
                        {days < 0 ? `${Math.abs(days)}d overdue` : days === 0 ? "Due today" : `${days}d left`}
                      </span>
                    )}
                  </div>
                  <p className="text-[11px] text-gray-800 font-semibold leading-snug">{k.vuln_name}</p>
                  <p className="text-[9px] text-gray-500 mt-0.5">{k.vendor} · {k.product}</p>
                  {k.required_action && (
                    <p className="text-[9px] text-gray-600 mt-1.5 bg-red-50 border border-red-100 rounded-lg px-2.5 py-1.5 leading-relaxed">
                      <span className="font-bold text-red-700">Action: </span>{k.required_action}
                    </p>
                  )}
                  <div className="flex gap-1 mt-1.5">
                    {cveRefs(k.cve_id).slice(0, 2).map(r => <RefChip key={r.label} label={r.label} url={r.url} />)}
                  </div>
                </div>
                <StatusPill status={st as IOCStatus} onChange={s => set(k.cve_id, s)} />
              </div>
            </div>
          );
        })}
      </div>
    </Card>
  );
}

function FeedGrid({ feeds }: { feeds: FeedHealth[] }) {
  const dot: Record<string, string> = {
    ok: "bg-green-500", live: "bg-green-500 animate-pulse",
    error: "bg-red-500", degraded: "bg-amber-500", unknown: "bg-gray-300",
  };
  const liveCount = feeds.filter(f => ["ok","live"].includes(f.status)).length;
  return (
    <Card>
      <SectionHeader title="Feed Health" icon={<Wifi className="w-4 h-4" />} color="blue"
        action={
          <span className="text-[10px] font-semibold text-green-600">{liveCount}/{feeds.length} live</span>
        }
      />
      <div className="p-3 grid grid-cols-2 gap-1.5">
        {feeds.length === 0 ? (
          <div className="col-span-2 py-6 text-center text-[10px] text-gray-400">No feeds configured</div>
        ) : feeds.map(f => (
          <div key={f.source} className={cn(
            "flex items-center gap-2 px-2.5 py-2 rounded-xl bg-gray-50 border transition-colors",
            f.status === "error" ? "border-red-200 bg-red-50" : "border-gray-100 hover:bg-white"
          )}>
            <div className={cn("w-2 h-2 rounded-full flex-shrink-0", dot[f.status] ?? dot.unknown)} />
            <div className="min-w-0 flex-1">
              <p className="text-[10px] text-gray-700 font-semibold truncate">{f.source}</p>
              <p className="text-[9px] text-gray-400">
                {f.entry_count > 0 ? f.entry_count.toLocaleString() : "0"} · {f.last_success ? relTime(f.last_success) : "never"}
              </p>
            </div>
          </div>
        ))}
      </div>
    </Card>
  );
}

function RecentThreatIntel({ news, feeds, kev }: { news: NewsItem[]; feeds: FeedHealth[]; kev: KEVEntry[] }) {
  const [stars,  setStars]  = useState<Record<string, boolean>>(() => lsGet("al_news_stars3", {}));
  const [filter, setFilter] = useState<"all"|"news"|"kev"|"feed">("all");

  const toggleStar = (id: string) => {
    const n = { ...stars, [id]: !stars[id] }; setStars(n); lsSet("al_news_stars3", n);
  };

  type StreamItem = {
    id: string; kind: "news"|"kev"|"feed";
    title: string; summary?: string; source: string;
    severity?: string; url?: string; cve_refs?: string[]; ts: number;
  };

  const stream: StreamItem[] = [
    ...news.map((n, i): StreamItem => ({
      id: `n${i}`, kind: "news", title: n.title, summary: n.summary,
      source: n.source, severity: n.severity, url: n.url,
      cve_refs: parseArr(n.cve_refs), ts: n.published_at,
    })),
    ...kev.map((k): StreamItem => ({
      id: `k${k.cve_id}`, kind: "kev",
      title: `CISA KEV — ${k.cve_id}: ${k.vuln_name}`,
      summary: k.required_action, source: "CISA", severity: "critical",
      ts: k.date_added ? Math.floor(new Date(k.date_added).getTime() / 1000) : 0,
    })),
    ...feeds.filter(f => f.last_success > 0).map((f): StreamItem => ({
      id: `f${f.source}`, kind: "feed",
      title: `${f.source} synced — ${f.entry_count.toLocaleString()} entries`,
      source: "Feed Sync", severity: f.status === "error" ? "high" : "info",
      ts: f.last_success,
    })),
  ].sort((a, b) => b.ts - a.ts);

  const counts = {
    all:  stream.length,
    news: stream.filter(s => s.kind === "news").length,
    kev:  stream.filter(s => s.kind === "kev").length,
    feed: stream.filter(s => s.kind === "feed").length,
  };

  const visible = filter === "all" ? stream : stream.filter(s => s.kind === filter);

  const kindCfg: Record<string, { bg: string; text: string; badge: string; icon: React.ReactNode; label: string }> = {
    news: { bg: "bg-blue-50",  text: "text-blue-600",  badge: "bg-blue-100 text-blue-700",  icon: <Rss className="w-3.5 h-3.5" />,      label: "News"      },
    kev:  { bg: "bg-red-50",   text: "text-red-600",   badge: "bg-red-100 text-red-700",    icon: <Zap className="w-3.5 h-3.5" />,      label: "CISA KEV"  },
    feed: { bg: "bg-green-50", text: "text-green-600", badge: "bg-green-100 text-green-700",icon: <Database className="w-3.5 h-3.5" />, label: "Feed Sync" },
  };

  return (
    <div className="bg-white border border-gray-200 rounded-2xl shadow-sm overflow-hidden">
      {/* Amber top stripe */}
      <div className="h-0.5 bg-gradient-to-r from-amber-400 via-orange-400 to-amber-500" />

      {/* Header */}
      <div className="flex items-center gap-2.5 px-5 py-4 border-b border-gray-100">
        <div className="p-1.5 rounded-lg bg-amber-50 text-amber-600 flex-shrink-0">
          <Bell className="w-4 h-4" />
        </div>
        <span className="text-[11px] font-black text-gray-800 uppercase tracking-wide">Recent Threat Intel</span>
        <span className="px-2 py-0.5 bg-gray-100 text-gray-500 rounded-full text-[10px] font-bold">{stream.length}</span>

        {/* Filter tabs */}
        <div className="ml-auto flex items-center border border-gray-200 rounded-xl overflow-hidden">
          {(["all","news","kev","feed"] as const).map(f => (
            <button key={f} onClick={() => setFilter(f)}
              className={cn(
                "flex items-center gap-1.5 px-3 py-1.5 text-[10px] font-bold capitalize transition-all",
                filter === f ? "bg-orange-500 text-white" : "text-gray-400 hover:text-gray-600 hover:bg-gray-50"
              )}>
              {f}
              <span className={cn(
                "px-1.5 py-0.5 rounded-full text-[8px] font-black",
                filter === f ? "bg-white/20 text-white" : "bg-gray-100 text-gray-500"
              )}>
                {counts[f]}
              </span>
            </button>
          ))}
        </div>
      </div>

      {/* Card grid */}
      {visible.length === 0 ? (
        <div className="py-16 text-center">
          <Bell className="w-8 h-8 text-gray-200 mx-auto mb-2" />
          <p className="text-[11px] text-gray-400 font-medium">No intel events yet</p>
        </div>
      ) : (
        <div className="p-4 grid grid-cols-3 gap-3">
          {visible.map(item => {
            const ks = kindCfg[item.kind] ?? kindCfg.news;
            const isStarred = !!stars[item.id];
            return (
              <div key={item.id}
                className={cn(
                  "rounded-xl border flex flex-col gap-2.5 p-3.5 transition-all hover:shadow-md group",
                  isStarred
                    ? "bg-amber-50/60 border-amber-200"
                    : "bg-white border-gray-100 hover:border-gray-200"
                )}>

                {/* Kind badge + severity + timestamp */}
                <div className="flex items-center gap-2">
                  <div className={cn("p-1.5 rounded-lg flex-shrink-0", ks.bg)}>
                    <span className={ks.text}>{ks.icon}</span>
                  </div>
                  <span className={cn("px-2 py-0.5 rounded-full text-[9px] font-bold", ks.badge)}>
                    {ks.label}
                  </span>
                  {item.severity && item.severity !== "info" && <SevBadge sev={item.severity} />}
                  <span className="ml-auto text-[9px] text-gray-400 whitespace-nowrap tabular-nums">
                    {relTime(item.ts)}
                  </span>
                </div>

                {/* Title */}
                <p className="text-[11px] text-gray-800 font-semibold leading-snug line-clamp-2 flex-1">
                  {item.title}
                </p>

                {/* Summary */}
                {item.summary && (
                  <p className="text-[10px] text-gray-500 leading-relaxed line-clamp-2">
                    {item.summary}
                  </p>
                )}

                {/* CVE refs */}
                {item.cve_refs && item.cve_refs.length > 0 && (
                  <div className="flex gap-1 flex-wrap">
                    {item.cve_refs.slice(0, 4).map(r => (
                      <span key={r}
                        className="font-mono text-[8px] px-1.5 py-0.5 bg-red-50 text-red-600 border border-red-100 rounded">
                        {r}
                      </span>
                    ))}
                  </div>
                )}

                {/* Footer */}
                <div className="flex items-center gap-2 pt-2 border-t border-gray-100 mt-auto">
                  <span className="text-[9px] text-gray-400 font-medium flex-1 truncate">{item.source}</span>
                  {item.url && (
                    <a href={item.url} target="_blank" rel="noopener noreferrer"
                      className="flex items-center gap-0.5 text-[9px] text-blue-500 hover:text-blue-700 font-semibold transition-colors">
                      <ExternalLink className="w-2.5 h-2.5" />Read
                    </a>
                  )}
                  <button onClick={() => toggleStar(item.id)}
                    className={cn(
                      "flex items-center gap-0.5 text-[9px] font-semibold transition-all",
                      isStarred
                        ? "text-amber-500"
                        : "text-gray-300 hover:text-amber-400 opacity-0 group-hover:opacity-100"
                    )}>
                    <Star className={cn("w-3 h-3", isStarred && "fill-current")} />
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function ThreatIntelligence() {
  const [data,    setData]    = useState<DashData | null>(null);
  const [ipIocs,  setIpIocs]  = useState<IOC[]>([]);
  const [domIocs, setDomIocs] = useState<IOC[]>([]);
  const [loading, setLoading] = useState(true);
  const [lastFetch, setLastFetch] = useState(0);

  const load = useCallback(async () => {
    try {
      const [d, ip, dom] = await Promise.allSettled([
        fetch(`${THREAT}/intel/dashboard?cve_limit=20&news_limit=20&kev_limit=20`).then(r => r.ok ? r.json() : null),
        fetch(`${THREAT}/iocs?ioc_type=ip&limit=300`).then(r => r.ok ? r.json() : null),
        fetch(`${THREAT}/iocs?ioc_type=domain&limit=300`).then(r => r.ok ? r.json() : null),
      ]);
      if (d.status   === "fulfilled" && d.value)         setData(d.value);
      if (ip.status  === "fulfilled" && ip.value?.iocs)  setIpIocs(ip.value.iocs);
      if (dom.status === "fulfilled" && dom.value?.iocs) setDomIocs(dom.value.iocs);
      setLastFetch(Math.floor(Date.now() / 1000));
    } finally { setLoading(false); }
  }, []);

  useEffect(() => { load(); const t = setInterval(load, 60_000); return () => clearInterval(t); }, [load]);

  const allIocs = useMemo(() => [...ipIocs, ...domIocs], [ipIocs, domIocs]);
  const stats   = data?.stats;

  return (
    <div className="space-y-4 pb-6">

      {/* ── Header — matches Asset Registry pattern ─────────────────────────── */}
      <div className="bg-white border border-gray-200 rounded-2xl shadow-sm overflow-hidden">
        <div className="h-1 bg-gradient-to-r from-orange-400 via-amber-400 to-orange-500" />
        <div className="p-5">
          <div className="flex items-start justify-between gap-4">
            <div className="flex items-start gap-3">
              <div className="w-10 h-10 rounded-xl bg-orange-50 border border-orange-100 flex items-center justify-center flex-shrink-0">
                <Crosshair className="w-5 h-5 text-orange-500" />
              </div>
              <div>
                <h1 className="text-base font-bold text-gray-900">Threat Intelligence</h1>
                <p className="text-xs text-gray-500 mt-0.5">
                  Actionable IOCs · block in firewall / EDR / DNS · CISA KEV · CVE tracking
                </p>
              </div>
            </div>
            <button onClick={load}
              className="flex items-center gap-1.5 px-3 py-2 rounded-xl bg-gray-100 hover:bg-gray-200 text-gray-600 text-xs font-semibold transition-colors">
              <RefreshCw className={cn("w-3.5 h-3.5", loading && "animate-spin")} />
              {lastFetch ? relTime(lastFetch) : "Loading…"}
            </button>
          </div>

          {/* KPI strip — same tiles as Asset Registry */}
          <div className="grid grid-cols-5 gap-2.5 mt-4 pt-4 border-t border-gray-100">
            {[
              { label: "IOCs Cached",   val: allIocs.length,       sub: "IPs + domains",         color: "text-red-700",   bg: "bg-red-50 border-red-100" },
              { label: "CISA KEV",      val: stats?.kev_count,     sub: "actively exploited",     color: "text-red-600",   bg: "bg-red-50 border-red-100" },
              { label: "Critical CVEs", val: stats?.nvd_critical,  sub: "CVSS ≥ 9.0",            color: "text-amber-700", bg: "bg-amber-50 border-amber-100" },
              { label: "Threat Actors", val: stats?.actor_count,   sub: "tracked groups",         color: "text-blue-700",  bg: "bg-blue-50 border-blue-100" },
              { label: "Active Feeds",  val: stats ? `${stats.active_feeds}/${stats.total_feeds}` : "—", sub: "live intel feeds", color: "text-green-700", bg: "bg-green-50 border-green-100" },
            ].map(k => (
              <div key={k.label} className={cn("rounded-xl p-3 border text-center", k.bg)}>
                <div className={cn("text-xl font-black tabular-nums leading-none", k.color)}>
                  {k.val ?? "—"}
                </div>
                <div className="text-[11px] font-semibold text-gray-600 mt-1">{k.label}</div>
                <div className="text-[9px] text-gray-400 mt-0.5">{k.sub}</div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* ── Main layout ──────────────────────────────────────────────────────── */}
      <div className="grid grid-cols-[1fr_340px] gap-4 items-start">

        {/* Left: IOC table */}
        {loading && !allIocs.length
          ? <Skeleton h="h-64" />
          : <IOCTable iocs={allIocs} />
        }

        {/* Right: sidebar */}
        <div className="space-y-3">
          <ActionSummary iocs={allIocs} stats={stats} />
          {loading && !data ? (
            <><Skeleton h="h-48" /><Skeleton h="h-64" /><Skeleton h="h-40" /></>
          ) : (
            <>
              <CVEList  cves={data?.top_cves ?? []} />
              <KEVList  kev={data?.kev_recent ?? []} />
              <FeedGrid feeds={data?.feeds ?? []} />
            </>
          )}
        </div>
      </div>

      {/* ── Recent Threat Intel — full-width below IOC Action Center ─────────── */}
      {loading && !data
        ? <Skeleton h="h-80" />
        : <RecentThreatIntel news={data?.news ?? []} feeds={data?.feeds ?? []} kev={data?.kev_recent ?? []} />
      }
    </div>
  );
}
