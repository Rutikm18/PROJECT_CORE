/**
 * NetworkThreats — Vector terrain (network-layer threat intelligence).
 *
 * Domain context:
 *   Correlates live network connections, DNS queries, and ARP tables against
 *   curated threat intelligence feeds (Feodo, URLhaus, Emerging Threats,
 *   AbuseIPDB, GreyNoise).  High-confidence matches indicate active C2
 *   beaconing or exfiltration channels.
 *
 * Attack terrain: Vector — the network pathways an adversary exploits after
 * initial access to reach command infrastructure or exfiltrate data.
 */
import { useState, useMemo, type ReactNode } from "react";
import {
  Globe, CheckCircle2, AlertTriangle, Radio, Shield,
  Wifi, Zap, Database, ExternalLink, Network,
  Activity, Copy, Check,
} from "lucide-react";
import {
  TerrainDetectionPage, useDetectionData, type DetectionFinding,
} from "./DetectionShared";
import { cn } from "../../lib/utils";

// ── Cell renderers ────────────────────────────────────────────────────────────

function RiskScore({ f }: { f: DetectionFinding }) {
  const s   = f.composite_score ?? f.score;
  const cls = s >= 8 ? "text-red-600 bg-red-50 border-red-200"
              : s >= 6 ? "text-amber-600 bg-amber-50 border-amber-200"
              :          "text-blue-600 bg-blue-50 border-blue-200";
  return (
    <div className={cn("inline-flex items-center gap-1 px-2 py-0.5 rounded-full border text-[10px] font-black tabular-nums", cls)}>
      {s.toFixed(1)}<span className="text-[8px] font-normal opacity-60">/10</span>
    </div>
  );
}

function FeedChip({ f }: { f: DetectionFinding }) {
  const src      = f.source ?? "";
  const isFeed   = src.startsWith("feed:");
  const feedName = isFeed ? src.replace("feed:", "") : src;
  const FEED_COLORS: Record<string, string> = {
    feodo:      "bg-red-50 text-red-700 border-red-200",
    urlhaus:    "bg-purple-50 text-purple-700 border-purple-200",
    emerging:   "bg-amber-50 text-amber-700 border-amber-200",
    abuseipdb:  "bg-orange-50 text-orange-700 border-orange-200",
    greynoise:  "bg-blue-50 text-blue-700 border-blue-200",
    threatfox:  "bg-rose-50 text-rose-700 border-rose-200",
  };
  const colorKey = Object.keys(FEED_COLORS).find(k => feedName.toLowerCase().includes(k));
  const cls = isFeed
    ? (FEED_COLORS[colorKey ?? ""] ?? "bg-red-50 text-red-700 border-red-200")
    : "bg-gray-100 text-gray-600 border-gray-200";
  return (
    <span className={cn("text-[9px] font-semibold px-2 py-0.5 rounded-full border flex items-center gap-1", cls)}>
      {isFeed && <span className="w-1 h-1 rounded-full bg-current animate-pulse" />}
      {feedName || src}
    </span>
  );
}

function ConfPct({ f }: { f: DetectionFinding }) {
  const pct   = f.confidence_pct ?? 70;
  const color = pct >= 90 ? "text-green-600" : pct >= 70 ? "text-blue-600" : "text-amber-600";
  return <span className={cn("text-[10px] font-bold tabular-nums", color)}>{pct}%</span>;
}

// ── KPI stat tile ─────────────────────────────────────────────────────────────

function StatTile({
  label, value, sub, icon, valueClass, warn = false,
}: {
  label: string; value: string | number; sub?: string;
  icon: ReactNode; valueClass: string; warn?: boolean;
}) {
  return (
    <div className={cn(
      "flex-1 rounded-xl border px-4 py-3 transition-all",
      warn ? "bg-red-50 border-red-200 shadow-sm" : "bg-white border-gray-100"
    )}>
      <div className={cn("mb-1 opacity-60", warn ? "text-red-500" : "text-gray-400")}>{icon}</div>
      <div className={cn("text-xl font-black tabular-nums leading-none", valueClass)}>{value}</div>
      {sub && <div className="text-[9px] text-gray-400 mt-0.5 font-medium">{sub}</div>}
      <div className="text-[10px] text-gray-500 font-semibold mt-1">{label}</div>
    </div>
  );
}

// ── IOC export helper ─────────────────────────────────────────────────────────

function CopyIocButton({ findings }: { findings: DetectionFinding[] }) {
  const [copied, setCopied] = useState(false);

  const copyIocs = () => {
    const iocs = findings
      .map(f => {
        const ev = typeof f.evidence === "string" ? {} : (f.evidence ?? {});
        return (ev as Record<string, unknown>).dst_ip as string
            || (ev as Record<string, unknown>).remote_ip as string
            || f.source?.replace("feed:", "") || "";
      })
      .filter(Boolean)
      .join("\n");
    navigator.clipboard?.writeText(iocs || findings.map(f => f.title).join("\n"));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <button
      onClick={copyIocs}
      className="flex items-center gap-1.5 px-3 py-1.5 text-[10px] font-bold bg-white border border-gray-200 text-gray-600 rounded-xl hover:border-purple-300 hover:text-purple-700 hover:bg-purple-50 transition-all"
    >
      {copied ? <Check className="w-3 h-3 text-green-500" /> : <Copy className="w-3 h-3" />}
      {copied ? "Copied!" : "Copy IOC List"}
    </button>
  );
}

// ── Feed filter chip row (dynamic from live data) ─────────────────────────────

type FeedFilter = "all" | string;
const KNOWN_FEEDS = ["feodo", "urlhaus", "emerging", "abuseipdb", "greynoise", "threatfox"];
const FEED_COLORS: Record<string, { on: string; off: string }> = {
  feodo:     { on: "bg-red-600 text-white border-red-600",       off: "bg-white text-red-600 border-red-200 hover:bg-red-50" },
  urlhaus:   { on: "bg-purple-600 text-white border-purple-600", off: "bg-white text-purple-600 border-purple-200 hover:bg-purple-50" },
  emerging:  { on: "bg-amber-500 text-white border-amber-500",   off: "bg-white text-amber-700 border-amber-200 hover:bg-amber-50" },
  abuseipdb: { on: "bg-orange-600 text-white border-orange-600", off: "bg-white text-orange-600 border-orange-200 hover:bg-orange-50" },
  greynoise: { on: "bg-blue-600 text-white border-blue-600",     off: "bg-white text-blue-600 border-blue-200 hover:bg-blue-50" },
  threatfox: { on: "bg-rose-600 text-white border-rose-600",     off: "bg-white text-rose-600 border-rose-200 hover:bg-rose-50" },
};

// ── Main ──────────────────────────────────────────────────────────────────────

export default function NetworkThreats() {
  const [validatedOnly,   setValidatedOnly]   = useState(false);
  const [feedFilter,      setFeedFilter]      = useState<FeedFilter>("all");
  const [confFilter,      setConfFilter]      = useState<"all" | "70" | "90">("all");
  const [kevOnly,         setKevOnly]         = useState(false);

  // Build base API URL
  const baseUrl = validatedOnly
    ? "/api/v1/detection/network?validated_only=true"
    : "/api/v1/detection/network";

  // Fetch for domain KPIs
  const { findings: raw } = useDetectionData(`${baseUrl}&limit=500`);

  // Extract distinct feed sources from live data
  const activeFeedKeys = useMemo(() => {
    const feedSet = new Set<string>();
    raw.forEach(f => {
      const src = (f.source ?? "").toLowerCase();
      KNOWN_FEEDS.forEach(feed => { if (src.includes(feed)) feedSet.add(feed); });
    });
    return [...feedSet].sort();
  }, [raw]);

  const stats = useMemo(() => ({
    total:     raw.length,
    highConf:  raw.filter(f => (f.confidence_pct ?? 0) >= 80).length,
    kev:       raw.filter(f => f.kev).length,
    exploit:   raw.filter(f => f.exploit_available).length,
    feedCount: new Set(raw.map(f => f.source?.replace("feed:", "")).filter(Boolean)).size,
    activeC2:  raw.filter(f => (f.composite_score ?? f.score) >= 8).length,
  }), [raw]);

  const hasHighRisk = stats.activeC2 > 0;

  // pageKey forces TerrainDetectionPage remount when ANY filter changes
  const pageKey = `${validatedOnly}:${feedFilter}:${confFilter}:${kevOnly}`;

  // initialCategoryFilter for feed source filtering
  const initialCategory = feedFilter !== "all" ? feedFilter : undefined;
  const initialConf     = confFilter !== "all" ? Number(confFilter) : undefined;

  return (
    <div className="space-y-0 pb-6">

      {/* ── Alert strip ───────────────────────────────────────────────────────── */}
      {hasHighRisk && (
        <div className="flex items-center gap-3 px-5 py-2.5 bg-purple-700">
          <Wifi className="w-4 h-4 text-white flex-shrink-0 al-heartbeat" />
          <span className="text-[11px] text-white font-bold">
            {stats.activeC2} high-risk network {stats.activeC2 === 1 ? "connection" : "connections"} detected — possible C2 beaconing or exfiltration in progress.
          </span>
          <button
            className="ml-auto flex items-center gap-1 text-[10px] text-purple-200 hover:text-white font-semibold transition-colors flex-shrink-0"
          >
            Hunt Now <ExternalLink className="w-3 h-3" />
          </button>
        </div>
      )}

      {/* ── Domain header + KPIs ─────────────────────────────────────────────── */}
      <div className="bg-white border-b border-gray-100 px-5 py-4">
        <div className="flex items-center gap-3 mb-4">
          <div className="w-9 h-9 rounded-xl bg-blue-50 border border-blue-100 flex items-center justify-center flex-shrink-0">
            <Globe className="w-4.5 h-4.5 text-blue-600" />
          </div>
          <div className="flex-1 min-w-0">
            <h2 className="text-sm font-bold text-gray-900">Vector — Network Threats</h2>
            <p className="text-[10px] text-gray-400 mt-0.5">
              Threat intelligence feed correlation · C2 beaconing · malicious IP/domain matching · DNS anomalies · ARP poisoning
            </p>
          </div>
          <div className="flex items-center gap-2 flex-shrink-0">
            <CopyIocButton findings={raw} />
            <a
              href="https://feodotracker.abuse.ch/browse/"
              target="_blank" rel="noopener noreferrer"
              className="flex items-center gap-1.5 px-3 py-1.5 text-[10px] font-bold bg-red-50 border border-red-200 text-red-700 rounded-xl hover:bg-red-100 transition-all"
            >
              <Radio className="w-3 h-3 animate-pulse" />Feodo Tracker
            </a>
          </div>
        </div>

        {/* KPI row */}
        <div className="flex gap-2">
          <StatTile
            label="Network Threats" value={stats.total} sub="total findings"
            icon={<Database className="w-3.5 h-3.5" />}
            valueClass="text-gray-800"
          />
          <StatTile
            label="High Confidence" value={stats.highConf} sub="≥80% confidence"
            icon={<Activity className="w-3.5 h-3.5" />}
            valueClass={stats.highConf > 0 ? "text-purple-600" : "text-gray-600"}
          />
          <StatTile
            label="Active C2 Risk" value={stats.activeC2} sub="risk score ≥8"
            icon={<Network className="w-3.5 h-3.5" />}
            valueClass={stats.activeC2 > 0 ? "text-red-600" : "text-gray-600"}
            warn={stats.activeC2 > 0}
          />
          <StatTile
            label="KEV IOCs" value={stats.kev} sub="known exploited"
            icon={<Zap className="w-3.5 h-3.5" />}
            valueClass={stats.kev > 0 ? "text-amber-600" : "text-gray-600"}
            warn={stats.kev > 0}
          />
          <StatTile
            label="Active Feeds" value={stats.feedCount} sub="threat intel sources"
            icon={<Radio className="w-3.5 h-3.5" />}
            valueClass="text-blue-600"
          />
        </div>
      </div>

      {/* ── Filter controls ───────────────────────────────────────────────────── */}
      <div className="bg-white border-b border-gray-100 px-5 pt-4 pb-3 space-y-3">

        {/* Row 1 — Threat feed chips */}
        {activeFeedKeys.length > 0 && (
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-[10px] font-bold text-gray-400 uppercase tracking-wider whitespace-nowrap">Threat Feed</span>
            <div className="flex items-center gap-1 flex-wrap">
              <button
                onClick={() => setFeedFilter("all")}
                className={cn(
                  "px-2.5 py-1 rounded-lg text-[10px] font-semibold border transition-all",
                  feedFilter === "all"
                    ? "bg-gray-700 text-white border-gray-700 shadow-sm"
                    : "bg-white text-gray-500 border-gray-200 hover:bg-gray-50"
                )}
              >
                All Feeds
              </button>
              {activeFeedKeys.map(feed => {
                const colors = FEED_COLORS[feed] ?? { on: "bg-blue-600 text-white border-blue-600", off: "bg-white text-blue-600 border-blue-200 hover:bg-blue-50" };
                return (
                  <button
                    key={feed}
                    onClick={() => setFeedFilter(feedFilter === feed ? "all" : feed)}
                    className={cn(
                      "flex items-center gap-1 px-2.5 py-1 rounded-lg text-[10px] font-semibold border transition-all",
                      feedFilter === feed ? colors.on : colors.off
                    )}
                  >
                    {feedFilter === feed && <span className="w-1.5 h-1.5 rounded-full bg-current animate-pulse" />}
                    {feed}
                  </button>
                );
              })}
            </div>
          </div>
        )}

        {/* Row 2 — Confidence + Validated + KEV */}
        <div className="flex items-center gap-2 flex-wrap">
          {/* Validated toggle */}
          <div className="inline-flex bg-gray-100 rounded-lg p-0.5">
            <button
              onClick={() => setValidatedOnly(false)}
              className={cn("px-3 py-1.5 rounded-md text-[10px] font-bold transition-all", !validatedOnly ? "bg-white text-blue-600 shadow-sm" : "text-gray-500 hover:text-gray-700")}
            >
              All Vector
            </button>
            <button
              onClick={() => setValidatedOnly(true)}
              className={cn("flex items-center gap-1 px-3 py-1.5 rounded-md text-[10px] font-bold transition-all", validatedOnly ? "bg-white text-emerald-600 shadow-sm" : "text-gray-500 hover:text-gray-700")}
            >
              <CheckCircle2 className="w-3 h-3" />Validated
            </button>
          </div>

          {/* Confidence threshold */}
          <div className="flex items-center gap-1">
            <span className="text-[10px] text-gray-500 font-semibold">Min Confidence</span>
            {(["all", "70", "90"] as const).map(v => (
              <button
                key={v}
                onClick={() => setConfFilter(v)}
                className={cn(
                  "px-2.5 py-1 rounded-lg text-[10px] font-bold border transition-all",
                  confFilter === v
                    ? v === "all"   ? "bg-gray-700 text-white border-gray-700"
                      : v === "70" ? "bg-blue-600 text-white border-blue-600"
                      :               "bg-purple-600 text-white border-purple-600"
                    : "bg-white text-gray-500 border-gray-200 hover:bg-gray-50"
                )}
              >
                {v === "all" ? "Any" : `≥${v}%`}
              </button>
            ))}
          </div>

          {/* KEV only */}
          <button
            onClick={() => setKevOnly(v => !v)}
            className={cn(
              "flex items-center gap-1.5 px-3 py-1.5 rounded-xl border text-[10px] font-bold transition-all",
              kevOnly
                ? "bg-amber-500 text-white border-amber-500 shadow-sm"
                : "bg-white text-gray-600 border-gray-200 hover:border-amber-300 hover:text-amber-600 hover:bg-amber-50"
            )}
          >
            <Zap className="w-3 h-3" />KEV IOCs
            {stats.kev > 0 && (
              <span className={cn("ml-0.5 text-[8px] font-black px-1 rounded", kevOnly ? "bg-amber-400 text-white" : "bg-amber-100 text-amber-700")}>
                {stats.kev}
              </span>
            )}
          </button>

          {validatedOnly && (
            <span className="ml-auto text-[9px] text-emerald-700 font-semibold flex items-center gap-1 bg-emerald-50 px-2 py-1 rounded border border-emerald-200">
              <CheckCircle2 className="w-3 h-3" />precision_score ≥ threshold
            </span>
          )}
        </div>

        {/* Context hint */}
        {stats.activeC2 > 0 && (
          <div className="flex items-start gap-2.5 px-3 py-2.5 bg-blue-50 border border-blue-200 rounded-xl">
            <Shield className="w-3.5 h-3.5 text-blue-600 flex-shrink-0 mt-0.5" />
            <div className="text-[10px] text-blue-900 leading-relaxed">
              <span className="font-bold">Network triage playbook: </span>
              Capture packets for suspicious connections (
              <code className="font-mono text-[9px] bg-blue-100 px-1 rounded">tcpdump -w capture.pcap</code>),
              check DNS resolution chain, verify JA3 TLS fingerprint against GreyNoise,
              and block at the perimeter firewall if beaconing interval &lt; 300s.
            </div>
          </div>
        )}
      </div>

      {/* ── Main detection table ──────────────────────────────────────────────── */}
      <TerrainDetectionPage
        key={pageKey}
        apiUrl={baseUrl}
        accent="red"
        emptyMsg={
          validatedOnly
            ? "No validated findings in Vector."
            : "No network threat findings yet. Findings appear when agent connections match threat feed IOCs."
        }
        initialKevOnly={kevOnly}
        initialCategoryFilter={feedFilter !== "all" ? feedFilter : undefined}
        columns={[
          { key: "source",          label: "Feed Source", render: f => <FeedChip f={f} /> },
          { key: "confidence_pct",  label: "Confidence",  render: f => <ConfPct f={f} /> },
          { key: "composite_score", label: "Risk",        render: f => <RiskScore f={f} /> },
        ]}
      />
    </div>
  );
}
