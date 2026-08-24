/**
 * PortalPages — the customer's four screens.
 *
 * Each mirrors an operator page against the scoped endpoints, with the
 * downgrade applied: read-only, own endpoints only, and no action that changes
 * infrastructure or crosses a tenant. Built from the same tokens as the
 * operator dashboard so the two read as one product.
 */
import { useCallback, useEffect, useMemo, useState } from "react";
import { Link, useParams } from "react-router";
import {
  AlertTriangle, ArrowLeft, CheckCircle2, Database, Monitor,
  RefreshCw, Save, Shield, Zap,
} from "lucide-react";
import { cn } from "../../lib/utils";
import { usePortalSession } from "./PortalShell";
import {
  portalApi, type PortalAgent, type PortalFinding, type PortalSummary,
} from "./portalClient";

// ── Shared bits ─────────────────────────────────────────────────────────────

export const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"] as const;

export function severityTone(severity: string): string {
  return {
    critical: "bg-red-50 text-red-700 border-red-200",
    high:     "bg-amber-50 text-amber-700 border-amber-200",
    medium:   "bg-yellow-50 text-yellow-700 border-yellow-200",
    low:      "bg-blue-50 text-blue-700 border-blue-200",
    info:     "bg-[--gray-100] text-[--gray-600] border-[--gray-200]",
  }[severity] ?? "bg-[--gray-100] text-[--gray-600] border-[--gray-200]";
}

/** Order severities by urgency, not alphabetically, and drop empty buckets. */
export function orderedSeverities(
  counts: Record<string, number> | undefined,
): [string, number][] {
  return SEVERITY_ORDER
    .map(s => [s, counts?.[s] ?? 0] as [string, number])
    .filter(([, n]) => n > 0);
}

function Card({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <div className={cn(
      "bg-white border border-[--gray-200] rounded-2xl shadow-card p-5 space-y-4", className,
    )}>{children}</div>
  );
}

function Stat({ label, value, sub, tone = "neutral", icon }: {
  label: string; value: string | number; sub?: string; icon?: React.ReactNode;
  tone?: "neutral" | "bad" | "warn" | "good";
}) {
  const toneCls = {
    neutral: "text-[--gray-800]", bad: "text-red-600",
    warn: "text-amber-600", good: "text-emerald-600",
  }[tone];
  return (
    <div className="flex-1 min-w-[130px] rounded-xl border border-[--gray-100] px-4 py-3 bg-white">
      {icon && <div className="mb-1 opacity-60 text-[--gray-400]">{icon}</div>}
      <div className={cn("text-xl font-black tabular-nums leading-none", toneCls)}>{value}</div>
      {sub && <div className="text-[9px] text-[--gray-400] mt-0.5 font-medium">{sub}</div>}
      <div className="text-[10px] text-[--gray-500] font-semibold mt-1">{label}</div>
    </div>
  );
}

function Loading() {
  return (
    <div className="flex items-center justify-center py-20">
      <RefreshCw className="w-4 h-4 animate-spin text-[--gray-300]" />
    </div>
  );
}

function Empty({ message }: { message: string }) {
  return (
    <div className="text-center py-14">
      <Shield className="w-8 h-8 text-[--gray-200] mx-auto mb-3" />
      <p className="text-[11px] text-[--gray-400] max-w-[420px] mx-auto leading-relaxed">{message}</p>
    </div>
  );
}

function useResource<T>(path: string): { data: T | null; loading: boolean; reload: () => void } {
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(true);
  const [nonce, setNonce] = useState(0);

  useEffect(() => {
    let dead = false;
    setLoading(true);
    portalApi<T>(path)
      .then(body => { if (!dead) setData(body); })
      .catch(() => { if (!dead) setData(null); })
      .finally(() => { if (!dead) setLoading(false); });
    return () => { dead = true; };
  }, [path, nonce]);

  return { data, loading, reload: useCallback(() => setNonce(n => n + 1), []) };
}

// ── Dashboard ───────────────────────────────────────────────────────────────

export function PortalDashboard() {
  const { me } = usePortalSession();
  const { data, loading } = useResource<PortalSummary>("/summary");

  if (loading) return <Loading />;
  const summary = data ?? {
    total: 0, by_severity: {}, critical: 0, high: 0, validated: 0,
    by_terrain: {}, agent_count: 0,
  };
  const severities = orderedSeverities(summary.by_severity);

  return (
    <div className="space-y-4">
      <Card>
        <div>
          <h1 className="text-[15px] font-bold text-[--gray-900]">
            {me?.org.name ?? "Your"} security posture
          </h1>
          <p className="text-[10px] text-[--gray-500] mt-1">
            Findings across {summary.agent_count} endpoint{summary.agent_count === 1 ? "" : "s"} you own.
          </p>
        </div>
        <div className="flex gap-2 flex-wrap">
          <Stat label="Open findings" value={summary.total} sub="currently active"
            icon={<Database className="w-3.5 h-3.5" />} />
          <Stat label="Critical" value={summary.critical} sub="need attention now"
            tone={summary.critical > 0 ? "bad" : "good"}
            icon={<AlertTriangle className="w-3.5 h-3.5" />} />
          <Stat label="High" value={summary.high} sub="severity high"
            tone={summary.high > 0 ? "warn" : "good"}
            icon={<Zap className="w-3.5 h-3.5" />} />
          <Stat label="Validated" value={summary.validated} sub="confirmed by analysis"
            tone="good" icon={<CheckCircle2 className="w-3.5 h-3.5" />} />
          <Stat label="Endpoints" value={summary.agent_count} sub="reporting to us"
            icon={<Monitor className="w-3.5 h-3.5" />} />
        </div>
      </Card>

      <Card>
        <h2 className="text-[11px] font-bold text-[--gray-700] uppercase tracking-wide">By severity</h2>
        {severities.length === 0 ? (
          <Empty message="No open findings. New issues appear here as soon as they are detected on your endpoints." />
        ) : (
          <div className="space-y-2">
            {severities.map(([severity, count]) => {
              const pct = summary.total ? Math.round((count / summary.total) * 100) : 0;
              return (
                <Link key={severity} to={`/portal/findings?severity=${severity}`}
                  className="block group">
                  <div className="flex items-center gap-3">
                    <span className={cn(
                      "text-[9px] font-bold uppercase px-2 py-0.5 rounded-full border w-[70px] text-center",
                      severityTone(severity),
                    )}>{severity}</span>
                    <div className="flex-1 h-2 rounded-full bg-[--gray-100] overflow-hidden">
                      <div className="h-full rounded-full bg-purple-500 transition-all group-hover:bg-purple-600"
                        style={{ width: `${pct}%` }} />
                    </div>
                    <span className="text-[11px] font-black tabular-nums text-[--gray-700] w-10 text-right">
                      {count}
                    </span>
                  </div>
                </Link>
              );
            })}
          </div>
        )}
      </Card>
    </div>
  );
}

// ── Findings ────────────────────────────────────────────────────────────────

export function PortalFindings() {
  const [severity, setSeverity] = useState<string>(
    () => new URLSearchParams(window.location.search).get("severity") ?? "",
  );
  const path = useMemo(
    () => `/findings?limit=100${severity ? `&severity=${severity}` : ""}`,
    [severity],
  );
  const { data, loading } = useResource<{ findings: PortalFinding[]; total: number }>(path);

  return (
    <div className="space-y-4">
      <Card>
        <div className="flex items-center justify-between gap-3 flex-wrap">
          <div>
            <h1 className="text-[15px] font-bold text-[--gray-900]">Findings</h1>
            <p className="text-[10px] text-[--gray-500] mt-1">
              Read-only. Contact your security provider to dispute or close a finding.
            </p>
          </div>
          <div className="flex items-center gap-1 flex-wrap">
            {["", ...SEVERITY_ORDER].map(s => (
              <button key={s || "all"} onClick={() => setSeverity(s)}
                className={cn(
                  "px-2.5 py-1 rounded-lg text-[10px] font-semibold border transition-all capitalize",
                  severity === s
                    ? "bg-purple-600 text-white border-purple-600"
                    : "bg-white text-[--gray-500] border-[--gray-200] hover:border-purple-300",
                )}>{s || "All"}</button>
            ))}
          </div>
        </div>
      </Card>

      <Card>
        {loading ? <Loading /> : !data?.findings?.length ? (
          <Empty message={
            severity
              ? `No ${severity} findings on your endpoints right now.`
              : "No open findings on your endpoints. New issues appear here automatically."
          } />
        ) : (
          <>
            <div className="text-[10px] text-[--gray-400]">{data.total} finding{data.total === 1 ? "" : "s"}</div>
            <div className="space-y-1.5">
              {data.findings.map(f => (
                <Link key={f.id} to={`/portal/findings/${f.id}`}
                  className="block border border-[--gray-200] rounded-xl px-3 py-2.5 hover:border-purple-300 hover:bg-purple-50/30 transition-all">
                  <div className="flex items-start gap-2.5 flex-wrap">
                    <span className={cn(
                      "text-[9px] font-bold uppercase px-2 py-0.5 rounded-full border flex-shrink-0",
                      severityTone(f.severity),
                    )}>{f.severity}</span>
                    <div className="flex-1 min-w-0">
                      <div className="text-[12px] font-semibold text-[--gray-800]">{f.title}</div>
                      <div className="text-[9px] text-[--gray-400] font-mono mt-0.5">
                        {f.agent_id}{f.mitre_technique ? ` · ${f.mitre_technique}` : ""}
                      </div>
                    </div>
                    <div className="flex items-center gap-1.5 flex-shrink-0">
                      {f.kev && <span className="text-[8px] font-bold uppercase px-1.5 py-0.5 rounded bg-red-100 text-red-700">KEV</span>}
                      {f.exploit_available && <span className="text-[8px] font-bold uppercase px-1.5 py-0.5 rounded bg-amber-100 text-amber-700">Exploit</span>}
                      <span className="text-[11px] font-black tabular-nums text-[--gray-600]">
                        {(f.composite_score ?? f.score).toFixed(1)}
                      </span>
                    </div>
                  </div>
                </Link>
              ))}
            </div>
          </>
        )}
      </Card>
    </div>
  );
}

export function PortalFindingDetail() {
  const { findingId } = useParams<{ findingId: string }>();
  const { data, loading } = useResource<PortalFinding>(`/findings/${findingId}`);

  if (loading) return <Loading />;
  if (!data) {
    return (
      <Card>
        <Empty message="This finding is not available on your account. It may have been resolved, or it belongs to a different organisation." />
        <Link to="/portal/findings" className="text-[11px] font-bold text-purple-700 hover:text-purple-900 flex items-center gap-1.5 justify-center">
          <ArrowLeft className="w-3.5 h-3.5" />Back to findings
        </Link>
      </Card>
    );
  }

  return (
    <div className="space-y-4">
      <Link to="/portal/findings" className="text-[11px] font-bold text-purple-700 hover:text-purple-900 inline-flex items-center gap-1.5">
        <ArrowLeft className="w-3.5 h-3.5" />Back to findings
      </Link>
      <Card>
        <div className="flex items-start gap-2.5 flex-wrap">
          <span className={cn(
            "text-[9px] font-bold uppercase px-2 py-0.5 rounded-full border",
            severityTone(data.severity),
          )}>{data.severity}</span>
          <h1 className="text-[15px] font-bold text-[--gray-900] flex-1 min-w-0">{data.title}</h1>
        </div>
        <p className="text-[12px] text-[--gray-600] leading-relaxed">{data.description}</p>

        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
          {[
            ["Endpoint", data.agent_id],
            ["Risk score", (data.composite_score ?? data.score).toFixed(1)],
            ["First seen", new Date(data.first_detected_at * 1000).toLocaleDateString()],
            ["Last seen", new Date(data.last_detected_at * 1000).toLocaleDateString()],
          ].map(([label, value]) => (
            <div key={label} className="border border-[--gray-100] rounded-xl px-3 py-2">
              <div className="text-[9px] text-[--gray-400] font-semibold uppercase tracking-wide">{label}</div>
              <div className="text-[11px] font-semibold text-[--gray-800] mt-0.5 font-mono break-all">{value}</div>
            </div>
          ))}
        </div>

        {data.cve_ids?.length > 0 && (
          <div>
            <div className="text-[9px] text-[--gray-400] font-semibold uppercase tracking-wide mb-1.5">CVEs</div>
            <div className="flex gap-1.5 flex-wrap">
              {data.cve_ids.map(cve => (
                <span key={cve} className="text-[10px] font-mono px-2 py-1 rounded-lg bg-[--gray-100] text-[--gray-700] border border-[--gray-200]">
                  {cve}
                </span>
              ))}
            </div>
          </div>
        )}

        {Object.keys(data.evidence ?? {}).length > 0 && (
          <div>
            <div className="text-[9px] text-[--gray-400] font-semibold uppercase tracking-wide mb-1.5">Evidence</div>
            <div className="space-y-1">
              {Object.entries(data.evidence).map(([key, value]) => (
                <div key={key} className="flex items-start justify-between gap-3 text-[10px] border-b border-[--gray-100] last:border-0 py-1">
                  <span className="font-mono text-[--gray-500]">{key}</span>
                  <span className="font-mono text-[--gray-800] text-right break-all">{String(value)}</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </Card>
    </div>
  );
}

// ── Endpoints ───────────────────────────────────────────────────────────────

export function PortalAgents() {
  const { data, loading } = useResource<{ agents: PortalAgent[] }>("/agents");
  if (loading) return <Loading />;
  const agents = data?.agents ?? [];

  return (
    <Card>
      <div>
        <h1 className="text-[15px] font-bold text-[--gray-900]">Your endpoints</h1>
        <p className="text-[10px] text-[--gray-500] mt-1">
          Devices reporting to your security provider on your behalf.
        </p>
      </div>
      {agents.length === 0 ? (
        <Empty message="No endpoints are assigned to your organisation yet. Your security provider assigns them when agents are deployed." />
      ) : (
        <div className="space-y-1.5">
          {agents.map(a => (
            <div key={a.agent_id} className="flex items-center justify-between gap-3 border border-[--gray-200] rounded-xl px-3 py-2.5 flex-wrap">
              <div className="min-w-0">
                <div className="text-[12px] font-semibold text-[--gray-800]">{a.hostname || a.agent_id}</div>
                <div className="text-[9px] text-[--gray-400] font-mono">
                  {a.agent_id}{a.os ? ` · ${a.os} ${a.os_version}` : ""}
                </div>
              </div>
              <span className={cn(
                "text-[10px] font-black tabular-nums px-2 py-1 rounded-lg border",
                a.finding_count > 0
                  ? "bg-amber-50 text-amber-700 border-amber-200"
                  : "bg-emerald-50 text-emerald-700 border-emerald-200",
              )}>
                {a.finding_count} finding{a.finding_count === 1 ? "" : "s"}
              </span>
            </div>
          ))}
        </div>
      )}
    </Card>
  );
}

// ── Settings (the only write) ───────────────────────────────────────────────

interface Preferences {
  display_name: string; timezone: string;
  notification_email: string; default_severity_filter: string;
}

export function PortalSettings() {
  const { data, loading, reload } = useResource<Preferences>("/preferences");
  const [form, setForm] = useState<Preferences | null>(null);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => { if (data) setForm(data); }, [data]);

  if (loading || !form) return <Loading />;

  const save = async () => {
    setBusy(true); setError(null); setSaved(false);
    try {
      await portalApi("/preferences", { method: "PUT", body: JSON.stringify(form) });
      setSaved(true);
      setTimeout(() => setSaved(false), 2000);
      reload();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally { setBusy(false); }
  };

  const field = (key: keyof Preferences, label: string, placeholder: string) => (
    <div>
      <label className="block text-[11px] font-semibold text-[--gray-700] mb-1.5">{label}</label>
      <input
        className="w-full px-3 py-2 text-[12px] border border-[--gray-200] rounded-xl bg-white focus:outline-none focus:ring-2 focus:ring-purple-200 focus:border-purple-300 transition-all placeholder:text-[--gray-300]"
        value={form[key]} placeholder={placeholder}
        onChange={e => setForm({ ...form, [key]: e.target.value })} />
    </div>
  );

  return (
    <Card>
      <div>
        <h1 className="text-[15px] font-bold text-[--gray-900]">Dashboard settings</h1>
        <p className="text-[10px] text-[--gray-500] mt-1 leading-relaxed">
          How this dashboard looks and where it sends you notifications. Your organisation's
          licence, users and endpoint assignments are managed by your security provider.
        </p>
      </div>

      {error && (
        <div className="flex items-start gap-2 px-3 py-2 bg-red-50 border border-red-200 rounded-xl">
          <AlertTriangle className="w-3.5 h-3.5 text-red-600 flex-shrink-0 mt-0.5" />
          <span className="text-[10px] text-red-800">{error}</span>
        </div>
      )}

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        {field("display_name", "Display name", "Acme Security")}
        {field("timezone", "Timezone", "UTC")}
        {field("notification_email", "Notification email", "security@acme.com")}
        {field("default_severity_filter", "Default severity filter", "critical")}
      </div>

      <div className="flex items-center justify-end gap-2">
        {saved && (
          <span className="text-[10px] text-emerald-600 flex items-center gap-1">
            <CheckCircle2 className="w-3 h-3" />Saved
          </span>
        )}
        <button onClick={() => void save()} disabled={busy}
          className="flex items-center gap-1.5 px-4 py-2 bg-purple-600 hover:bg-purple-700 disabled:bg-purple-300 text-white text-[11px] font-bold rounded-xl transition-colors">
          <Save className="w-3.5 h-3.5" />Save changes
        </button>
      </div>
    </Card>
  );
}
