/**
 * CustomersPanel — Settings → Customer Dashboards.
 *
 * Provisioning for the customer portal: create an org, issue its licence, bind
 * the agents it may see, invite its users, and switch its access off.
 *
 * TWO SECRETS ARE SHOWN ONCE
 * The licence key and the invite link exist in exactly one API response and are
 * unrecoverable afterwards — the server stores only their SHA-256. The UI has
 * to make that unmissable rather than mentioning it in passing, because the
 * recovery path is "rotate the licence" / "resend the invite", and an operator
 * who closes the panel without copying will not know that until later.
 *
 * AGENT ASSIGNMENT IS THE SECURITY CONTROL
 * It reads like a tagging feature and is not: it is the only thing deciding
 * what a customer can see. The copy says so.
 */
import { useCallback, useEffect, useMemo, useState } from "react";
import {
  AlertTriangle, Building2, Check, CheckCircle2, ClipboardCopy, KeyRound,
  Monitor, Plus, RefreshCw, ScrollText, ShieldOff, UserPlus, X, XCircle,
} from "lucide-react";
import { cn } from "../../../lib/utils";

const API = "/api/v1/customers";

// ── Types ───────────────────────────────────────────────────────────────────

export interface Customer {
  org_id: string;
  slug: string;
  name: string;
  contact_email: string;
  status: "active" | "suspended" | "pending";
  max_agents: number;
  tier: string;
  agent_count: number;
  user_count: number;
  license_expires_at: number;
  license_expired: boolean;
  license_days_remaining: number | null;
}

export interface PortalUser {
  user_id: string;
  email: string;
  role: string;
  status: string;
  last_login_at: number;
  activated_at: number;
}

interface AuditEntry {
  id: number; actor: string; action: string; created_at: number; detail: string;
}

/** A secret the server will never return again. */
interface OneTimeSecret {
  kind: "license" | "invite";
  label: string;
  value: string;
  notice: string;
}

// ── Pure helpers (exported for test) ────────────────────────────────────────

/** Seats used against the licence, and whether the customer is at the cap. */
export function seatState(customer: Pick<Customer, "agent_count" | "max_agents">) {
  const { agent_count: used, max_agents: cap } = customer;
  if (!cap) return { label: `${used}`, atCap: false, tone: "gray" as const };
  return {
    label: `${used} / ${cap}`,
    atCap: used >= cap,
    tone: used >= cap ? ("red" as const) : used / cap >= 0.8 ? ("amber" as const) : ("gray" as const),
  };
}

/** How a licence should read: expired beats expiring beats fine. */
export function licenseState(customer: Pick<Customer, "license_expired" | "license_days_remaining">) {
  if (customer.license_expired) return { label: "Expired", tone: "red" as const };
  const days = customer.license_days_remaining;
  if (days === null || days === undefined) return { label: "Perpetual", tone: "gray" as const };
  if (days <= 30) return { label: `${days}d left`, tone: "amber" as const };
  return { label: `${days}d left`, tone: "gray" as const };
}

export function statusTone(status: string): "emerald" | "red" | "amber" {
  if (status === "active") return "emerald";
  if (status === "suspended") return "red";
  return "amber";
}

// ── Small pieces ────────────────────────────────────────────────────────────

function SectionLabel({ icon: Icon, children }: { icon: React.ElementType; children: React.ReactNode }) {
  return (
    <div className="flex items-center gap-2">
      <Icon className="w-3.5 h-3.5 flex-shrink-0" style={{ color: "#7C3AED" }} />
      <h2 className="text-[11px] font-bold text-[--gray-700] uppercase tracking-wide">{children}</h2>
    </div>
  );
}

function Card({ children }: { children: React.ReactNode }) {
  return (
    <div className="bg-white border border-[--gray-200] rounded-2xl shadow-card p-5 space-y-4">
      {children}
    </div>
  );
}

function Pill({ children, tone = "gray" }: { children: React.ReactNode; tone?: string }) {
  const tones: Record<string, string> = {
    gray:    "bg-[--gray-100] text-[--gray-600] border-[--gray-200]",
    purple:  "bg-purple-50 text-purple-700 border-purple-200",
    red:     "bg-red-50 text-red-700 border-red-200",
    amber:   "bg-amber-50 text-amber-700 border-amber-200",
    emerald: "bg-emerald-50 text-emerald-700 border-emerald-200",
  };
  return (
    <span className={cn(
      "text-[9px] font-semibold px-1.5 py-0.5 rounded-full border whitespace-nowrap",
      tones[tone] ?? tones.gray,
    )}>{children}</span>
  );
}

const inputCls = "w-full px-3 py-2 text-[12px] border border-[--gray-200] rounded-xl bg-white focus:outline-none focus:ring-2 focus:ring-purple-200 focus:border-purple-300 transition-all placeholder:text-[--gray-300]";

function CopyButton({ value }: { value: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      onClick={() => {
        navigator.clipboard?.writeText(value);
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
      }}
      className="flex items-center gap-1.5 px-3 py-1.5 bg-purple-600 hover:bg-purple-700 text-white text-[11px] font-bold rounded-xl transition-colors flex-shrink-0"
    >
      {copied ? <Check className="w-3.5 h-3.5" /> : <ClipboardCopy className="w-3.5 h-3.5" />}
      {copied ? "Copied" : "Copy"}
    </button>
  );
}

/**
 * A value the server will not return again. Deliberately loud, and it does not
 * dismiss on outside click — closing it is a decision, not an accident.
 */
function OneTimeSecretPanel({ secret, onDone }: { secret: OneTimeSecret; onDone: () => void }) {
  return (
    <div className="border border-amber-300 bg-amber-50 rounded-2xl p-5 space-y-3">
      <div className="flex items-start gap-2.5">
        <AlertTriangle className="w-4 h-4 text-amber-600 flex-shrink-0 mt-0.5" />
        <div className="min-w-0">
          <div className="text-[12px] font-bold text-amber-900">{secret.label}</div>
          <p className="text-[10px] text-amber-800 leading-relaxed mt-1">{secret.notice}</p>
        </div>
      </div>
      <div className="flex items-start gap-2">
        <code className="flex-1 min-w-0 text-[10px] font-mono bg-white border border-amber-200 rounded-xl px-3 py-2.5 break-all leading-relaxed">
          {secret.value}
        </code>
        <CopyButton value={secret.value} />
      </div>
      <button
        onClick={onDone}
        className="text-[11px] font-bold text-amber-900 underline underline-offset-2 hover:text-amber-950"
      >
        I have copied it — dismiss
      </button>
    </div>
  );
}

// ── Main panel ──────────────────────────────────────────────────────────────

export default function CustomersPanel() {
  const [customers, setCustomers] = useState<Customer[]>([]);
  const [loading,   setLoading]   = useState(true);
  const [error,     setError]     = useState<string | null>(null);
  const [secret,    setSecret]    = useState<OneTimeSecret | null>(null);
  const [selected,  setSelected]  = useState<string | null>(null);
  const [creating,  setCreating]  = useState(false);
  const [busy,      setBusy]      = useState(false);

  const [form, setForm] = useState({
    name: "", slug: "", contact_email: "", max_agents: 25, valid_days: 365,
  });

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const r = await fetch(API);
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      setCustomers((await r.json()).customers ?? []);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally { setLoading(false); }
  }, []);

  useEffect(() => { void load(); }, [load]);

  const call = async (path: string, init?: RequestInit) => {
    setBusy(true); setError(null);
    try {
      const r = await fetch(`${API}${path}`, {
        ...init,
        headers: { "Content-Type": "application/json", ...(init?.headers ?? {}) },
      });
      const body = await r.json().catch(() => ({}));
      if (!r.ok) {
        throw new Error(
          typeof body.detail === "string" ? body.detail : `HTTP ${r.status}`,
        );
      }
      return body;
    } finally { setBusy(false); }
  };

  const createCustomer = async () => {
    try {
      const body = await call("", { method: "POST", body: JSON.stringify(form) });
      setSecret({
        kind: "license",
        label: `Licence key for ${body.customer.name}`,
        value: body.license_key,
        notice: body.notice,
      });
      setCreating(false);
      setForm({ name: "", slug: "", contact_email: "", max_agents: 25, valid_days: 365 });
      await load();
    } catch (e) { setError(e instanceof Error ? e.message : String(e)); }
  };

  const setStatus = async (orgId: string, status: "active" | "suspended") => {
    try {
      await call(`/${orgId}/status?status=${status}`, { method: "POST" });
      await load();
    } catch (e) { setError(e instanceof Error ? e.message : String(e)); }
  };

  const slugPreview = useMemo(
    () => form.slug.trim().toLowerCase().replace(/\s+/g, "-"),
    [form.slug],
  );

  if (loading && customers.length === 0) {
    return (
      <div className="bg-white border border-[--gray-200] rounded-2xl p-8 text-center text-[11px] text-[--gray-400]">
        <RefreshCw className="w-4 h-4 animate-spin inline mr-2" />Loading customers…
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <Card>
        <div className="flex items-start justify-between gap-3 flex-wrap">
          <div className="min-w-0">
            <SectionLabel icon={Building2}>Customer Dashboards</SectionLabel>
            <p className="text-[10px] text-[--gray-500] leading-relaxed mt-1.5">
              Each customer gets a scoped, read-only dashboard at <code className="text-[9px] font-mono">/portal</code>,
              showing only the agents you assign to them. They cannot reach the operator API,
              change any setting outside their own display, or see another customer's endpoints.
            </p>
          </div>
          <div className="flex items-center gap-2 flex-shrink-0">
            <button
              onClick={() => void load()}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-white border border-[--gray-200] text-[--gray-600] text-[11px] font-bold rounded-xl hover:border-purple-300 hover:text-purple-700 transition-colors"
            >
              <RefreshCw className={cn("w-3.5 h-3.5", loading && "animate-spin")} />Refresh
            </button>
            <button
              onClick={() => setCreating(v => !v)}
              className="flex items-center gap-1.5 px-4 py-2 bg-purple-600 hover:bg-purple-700 text-white text-[11px] font-bold rounded-xl transition-colors"
            >
              <Plus className="w-3.5 h-3.5" />New customer
            </button>
          </div>
        </div>

        {error && (
          <div className="flex items-start gap-2 px-3 py-2 bg-red-50 border border-red-200 rounded-xl">
            <XCircle className="w-3.5 h-3.5 text-red-600 flex-shrink-0 mt-0.5" />
            <span className="text-[10px] text-red-800">{error}</span>
          </div>
        )}

        {secret && <OneTimeSecretPanel secret={secret} onDone={() => setSecret(null)} />}

        {creating && (
          <div className="border border-[--gray-200] rounded-2xl p-4 space-y-3 bg-[--gray-50]">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div>
                <label className="block text-[11px] font-semibold text-[--gray-700] mb-1.5">Company name</label>
                <input className={inputCls} value={form.name} placeholder="Acme Corporation"
                  onChange={e => setForm(f => ({ ...f, name: e.target.value }))} />
              </div>
              <div>
                <label className="block text-[11px] font-semibold text-[--gray-700] mb-1.5">
                  Slug <span className="font-normal text-[9px] text-[--gray-400]">used in their portal URL</span>
                </label>
                <input className={inputCls} value={form.slug} placeholder="acme"
                  onChange={e => setForm(f => ({ ...f, slug: e.target.value }))} />
                {slugPreview && (
                  <div className="text-[9px] text-[--gray-400] mt-1 font-mono">stored as {slugPreview}</div>
                )}
              </div>
              <div>
                <label className="block text-[11px] font-semibold text-[--gray-700] mb-1.5">Contact email</label>
                <input className={inputCls} value={form.contact_email} placeholder="security@acme.com"
                  onChange={e => setForm(f => ({ ...f, contact_email: e.target.value }))} />
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-[11px] font-semibold text-[--gray-700] mb-1.5">Agent seats</label>
                  <input type="number" min={1} className={inputCls} value={form.max_agents}
                    onChange={e => setForm(f => ({ ...f, max_agents: Number(e.target.value) }))} />
                </div>
                <div>
                  <label className="block text-[11px] font-semibold text-[--gray-700] mb-1.5">Licence days</label>
                  <input type="number" min={0} className={inputCls} value={form.valid_days}
                    onChange={e => setForm(f => ({ ...f, valid_days: Number(e.target.value) }))} />
                </div>
              </div>
            </div>
            <div className="flex items-center justify-end gap-2">
              <button onClick={() => setCreating(false)}
                className="px-3 py-2 text-[11px] font-bold text-[--gray-500] hover:text-[--gray-700]">
                Cancel
              </button>
              <button
                disabled={busy || !form.name.trim() || slugPreview.length < 3}
                onClick={() => void createCustomer()}
                className="flex items-center gap-1.5 px-4 py-2 bg-purple-600 hover:bg-purple-700 disabled:bg-purple-300 text-white text-[11px] font-bold rounded-xl transition-colors"
              >
                <KeyRound className="w-3.5 h-3.5" />Create &amp; issue licence
              </button>
            </div>
          </div>
        )}
      </Card>

      {/* ── Customer table ──────────────────────────────────────────────── */}
      <Card>
        <SectionLabel icon={Building2}>Customers ({customers.length})</SectionLabel>
        {customers.length === 0 ? (
          <div className="text-[10px] text-[--gray-400]">
            No customer dashboards yet. Creating one issues a licence key and gives you a
            single-use setup link to send them.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-[12px]">
              <thead>
                <tr className="text-[9px] text-[--gray-400] uppercase tracking-wide border-b border-[--gray-200]">
                  <th className="text-left py-2 pr-3 font-semibold">Customer</th>
                  <th className="text-left py-2 px-3 font-semibold">Status</th>
                  <th className="text-right py-2 px-3 font-semibold">Agents</th>
                  <th className="text-right py-2 px-3 font-semibold">Users</th>
                  <th className="text-left py-2 px-3 font-semibold">Licence</th>
                  <th className="text-right py-2 pl-3 font-semibold">Access</th>
                </tr>
              </thead>
              <tbody>
                {customers.map(c => {
                  const seats = seatState(c);
                  const lic = licenseState(c);
                  return (
                    <tr key={c.org_id}
                      className={cn(
                        "border-b border-[--gray-100] last:border-0 cursor-pointer hover:bg-[--gray-50]",
                        selected === c.org_id && "bg-purple-50/40",
                      )}
                      onClick={() => setSelected(selected === c.org_id ? null : c.org_id)}>
                      <td className="py-2.5 pr-3">
                        <div className="font-semibold text-[--gray-800]">{c.name}</div>
                        <div className="text-[9px] font-mono text-[--gray-400]">{c.slug}</div>
                      </td>
                      <td className="py-2.5 px-3"><Pill tone={statusTone(c.status)}>{c.status}</Pill></td>
                      <td className="py-2.5 px-3 text-right tabular-nums">
                        <span className={cn(seats.atCap && "text-red-600 font-bold")}>{seats.label}</span>
                      </td>
                      <td className="py-2.5 px-3 text-right tabular-nums text-[--gray-500]">{c.user_count}</td>
                      <td className="py-2.5 px-3"><Pill tone={lic.tone}>{lic.label}</Pill></td>
                      <td className="py-2.5 pl-3 text-right">
                        <button
                          disabled={busy}
                          onClick={e => {
                            e.stopPropagation();
                            void setStatus(c.org_id, c.status === "active" ? "suspended" : "active");
                          }}
                          className={cn(
                            "inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-[10px] font-bold border transition-all",
                            c.status === "active"
                              ? "bg-white text-red-600 border-red-200 hover:bg-red-50"
                              : "bg-white text-emerald-600 border-emerald-200 hover:bg-emerald-50",
                          )}>
                          {c.status === "active"
                            ? <><ShieldOff className="w-3 h-3" />Disable</>
                            : <><CheckCircle2 className="w-3 h-3" />Enable</>}
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
            <p className="text-[9px] text-[--gray-400] mt-2 leading-relaxed">
              Disabling ends live sessions on the customer's next request — not at their next
              login. Select a row to assign agents and manage users.
            </p>
          </div>
        )}
      </Card>

      {selected && (
        <CustomerDetail
          orgId={selected}
          onSecret={setSecret}
          onChanged={load}
          onError={setError}
        />
      )}
    </div>
  );
}

// ── Detail: agents, users, audit ────────────────────────────────────────────

function CustomerDetail({
  orgId, onSecret, onChanged, onError,
}: {
  orgId: string;
  onSecret: (s: OneTimeSecret) => void;
  onChanged: () => void;
  onError: (msg: string) => void;
}) {
  const [assigned,   setAssigned]   = useState<string[]>([]);
  const [unassigned, setUnassigned] = useState<string[]>([]);
  const [users,      setUsers]      = useState<PortalUser[]>([]);
  const [audit,      setAudit]      = useState<AuditEntry[]>([]);
  const [picked,     setPicked]     = useState<Set<string>>(new Set());
  const [email,      setEmail]      = useState("");
  const [busy,       setBusy]       = useState(false);

  const load = useCallback(async () => {
    try {
      const [a, u, us, au] = await Promise.all([
        fetch(`${API}/${orgId}/agents`).then(r => r.json()),
        fetch(`${API}/-/unassigned-agents`).then(r => r.json()),
        fetch(`${API}/${orgId}/users`).then(r => r.json()),
        fetch(`${API}/${orgId}/audit?limit=25`).then(r => r.json()),
      ]);
      setAssigned(a.agent_ids ?? []);
      setUnassigned(u.agent_ids ?? []);
      setUsers(us.users ?? []);
      setAudit(au.entries ?? []);
    } catch { /* the panel above surfaces load failures */ }
  }, [orgId]);

  useEffect(() => { void load(); setPicked(new Set()); }, [load]);

  const post = async (path: string, init?: RequestInit) => {
    setBusy(true);
    try {
      const r = await fetch(`${API}${path}`, {
        method: "POST",
        ...init,
        headers: { "Content-Type": "application/json", ...(init?.headers ?? {}) },
      });
      const body = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(typeof body.detail === "string" ? body.detail : `HTTP ${r.status}`);
      return body;
    } finally { setBusy(false); }
  };

  const assign = async () => {
    try {
      await post(`/${orgId}/agents`, { body: JSON.stringify({ agent_ids: [...picked] }) });
      setPicked(new Set());
      await load(); onChanged();
    } catch (e) { onError(e instanceof Error ? e.message : String(e)); }
  };

  const invite = async () => {
    try {
      const body = await post(`/${orgId}/users`, { body: JSON.stringify({ email }) });
      onSecret({
        kind: "invite",
        label: `Setup link for ${email}`,
        value: `${window.location.origin}${body.invite_path}`,
        notice: body.notice,
      });
      setEmail("");
      await load(); onChanged();
    } catch (e) { onError(e instanceof Error ? e.message : String(e)); }
  };

  return (
    <>
      <Card>
        <SectionLabel icon={Monitor}>Assigned Agents</SectionLabel>
        <p className="text-[10px] text-[--gray-500] leading-relaxed">
          This decides what the customer can see. An agent belongs to one customer at a time,
          and assigning more than the licence allows is refused.
        </p>

        <div className="flex gap-1.5 flex-wrap">
          {assigned.length === 0
            ? <span className="text-[10px] text-[--gray-400]">No agents assigned — this customer's dashboard will be empty.</span>
            : assigned.map(id => (
                <span key={id} className="inline-flex items-center gap-1.5 text-[10px] font-mono bg-purple-50 border border-purple-200 text-purple-800 rounded-lg px-2 py-1">
                  {id}
                  <button
                    disabled={busy}
                    onClick={async () => {
                      try {
                        await fetch(`${API}/${orgId}/agents/${encodeURIComponent(id)}`, { method: "DELETE" });
                        await load(); onChanged();
                      } catch { /* surfaced above */ }
                    }}
                    className="text-purple-400 hover:text-red-600"><X className="w-3 h-3" /></button>
                </span>
              ))}
        </div>

        {unassigned.length > 0 && (
          <div className="border-t border-[--gray-100] pt-3 space-y-2">
            <div className="text-[9px] font-bold text-[--gray-500] uppercase tracking-wide">
              Unassigned agents ({unassigned.length})
            </div>
            <div className="flex gap-1.5 flex-wrap max-h-32 overflow-y-auto">
              {unassigned.map(id => {
                const on = picked.has(id);
                return (
                  <button key={id}
                    onClick={() => setPicked(p => {
                      const next = new Set(p);
                      if (on) { next.delete(id); } else { next.add(id); }
                      return next;
                    })}
                    className={cn(
                      "text-[10px] font-mono rounded-lg px-2 py-1 border transition-all",
                      on ? "bg-purple-600 text-white border-purple-600"
                         : "bg-white text-[--gray-600] border-[--gray-200] hover:border-purple-300",
                    )}>{id}</button>
                );
              })}
            </div>
            <button
              disabled={busy || picked.size === 0}
              onClick={() => void assign()}
              className="flex items-center gap-1.5 px-4 py-2 bg-purple-600 hover:bg-purple-700 disabled:bg-purple-300 text-white text-[11px] font-bold rounded-xl transition-colors">
              <Plus className="w-3.5 h-3.5" />Assign {picked.size || ""} agent{picked.size === 1 ? "" : "s"}
            </button>
          </div>
        )}
      </Card>

      <Card>
        <SectionLabel icon={UserPlus}>Portal Users</SectionLabel>
        <p className="text-[10px] text-[--gray-500] leading-relaxed">
          You never set a customer's password. Inviting them produces a single-use setup link,
          shown once, which they use to choose their own.
        </p>

        {users.length > 0 && (
          <div className="space-y-1">
            {users.map(u => (
              <div key={u.user_id} className="flex items-center justify-between gap-2 bg-white border border-[--gray-200] rounded-lg px-2.5 py-1.5 flex-wrap">
                <div className="min-w-0">
                  <div className="text-[11px] font-semibold text-[--gray-800]">{u.email}</div>
                  <div className="text-[9px] text-[--gray-400]">
                    {u.last_login_at ? `last login ${new Date(u.last_login_at * 1000).toLocaleString()}` : "never signed in"}
                  </div>
                </div>
                <div className="flex items-center gap-1.5 flex-shrink-0">
                  <Pill tone={u.status === "active" ? "emerald" : "amber"}>{u.status}</Pill>
                  <button
                    disabled={busy}
                    onClick={async () => {
                      try {
                        const body = await post(`/${orgId}/users/${u.user_id}/invite`);
                        onSecret({
                          kind: "invite",
                          label: `New setup link for ${u.email}`,
                          value: `${window.location.origin}${body.invite_path}`,
                          notice: body.notice,
                        });
                      } catch (e) { onError(e instanceof Error ? e.message : String(e)); }
                    }}
                    className="text-[10px] font-bold text-purple-700 hover:text-purple-900 underline underline-offset-2">
                    Resend link
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}

        <div className="flex items-center gap-2">
          <input
            className={inputCls}
            placeholder="security@acme.com"
            value={email}
            onChange={e => setEmail(e.target.value)}
            onKeyDown={e => { if (e.key === "Enter" && email.includes("@")) void invite(); }}
          />
          <button
            disabled={busy || !email.includes("@")}
            onClick={() => void invite()}
            className="flex items-center gap-1.5 px-4 py-2 bg-purple-600 hover:bg-purple-700 disabled:bg-purple-300 text-white text-[11px] font-bold rounded-xl transition-colors flex-shrink-0">
            <UserPlus className="w-3.5 h-3.5" />Invite
          </button>
        </div>
      </Card>

      <Card>
        <SectionLabel icon={ScrollText}>Audit Trail</SectionLabel>
        {audit.length === 0 ? (
          <div className="text-[10px] text-[--gray-400]">Nothing recorded yet.</div>
        ) : (
          <div className="space-y-1">
            {audit.map(e => (
              <div key={e.id} className="flex items-center justify-between gap-2 text-[10px] border-b border-[--gray-100] last:border-0 py-1.5 flex-wrap">
                <code className="font-mono font-semibold text-[--gray-700]">{e.action}</code>
                <div className="flex items-center gap-2 text-[--gray-400] flex-shrink-0">
                  <span>{e.actor || "system"}</span>
                  <span className="tabular-nums">{new Date(e.created_at * 1000).toLocaleString()}</span>
                </div>
              </div>
            ))}
          </div>
        )}
      </Card>
    </>
  );
}
