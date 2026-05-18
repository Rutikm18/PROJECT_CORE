/**
 * Settings — Organisation profile, license validity, role access matrix,
 * and platform configuration.
 *
 * GET  /api/v1/settings        — load all settings + license + roles
 * PUT  /api/v1/settings        — persist changes
 * POST /api/v1/settings/reset  — factory reset
 */
import { useState, useEffect, useCallback } from "react";
import {
  Building2, MapPin, Mail, Calendar, ShieldCheck, Settings2,
  Bell, RefreshCw, Save, AlertTriangle, CheckCircle2, Info,
  Clock, Users, Lock, Unlock, Globe, RotateCcw, ChevronRight,
} from "lucide-react";
import { cn } from "../../lib/utils";

const API = "/api/v1/settings";

// ── Types ─────────────────────────────────────────────────────────────────────

interface OrgSettings {
  org_name:            string;
  org_description:     string;
  org_location:        string;
  contact_email:       string;
  org_industry:        string;
  org_size:            string;
  issue_date:          string;
  valid_until:         string;
  license_key:         string;
  role_admin_label:    string;
  role_analyst_label:  string;
  role_viewer_label:   string;
  platform_refresh_secs: string;
  platform_timezone:   string;
  platform_max_page:   string;
  notif_critical_email:  string;
  notif_sla_breach:      string;
  notif_digest_daily:    string;
  notif_email_recipient: string;
}

interface LicenseStatus {
  status:         "active" | "expiring" | "expired" | "unconfigured" | "invalid_date";
  days_remaining: number | null;
  issue_date:     string;
  valid_until:    string;
}

interface RoleEntry {
  label:       string;
  description: string;
  permissions: string[];
  color:       string;
}

type TabId = "org" | "license" | "roles" | "platform";

const EMPTY: OrgSettings = {
  org_name: "", org_description: "", org_location: "", contact_email: "",
  org_industry: "", org_size: "", issue_date: "", valid_until: "",
  license_key: "", role_admin_label: "Administrator",
  role_analyst_label: "SOC Analyst", role_viewer_label: "Read-Only Viewer",
  platform_refresh_secs: "30", platform_timezone: "UTC",
  platform_max_page: "50", notif_critical_email: "false",
  notif_sla_breach: "false", notif_digest_daily: "false",
  notif_email_recipient: "",
};

// ── Helpers ───────────────────────────────────────────────────────────────────

function licenseColor(status: LicenseStatus["status"]) {
  if (status === "active")        return { ring: "#059669", text: "#065F46", bg: "#f0fdf9", border: "#6ee7b7", label: "Active" };
  if (status === "expiring")      return { ring: "#d97706", text: "#92400e", bg: "#fffbf0", border: "#fcd34d", label: "Expiring Soon" };
  if (status === "expired")       return { ring: "#dc2626", text: "#991b1b", bg: "#fef5f5", border: "#fca5a5", label: "Expired" };
  return { ring: "#9ca3af", text: "#6b7280", bg: "#f9fafb", border: "#e5e7eb", label: "Not Configured" };
}

function LicenseRing({ days, status }: { days: number | null; status: LicenseStatus["status"] }) {
  const total  = 365;
  const filled = Math.max(0, Math.min(total, days ?? 0));
  const pct    = status === "unconfigured" ? 0 : (filled / total);
  const r      = 44;
  const circ   = 2 * Math.PI * r;
  const c      = licenseColor(status);
  return (
    <svg width={104} height={104} viewBox="0 0 104 104">
      <circle cx={52} cy={52} r={r} fill="none" stroke="#f3f4f6" strokeWidth={8} />
      <circle cx={52} cy={52} r={r} fill="none"
        stroke={c.ring} strokeWidth={8}
        strokeDasharray={`${pct * circ} ${circ}`}
        strokeLinecap="round"
        transform="rotate(-90 52 52)"
        style={{ transition: "stroke-dasharray 1s cubic-bezier(0.22,1,0.36,1)" }}
      />
      <text x="52" y="47" textAnchor="middle" dominantBaseline="middle"
        fill={c.ring} fontSize="18" fontWeight="800">
        {days !== null && days >= 0 ? days : "—"}
      </text>
      <text x="52" y="63" textAnchor="middle" dominantBaseline="middle"
        fill={c.ring} fontSize="8" fontWeight="600">
        {days === null ? "days" : days === 1 ? "day left" : "days left"}
      </text>
    </svg>
  );
}

function Field({
  label, required, hint, children,
}: {
  label: string; required?: boolean; hint?: string; children: React.ReactNode;
}) {
  return (
    <div>
      <label className="block text-[11px] font-semibold text-[--gray-700] mb-1.5">
        {label}
        {required && <span className="ml-1 text-[--red-500]">*</span>}
        {hint && <span className="ml-1.5 text-[9px] font-normal text-[--gray-400]">{hint}</span>}
      </label>
      {children}
    </div>
  );
}

const inputCls = "w-full px-3 py-2 text-[12px] border border-[--gray-200] rounded-xl bg-white focus:outline-none focus:ring-2 focus:ring-purple-200 focus:border-purple-300 transition-all placeholder:text-[--gray-300]";
const selectCls = inputCls + " cursor-pointer";

function Toggle({ value, onChange, label }: { value: boolean; onChange: (v: boolean) => void; label: string }) {
  return (
    <label className="flex items-center gap-3 cursor-pointer group">
      <button
        type="button"
        onClick={() => onChange(!value)}
        className={cn(
          "relative w-9 h-5 rounded-full transition-colors duration-200 flex-shrink-0",
          value ? "bg-purple-600" : "bg-[--gray-200]"
        )}
      >
        <span className={cn(
          "absolute top-0.5 left-0.5 w-4 h-4 bg-white rounded-full shadow-sm transition-transform duration-200",
          value ? "translate-x-4" : "translate-x-0"
        )} />
      </button>
      <span className="text-[12px] text-[--gray-700] font-medium group-hover:text-[--gray-900]">{label}</span>
    </label>
  );
}

// ── Permission chip ───────────────────────────────────────────────────────────

const PERM_LABELS: Record<string, string> = {
  view_all_findings: "View all findings",
  update_finding:    "Update findings",
  bulk_action:       "Bulk actions",
  add_comment:       "Add comments",
  manage_settings:   "Manage settings",
  manage_keys:       "Manage API keys",
  view_raw_data:     "View raw telemetry",
  export_data:       "Export data",
  manage_users:      "Manage users",
};

// ── Main component ────────────────────────────────────────────────────────────

export default function Settings() {
  const [tab,     setTab]     = useState<TabId>("org");
  const [form,    setForm]    = useState<OrgSettings>(EMPTY);
  const [license, setLicense] = useState<LicenseStatus | null>(null);
  const [roles,   setRoles]   = useState<Record<string, RoleEntry>>({});
  const [loading, setLoading] = useState(true);
  const [saving,  setSaving]  = useState(false);
  const [saved,   setSaved]   = useState(false);
  const [error,   setError]   = useState<string | null>(null);
  const [dirty,   setDirty]   = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const r = await fetch(API);
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const d = await r.json();
      setForm({ ...EMPTY, ...d.settings });
      setLicense(d.license ?? null);
      setRoles(d.roles ?? {});
      setError(null);
    } catch (e) { setError(String(e)); }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { load(); }, [load]);

  const set = (k: keyof OrgSettings, v: string) => {
    setForm(f => ({ ...f, [k]: v }));
    setDirty(true);
    setSaved(false);
  };

  const save = async () => {
    setSaving(true);
    setError(null);
    try {
      const r = await fetch(API, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(form),
      });
      if (!r.ok) {
        const d = await r.json();
        throw new Error(d.detail ?? `HTTP ${r.status}`);
      }
      const d = await r.json();
      setForm({ ...EMPTY, ...d.settings });
      setLicense(d.license ?? null);
      setDirty(false);
      setSaved(true);
      setTimeout(() => setSaved(false), 3000);
    } catch (e) { setError(String(e)); }
    finally { setSaving(false); }
  };

  const licC = license ? licenseColor(license.status) : licenseColor("unconfigured");

  const TABS: { id: TabId; label: string; icon: React.ElementType }[] = [
    { id: "org",      label: "Organisation",   icon: Building2  },
    { id: "license",  label: "License",        icon: ShieldCheck },
    { id: "roles",    label: "Role Access",    icon: Users      },
    { id: "platform", label: "Platform",       icon: Settings2  },
  ];

  return (
    <div className="space-y-4 pb-8">

      {/* ── Header ─────────────────────────────────────────────────────────── */}
      <div className="bg-white border border-[--gray-200] rounded-2xl shadow-card overflow-hidden">
        <div className="h-[3px]" style={{ background: "linear-gradient(90deg,#7C3AED,#8B5CF6,#A78BFA)" }} />
        <div className="p-5 flex items-start justify-between gap-4">
          <div className="flex items-start gap-3">
            <div className="w-10 h-10 rounded-xl flex items-center justify-center flex-shrink-0"
              style={{ background: "linear-gradient(135deg,rgba(124,58,237,0.1),rgba(139,92,246,0.15))", border: "1px solid rgba(124,58,237,0.2)" }}>
              <Settings2 className="w-5 h-5" style={{ color: "#7C3AED" }} />
            </div>
            <div>
              <h1 className="text-base font-bold text-[--gray-900]">Settings</h1>
              <p className="text-[11px] text-[--gray-500] mt-0.5">
                Organisation profile · License validity · Role access · Platform configuration
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            {dirty && !saved && (
              <span className="text-[10px] text-amber-600 font-semibold flex items-center gap-1">
                <div className="w-1.5 h-1.5 rounded-full bg-amber-500" />Unsaved changes
              </span>
            )}
            {saved && (
              <span className="text-[10px] text-green-600 font-semibold flex items-center gap-1 al-bounce-in">
                <CheckCircle2 className="w-3.5 h-3.5" />Saved
              </span>
            )}
            <button onClick={load} className="p-2 hover:bg-[--gray-50] rounded-lg transition-colors">
              <RefreshCw className={cn("w-3.5 h-3.5 text-[--gray-400]", loading && "animate-spin")} />
            </button>
            <button
              onClick={save}
              disabled={saving || !dirty}
              className="flex items-center gap-1.5 px-4 py-2 rounded-xl text-[11px] font-bold text-white transition-all disabled:opacity-50"
              style={{ background: "linear-gradient(135deg,#7C3AED,#6D28D9)", boxShadow: dirty ? "0 2px 8px rgba(124,58,237,0.35)" : undefined }}
            >
              <Save className="w-3.5 h-3.5" />
              {saving ? "Saving…" : "Save Changes"}
            </button>
          </div>
        </div>
      </div>

      {error && (
        <div className="flex items-center gap-2 px-4 py-3 bg-red-50 border border-red-200 rounded-2xl text-[11px] text-red-700">
          <AlertTriangle className="w-3.5 h-3.5 flex-shrink-0" />{error}
        </div>
      )}

      {/* ── Tab bar ─────────────────────────────────────────────────────────── */}
      <div className="flex items-center gap-1 bg-white border border-[--gray-200] rounded-2xl shadow-card p-1.5">
        {TABS.map(t => {
          const Icon = t.icon;
          return (
            <button key={t.id} onClick={() => setTab(t.id)}
              className={cn(
                "flex items-center gap-1.5 px-4 py-2 rounded-xl text-[11px] font-semibold transition-all",
                tab === t.id
                  ? "text-white shadow-sm"
                  : "text-[--gray-500] hover:bg-[--gray-50] hover:text-[--gray-700]"
              )}
              style={tab === t.id ? { background: "linear-gradient(135deg,#7C3AED,#6D28D9)" } : {}}
            >
              <Icon className="w-3.5 h-3.5" />{t.label}
            </button>
          );
        })}
      </div>

      {/* ══════════════════════════════════════════════════════════════════════
          TAB: Organisation
      ══════════════════════════════════════════════════════════════════════ */}
      {tab === "org" && (
        <div className="grid grid-cols-[1fr_320px] gap-4">
          <div className="bg-white border border-[--gray-200] rounded-2xl shadow-card p-5 space-y-4">
            <SectionLabel icon={Building2}>Organisation Details</SectionLabel>

            <Field label="Organisation Name" required>
              <input
                type="text"
                value={form.org_name}
                onChange={e => set("org_name", e.target.value)}
                placeholder="e.g. Acme Security Inc."
                className={inputCls}
              />
            </Field>

            <Field label="Description" hint="(optional)">
              <textarea
                rows={3}
                value={form.org_description}
                onChange={e => set("org_description", e.target.value)}
                placeholder="Brief description of your organisation or team…"
                className={inputCls + " resize-none"}
              />
            </Field>

            <div className="grid grid-cols-2 gap-4">
              <Field label="Location" hint="(optional)">
                <div className="relative">
                  <MapPin className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-[--gray-300] pointer-events-none" />
                  <input
                    type="text"
                    value={form.org_location}
                    onChange={e => set("org_location", e.target.value)}
                    placeholder="City, Country"
                    className={inputCls + " pl-8"}
                  />
                </div>
              </Field>

              <Field label="Contact Email" hint="(optional)">
                <div className="relative">
                  <Mail className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-[--gray-300] pointer-events-none" />
                  <input
                    type="email"
                    value={form.contact_email}
                    onChange={e => set("contact_email", e.target.value)}
                    placeholder="security@company.com"
                    className={inputCls + " pl-8"}
                  />
                </div>
              </Field>
            </div>

            <div className="grid grid-cols-2 gap-4">
              <Field label="Industry" hint="(optional)">
                <select value={form.org_industry} onChange={e => set("org_industry", e.target.value)} className={selectCls}>
                  <option value="">Select industry…</option>
                  {["Financial Services","Healthcare","Technology","Government","Defense","Retail","Manufacturing","Energy","Telecommunications","Education","Other"].map(i => (
                    <option key={i} value={i}>{i}</option>
                  ))}
                </select>
              </Field>

              <Field label="Organisation Size" hint="(optional)">
                <select value={form.org_size} onChange={e => set("org_size", e.target.value)} className={selectCls}>
                  <option value="">Select size…</option>
                  {["1–10","11–50","51–200","201–1000","1001–5000","5000+"].map(s => (
                    <option key={s} value={s}>{s} employees</option>
                  ))}
                </select>
              </Field>
            </div>
          </div>

          {/* Side card — quick summary */}
          <div className="space-y-3">
            <div className="bg-white border border-[--gray-200] rounded-2xl shadow-card p-4">
              <SectionLabel icon={Info}>Profile Summary</SectionLabel>
              <div className="mt-3 space-y-2.5">
                {[
                  { label: "Name",      value: form.org_name      || "—", icon: Building2 },
                  { label: "Location",  value: form.org_location  || "—", icon: MapPin    },
                  { label: "Email",     value: form.contact_email || "—", icon: Mail      },
                  { label: "Industry",  value: form.org_industry  || "—", icon: Globe     },
                  { label: "Size",      value: form.org_size      || "—", icon: Users     },
                ].map(r => {
                  const Icon = r.icon;
                  return (
                    <div key={r.label} className="flex items-center gap-2.5 py-1.5 border-b border-[--gray-50] last:border-0">
                      <Icon className="w-3.5 h-3.5 flex-shrink-0 text-[--gray-300]" />
                      <span className="text-[10px] text-[--gray-400] w-16 flex-shrink-0">{r.label}</span>
                      <span className="text-[11px] text-[--gray-700] font-medium truncate">{r.value}</span>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* License mini card */}
            {license && (
              <div className="rounded-2xl border p-4" style={{ background: licC.bg, borderColor: licC.border }}>
                <div className="flex items-center gap-2 mb-1">
                  <ShieldCheck className="w-3.5 h-3.5" style={{ color: licC.ring }} />
                  <span className="text-[10px] font-bold uppercase tracking-wide" style={{ color: licC.text }}>
                    License {licC.label}
                  </span>
                </div>
                <div className="text-[11px]" style={{ color: licC.text }}>
                  {license.days_remaining !== null
                    ? `${license.days_remaining} days remaining`
                    : "No expiry date set"}
                </div>
                <button onClick={() => setTab("license")} className="mt-2 text-[10px] font-semibold flex items-center gap-1" style={{ color: licC.ring }}>
                  View details <ChevronRight className="w-3 h-3" />
                </button>
              </div>
            )}
          </div>
        </div>
      )}

      {/* ══════════════════════════════════════════════════════════════════════
          TAB: License
      ══════════════════════════════════════════════════════════════════════ */}
      {tab === "license" && (
        <div className="grid grid-cols-[1fr_280px] gap-4">
          <div className="bg-white border border-[--gray-200] rounded-2xl shadow-card p-5 space-y-5">
            <SectionLabel icon={ShieldCheck}>License & Validity</SectionLabel>

            <div className="grid grid-cols-2 gap-4">
              <Field label="Issue Date" required>
                <div className="relative">
                  <Calendar className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-[--gray-300] pointer-events-none" />
                  <input
                    type="date"
                    value={form.issue_date}
                    onChange={e => set("issue_date", e.target.value)}
                    className={inputCls + " pl-8"}
                  />
                </div>
              </Field>

              <Field label="Valid Until" required hint="license expiry">
                <div className="relative">
                  <Clock className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-[--gray-300] pointer-events-none" />
                  <input
                    type="date"
                    value={form.valid_until}
                    onChange={e => set("valid_until", e.target.value)}
                    className={inputCls + " pl-8"}
                  />
                </div>
              </Field>
            </div>

            <Field label="License Key" hint="(optional — for reference only)">
              <input
                type="text"
                value={form.license_key}
                onChange={e => set("license_key", e.target.value)}
                placeholder="AL-XXXX-XXXX-XXXX-XXXX"
                className={inputCls + " font-mono tracking-wider"}
              />
            </Field>

            {/* Status banner */}
            {license && (
              <div
                className="rounded-xl border p-4 flex items-center gap-4"
                style={{ background: licC.bg, borderColor: licC.border }}
              >
                <div className="flex-shrink-0">
                  {license.status === "active"   && <CheckCircle2 className="w-5 h-5" style={{ color: licC.ring }} />}
                  {license.status === "expiring" && <AlertTriangle className="w-5 h-5" style={{ color: licC.ring }} />}
                  {license.status === "expired"  && <Lock className="w-5 h-5" style={{ color: licC.ring }} />}
                  {(license.status === "unconfigured" || license.status === "invalid_date") && <Info className="w-5 h-5" style={{ color: licC.ring }} />}
                </div>
                <div>
                  <div className="text-[12px] font-bold" style={{ color: licC.text }}>{licC.label}</div>
                  <div className="text-[10px] mt-0.5" style={{ color: licC.text, opacity: 0.8 }}>
                    {license.days_remaining !== null && license.days_remaining >= 0
                      ? `${license.days_remaining} day${license.days_remaining === 1 ? "" : "s"} remaining · expires ${form.valid_until}`
                      : license.days_remaining !== null && license.days_remaining < 0
                      ? `Expired ${Math.abs(license.days_remaining)} days ago`
                      : "Set issue date and valid until date to activate"}
                  </div>
                </div>
              </div>
            )}

            {/* Timeline bar */}
            {form.issue_date && form.valid_until && license?.days_remaining !== null && (
              <div>
                <div className="flex items-center justify-between text-[10px] text-[--gray-500] mb-1.5">
                  <span>Issued: {form.issue_date}</span>
                  <span>Expires: {form.valid_until}</span>
                </div>
                <div className="h-2 bg-[--gray-100] rounded-full overflow-hidden">
                  <div
                    className="h-full rounded-full transition-all duration-700"
                    style={{
                      width: `${Math.max(0, Math.min(100, license?.status === "expired" ? 100 : Math.max(5, 100 - ((license?.days_remaining ?? 365) / 365) * 100)))}%`,
                      background: licC.ring,
                    }}
                  />
                </div>
                <div className="flex items-center justify-between text-[9px] text-[--gray-400] mt-1">
                  <span>Start</span><span>End</span>
                </div>
              </div>
            )}
          </div>

          {/* Ring card */}
          <div className="bg-white border border-[--gray-200] rounded-2xl shadow-card p-5 flex flex-col items-center gap-3">
            <SectionLabel icon={Clock}>Days Remaining</SectionLabel>
            <div className="mt-2">
              <LicenseRing days={license?.days_remaining ?? null} status={license?.status ?? "unconfigured"} />
            </div>
            <div className="text-center">
              <div className="text-[12px] font-bold" style={{ color: licC.ring }}>{licC.label}</div>
              {license?.status === "expiring" && (
                <p className="text-[10px] text-amber-700 mt-1 leading-relaxed">
                  Renew before {form.valid_until} to avoid service interruption.
                </p>
              )}
              {license?.status === "expired" && (
                <p className="text-[10px] text-red-700 mt-1 leading-relaxed">
                  License has expired. Contact your administrator.
                </p>
              )}
            </div>
          </div>
        </div>
      )}

      {/* ══════════════════════════════════════════════════════════════════════
          TAB: Role Access
      ══════════════════════════════════════════════════════════════════════ */}
      {tab === "roles" && (
        <div className="space-y-4">
          <div className="bg-white border border-[--gray-200] rounded-2xl shadow-card p-5">
            <SectionLabel icon={Users}>Role Access Matrix</SectionLabel>
            <p className="text-[11px] text-[--gray-500] mt-1.5 mb-4 leading-relaxed">
              Roles control what each analyst can see and do within Attacklens.
              Role assignment happens at login via JWT claims. The matrix below shows
              the built-in permission set per role — these cannot be modified from the UI.
            </p>

            <div className="grid grid-cols-3 gap-4">
              {Object.entries(roles).map(([roleKey, role]) => {
                const colorMap: Record<string, { bg: string; border: string; accent: string; chip: string }> = {
                  admin:   { bg: "#fef5f5", border: "#fca5a5", accent: "#dc2626", chip: "bg-red-100 text-red-700" },
                  analyst: { bg: "#eff6ff", border: "#93c5fd", accent: "#2563eb", chip: "bg-blue-100 text-blue-700" },
                  viewer:  { bg: "#f9fafb", border: "#d1d5db", accent: "#6b7280", chip: "bg-gray-100 text-gray-600" },
                };
                const c = colorMap[roleKey] ?? colorMap.viewer;
                return (
                  <div key={roleKey} className="rounded-2xl border p-4" style={{ background: c.bg, borderColor: c.border }}>
                    <div className="flex items-center gap-2 mb-1">
                      {roleKey === "admin"   && <Lock className="w-4 h-4" style={{ color: c.accent }} />}
                      {roleKey === "analyst" && <ShieldCheck className="w-4 h-4" style={{ color: c.accent }} />}
                      {roleKey === "viewer"  && <Unlock className="w-4 h-4" style={{ color: c.accent }} />}
                      <span className="text-[13px] font-bold" style={{ color: c.accent }}>{role.label}</span>
                    </div>
                    <p className="text-[10px] text-[--gray-500] leading-relaxed mb-3">{role.description}</p>
                    <div className="space-y-1.5">
                      {Object.entries(PERM_LABELS).map(([perm, permLabel]) => {
                        const has = role.permissions.includes(perm);
                        return (
                          <div key={perm} className="flex items-center gap-2">
                            <div className={cn("w-3.5 h-3.5 rounded-full flex items-center justify-center flex-shrink-0",
                              has ? "bg-green-100" : "bg-[--gray-100]")}>
                              {has
                                ? <CheckCircle2 className="w-2.5 h-2.5 text-green-600" />
                                : <div className="w-1.5 h-1.5 rounded-full bg-[--gray-300]" />
                              }
                            </div>
                            <span className={cn("text-[10px]", has ? "text-[--gray-700] font-medium" : "text-[--gray-400]")}>
                              {permLabel}
                            </span>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Custom role labels */}
          <div className="bg-white border border-[--gray-200] rounded-2xl shadow-card p-5">
            <SectionLabel icon={Settings2}>Custom Role Labels</SectionLabel>
            <p className="text-[11px] text-[--gray-500] mt-1 mb-4">Customise the display name for each role shown in the top header.</p>
            <div className="grid grid-cols-3 gap-4">
              {([
                ["role_admin_label",   "Administrator label"],
                ["role_analyst_label", "Analyst label"],
                ["role_viewer_label",  "Viewer label"],
              ] as [keyof OrgSettings, string][]).map(([key, label]) => (
                <Field key={key} label={label}>
                  <input
                    type="text"
                    value={form[key]}
                    onChange={e => set(key, e.target.value)}
                    className={inputCls}
                  />
                </Field>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* ══════════════════════════════════════════════════════════════════════
          TAB: Platform
      ══════════════════════════════════════════════════════════════════════ */}
      {tab === "platform" && (
        <div className="grid grid-cols-2 gap-4">

          {/* Platform config */}
          <div className="bg-white border border-[--gray-200] rounded-2xl shadow-card p-5 space-y-4">
            <SectionLabel icon={Settings2}>Platform Configuration</SectionLabel>

            <Field label="Auto-refresh Interval">
              <select value={form.platform_refresh_secs} onChange={e => set("platform_refresh_secs", e.target.value)} className={selectCls}>
                {[["15","Every 15 seconds"],["30","Every 30 seconds (recommended)"],["60","Every 60 seconds"],["120","Every 2 minutes"],["300","Every 5 minutes"]].map(([v,l]) => (
                  <option key={v} value={v}>{l}</option>
                ))}
              </select>
            </Field>

            <Field label="Timezone">
              <select value={form.platform_timezone} onChange={e => set("platform_timezone", e.target.value)} className={selectCls}>
                {["UTC","America/New_York","America/Chicago","America/Los_Angeles","America/Toronto",
                  "Europe/London","Europe/Paris","Europe/Berlin","Asia/Dubai","Asia/Kolkata",
                  "Asia/Singapore","Asia/Tokyo","Australia/Sydney"].map(tz => (
                  <option key={tz} value={tz}>{tz}</option>
                ))}
              </select>
            </Field>

            <Field label="Findings per page">
              <select value={form.platform_max_page} onChange={e => set("platform_max_page", e.target.value)} className={selectCls}>
                {[["25","25 per page"],["50","50 per page (default)"],["100","100 per page"],["200","200 per page"]].map(([v,l]) => (
                  <option key={v} value={v}>{l}</option>
                ))}
              </select>
            </Field>
          </div>

          {/* Notifications */}
          <div className="bg-white border border-[--gray-200] rounded-2xl shadow-card p-5 space-y-4">
            <SectionLabel icon={Bell}>Alert & Notification Settings</SectionLabel>

            <div className="space-y-3">
              <Toggle
                value={form.notif_critical_email === "true"}
                onChange={v => set("notif_critical_email", String(v))}
                label="Email alert on critical findings"
              />
              <Toggle
                value={form.notif_sla_breach === "true"}
                onChange={v => set("notif_sla_breach", String(v))}
                label="Email alert on SLA breach"
              />
              <Toggle
                value={form.notif_digest_daily === "true"}
                onChange={v => set("notif_digest_daily", String(v))}
                label="Daily digest email summary"
              />
            </div>

            {(form.notif_critical_email === "true" || form.notif_sla_breach === "true" || form.notif_digest_daily === "true") && (
              <Field label="Recipient Email" required hint="for enabled notifications">
                <div className="relative">
                  <Mail className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-[--gray-300] pointer-events-none" />
                  <input
                    type="email"
                    value={form.notif_email_recipient}
                    onChange={e => set("notif_email_recipient", e.target.value)}
                    placeholder="soc-team@company.com"
                    className={inputCls + " pl-8"}
                  />
                </div>
              </Field>
            )}

            <div className="rounded-xl p-3 border border-[--gray-100] bg-[--gray-25] text-[10px] text-[--gray-500] leading-relaxed">
              <Info className="w-3 h-3 inline mr-1.5 text-[--gray-400]" />
              Email delivery requires SMTP configuration in the server environment
              (<code className="font-mono text-[9px]">SMTP_HOST</code>, <code className="font-mono text-[9px]">SMTP_USER</code>, <code className="font-mono text-[9px]">SMTP_PASS</code>).
            </div>
          </div>

          {/* Danger zone */}
          <div className="col-span-2 bg-red-50 border border-red-200 rounded-2xl p-4">
            <div className="flex items-center justify-between">
              <div className="flex items-start gap-3">
                <AlertTriangle className="w-4 h-4 text-red-500 flex-shrink-0 mt-0.5" />
                <div>
                  <div className="text-[12px] font-bold text-red-700">Danger Zone</div>
                  <div className="text-[10px] text-red-600 mt-0.5">
                    Reset all settings to factory defaults. This cannot be undone.
                  </div>
                </div>
              </div>
              <button
                onClick={async () => {
                  if (!confirm("Reset ALL settings to defaults? This cannot be undone.")) return;
                  await fetch(`${API}/reset`, { method: "POST" });
                  await load();
                  setDirty(false);
                }}
                className="flex items-center gap-1.5 px-4 py-2 bg-white border border-red-300 text-red-700 text-[11px] font-bold rounded-xl hover:bg-red-100 transition-colors"
              >
                <RotateCcw className="w-3.5 h-3.5" />Reset to Defaults
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function SectionLabel({ icon: Icon, children }: { icon: React.ElementType; children: React.ReactNode }) {
  return (
    <div className="flex items-center gap-2">
      <Icon className="w-3.5 h-3.5 flex-shrink-0" style={{ color: "#7C3AED" }} />
      <h2 className="text-[11px] font-bold text-[--gray-700] uppercase tracking-wide">{children}</h2>
    </div>
  );
}
