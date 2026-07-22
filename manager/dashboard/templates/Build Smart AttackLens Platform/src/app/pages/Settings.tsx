/**
 * Settings — Organisation profile, license validity, role access matrix,
 * and platform configuration.
 *
 * GET  /api/v1/settings        — load all settings + license + roles
 * PUT  /api/v1/settings        — persist changes
 * POST /api/v1/settings/reset  — factory reset
 */
import { useState, useEffect, useRef, useCallback } from "react";
import { useParams, useNavigate } from "react-router";
import {
  Building2, MapPin, Mail, Calendar, ShieldCheck, Settings2,
  Bell, RefreshCw, Save, AlertTriangle, CheckCircle2, Info,
  Clock, Users, Lock, Unlock, Globe, RotateCcw, ChevronRight,
  Brain, Target, Trash2, Plus, Database, Archive, FolderOpen,
  Cpu, Eye, EyeOff, Zap, ExternalLink, TestTube2,
} from "lucide-react";
import { cn } from "../../lib/utils";
import { setTimezone, tzAbbr, tzOffsetStr, TIMEZONE_LIST, TZ_DEFAULT, isValidTimezone, fmtTime } from "../context/timezoneStore";

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

type TabId = "org" | "license" | "roles" | "platform" | "validation" | "retention" | "ai";

const EMPTY: OrgSettings = {
  org_name: "", org_description: "", org_location: "", contact_email: "",
  org_industry: "", org_size: "", issue_date: "", valid_until: "",
  license_key: "", role_admin_label: "Administrator",
  role_analyst_label: "SOC Analyst", role_viewer_label: "Read-Only Viewer",
  platform_refresh_secs: "30", platform_timezone: TZ_DEFAULT,
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

const VALID_SECTIONS: TabId[] = ["org", "license", "roles", "platform", "validation", "retention", "ai"];

export default function Settings() {
  const { section } = useParams<{ section?: string }>();
  const navigate = useNavigate();
  const tab: TabId = VALID_SECTIONS.includes(section as TabId) ? (section as TabId) : "org";
  const setTab = (t: TabId) => navigate(`/settings/${t}`);
  const [form,    setForm]    = useState<OrgSettings>(EMPTY);
  const [license, setLicense] = useState<LicenseStatus | null>(null);
  const [roles,   setRoles]   = useState<Record<string, RoleEntry>>({});
  const [loading, setLoading] = useState(true);
  const [saving,  setSaving]  = useState(false);
  const [saved,   setSaved]   = useState(false);
  const [error,   setError]   = useState<string | null>(null);
  const [dirty,   setDirty]   = useState(false);
  const [dirtyFields, setDirtyFields] = useState<Set<keyof OrgSettings>>(() => new Set());

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
      setDirty(false);
      setDirtyFields(new Set());
      // Seed the localStorage-backed timezone store from the authoritative backend value
      if (d.settings?.platform_timezone) setTimezone(d.settings.platform_timezone);
    } catch (e) { setError(e instanceof Error ? e.message : String(e)); }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { load(); }, [load]);

  const set = (k: keyof OrgSettings, v: string) => {
    setForm(f => ({ ...f, [k]: v }));
    setDirtyFields(fields => {
      const next = new Set(fields);
      next.add(k);
      return next;
    });
    setDirty(true);
    setSaved(false);
  };

  const save = async () => {
    if (dirtyFields.size === 0) return;
    setSaving(true);
    setError(null);
    try {
      const patch = Array.from(dirtyFields).reduce((acc, key) => {
        acc[key] = form[key];
        return acc;
      }, {} as Partial<OrgSettings>);
      const r = await fetch(API, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(patch),
      });
      if (!r.ok) {
        const d = await r.json().catch(() => ({}));
        const detail = d.detail;
        const msg =
          typeof detail === "string" ? detail
          : Array.isArray(detail) ? detail.map((x: { msg?: string }) => x.msg ?? JSON.stringify(x)).join("; ")
          : detail ? JSON.stringify(detail)
          : `HTTP ${r.status}`;
        throw new Error(msg);
      }
      const d = await r.json();
      setForm({ ...EMPTY, ...d.settings });
      setLicense(d.license ?? null);
      setDirty(false);
      setDirtyFields(new Set());
      setSaved(true);
      setTimeout(() => setSaved(false), 3000);
      // Propagate timezone change to the header clock instantly (no page reload)
      if (d.settings?.platform_timezone) setTimezone(d.settings.platform_timezone);
    } catch (e) { setError(e instanceof Error ? e.message : String(e)); }
    finally { setSaving(false); }
  };

  const licC = license ? licenseColor(license.status) : licenseColor("unconfigured");

  const TABS: { id: TabId; label: string; icon: React.ElementType }[] = [
    { id: "org",        label: "Organisation",  icon: Building2  },
    { id: "license",    label: "License",       icon: ShieldCheck },
    { id: "roles",      label: "Role Access",   icon: Users      },
    { id: "platform",   label: "Platform",      icon: Settings2  },
    { id: "validation", label: "Validation",    icon: Brain      },
    { id: "retention",  label: "Data Retention", icon: Database  },
    { id: "ai",         label: "AI Provider",   icon: Cpu        },
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

            <Field label="Timezone" hint="Used for all clocks and timestamps across the platform">
              {/* Grouped timezone select */}
              <select
                value={form.platform_timezone}
                onChange={e => set("platform_timezone", e.target.value)}
                className={selectCls}
              >
                {(["UTC", "Asia", "Europe", "Americas", "Pacific", "Africa"] as const).map(group => {
                  const items = TIMEZONE_LIST.filter(t => t.group === group);
                  return (
                    <optgroup key={group} label={group}>
                      {items.map(({ tz, label }) => (
                        <option key={tz} value={tz}>{label}</option>
                      ))}
                    </optgroup>
                  );
                })}
              </select>

              {/* Live preview */}
              <div className="mt-2.5 flex items-center gap-2 px-3 py-2.5 rounded-xl bg-gray-50 border border-gray-100">
                <Clock className="w-3.5 h-3.5 text-orange-500 flex-shrink-0" />
                <div className="min-w-0">
                  <span className="text-[10px] font-semibold text-gray-700">
                    {fmtTime(form.platform_timezone)}
                  </span>
                  <span className="text-[10px] text-gray-400 mx-1.5">·</span>
                  <span className="text-[10px] text-gray-500">
                    {isValidTimezone(form.platform_timezone)
                      ? new Date().toLocaleDateString("en-US", {
                          weekday: "short", day: "numeric", month: "short", year: "numeric",
                          timeZone: form.platform_timezone,
                        })
                      : "—"}
                  </span>
                  <span className="text-[9px] font-bold text-orange-600 ml-2 px-1.5 py-0.5 bg-orange-50 border border-orange-200 rounded-md">
                    {tzAbbr(form.platform_timezone)} (UTC{tzOffsetStr(form.platform_timezone)})
                  </span>
                </div>
              </div>
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
                  try {
                    const r = await fetch(`${API}/reset`, { method: "POST" });
                    if (!r.ok) throw new Error(`Reset failed: HTTP ${r.status}`);
                    await load();
                    setDirty(false);
                    setDirtyFields(new Set());
                  } catch (e) { setError(e instanceof Error ? e.message : String(e)); }
                }}
                className="flex items-center gap-1.5 px-4 py-2 bg-white border border-red-300 text-red-700 text-[11px] font-bold rounded-xl hover:bg-red-100 transition-colors"
              >
                <RotateCcw className="w-3.5 h-3.5" />Reset to Defaults
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ══════════════════════════════════════════════════════════════════════
          TAB: Validation & Confidence Scoring
      ══════════════════════════════════════════════════════════════════════ */}
      {tab === "validation" && (
        <ValidationSettingsPanel />
      )}

      {/* ══════════════════════════════════════════════════════════════════════
          TAB: Data Retention
      ══════════════════════════════════════════════════════════════════════ */}
      {tab === "retention" && (
        <RetentionSettingsPanel />
      )}

      {/* ══════════════════════════════════════════════════════════════════════
          TAB: AI Provider
      ══════════════════════════════════════════════════════════════════════ */}
      {tab === "ai" && (
        <AIProviderPanel />
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

// ── Validation & Confidence Scoring panel ──────────────────────────────────
// Lets analysts configure the AI Precision Validator threshold globally, per
// attack terrain (Citadels / Vector / Origin / Identity / Posture), and per
// agent.  Higher threshold → fewer findings but higher precision.
// Resolution priority at evaluation time: per-agent > per-terrain > global.

interface VTerrain {
  id:         string;
  label:      string;
  categories: string[];
  threshold:  number | null;
}
interface VAgent {
  agent_id:   string;
  hostname:   string;
  os:         string;
  asset_tier: string;
  threshold:  number | null;
  priority?:  string;
}
interface VPriorityOption {
  level: string;
  label: string;
  confidence_multiplier: number;
  confidence_delta: number;
  precision_delta: number;
  asset_tier_floor: string;
}
interface VSettings {
  global_threshold:    number;
  terrain_thresholds:  Record<string, number>;
  agent_thresholds:    Record<string, number>;
  agent_priorities:    Record<string, string>;
  use_ai_verdict:      boolean;
  min_strength:        number;
  terrains:            VTerrain[];
  agents:              VAgent[];
  bounds:              { min: number; max: number };
  priority_levels?:     string[];
  priority_options?:    VPriorityOption[];
}

const VAPI = "/api/v1/settings/validation";

function thresholdTone(t: number): string {
  if (t >= 0.95) return "text-emerald-700";
  if (t >= 0.90) return "text-emerald-600";
  if (t >= 0.80) return "text-amber-600";
  return "text-red-600";
}

function ThresholdSlider({
  value,
  bounds,
  onChange,
  label,
  description,
  disabled,
}: {
  value: number;
  bounds: { min: number; max: number };
  onChange: (v: number) => void;
  label?: string;
  description?: string;
  disabled?: boolean;
}) {
  const pct = Math.round(value * 100);
  return (
    <div className="space-y-1.5">
      {label && (
        <div className="flex items-center justify-between">
          <div>
            <div className="text-[11px] font-semibold text-[--gray-700]">{label}</div>
            {description && <div className="text-[9px] text-[--gray-400] mt-0.5">{description}</div>}
          </div>
          <div className={cn("text-[13px] font-black tabular-nums", thresholdTone(value))}>
            {pct}%
          </div>
        </div>
      )}
      <input
        type="range"
        min={Math.round(bounds.min * 100)}
        max={Math.round(bounds.max * 100)}
        step={1}
        value={pct}
        disabled={disabled}
        onChange={e => onChange(Number(e.target.value) / 100)}
        className="w-full accent-purple-600 cursor-pointer disabled:cursor-not-allowed disabled:opacity-50"
      />
      <div className="flex items-center justify-between text-[8px] text-[--gray-300] font-mono">
        <span>{Math.round(bounds.min * 100)}%</span>
        <span className="text-[--gray-400]">higher = stricter</span>
        <span>{Math.round(bounds.max * 100)}%</span>
      </div>
    </div>
  );
}

function ValidationSettingsPanel() {
  const [data,    setData]    = useState<VSettings | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving,  setSaving]  = useState(false);
  const [error,   setError]   = useState<string | null>(null);
  const [saved,   setSaved]   = useState(false);
  const [pickerAgent, setPickerAgent] = useState("");
  const [priorityAgent, setPriorityAgent] = useState("");
  const [priorityLevel, setPriorityLevel] = useState("top");

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const r = await fetch(VAPI);
      if (!r.ok) throw new Error(`${r.status}`);
      const d: VSettings = await r.json();
      // Make sure each terrain has its current effective threshold in the map.
      const tt = { ...d.terrain_thresholds };
      d.terrains.forEach(t => {
        if (t.threshold != null && tt[t.id] == null) tt[t.id] = t.threshold;
      });
      setData({
        ...d,
        terrain_thresholds: tt,
        agent_priorities: d.agent_priorities || {},
        priority_options: d.priority_options || [
          { level: "top", label: "Top priority", confidence_multiplier: 1.1, confidence_delta: 0.06, precision_delta: 0.04, asset_tier_floor: "crown_jewel" },
          { level: "high", label: "High priority", confidence_multiplier: 1.05, confidence_delta: 0.03, precision_delta: 0.025, asset_tier_floor: "server" },
          { level: "standard", label: "Standard priority", confidence_multiplier: 1, confidence_delta: 0, precision_delta: 0, asset_tier_floor: "endpoint" },
          { level: "low", label: "Low priority", confidence_multiplier: 1, confidence_delta: 0, precision_delta: 0, asset_tier_floor: "unknown" },
        ],
      });
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally { setLoading(false); }
  }, []);

  useEffect(() => { load(); }, [load]);

  const save = async (patch: Partial<{
    global_threshold:   number;
    terrain_thresholds: Record<string, number>;
    agent_thresholds:   Record<string, number>;
    agent_priorities:   Record<string, string>;
    use_ai_verdict:     boolean;
    min_strength:       number;
  }>) => {
    setSaving(true); setSaved(false);
    try {
      const r = await fetch(VAPI, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(patch),
      });
      if (!r.ok) throw new Error(`${r.status}`);
      const d: VSettings = await r.json();
      setData({
        ...d,
        agent_priorities: d.agent_priorities || {},
        priority_options: d.priority_options || data?.priority_options || [],
      });
      setSaved(true);
      setTimeout(() => setSaved(false), 1500);
      setError(null);
    } catch (e) { setError(e instanceof Error ? e.message : String(e)); }
    finally { setSaving(false); }
  };

  if (loading || !data) {
    return (
      <div className="bg-white border border-[--gray-200] rounded-2xl p-8 text-center text-[11px] text-[--gray-400]">
        <RefreshCw className="w-4 h-4 animate-spin inline mr-2" />Loading validation settings…
      </div>
    );
  }

  const unconfiguredAgents = data.agents.filter(
    a => !(a.agent_id in (data.agent_thresholds || {}))
  );
  const priorityOptions = data.priority_options || [];
  const unprioritizedAgents = data.agents.filter(
    a => !(a.agent_id in (data.agent_priorities || {}))
  );

  return (
    <div className="space-y-4">

      {/* ── Global threshold + LLM toggle ──────────────────────────────── */}
      <div className="bg-white border border-[--gray-200] rounded-2xl shadow-card p-5 space-y-4">
        <SectionLabel icon={Brain}>Global Detection Confidence Threshold</SectionLabel>
        <p className="text-[10px] text-[--gray-500] leading-relaxed">
          The Validated Findings page only shows findings whose AI Precision composite score is at least this value.
          Per-terrain and per-agent overrides below take priority over this global default.
        </p>

        <ThresholdSlider
          value={data.global_threshold}
          bounds={data.bounds}
          onChange={v => setData({ ...data, global_threshold: v })}
          label="Global Detection Confidence threshold"
          description="Applies to every finding that has no terrain or agent override."
        />

        <div className="flex items-center justify-between gap-3 pt-3 border-t border-[--gray-100]">
          <div>
            <div className="text-[11px] font-semibold text-[--gray-700]">Use LLM verdict</div>
            <div className="text-[9px] text-[--gray-400] mt-0.5">
              When OFF the validator falls back to deterministic factors only. Useful if Anthropic credits are tight.
            </div>
          </div>
          <Toggle
            value={data.use_ai_verdict}
            onChange={v => setData({ ...data, use_ai_verdict: v })}
            label=""
          />
        </div>

        <div className="flex items-center justify-end gap-2 pt-2">
          {error && <span className="text-[10px] text-red-600">{error}</span>}
          {saved && <span className="text-[10px] text-emerald-600 flex items-center gap-1"><CheckCircle2 className="w-3 h-3" />Saved</span>}
          <button
            disabled={saving}
            onClick={() => save({
              global_threshold: data.global_threshold,
              use_ai_verdict:   data.use_ai_verdict,
            })}
            className="flex items-center gap-1.5 px-4 py-2 bg-purple-600 hover:bg-purple-700 disabled:bg-purple-300 text-white text-[11px] font-bold rounded-xl transition-colors">
            <Save className="w-3.5 h-3.5" />Save global
          </button>
        </div>
      </div>

      {/* ── Per-terrain overrides ──────────────────────────────────────── */}
      <div className="bg-white border border-[--gray-200] rounded-2xl shadow-card p-5 space-y-4">
        <SectionLabel icon={Target}>Per-Terrain Overrides</SectionLabel>
        <p className="text-[10px] text-[--gray-500] leading-relaxed">
          Tighten or loosen the threshold for an entire attack terrain (Citadels = execution &amp; persistence, Vector = network, Origin = surface &amp; CVEs, Identity = accounts, Posture = security controls).
        </p>
        <div className="space-y-3">
          {data.terrains.map(terrain => {
            const enabled = terrain.id in data.terrain_thresholds;
            const value   = data.terrain_thresholds[terrain.id] ?? data.global_threshold;
            return (
              <div key={terrain.id}
                   className={cn(
                     "rounded-xl border p-3 space-y-2 transition-all",
                     enabled ? "border-purple-200 bg-purple-50/30" : "border-[--gray-200] bg-white"
                   )}>
                <div className="flex items-center justify-between gap-3">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="text-[12px] font-bold text-[--gray-800]">{terrain.label}</span>
                      {enabled && (
                        <span className="px-1.5 py-0.5 bg-purple-100 text-purple-700 rounded text-[8px] font-bold uppercase tracking-wide">override active</span>
                      )}
                    </div>
                    <div className="text-[9px] text-[--gray-400] mt-0.5 truncate">
                      Categories: {terrain.categories.join(", ")}
                    </div>
                  </div>
                  <button
                    onClick={() => {
                      const next = { ...data.terrain_thresholds };
                      if (enabled) delete next[terrain.id];
                      else next[terrain.id] = data.global_threshold;
                      setData({ ...data, terrain_thresholds: next });
                    }}
                    className={cn(
                      "px-2 py-1 rounded-lg text-[10px] font-bold border transition-colors",
                      enabled
                        ? "bg-white text-red-600 border-red-200 hover:bg-red-50"
                        : "bg-purple-50 text-purple-700 border-purple-200 hover:bg-purple-100"
                    )}>
                    {enabled ? <Trash2 className="w-3 h-3 inline" /> : <Plus className="w-3 h-3 inline" />}
                  </button>
                </div>
                {enabled && (
                  <ThresholdSlider
                    value={value}
                    bounds={data.bounds}
                    onChange={v => {
                      const next = { ...data.terrain_thresholds, [terrain.id]: v };
                      setData({ ...data, terrain_thresholds: next });
                    }}
                  />
                )}
              </div>
            );
          })}
        </div>
        <div className="flex items-center justify-end gap-2 pt-2">
          <button
            disabled={saving}
            onClick={() => save({ terrain_thresholds: data.terrain_thresholds })}
            className="flex items-center gap-1.5 px-4 py-2 bg-purple-600 hover:bg-purple-700 disabled:bg-purple-300 text-white text-[11px] font-bold rounded-xl transition-colors">
            <Save className="w-3.5 h-3.5" />Save terrain overrides
          </button>
        </div>
      </div>

      {/* ── Per-agent overrides ────────────────────────────────────────── */}
      <div className="bg-white border border-[--gray-200] rounded-2xl shadow-card p-5 space-y-4">
        <SectionLabel icon={Users}>Per-Agent Overrides</SectionLabel>
        <p className="text-[10px] text-[--gray-500] leading-relaxed">
          Pin a stricter (or looser) threshold to specific hosts — e.g. crown-jewel servers
          might require 95%, sandbox dev laptops can drop to 80%. Per-agent overrides beat
          terrain and global settings.
        </p>

        {/* Add agent picker */}
        {unconfiguredAgents.length > 0 && (
          <div className="flex items-center gap-2 pb-3 border-b border-[--gray-100]">
            <select
              value={pickerAgent}
              onChange={e => setPickerAgent(e.target.value)}
              className={selectCls + " flex-1"}
            >
              <option value="">Add agent…</option>
              {unconfiguredAgents.map(a => (
                <option key={a.agent_id} value={a.agent_id}>
                  {a.hostname} · {a.asset_tier} · {a.os || "—"}
                </option>
              ))}
            </select>
            <button
              disabled={!pickerAgent}
              onClick={() => {
                if (!pickerAgent) return;
                const next = { ...data.agent_thresholds, [pickerAgent]: data.global_threshold };
                setData({ ...data, agent_thresholds: next });
                setPickerAgent("");
              }}
              className="flex items-center gap-1 px-3 py-2 bg-purple-600 hover:bg-purple-700 disabled:bg-[--gray-300] text-white text-[10px] font-bold rounded-xl transition-colors">
              <Plus className="w-3 h-3" />Add
            </button>
          </div>
        )}

        {/* Configured agents list */}
        <div className="space-y-2">
          {Object.keys(data.agent_thresholds).length === 0 && (
            <div className="text-[10px] text-[--gray-400] italic text-center py-4">
              No per-agent overrides yet. Pick an agent above to add one.
            </div>
          )}
          {Object.entries(data.agent_thresholds).map(([aid, val]) => {
            const agent = data.agents.find(a => a.agent_id === aid);
            return (
              <div key={aid} className="rounded-xl border border-purple-200 bg-purple-50/30 p-3 space-y-2">
                <div className="flex items-center justify-between gap-3">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-[12px] font-bold text-[--gray-800]">{agent?.hostname || aid}</span>
                      {agent?.asset_tier && (
                        <span className="px-1.5 py-0.5 bg-gray-100 text-gray-600 rounded text-[8px] font-mono">{agent.asset_tier}</span>
                      )}
                      {agent?.os && (
                        <span className="px-1.5 py-0.5 bg-blue-50 text-blue-700 rounded text-[8px] font-mono">{agent.os}</span>
                      )}
                    </div>
                    <div className="text-[9px] text-[--gray-400] mt-0.5 font-mono truncate">{aid}</div>
                  </div>
                  <button
                    onClick={() => {
                      const next = { ...data.agent_thresholds };
                      delete next[aid];
                      setData({ ...data, agent_thresholds: next });
                    }}
                    className="px-2 py-1 rounded-lg text-[10px] font-bold border bg-white text-red-600 border-red-200 hover:bg-red-50 transition-colors">
                    <Trash2 className="w-3 h-3 inline" />
                  </button>
                </div>
                <ThresholdSlider
                  value={val}
                  bounds={data.bounds}
                  onChange={v => {
                    const next = { ...data.agent_thresholds, [aid]: v };
                    setData({ ...data, agent_thresholds: next });
                  }}
                />
              </div>
            );
          })}
        </div>

        <div className="flex items-center justify-end gap-2 pt-2">
          <button
            disabled={saving}
            onClick={() => save({ agent_thresholds: data.agent_thresholds })}
            className="flex items-center gap-1.5 px-4 py-2 bg-purple-600 hover:bg-purple-700 disabled:bg-purple-300 text-white text-[11px] font-bold rounded-xl transition-colors">
            <Save className="w-3.5 h-3.5" />Save agent overrides
          </button>
        </div>
      </div>

      {/* ── Per-agent asset priority confidence boost ──────────────────── */}
      <div className="bg-white border border-[--gray-200] rounded-2xl shadow-card p-5 space-y-4">
        <SectionLabel icon={Zap}>Asset Priority Confidence</SectionLabel>
        <div className="grid grid-cols-[1fr_180px_96px] gap-2 pb-3 border-b border-[--gray-100]">
          <select
            value={priorityAgent}
            onChange={e => setPriorityAgent(e.target.value)}
            className={selectCls}
          >
            <option value="">Add priority agent…</option>
            {unprioritizedAgents.map(a => (
              <option key={a.agent_id} value={a.agent_id}>
                {a.hostname} · {a.asset_tier} · {a.os || "—"}
              </option>
            ))}
          </select>
          <select
            value={priorityLevel}
            onChange={e => setPriorityLevel(e.target.value)}
            className={selectCls}
          >
            {priorityOptions.map(p => (
              <option key={p.level} value={p.level}>{p.label}</option>
            ))}
          </select>
          <button
            disabled={!priorityAgent}
            onClick={() => {
              if (!priorityAgent) return;
              const next = { ...data.agent_priorities, [priorityAgent]: priorityLevel };
              setData({ ...data, agent_priorities: next });
              setPriorityAgent("");
              setPriorityLevel("top");
            }}
            className="flex items-center justify-center gap-1 px-3 py-2 bg-purple-600 hover:bg-purple-700 disabled:bg-[--gray-300] text-white text-[10px] font-bold rounded-xl transition-colors">
            <Plus className="w-3 h-3" />Add
          </button>
        </div>

        <div className="grid grid-cols-2 gap-3">
          {Object.keys(data.agent_priorities || {}).length === 0 && (
            <div className="col-span-2 text-[10px] text-[--gray-400] italic text-center py-4">
              No asset priority overrides configured.
            </div>
          )}
          {Object.entries(data.agent_priorities || {}).map(([aid, level]) => {
            const agent = data.agents.find(a => a.agent_id === aid);
            const option = priorityOptions.find(p => p.level === level);
            const lift = option ? Math.round((option.confidence_multiplier - 1) * 100) : 0;
            return (
              <div key={aid} className="rounded-xl border border-purple-200 bg-purple-50/30 p-3 space-y-2">
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0">
                    <div className="text-[12px] font-bold text-[--gray-800] truncate">{agent?.hostname || aid}</div>
                    <div className="text-[9px] text-[--gray-400] mt-0.5 font-mono truncate">{aid}</div>
                  </div>
                  <button
                    onClick={() => {
                      const next = { ...data.agent_priorities };
                      delete next[aid];
                      setData({ ...data, agent_priorities: next });
                    }}
                    className="px-2 py-1 rounded-lg text-[10px] font-bold border bg-white text-red-600 border-red-200 hover:bg-red-50 transition-colors">
                    <Trash2 className="w-3 h-3 inline" />
                  </button>
                </div>
                <div className="grid grid-cols-[1fr_auto] gap-2 items-center">
                  <select
                    value={level}
                    onChange={e => {
                      const next = { ...data.agent_priorities, [aid]: e.target.value };
                      setData({ ...data, agent_priorities: next });
                    }}
                    className={selectCls}
                  >
                    {priorityOptions.map(p => (
                      <option key={p.level} value={p.level}>{p.label}</option>
                    ))}
                  </select>
                  <span className="px-2 py-1 rounded-lg bg-white border border-purple-100 text-[9px] font-bold text-purple-700 tabular-nums">
                    {lift > 0 ? `+${lift}%` : "0%"}
                  </span>
                </div>
                <div className="flex items-center gap-1.5 text-[9px] text-[--gray-400]">
                  <ShieldCheck className="w-3 h-3" />
                  <span>{option?.asset_tier_floor || "endpoint"} floor</span>
                  {agent?.asset_tier && <span>· current {agent.asset_tier}</span>}
                </div>
              </div>
            );
          })}
        </div>

        <div className="flex items-center justify-end gap-2 pt-2">
          <button
            disabled={saving}
            onClick={() => save({ agent_priorities: data.agent_priorities || {} })}
            className="flex items-center gap-1.5 px-4 py-2 bg-purple-600 hover:bg-purple-700 disabled:bg-purple-300 text-white text-[11px] font-bold rounded-xl transition-colors">
            <Save className="w-3.5 h-3.5" />Save priority overrides
          </button>
        </div>
      </div>

      {/* ── Info footer ────────────────────────────────────────────────── */}
      <div className="rounded-xl border border-blue-200 bg-blue-50 px-4 py-3 flex items-start gap-2 text-[10px] text-blue-800">
        <Info className="w-3.5 h-3.5 flex-shrink-0 mt-0.5" />
        <div className="leading-relaxed">
          <strong>How resolution works:</strong> when a cluster is evaluated, the threshold is taken from
          the first match in this priority order — <strong>per-agent override</strong> →
          <strong> per-terrain override</strong> → <strong>global threshold</strong>. Changes apply within ~30s
          (settings cache); asset priority is applied before confidence scoring and is capped for weak evidence.
        </div>
      </div>
    </div>
  );
}

// ── Data Retention panel ─────────────────────────────────────────────────────
// How long raw telemetry stays queryable, and what happens to it once that
// window elapses. Period changes are persisted via the main /api/v1/settings
// PUT (same org_settings store as every other field); the dedicated
// /retention GET below also returns live size stats so the dashboard can
// show actual data volume rather than just the configured policy.

const RETENTION_API = "/api/v1/settings";

interface RetentionConfig {
  period_months:           number;
  period_days:             number;
  action:                  "delete" | "archive";
  slow_fetch_warning:      boolean;
  auto_resolve_stale_days: number;
  available_periods:       number[];
  available_actions:       string[];
}
interface RetentionStats {
  live_payloads: { row_count: number; approx_bytes: number; table_bytes: number } | null;
  archive: { path: string; file_count: number; total_bytes: number;
             oldest_file_ts: number | null; newest_file_ts: number | null } | null;
  postgres: { db_bytes: number } | null;
}

const RETENTION_PERIOD_LABELS: Record<number, string> = {
  0: "1 day",
  7: "7 days",
  15: "15 days",
  1: "1 month",
  3: "3 months",
  6: "6 months",
  12: "1 year",
  24: "2 years",
};

const STORAGE_REFRESH_INTERVAL_MS = 60_000; // refresh storage stats every 60 s

function formatBytes(n: number | null | undefined): string {
  if (n == null || n <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let i = 0, v = n;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(v >= 10 || i === 0 ? 0 : 1)} ${units[i]}`;
}

function RetentionSettingsPanel() {
  const [config,      setConfig]      = useState<RetentionConfig | null>(null);
  const [stats,       setStats]       = useState<RetentionStats | null>(null);
  const [loading,     setLoading]     = useState(true);
  const [refreshing,  setRefreshing]  = useState(false);
  const [saving,      setSaving]      = useState(false);
  const [saved,       setSaved]       = useState(false);
  const [error,       setError]       = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const loadStats = useCallback(async (quiet = false) => {
    if (!quiet) setRefreshing(true);
    try {
      const r = await fetch(`${RETENTION_API}/retention`);
      if (!r.ok) throw new Error(`${r.status}`);
      const d = await r.json();
      setConfig(d.config);
      setStats(d.stats);
      setLastUpdated(new Date());
      setError(null);
    } catch (e) { setError(e instanceof Error ? e.message : String(e)); }
    finally { if (!quiet) setRefreshing(false); }
  }, []);

  const load = useCallback(async () => {
    setLoading(true);
    await loadStats(true);
    setLoading(false);
  }, [loadStats]);

  useEffect(() => {
    load();
    timerRef.current = setInterval(() => loadStats(true), STORAGE_REFRESH_INTERVAL_MS);
    return () => { if (timerRef.current) clearInterval(timerRef.current); };
  }, [load, loadStats]);

  const save = async (periodMonths: number, action: "delete" | "archive", autoResolveDays?: number) => {
    setSaving(true); setSaved(false);
    try {
      const body: Record<string, string> = {
        retention_period_months: String(periodMonths),
        retention_action: action,
      };
      if (autoResolveDays !== undefined) {
        body.auto_resolve_stale_days = String(autoResolveDays);
      }
      const r = await fetch(RETENTION_API, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      if (!r.ok) {
        const d = await r.json().catch(() => ({}));
        const detail = d.detail;
        const msg =
          typeof detail === "string" ? detail
          : Array.isArray(detail) ? detail.map((x: { msg?: string }) => x.msg ?? JSON.stringify(x)).join("; ")
          : detail ? JSON.stringify(detail)
          : `HTTP ${r.status}`;
        throw new Error(msg);
      }
      await load();
      setSaved(true);
      setTimeout(() => setSaved(false), 1500);
      setError(null);
    } catch (e) { setError(e instanceof Error ? e.message : String(e)); }
    finally { setSaving(false); }
  };

  if (loading || !config) {
    return (
      <div className="bg-white border border-[--gray-200] rounded-2xl p-8 text-center text-[11px] text-[--gray-400]">
        <RefreshCw className="w-4 h-4 animate-spin inline mr-2" />Loading retention settings…
      </div>
    );
  }

  return (
    <div className="grid grid-cols-2 gap-4">

      {/* ── Retention period ─────────────────────────────────────────────── */}
      <div className="bg-white border border-[--gray-200] rounded-2xl shadow-card p-5 space-y-4">
        <SectionLabel icon={Clock}>Retention Period</SectionLabel>
        <p className="text-[10px] text-[--gray-500] leading-relaxed">
          How long raw telemetry stays in the live, queryable store before the action below applies.
          Short windows keep storage tight; longer windows make historical investigations easier.
          Default is 1 day.
        </p>

        <Field label="Keep data for" hint="default: 1 day">
          <select
            value={config.period_months}
            onChange={e => save(Number(e.target.value), config.action)}
            disabled={saving}
            className={selectCls}
          >
            {config.available_periods.map(m => (
              <option key={m} value={m}>{RETENTION_PERIOD_LABELS[m] ?? `${m} months`}</option>
            ))}
          </select>
        </Field>

        {config.slow_fetch_warning && (
          <div className="flex items-start gap-2 px-3 py-2.5 bg-amber-50 border border-amber-200 rounded-xl text-[10px] text-amber-800 leading-relaxed">
            <AlertTriangle className="w-3.5 h-3.5 flex-shrink-0 mt-0.5" />
            <div>
              <strong>Slower fetches at this window.</strong> 1- and 2-year retention keep a much larger
              dataset live — Deep Analysis and raw-telemetry queries over the full window will take
              noticeably longer to return.
            </div>
          </div>
        )}

        <div className="flex items-center justify-end gap-2 pt-1">
          {error && <span className="text-[10px] text-red-600">{error}</span>}
          {saved && <span className="text-[10px] text-emerald-600 flex items-center gap-1"><CheckCircle2 className="w-3 h-3" />Saved</span>}
        </div>
      </div>

      {/* ── Past-retention action ────────────────────────────────────────── */}
      <div className="bg-white border border-[--gray-200] rounded-2xl shadow-card p-5 space-y-4">
        <SectionLabel icon={Trash2}>When Data Ages Out</SectionLabel>
        <p className="text-[10px] text-[--gray-500] leading-relaxed">
          What happens to telemetry once it's older than the retention period above. Default is Delete.
        </p>

        <div className="space-y-2">
          <button
            type="button"
            disabled={saving}
            onClick={() => save(config.period_months, "delete")}
            className={cn(
              "w-full flex items-start gap-3 p-3 rounded-xl border text-left transition-all",
              config.action === "delete"
                ? "border-purple-300 bg-purple-50/40"
                : "border-[--gray-200] hover:border-[--gray-300]"
            )}
          >
            <Trash2 className={cn("w-4 h-4 flex-shrink-0 mt-0.5", config.action === "delete" ? "text-purple-600" : "text-[--gray-400]")} />
            <div>
              <div className="flex items-center gap-2">
                <span className="text-[12px] font-bold text-[--gray-800]">Delete</span>
                <span className="px-1.5 py-0.5 bg-[--gray-100] text-[--gray-500] rounded text-[8px] font-bold uppercase tracking-wide">default</span>
                {config.action === "delete" && (
                  <span className="px-1.5 py-0.5 bg-purple-100 text-purple-700 rounded text-[8px] font-bold uppercase tracking-wide">active</span>
                )}
              </div>
              <div className="text-[10px] text-[--gray-500] mt-0.5">
                Telemetry is permanently removed once it ages past the retention period. Lowest storage cost.
              </div>
            </div>
          </button>

          <button
            type="button"
            disabled={saving}
            onClick={() => save(config.period_months, "archive")}
            className={cn(
              "w-full flex items-start gap-3 p-3 rounded-xl border text-left transition-all",
              config.action === "archive"
                ? "border-purple-300 bg-purple-50/40"
                : "border-[--gray-200] hover:border-[--gray-300]"
            )}
          >
            <Archive className={cn("w-4 h-4 flex-shrink-0 mt-0.5", config.action === "archive" ? "text-purple-600" : "text-[--gray-400]")} />
            <div>
              <div className="flex items-center gap-2">
                <span className="text-[12px] font-bold text-[--gray-800]">Compress &amp; Store</span>
                {config.action === "archive" && (
                  <span className="px-1.5 py-0.5 bg-purple-100 text-purple-700 rounded text-[8px] font-bold uppercase tracking-wide">active</span>
                )}
              </div>
              <div className="text-[10px] text-[--gray-500] mt-0.5">
                Aged-out telemetry is kept indefinitely as compressed NDJSON+gzip files on disk instead of
                being deleted — see the location below.
              </div>
            </div>
          </button>
        </div>
      </div>

      {/* ── Auto-Resolve stale findings ──────────────────────────────────── */}
      <div className="col-span-2 bg-white border border-[--gray-200] rounded-2xl shadow-card p-5 space-y-4">
        <SectionLabel icon={CheckCircle2}>Auto-Resolve Stale Findings</SectionLabel>
        <p className="text-[10px] text-[--gray-500] leading-relaxed">
          When an agent's next scan no longer contains previously-seen evidence
          (e.g. port 3389 was open but is now closed, a package was removed, a
          process exited), the finding is automatically marked <strong>auto_resolved</strong> with
          a timestamp after this many days. Covers ports, processes, connections,
          services, users, tasks, packages, apps, containers, configs, binaries,
          SBOM, sysctl, and network connections.
        </p>
        <Field label="Auto-resolve after" hint="default: 2 days (48h)">
          <select
            value={config.auto_resolve_stale_days}
            onChange={e => save(config.period_months, config.action, Number(e.target.value))}
            disabled={saving}
            className={selectCls}
          >
            {[1, 2, 5, 7, 14].map(d => (
              <option key={d} value={d}>{d === 1 ? "1 day" : `${d} days`}{d === 2 ? " (default)" : ""}</option>
            ))}
          </select>
        </Field>
      </div>

      {/* ── Live data size ───────────────────────────────────────────────── */}
      <div className="col-span-2 bg-white border border-[--gray-200] rounded-2xl shadow-card p-5 space-y-3">
        <div className="flex items-center justify-between">
          <SectionLabel icon={Database}>Current Data Size</SectionLabel>
          <div className="flex items-center gap-2">
            {lastUpdated && (
              <span className="text-[9px] text-[--gray-400]">
                Updated {lastUpdated.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })}
              </span>
            )}
            <button
              type="button"
              onClick={() => loadStats(false)}
              disabled={refreshing}
              className="p-1 rounded-lg hover:bg-[--gray-100] text-[--gray-400] hover:text-[--gray-600] transition-colors"
              title="Refresh storage stats"
            >
              <RefreshCw className={cn("w-3.5 h-3.5", refreshing && "animate-spin")} />
            </button>
          </div>
        </div>
        <div className="grid grid-cols-3 gap-3">
          <div className="rounded-xl border border-[--gray-100] bg-[--gray-25] p-3.5">
            <div className="text-[9px] font-semibold text-[--gray-400] uppercase tracking-wide">Live payloads</div>
            <div className="text-[18px] font-black text-[--gray-800] mt-1">
              {formatBytes(stats?.live_payloads?.approx_bytes)}
            </div>
            <div className="text-[10px] text-[--gray-400] mt-0.5">
              {(stats?.live_payloads?.row_count ?? 0).toLocaleString()} rows
              {stats?.live_payloads?.table_bytes
                ? ` · ${formatBytes(stats.live_payloads.table_bytes)} on disk`
                : ""}
            </div>
          </div>

          <div className="rounded-xl border border-[--gray-100] bg-[--gray-25] p-3.5">
            <div className="text-[9px] font-semibold text-[--gray-400] uppercase tracking-wide">Total database</div>
            <div className="text-[18px] font-black text-[--gray-800] mt-1">
              {formatBytes(stats?.postgres?.db_bytes ?? null)}
            </div>
            <div className="text-[10px] text-[--gray-400] mt-0.5">
              Postgres total (all tables)
            </div>
          </div>

          <div className={cn(
            "rounded-xl border p-3.5",
            config.action === "archive" ? "border-[--gray-100] bg-[--gray-25]" : "border-[--gray-100] bg-[--gray-25] opacity-50"
          )}>
            <div className="text-[9px] font-semibold text-[--gray-400] uppercase tracking-wide">Archived (compressed)</div>
            {config.action === "archive" && stats?.archive ? (
              <>
                <div className="text-[18px] font-black text-[--gray-800] mt-1">
                  {formatBytes(stats.archive.total_bytes)}
                </div>
                <div className="text-[10px] text-[--gray-400] mt-0.5">
                  {stats.archive.file_count.toLocaleString()} compressed files
                </div>
                <div className="flex items-center gap-1.5 mt-2 pt-2 border-t border-[--gray-100]">
                  <FolderOpen className="w-3 h-3 text-[--gray-400] flex-shrink-0" />
                  <code className="text-[9px] font-mono text-[--gray-500] truncate">{stats.archive.path}</code>
                </div>
              </>
            ) : (
              <div className="text-[11px] text-[--gray-400] mt-1">
                Not in use — switch to "Compress &amp; Store" to keep aged-out data instead of deleting it.
              </div>
            )}
          </div>
        </div>
        <p className="text-[9px] text-[--gray-400]">Auto-refreshes every 60 s — or click the refresh icon above.</p>
      </div>
    </div>
  );
}

// ── AI Provider panel ──────────────────────────────────────────────────────────

type AIProvider = "anthropic" | "openai" | "gemini" | "ollama";

interface AIProviderConfig {
  configured:  boolean;
  provider:    AIProvider | null;
  model:       string | null;
  key_set:     boolean;
  key_preview: string | null;
  base_url:    string;
  updated_at:  number | null;
}

interface ModelInfo {
  id:      string;
  note:    string;
  default: boolean;
}

interface ProviderInfo {
  models:       ModelInfo[];
  requires_key: boolean;
}

const PROVIDER_LABELS: Record<string, string> = {
  anthropic: "Anthropic (Claude)",
  openai:    "OpenAI (GPT)",
  gemini:    "Google Gemini",
  ollama:    "Ollama (Local)",
};

const PROVIDER_COLORS: Record<string, string> = {
  anthropic: "from-orange-500 to-amber-500",
  openai:    "from-green-500 to-emerald-500",
  gemini:    "from-blue-500 to-indigo-500",
  ollama:    "from-purple-500 to-violet-500",
};

const PROVIDER_DESCRIPTIONS: Record<string, string> = {
  anthropic: "Claude Haiku 4.5 — fast, cost-efficient, great for security analysis",
  openai:    "GPT-4o-mini — affordable API, broad compatibility",
  gemini:    "Gemini 1.5 Flash — fast & cheap, 1M token context",
  ollama:    "Local LLM — zero cost, complete data privacy, no internet required",
};

function AIProviderPanel() {
  const [config,     setConfig]     = useState<AIProviderConfig | null>(null);
  const [models,     setModels]     = useState<Record<string, ProviderInfo>>({});
  const [loading,    setLoading]    = useState(true);
  const [saving,     setSaving]     = useState(false);
  const [testing,    setTesting]    = useState(false);
  const [testResult, setTestResult] = useState<{ ok: boolean; message: string; latency_ms?: number } | null>(null);
  const [error,      setError]      = useState<string | null>(null);
  const [success,    setSuccess]    = useState<string | null>(null);

  // Form state
  const [provider, setProvider] = useState<AIProvider>("anthropic");
  const [apiKey,   setApiKey]   = useState("");
  const [model,    setModel]    = useState("");
  const [baseUrl,  setBaseUrl]  = useState("");
  const [showKey,  setShowKey]  = useState(false);

  const load = async () => {
    setLoading(true);
    try {
      const [cfgRes, modRes] = await Promise.all([
        fetch("/api/v1/ai/provider"),
        fetch("/api/v1/ai/models"),
      ]);
      const cfg = cfgRes.ok ? await cfgRes.json() : {};
      const mod = modRes.ok ? await modRes.json() : {};
      setConfig(cfg);
      setModels(mod.providers ?? {});
      if (cfg.configured && cfg.provider) {
        setProvider(cfg.provider);
        setModel(cfg.model ?? "");
        setBaseUrl(cfg.base_url ?? "");
      }
    } catch (e: any) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, []);

  const availableModels = models[provider]?.models ?? [];
  const requiresKey     = models[provider]?.requires_key ?? true;

  const handleProviderChange = (p: AIProvider) => {
    setProvider(p);
    setModel("");
    setApiKey("");
    setBaseUrl(p === "ollama" ? "http://localhost:11434" : "");
    setTestResult(null);
  };

  const handleSave = async () => {
    setSaving(true);
    setError(null);
    setSuccess(null);
    try {
      const selectedModel = model || (availableModels.find(m => m.default)?.id ?? availableModels[0]?.id ?? "");
      const resp = await fetch("/api/v1/ai/provider", {
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body:    JSON.stringify({
          provider,
          api_key:    apiKey,
          model:      selectedModel,
          base_url:   baseUrl,
          test_first: true,
        }),
      });
      const data = await resp.json();
      if (!resp.ok) throw new Error(data.detail ?? "Save failed");
      setSuccess(`Saved — ${data.message}`);
      setApiKey("");
      await load();
    } catch (e: any) {
      setError(e.message);
    } finally {
      setSaving(false);
    }
  };

  const handleTest = async () => {
    setTesting(true);
    setTestResult(null);
    try {
      const resp = await fetch("/api/v1/ai/test", { method: "POST" });
      const data = await resp.json();
      setTestResult({ ok: data.ok, message: data.message, latency_ms: data.latency_ms });
    } catch (e: any) {
      setTestResult({ ok: false, message: e.message });
    } finally {
      setTesting(false);
    }
  };

  const handleDelete = async () => {
    if (!confirm("Remove the AI provider configuration?")) return;
    try {
      const r = await fetch("/api/v1/ai/provider", { method: "DELETE" });
      if (!r.ok) throw new Error(`Delete failed: HTTP ${r.status}`);
      setSuccess("Configuration removed");
      setConfig(null);
      await load();
    } catch (e) { setError(e instanceof Error ? e.message : String(e)); }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center py-20 text-[--gray-400]">
        <RefreshCw className="w-4 h-4 animate-spin mr-2" />Loading AI provider config…
      </div>
    );
  }

  return (
    <div className="space-y-4 pb-8">

      {/* ── Header card ─────────────────────────────────────────────────── */}
      <div className="bg-white border border-[--gray-200] rounded-2xl shadow-card overflow-hidden">
        <div className="h-[3px] bg-gradient-to-r from-violet-500 via-purple-500 to-indigo-500" />
        <div className="p-5">
          <div className="flex items-start gap-3">
            <div className="w-10 h-10 rounded-xl flex items-center justify-center flex-shrink-0"
              style={{ background: "linear-gradient(135deg,rgba(124,58,237,0.1),rgba(139,92,246,0.15))", border: "1px solid rgba(124,58,237,0.2)" }}>
              <Cpu className="w-5 h-5" style={{ color: "#7C3AED" }} />
            </div>
            <div className="flex-1">
              <h2 className="text-sm font-bold text-[--gray-900]">AI Provider</h2>
              <p className="text-[11px] text-[--gray-500] mt-0.5">
                Customer-managed AI keys · Provider-agnostic · API keys encrypted at rest (AES-256-GCM)
              </p>
            </div>
            {config?.configured && (
              <div className="flex items-center gap-1.5 text-[10px] font-bold text-emerald-700 bg-emerald-50 px-2.5 py-1.5 rounded-lg border border-emerald-200">
                <CheckCircle2 className="w-3 h-3" />Configured
              </div>
            )}
          </div>
        </div>
      </div>

      {/* ── Current config summary ────────────────────────────────────── */}
      {config?.configured && config.provider && (
        <div className="bg-white border border-[--gray-200] rounded-2xl shadow-card p-5">
          <div className="flex items-center justify-between mb-4">
            <span className="text-[11px] font-bold text-[--gray-700] uppercase tracking-wider">Active Configuration</span>
            <div className="flex items-center gap-2">
              <button onClick={handleTest} disabled={testing}
                className="flex items-center gap-1.5 px-3 py-1.5 text-[10px] font-bold border border-violet-200 text-violet-700 bg-violet-50 rounded-lg hover:bg-violet-100 transition-all disabled:opacity-50">
                <TestTube2 className={cn("w-3 h-3", testing && "animate-pulse")} />
                {testing ? "Testing…" : "Test Connection"}
              </button>
              <button onClick={handleDelete}
                className="flex items-center gap-1.5 px-3 py-1.5 text-[10px] font-bold border border-red-200 text-red-600 rounded-lg hover:bg-red-50 transition-all">
                <Trash2 className="w-3 h-3" />Remove
              </button>
            </div>
          </div>
          <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
            {[
              { label: "Provider",   value: PROVIDER_LABELS[config.provider] ?? config.provider },
              { label: "Model",      value: config.model ?? "—" },
              { label: "API Key",    value: config.key_set ? config.key_preview ?? "set" : "not set" },
              { label: "Updated",    value: config.updated_at ? new Date(config.updated_at * 1000).toLocaleDateString() : "—" },
            ].map(item => (
              <div key={item.label} className="bg-gray-50 rounded-xl p-3 border border-gray-100">
                <p className="text-[9px] font-bold text-[--gray-400] uppercase tracking-wider mb-1">{item.label}</p>
                <p className="text-[11px] font-semibold text-[--gray-800] font-mono truncate">{item.value}</p>
              </div>
            ))}
          </div>
          {testResult && (
            <div className={cn(
              "mt-3 flex items-start gap-2 px-3 py-2.5 rounded-xl text-[10px] border",
              testResult.ok
                ? "bg-emerald-50 text-emerald-800 border-emerald-200"
                : "bg-red-50 text-red-800 border-red-200"
            )}>
              {testResult.ok
                ? <CheckCircle2 className="w-3.5 h-3.5 flex-shrink-0 mt-0.5" />
                : <AlertTriangle className="w-3.5 h-3.5 flex-shrink-0 mt-0.5" />}
              <span>{testResult.message}{testResult.latency_ms ? ` (${testResult.latency_ms}ms)` : ""}</span>
            </div>
          )}
        </div>
      )}

      {/* ── Configure / update form ───────────────────────────────────── */}
      <div className="bg-white border border-[--gray-200] rounded-2xl shadow-card overflow-hidden">
        <div className="px-5 py-4 border-b border-gray-100">
          <span className="text-[11px] font-bold text-[--gray-700] uppercase tracking-wider">
            {config?.configured ? "Update Configuration" : "Configure AI Provider"}
          </span>
        </div>

        <div className="p-5 space-y-6">

          {/* Provider selector */}
          <div>
            <p className="text-[10px] font-bold text-[--gray-600] uppercase tracking-wider mb-3">Choose Provider</p>
            <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
              {(["anthropic","openai","gemini","ollama"] as AIProvider[]).map(p => (
                <button key={p} onClick={() => handleProviderChange(p)}
                  className={cn(
                    "flex flex-col items-start p-3 rounded-xl border-2 text-left transition-all",
                    provider === p
                      ? "border-violet-400 bg-violet-50"
                      : "border-gray-200 hover:border-gray-300 hover:bg-gray-50"
                  )}>
                  <div className={cn("w-6 h-6 rounded-lg mb-2 bg-gradient-to-br", PROVIDER_COLORS[p])} />
                  <p className="text-[10px] font-bold text-[--gray-800]">{PROVIDER_LABELS[p]}</p>
                  <p className="text-[9px] text-[--gray-500] mt-0.5 leading-tight">{PROVIDER_DESCRIPTIONS[p]}</p>
                </button>
              ))}
            </div>
          </div>

          {/* Model selector */}
          <div>
            <label className="block text-[10px] font-bold text-[--gray-600] uppercase tracking-wider mb-2">
              Model
            </label>
            <select value={model} onChange={e => setModel(e.target.value)}
              className="w-full px-3 py-2 text-[11px] border border-[--gray-200] rounded-xl bg-white text-[--gray-800] focus:outline-none focus:ring-2 focus:ring-violet-200">
              <option value="">— Select model (or use default) —</option>
              {availableModels.map(m => (
                <option key={m.id} value={m.id}>
                  {m.id}{m.default ? " ★ default" : ""}{m.note ? `  ·  ${m.note}` : ""}
                </option>
              ))}
            </select>
          </div>

          {/* API Key */}
          {requiresKey && (
            <div>
              <label className="block text-[10px] font-bold text-[--gray-600] uppercase tracking-wider mb-2">
                API Key
                {config?.configured && config.provider === provider && config.key_set && (
                  <span className="ml-2 normal-case text-emerald-600 font-normal">
                    (currently set: {config.key_preview})
                  </span>
                )}
              </label>
              <div className="relative">
                <input
                  type={showKey ? "text" : "password"}
                  value={apiKey}
                  onChange={e => setApiKey(e.target.value)}
                  placeholder={
                    config?.configured && config.provider === provider && config.key_set
                      ? "Leave blank to keep existing key"
                      : `Paste your ${PROVIDER_LABELS[provider]} API key`
                  }
                  className="w-full px-3 py-2 pr-10 text-[11px] font-mono border border-[--gray-200] rounded-xl bg-white text-[--gray-800] focus:outline-none focus:ring-2 focus:ring-violet-200 placeholder-[--gray-400]"
                />
                <button type="button" onClick={() => setShowKey(v => !v)}
                  className="absolute right-2.5 top-1/2 -translate-y-1/2 text-[--gray-400] hover:text-[--gray-600]">
                  {showKey ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                </button>
              </div>
              <p className="text-[9px] text-[--gray-400] mt-1">
                Encrypted with AES-256-GCM before being written to disk. Never logged or transmitted.
              </p>
            </div>
          )}

          {/* Base URL (Ollama / custom) */}
          {(provider === "ollama" || baseUrl) && (
            <div>
              <label className="block text-[10px] font-bold text-[--gray-600] uppercase tracking-wider mb-2">
                {provider === "ollama" ? "Ollama Endpoint" : "Custom Base URL"}
              </label>
              <input
                type="text"
                value={baseUrl}
                onChange={e => setBaseUrl(e.target.value)}
                placeholder={provider === "ollama" ? "http://localhost:11434" : "https://your-proxy.example.com/v1"}
                className="w-full px-3 py-2 text-[11px] font-mono border border-[--gray-200] rounded-xl bg-white text-[--gray-800] focus:outline-none focus:ring-2 focus:ring-violet-200"
              />
              {provider === "ollama" && (
                <p className="text-[9px] text-[--gray-400] mt-1">
                  Make sure Ollama is running: <code className="font-mono">ollama serve</code>
                </p>
              )}
            </div>
          )}

          {/* Cost / capability card */}
          <div className="bg-gradient-to-br from-violet-50 to-indigo-50 border border-violet-100 rounded-xl p-4">
            <div className="flex items-center gap-2 mb-2">
              <Zap className="w-3.5 h-3.5 text-violet-600" />
              <span className="text-[10px] font-bold text-violet-800 uppercase tracking-wider">Recommended Use</span>
            </div>
            <div className="grid grid-cols-2 gap-3 text-[10px]">
              <div>
                <p className="font-semibold text-violet-700 mb-1">Finding Validation (fast)</p>
                <p className="text-violet-600">
                  {provider === "anthropic" ? "claude-haiku-4-5 — ~$0.001/finding" :
                   provider === "openai"    ? "gpt-4o-mini — ~$0.0003/finding" :
                   provider === "gemini"    ? "gemini-1.5-flash — ~$0.0001/finding" :
                                              "Any local model — $0 cost"}
                </p>
              </div>
              <div>
                <p className="font-semibold text-violet-700 mb-1">Remediation Plans (thorough)</p>
                <p className="text-violet-600">
                  {provider === "anthropic" ? "claude-sonnet-4-6 — ~$0.01/plan" :
                   provider === "openai"    ? "gpt-4o — ~$0.005/plan" :
                   provider === "gemini"    ? "gemini-1.5-pro — ~$0.003/plan" :
                                              "llama3.2:8b or mistral:7b — $0 cost"}
                </p>
              </div>
            </div>
          </div>

          {/* Feedback */}
          {error && (
            <div className="flex items-start gap-2 p-3 bg-red-50 text-red-800 rounded-xl border border-red-200 text-[11px]">
              <AlertTriangle className="w-3.5 h-3.5 flex-shrink-0 mt-0.5" />{error}
            </div>
          )}
          {success && (
            <div className="flex items-start gap-2 p-3 bg-emerald-50 text-emerald-800 rounded-xl border border-emerald-200 text-[11px]">
              <CheckCircle2 className="w-3.5 h-3.5 flex-shrink-0 mt-0.5" />{success}
            </div>
          )}

          {/* Save */}
          <div className="flex justify-end">
            <button onClick={handleSave} disabled={saving}
              className="flex items-center gap-2 px-5 py-2.5 text-[11px] font-bold bg-violet-600 text-white rounded-xl hover:bg-violet-700 disabled:opacity-50 transition-all shadow-sm">
              {saving
                ? <><RefreshCw className="w-3.5 h-3.5 animate-spin" />Saving &amp; Testing…</>
                : <><Save className="w-3.5 h-3.5" />Save Configuration</>}
            </button>
          </div>
        </div>
      </div>

      {/* ── Info card ─────────────────────────────────────────────────── */}
      <div className="bg-white border border-[--gray-200] rounded-2xl shadow-card p-5">
        <div className="flex items-center gap-2 mb-3">
          <Info className="w-3.5 h-3.5 text-[--gray-400]" />
          <span className="text-[10px] font-bold text-[--gray-600] uppercase tracking-wider">About AI-Assisted Analysis</span>
        </div>
        <div className="space-y-2 text-[10px] text-[--gray-600]">
          <p>• <strong>Finding Analysis</strong> — AI generates threat context, risk narrative, and urgency assessment for each finding</p>
          <p>• <strong>Remediation Plans</strong> — OS-specific step-by-step plans with actual shell commands and verification steps</p>
          <p>• <strong>Prioritization</strong> — AI ranks findings by true business risk (KEV + EPSS + attack chain) rather than CVSS alone</p>
          <p>• <strong>Caching</strong> — results are cached in intel.db; regenerate on demand with force=true</p>
          <p>• <strong>Privacy</strong> — only finding metadata is sent to the AI (no raw telemetry, no agent PII)</p>
          <p>• <strong>API key security</strong> — keys encrypted with AES-256-GCM, derived from your JWT_SECRET</p>
        </div>
      </div>
    </div>
  );
}
