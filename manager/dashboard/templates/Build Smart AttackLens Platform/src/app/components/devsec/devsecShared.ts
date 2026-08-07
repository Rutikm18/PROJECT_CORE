/**
 * devsecShared — accessors, required-capability catalogue, and health scoring
 * for the `developer_security` (DeepMesh) telemetry snapshot.
 *
 * Kept framework-free so both DevSecurityView (rendering + filter) and
 * DeepMeshHealth (accuracy/coverage) share one source of truth for what the
 * snapshot is *supposed* to contain and how to read it.
 */

// ── unknown-safe accessors ──────────────────────────────────────────────────
export type Row = Record<string, unknown>;
export const asObj = (v: unknown): Row =>
  v && typeof v === "object" && !Array.isArray(v) ? (v as Row) : {};
export const asArr = (v: unknown): Row[] =>
  Array.isArray(v) ? (v as Row[]).filter(r => r && typeof r === "object") : [];
export const str = (v: unknown): string =>
  v == null ? "" : typeof v === "object" ? JSON.stringify(v) : String(v);
export const truthy = (v: unknown) => v === true || v === "true" || v === 1;

// DOM id for a capability panel, so the DeepMesh section nav can scroll to it.
export const anchorId = (key: string) => `devsec-cap-${key}`;

// ── Filter shared by the Overview tables ────────────────────────────────────
export interface DevSecFilter { search: string; riskOnly: boolean }
export const matchesSearch = (f: DevSecFilter, ...fields: unknown[]): boolean => {
  if (!f.search) return true;
  const q = f.search.toLowerCase();
  return fields.some(v => str(v).toLowerCase().includes(q));
};

// ── The capabilities the macOS collector is expected to emit every cycle ─────
// Order roughly by security relevance. `items` is the array key that carries the
// capability's records (used to report a count); some capabilities are dict-only
// (git, docker) and report presence rather than a row count.
export interface CapabilitySpec { key: string; label: string; itemsKey?: string }
export const REQUIRED_CAPABILITIES: CapabilitySpec[] = [
  { key: "editor_extensions",   label: "Editor Extensions",   itemsKey: "items" },
  { key: "mcp_servers",         label: "MCP Servers",         itemsKey: "servers" },
  { key: "browser_extensions",  label: "Browser Extensions",  itemsKey: "items" },
  { key: "native_messaging",    label: "Native Messaging",    itemsKey: "items" },
  { key: "agent_cli_tools",     label: "AI / Agent CLI Tools", itemsKey: "items" },
  { key: "ai_applications",     label: "AI Applications",     itemsKey: "items" },
  { key: "listening_ports",     label: "Listening Ports",     itemsKey: "items" },
  { key: "processes",           label: "Processes",           itemsKey: "items" },
  { key: "launchd",             label: "LaunchDaemons",       itemsKey: "items" },
  { key: "cron",                label: "Cron Jobs",           itemsKey: "users" },
  { key: "shell_startup",       label: "Shell Startup",       itemsKey: "files" },
  { key: "node_packages",       label: "Node Packages",       itemsKey: "users" },
  { key: "python_packages",     label: "Python Packages",     itemsKey: "users" },
  { key: "homebrew",            label: "Homebrew" },
  { key: "git",                 label: "Git" },
  { key: "credential_locations", label: "Credential Locations", itemsKey: "locations" },
  { key: "docker",              label: "Docker" },
];

export type CapStatus = "ok" | "empty" | "error" | "missing";

export interface CapabilityHealth {
  key: string;
  label: string;
  status: CapStatus;
  count: number | null;   // records collected, when the capability is list-bearing
  error: string | null;   // collector error type, when status === "error"
}

export interface DeepMeshHealthReport {
  present: boolean;                 // a developer_security snapshot exists at all
  collectedAt: number | null;
  ageSec: number | null;
  fresh: boolean;                   // within 2× the 1h collection interval
  partial: boolean;                 // collector reported a partial snapshot
  capabilities: CapabilityHealth[];
  okCount: number;
  requiredCount: number;
  errors: { capability: string; error: string }[];   // collection.errors
  issues: { path: string; error: string }[];         // collection.issues (operational)
  truncated: boolean;
  durationMs: number | null;
  overall: "healthy" | "degraded" | "unhealthy" | "absent";
}

// Section is collected hourly; allow 2× before calling it stale (matches the
// spirit of the backend /raw/coverage staleness window).
export const FRESH_WINDOW_SEC = 2 * 3600;

/**
 * Compute an accuracy/coverage report from a single developer_security payload.
 * `nowSec` is injectable for deterministic tests.
 */
export function computeHealth(
  data: unknown,
  collectedAt: number | null,
  nowSec: number = Math.floor(Date.now() / 1000),
): DeepMeshHealthReport {
  const snap = asObj(data);
  const caps = asObj(snap.capabilities);
  const collection = asObj(snap.collection);
  const present = Object.keys(caps).length > 0;

  const errors = asArr(collection.errors).map(e => ({
    capability: str(e.capability), error: str(e.error),
  }));
  const errorByCap = new Map(errors.map(e => [e.capability, e.error]));
  const issues = asArr(collection.issues).map(i => ({
    path: str(i.path), error: str(i.error),
  }));

  const capabilities: CapabilityHealth[] = REQUIRED_CAPABILITIES.map(spec => {
    const raw = caps[spec.key];
    if (raw === undefined) {
      return { key: spec.key, label: spec.label, status: "missing", count: null, error: null };
    }
    const cap = asObj(raw);
    // The agent wraps a failed capability as {"error": "<ExceptionType>"}.
    const capError = str(cap.error) || errorByCap.get(spec.key) || "";
    if (capError) {
      return { key: spec.key, label: spec.label, status: "error", count: null, error: capError };
    }
    let count: number | null = null;
    if (spec.itemsKey) {
      const arr = asArr(cap[spec.itemsKey]);
      count = typeof cap.count === "number" ? (cap.count as number) : arr.length;
    }
    const status: CapStatus = count === 0 ? "empty" : "ok";
    return { key: spec.key, label: spec.label, status, count, error: null };
  });

  const okCount = capabilities.filter(c => c.status === "ok" || c.status === "empty").length;
  const ageSec = collectedAt != null ? Math.max(0, nowSec - collectedAt) : null;
  const fresh = ageSec != null && ageSec <= FRESH_WINDOW_SEC;
  const partial = truthy(collection.partial);
  const truncated = truthy(collection.payload_truncated);
  const durationMs = typeof collection.duration_ms === "number" ? (collection.duration_ms as number) : null;
  const missing = capabilities.filter(c => c.status === "missing").length;
  const errored = capabilities.filter(c => c.status === "error").length;

  let overall: DeepMeshHealthReport["overall"];
  if (!present) overall = "absent";
  else if (missing > 0 || errored >= 3 || !fresh) overall = "unhealthy";
  else if (partial || errored > 0 || errors.length > 0 || issues.length > 0 || truncated) overall = "degraded";
  else overall = "healthy";

  return {
    present, collectedAt, ageSec, fresh, partial, capabilities,
    okCount, requiredCount: REQUIRED_CAPABILITIES.length,
    errors, issues, truncated, durationMs, overall,
  };
}

export function relativeAge(ageSec: number | null): string {
  if (ageSec == null) return "—";
  if (ageSec < 90) return `${ageSec}s ago`;
  if (ageSec < 5400) return `${Math.round(ageSec / 60)}m ago`;
  if (ageSec < 172800) return `${Math.round(ageSec / 3600)}h ago`;
  return `${Math.round(ageSec / 86400)}d ago`;
}
