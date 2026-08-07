/**
 * DevSecurityView — structured renderer for the `developer_security` telemetry
 * section (coding-agent / AI-tool attack surface). Used by the DeepMesh page's
 * Overview tab and inline by Deep Analysis.
 *
 * Renders every capability as an anchored, collapsible panel: five hero surfaces
 * (editor extensions, MCP servers, browser extensions, listeners, CLI tools)
 * have bespoke risk-scored tables; the rest use a generic auto-table. A `focus`
 * prop (capability key) opens + scrolls to that panel — this is how the DeepMesh
 * section nav jumps to a capability's data. An optional filter (free-text +
 * risk-only) applies across the risk-scored tables.
 *
 * Pure/presentational — the host fetches and passes `data` (+ optional filter/focus).
 */
import { useState, useEffect, useRef } from "react";
import {
  Puzzle, Server, Globe, Radio, Terminal, AlertTriangle,
  ChevronRight, ChevronDown, ShieldAlert, Boxes, MessageSquare,
  Cpu, Zap, Clock, FileText, Package, GitBranch, KeyRound, Container,
} from "lucide-react";
import { cn } from "@/lib/utils";
import {
  asObj, asArr, str, truthy, matchesSearch, anchorId,
  type Row, type DevSecFilter,
} from "./devsecShared";

const NO_FILTER: DevSecFilter = { search: "", riskOnly: false };

// ── atoms ───────────────────────────────────────────────────────────────────
function Th({ children }: { children: React.ReactNode }) {
  return (
    <th className="px-3 py-2 text-left text-[9.5px] font-bold text-gray-400 uppercase tracking-wider whitespace-nowrap">
      {children}
    </th>
  );
}
function Td({ v, mono, danger }: { v: unknown; mono?: boolean; danger?: boolean }) {
  const s = str(v);
  return (
    <td
      className={cn(
        "px-3 py-2 text-[11px] max-w-[240px] truncate border-b border-gray-50",
        mono ? "font-mono text-gray-500" : "text-gray-700",
        danger && "font-semibold text-red-600",
      )}
      title={s}
    >
      {s || "—"}
    </td>
  );
}
function Flag({ v, label, tone = "amber" }: { v: unknown; label: string; tone?: "amber" | "red" | "green" | "gray" }) {
  if (!truthy(v)) return null;
  const tones = {
    amber: "bg-amber-50 text-amber-700 border-amber-100",
    red: "bg-red-50 text-red-700 border-red-100",
    green: "bg-green-50 text-green-700 border-green-100",
    gray: "bg-gray-100 text-gray-500 border-gray-200",
  } as const;
  return (
    <span className={cn("px-1.5 py-0.5 rounded text-[9px] font-bold border whitespace-nowrap", tones[tone])}>
      {label}
    </span>
  );
}

function Chip({ icon: Icon, label, value, tone = "gray" }: {
  icon: React.ElementType; label: string; value: React.ReactNode; tone?: "gray" | "orange" | "red" | "green";
}) {
  const tones = {
    gray: "bg-gray-50 border-gray-200 text-gray-600",
    orange: "bg-orange-50 border-orange-200 text-orange-700",
    red: "bg-red-50 border-red-200 text-red-700",
    green: "bg-green-50 border-green-200 text-green-700",
  } as const;
  return (
    <span className={cn("inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg border text-[10px] font-semibold", tones[tone])}>
      <Icon className="w-3 h-3" />
      <span className="text-gray-400 font-medium">{label}</span>
      <span className="tabular-nums font-bold">{value}</span>
    </span>
  );
}

// Collapsible, anchored panel. Opens + scrolls into view when `focused` flips on
// (or when `focusNonce` changes while focused — so re-clicking the nav re-scrolls).
function Panel({ id, icon: Icon, title, count, dot, defaultOpen = false, focused = false, focusNonce = 0, children }: {
  id: string; icon: React.ElementType; title: string; count?: number | null; dot: string;
  defaultOpen?: boolean; focused?: boolean; focusNonce?: number; children: React.ReactNode;
}) {
  const [open, setOpen] = useState(defaultOpen);
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (focused) {
      setOpen(true);
      ref.current?.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  }, [focused, focusNonce]);
  return (
    <div ref={ref} id={id}
      className={cn("border rounded-xl overflow-hidden bg-white scroll-mt-2",
        focused ? "border-violet-300 ring-1 ring-violet-200" : "border-gray-200")}>
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center gap-2 px-3.5 py-2.5 bg-gray-50/60 hover:bg-gray-50 transition-colors text-left"
      >
        {open ? <ChevronDown className="w-3 h-3 text-gray-400" /> : <ChevronRight className="w-3 h-3 text-gray-400" />}
        <span className="w-1.5 h-1.5 rounded-full flex-shrink-0" style={{ background: dot }} />
        <Icon className="w-3.5 h-3.5" style={{ color: dot }} />
        <span className="text-[12px] font-bold text-gray-800">{title}</span>
        {count != null && (
          <span className="ml-auto text-[9px] font-bold px-1.5 py-0.5 rounded-full bg-gray-100 text-gray-500 tabular-nums">
            {count}
          </span>
        )}
      </button>
      {open && <div className="overflow-x-auto">{children}</div>}
    </div>
  );
}

function EmptyRow({ text }: { text: string }) {
  return <div className="px-4 py-6 text-center text-[11px] text-gray-400">{text}</div>;
}

function tableBody(all: Row[], shown: Row[], emptyText: string, render: () => React.ReactNode) {
  if (all.length === 0) return <EmptyRow text={emptyText} />;
  if (shown.length === 0) return <EmptyRow text="No rows match the current filter" />;
  return render();
}

// ── Editor Extensions ───────────────────────────────────────────────────────
function extIsRisky(r: Row) {
  return truthy(r.interesting) || truthy(r.unknown_publisher) || truthy(r.auto_activates) || !truthy(r.manifest_valid);
}
function EditorExtensions({ cap, filter }: { cap: Row; filter: DevSecFilter }) {
  const items = asArr(cap.items);
  const truncated = truthy(cap.truncated);
  if (items.length === 0) {
    const cli = asArr(cap.cli_inventory).flatMap(inv =>
      (Array.isArray(inv.extensions) ? (inv.extensions as string[]) : []).map(e => ({
        editor: inv.editor, user: inv.user, id: e,
      })),
    );
    const shown = cli.filter(r => matchesSearch(filter, r.id, r.editor, r.user));
    return tableBody(cli, filter.riskOnly ? [] : shown, "No editor extensions found", () => (
      <table className="w-full text-xs">
        <thead><tr className="border-b border-gray-100 bg-gray-50/60"><Th>Editor</Th><Th>User</Th><Th>Extension (id@version)</Th></tr></thead>
        <tbody>
          {shown.map((r, i) => (
            <tr key={i} className="hover:bg-orange-50/20 transition-colors">
              <Td v={r.editor} /><Td v={r.user} /><Td v={r.id} mono />
            </tr>
          ))}
        </tbody>
      </table>
    ));
  }
  const shown = items.filter(r =>
    matchesSearch(filter, r.id, r.publisher, r.editor, r.version, r.directory)
    && (!filter.riskOnly || extIsRisky(r)));
  return (
    <>
      {tableBody(items, shown, "No editor extensions found", () => (
        <table className="w-full text-xs">
          <thead>
            <tr className="border-b border-gray-100 bg-gray-50/60">
              <Th>Extension</Th><Th>Editor</Th><Th>Version</Th><Th>Publisher</Th><Th>Flags</Th>
            </tr>
          </thead>
          <tbody>
            {shown.map((r, i) => {
              const interesting = truthy(r.interesting);
              return (
                <tr key={i} className={cn("hover:bg-orange-50/20 transition-colors", interesting && "bg-orange-50/10")}>
                  <Td v={r.id ?? r.directory} danger={interesting} />
                  <Td v={r.editor} />
                  <Td v={r.version} mono />
                  <Td v={r.publisher} />
                  <td className="px-3 py-2 border-b border-gray-50">
                    <div className="flex flex-wrap gap-1">
                      <Flag v={interesting} label="AI/agent" tone="orange" />
                      <Flag v={r.auto_activates} label="auto-activates" tone="amber" />
                      <Flag v={r.unknown_publisher} label="unknown publisher" tone="red" />
                      <Flag v={r.installed_from_vsix} label="VSIX" tone="amber" />
                      <Flag v={truthy(r.manifest_valid) ? false : true} label="invalid manifest" tone="red" />
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      ))}
      {truncated && <div className="px-3 py-1.5 text-[9px] text-amber-600 bg-amber-50/50 border-t border-amber-100">List truncated by collector cap</div>}
    </>
  );
}

// ── MCP Servers ─────────────────────────────────────────────────────────────
function mcpIsRisky(r: Row) {
  return truthy(r.uses_latest) || truthy(r.uses_unpinned_ephemeral_runner);
}
function McpServers({ cap, filter }: { cap: Row; filter: DevSecFilter }) {
  const servers = asArr(cap.servers);
  const configs = asArr(cap.configs);
  const truncated = truthy(cap.truncated);
  if (servers.length === 0) {
    if (configs.length > 0 && !filter.riskOnly) {
      const shown = configs.filter(c => matchesSearch(filter, c.path, c.format));
      return tableBody(configs, shown, "No MCP servers configured", () => (
        <table className="w-full text-xs">
          <thead><tr className="border-b border-gray-100 bg-gray-50/60"><Th>Config File</Th><Th>Format</Th><Th>Servers</Th><Th>Parsed</Th></tr></thead>
          <tbody>
            {shown.map((c, i) => (
              <tr key={i} className="hover:bg-orange-50/20 transition-colors">
                <Td v={c.path} mono /><Td v={c.format} /><Td v={c.server_count} mono />
                <td className="px-3 py-2 border-b border-gray-50"><Flag v={c.parsed} label="parsed" tone="green" /></td>
              </tr>
            ))}
          </tbody>
        </table>
      ));
    }
    return <EmptyRow text="No MCP servers configured" />;
  }
  const shown = servers.filter(r => {
    const args = Array.isArray(r.args) ? (r.args as unknown[]).join(" ") : "";
    return matchesSearch(filter, r.name, r.command, args, r.config_path)
      && (!filter.riskOnly || mcpIsRisky(r));
  });
  return (
    <>
      {tableBody(servers, shown, "No MCP servers configured", () => (
        <table className="w-full text-xs">
          <thead>
            <tr className="border-b border-gray-100 bg-gray-50/60">
              <Th>Name</Th><Th>Command</Th><Th>Args</Th><Th>Env keys</Th><Th>Config</Th><Th>Flags</Th>
            </tr>
          </thead>
          <tbody>
            {shown.map((r, i) => {
              const risky = mcpIsRisky(r);
              const args = Array.isArray(r.args) ? (r.args as unknown[]).join(" ") : "";
              const envKeys = Array.isArray(r.env_keys) ? (r.env_keys as unknown[]).length : 0;
              return (
                <tr key={i} className={cn("hover:bg-orange-50/20 transition-colors", risky && "bg-red-50/10")}>
                  <Td v={r.name} danger={risky} />
                  <Td v={r.command} mono />
                  <Td v={args} mono />
                  <Td v={envKeys} mono />
                  <Td v={r.config_path} mono />
                  <td className="px-3 py-2 border-b border-gray-50">
                    <div className="flex flex-wrap gap-1">
                      <Flag v={r.uses_latest} label="@latest" tone="red" />
                      <Flag v={r.uses_unpinned_ephemeral_runner} label="unpinned npx/uvx" tone="red" />
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      ))}
      {truncated && <div className="px-3 py-1.5 text-[9px] text-amber-600 bg-amber-50/50 border-t border-amber-100">List truncated by collector cap</div>}
    </>
  );
}

// ── Browser Extensions ──────────────────────────────────────────────────────
function browserIsRisky(r: Row) {
  const dperms = Array.isArray(r.dangerous_permissions) ? (r.dangerous_permissions as string[]) : [];
  return dperms.length > 0 || truthy(r.native_messaging);
}
function BrowserExtensions({ cap, filter }: { cap: Row; filter: DevSecFilter }) {
  const items = asArr(cap.items);
  const shown = items.filter(r =>
    matchesSearch(filter, r.name, r.browser, r.user) && (!filter.riskOnly || browserIsRisky(r)));
  return tableBody(items, shown, "No browser extensions found", () => (
    <table className="w-full text-xs">
      <thead>
        <tr className="border-b border-gray-100 bg-gray-50/60">
          <Th>Name</Th><Th>Browser</Th><Th>User</Th><Th>Version</Th><Th>Dangerous perms</Th>
        </tr>
      </thead>
      <tbody>
        {shown.map((r, i) => {
          const dperms = Array.isArray(r.dangerous_permissions) ? (r.dangerous_permissions as string[]) : [];
          const nm = truthy(r.native_messaging);
          return (
            <tr key={i} className={cn("hover:bg-orange-50/20 transition-colors", (dperms.length > 0 || nm) && "bg-red-50/10")}>
              <Td v={r.name} danger={dperms.length > 0 || nm} />
              <Td v={r.browser} />
              <Td v={r.user} />
              <Td v={r.version} mono />
              <td className="px-3 py-2 border-b border-gray-50">
                <div className="flex flex-wrap gap-1">
                  {dperms.slice(0, 6).map((p, j) => <Flag key={j} v={true} label={p} tone="red" />)}
                  <Flag v={nm} label="nativeMessaging" tone="red" />
                  {dperms.length === 0 && !nm && <span className="text-[10px] text-gray-400">—</span>}
                </div>
              </td>
            </tr>
          );
        })}
      </tbody>
    </table>
  ));
}

// ── Listening Ports ─────────────────────────────────────────────────────────
function Listeners({ cap, filter }: { cap: Row; filter: DevSecFilter }) {
  const items = asArr(cap.items);
  const shown = items.filter(r =>
    matchesSearch(filter, r.process, r.endpoint, r.port)
    && (!filter.riskOnly || truthy(r.wildcard) || truthy(r.interesting)));
  return tableBody(items, shown, "No listeners", () => (
    <table className="w-full text-xs">
      <thead>
        <tr className="border-b border-gray-100 bg-gray-50/60">
          <Th>Process</Th><Th>PID</Th><Th>Endpoint</Th><Th>Port</Th><Th>Exposure</Th>
        </tr>
      </thead>
      <tbody>
        {shown.map((r, i) => (
          <tr key={i} className={cn("hover:bg-orange-50/20 transition-colors", truthy(r.wildcard) && "bg-amber-50/10")}>
            <Td v={r.process} danger={truthy(r.interesting)} />
            <Td v={r.pid} mono />
            <Td v={r.endpoint} mono />
            <Td v={r.port} mono />
            <td className="px-3 py-2 border-b border-gray-50">
              {truthy(r.wildcard)
                ? <Flag v={true} label="all-interfaces" tone="amber" />
                : <span className="text-[10px] text-gray-400">localhost</span>}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  ));
}

// ── CLI tools ───────────────────────────────────────────────────────────────
function CliTools({ cap, filter }: { cap: Row; filter: DevSecFilter }) {
  const found = asArr(cap.items).filter(r => truthy(r.found));
  const shown = found.filter(r =>
    matchesSearch(filter, r.command, r.resolved) && (!filter.riskOnly || truthy(r.shadowed)));
  return tableBody(found, shown, "No AI/agent CLI tools found on PATH", () => (
    <table className="w-full text-xs">
      <thead>
        <tr className="border-b border-gray-100 bg-gray-50/60"><Th>Command</Th><Th>Resolved path</Th><Th>Shadowed</Th></tr>
      </thead>
      <tbody>
        {shown.map((r, i) => (
          <tr key={i} className="hover:bg-orange-50/20 transition-colors">
            <Td v={r.command} />
            <Td v={r.resolved} mono />
            <td className="px-3 py-2 border-b border-gray-50"><Flag v={r.shadowed} label="shadowed" tone="amber" /></td>
          </tr>
        ))}
      </tbody>
    </table>
  ));
}

// ── Generic capability (auto-table for the long-tail capabilities) ───────────
function firstArray(cap: Row): unknown[] | null {
  for (const v of Object.values(cap)) if (Array.isArray(v) && v.length) return v;
  return null;
}
function GenericCapability({ cap, itemsKey, filter }: { cap: Row; itemsKey?: string; filter: DevSecFilter }) {
  const primary = (itemsKey && Array.isArray(cap[itemsKey]) && (cap[itemsKey] as unknown[]).length)
    ? (cap[itemsKey] as unknown[])
    : firstArray(cap);

  if (primary && typeof primary[0] === "object" && primary[0] !== null) {
    const rows = asArr(primary);
    const cols = [...new Set(rows.flatMap(r => Object.keys(r)))].slice(0, 6);
    const shown = rows.filter(r => matchesSearch(filter, ...Object.values(r)));
    return tableBody(rows, shown, "No records", () => (
      <table className="w-full text-xs">
        <thead><tr className="border-b border-gray-100 bg-gray-50/60">{cols.map(c => <Th key={c}>{c}</Th>)}</tr></thead>
        <tbody>
          {shown.map((r, i) => (
            <tr key={i} className="hover:bg-orange-50/20 transition-colors">{cols.map(c => <Td key={c} v={r[c]} mono />)}</tr>
          ))}
        </tbody>
      </table>
    ));
  }
  if (primary && primary.length) {
    // array of scalars (e.g. homebrew formulae/casks)
    const vals = (primary as unknown[]).map(str).filter(v => matchesSearch(filter, v));
    if (vals.length === 0) return <EmptyRow text="No rows match the current filter" />;
    return (
      <div className="flex flex-wrap gap-1.5 p-3">
        {vals.slice(0, 400).map((v, i) => (
          <span key={i} className="text-[10px] font-mono text-gray-600 bg-gray-100 px-1.5 py-0.5 rounded">{v}</span>
        ))}
      </div>
    );
  }
  // dict-only capability: show scalar key/values, arrays as counts
  const entries = Object.entries(cap).filter(([k]) => k !== "status");
  if (entries.length === 0) return <EmptyRow text="Not collected in this snapshot" />;
  return (
    <table className="w-full text-xs">
      <tbody>
        {entries.map(([k, v]) => (
          <tr key={k} className="border-b border-gray-50">
            <td className="px-3 py-2 text-[11px] font-semibold text-gray-600 w-56 whitespace-nowrap">{k}</td>
            <td className="px-3 py-2 text-[11px] font-mono text-gray-700">
              {Array.isArray(v) ? `${v.length} items` : typeof v === "object" && v ? JSON.stringify(v) : str(v)}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

// ── Capability catalogue (order + presentation + which have bespoke tables) ──
type Bespoke = "editor_extensions" | "mcp_servers" | "browser_extensions" | "listening_ports" | "agent_cli_tools";
interface CapMeta { key: string; label: string; icon: React.ElementType; dot: string; itemsKey?: string; hero?: boolean }
const CAP_CATALOG: CapMeta[] = [
  { key: "editor_extensions",   label: "Editor Extensions",    icon: Puzzle,        dot: "#E8581A", itemsKey: "items",      hero: true },
  { key: "mcp_servers",         label: "MCP Servers",          icon: Server,        dot: "#8b5cf6", itemsKey: "servers",    hero: true },
  { key: "browser_extensions",  label: "Browser Extensions",   icon: Globe,         dot: "#6366f1", itemsKey: "items" },
  { key: "native_messaging",    label: "Native Messaging",     icon: MessageSquare, dot: "#0ea5e9", itemsKey: "items" },
  { key: "agent_cli_tools",     label: "AI / Agent CLI Tools", icon: Terminal,      dot: "#3b82f6", itemsKey: "items" },
  { key: "ai_applications",     label: "AI Applications",      icon: Boxes,         dot: "#a855f7", itemsKey: "items" },
  { key: "listening_ports",     label: "Listening Ports",      icon: Radio,         dot: "#f59e0b", itemsKey: "items" },
  { key: "processes",           label: "Processes",            icon: Cpu,           dot: "#3b82f6", itemsKey: "items" },
  { key: "launchd",             label: "LaunchDaemons",        icon: Zap,           dot: "#ef4444", itemsKey: "items" },
  { key: "cron",                label: "Cron Jobs",            icon: Clock,         dot: "#d97706", itemsKey: "users" },
  { key: "shell_startup",       label: "Shell Startup",        icon: FileText,      dot: "#9ca3af", itemsKey: "files" },
  { key: "node_packages",       label: "Node Packages",        icon: Package,       dot: "#10b981", itemsKey: "users" },
  { key: "python_packages",     label: "Python Packages",      icon: Package,       dot: "#10b981", itemsKey: "users" },
  { key: "homebrew",            label: "Homebrew",             icon: Boxes,         dot: "#f59e0b" },
  { key: "git",                 label: "Git",                  icon: GitBranch,     dot: "#6b7280", itemsKey: "users" },
  { key: "credential_locations", label: "Credential Locations", icon: KeyRound,     dot: "#dc2626", itemsKey: "locations" },
  { key: "docker",              label: "Docker",               icon: Container,     dot: "#06b6d4", itemsKey: "containers" },
];
const BESPOKE: Record<Bespoke, (p: { cap: Row; filter: DevSecFilter }) => React.ReactNode> = {
  editor_extensions:  EditorExtensions,
  mcp_servers:        McpServers,
  browser_extensions: BrowserExtensions,
  listening_ports:    Listeners,
  agent_cli_tools:    CliTools,
};

function capCount(cap: Row, meta: CapMeta): number {
  if (meta.key === "homebrew") {
    return (Array.isArray(cap.formulae) ? cap.formulae.length : 0) + (Array.isArray(cap.casks) ? cap.casks.length : 0);
  }
  if (typeof cap.count === "number") return cap.count as number;
  if (meta.itemsKey && Array.isArray(cap[meta.itemsKey])) return (cap[meta.itemsKey] as unknown[]).length;
  return 0;
}

// ── main ────────────────────────────────────────────────────────────────────
export default function DevSecurityView({ data, filter = NO_FILTER, focus, focusNonce }: {
  data: unknown; filter?: DevSecFilter; focus?: string; focusNonce?: number;
}) {
  const snap = asObj(data);
  const caps = asObj(snap.capabilities);
  const collection = asObj(snap.collection);

  if (Object.keys(caps).length === 0) {
    return (
      <pre className="text-[11px] font-mono text-gray-700 p-3 whitespace-pre-wrap break-words">
        {JSON.stringify(data, null, 2)}
      </pre>
    );
  }

  const partial = truthy(collection.partial);
  const errCount = asArr(collection.errors).length;
  const cnt = (key: string) => {
    const c = asObj(caps[key]);
    const meta = CAP_CATALOG.find(m => m.key === key)!;
    return Object.keys(c).length ? capCount(c, meta) : 0;
  };

  return (
    <div className="space-y-3 p-3">
      {/* Summary chips */}
      <div className="flex flex-wrap gap-2">
        <Chip icon={Puzzle} label="Editor Ext" value={cnt("editor_extensions")} tone={asArr(asObj(caps.editor_extensions).items).some(r => truthy(r.interesting)) ? "orange" : "gray"} />
        <Chip icon={Server} label="MCP Servers" value={cnt("mcp_servers")} tone={asArr(asObj(caps.mcp_servers).servers).some(mcpIsRisky) ? "red" : "gray"} />
        <Chip icon={Globe} label="Browser Ext" value={cnt("browser_extensions")} />
        <Chip icon={Radio} label="Listeners" value={cnt("listening_ports")} />
        <Chip icon={Terminal} label="CLI Tools" value={asArr(asObj(caps.agent_cli_tools).items).filter(r => truthy(r.found)).length} />
        {snap.platform ? <Chip icon={Boxes} label="Platform" value={str(snap.platform)} /> : null}
        {partial
          ? <Chip icon={AlertTriangle} label="Collection" value={`partial · ${errCount} err`} tone="red" />
          : <Chip icon={ShieldAlert} label="Collection" value="complete" tone="green" />}
      </div>

      {filter.riskOnly && (
        <div className="text-[10px] font-semibold text-red-600 bg-red-50 border border-red-100 rounded-lg px-2.5 py-1 inline-flex items-center gap-1.5">
          <ShieldAlert className="w-3 h-3" /> Showing risk-flagged items only (risk-scored capabilities)
        </div>
      )}

      {/* One anchored panel per capability */}
      {CAP_CATALOG.map(meta => {
        const cap = asObj(caps[meta.key]);
        const present = Object.keys(cap).length > 0;
        const capError = str(cap.error);
        const BespokeFn = BESPOKE[meta.key as Bespoke];
        return (
          <Panel key={meta.key} id={anchorId(meta.key)} icon={meta.icon} title={meta.label}
            dot={meta.dot} count={present ? capCount(cap, meta) : null}
            defaultOpen={!!meta.hero} focused={focus === meta.key} focusNonce={focusNonce}>
            {!present ? <EmptyRow text="Not collected in this snapshot" />
              : capError ? <EmptyRow text={`Collector error: ${capError}`} />
              : BespokeFn ? <BespokeFn cap={cap} filter={filter} />
              : <GenericCapability cap={cap} itemsKey={meta.itemsKey} filter={filter} />}
          </Panel>
        );
      })}

      {(partial || errCount > 0) && (
        <div className="rounded-xl border border-amber-200 bg-amber-50/50 px-3.5 py-2.5">
          <div className="flex items-center gap-2 text-[11px] font-semibold text-amber-700">
            <AlertTriangle className="w-3.5 h-3.5" /> Collection was partial
            {collection.duration_ms != null && (
              <span className="text-amber-500 font-normal">· {str(collection.duration_ms)}ms</span>
            )}
          </div>
          {errCount > 0 && (
            <div className="mt-1 text-[10px] font-mono text-amber-600 space-y-0.5">
              {asArr(collection.errors).slice(0, 8).map((e, i) => (
                <div key={i}>{str(e.capability)}: {str(e.error)}</div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// Exported so the DeepMesh section nav lists the same capabilities in the same
// order, with matching icon + accent colour.
export const DEVSEC_CAPABILITIES = CAP_CATALOG.map(({ key, label, dot, icon }) => ({ key, label, dot, icon }));
