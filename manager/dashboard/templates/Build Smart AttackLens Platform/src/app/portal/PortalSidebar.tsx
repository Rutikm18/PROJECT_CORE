/**
 * PortalSidebar — the customer's navigation rail.
 *
 * A structural mirror of the operator Sidebar: same groups, same rail, same
 * tokens, same collapse behaviour. What differs is which entries appear, and
 * that difference is driven by the server's capability map rather than by
 * anything the browser decides.
 *
 * Two entries are absent on purpose and it is worth saying why rather than
 * leaving it to be discovered:
 *
 *   Custom Rules — detection logic is fleet-wide, so it is operator-only by
 *   nature rather than by omission, and there is no customer equivalent.
 *
 * Deep Analysis and DeepMesh read raw telemetry, which is the customer's own
 * data: the endpoints are scoped per tenant, so both appear here gated on the
 * view_raw_telemetry capability.
 */
import { NavLink } from "react-router";
import {
  AlertTriangle, BarChart3, Crosshair, Database, Globe, Layers, LayoutDashboard,
  Monitor, PackageOpen, Radio, Settings, ShieldAlert, ShieldCheck, Terminal,
} from "lucide-react";
import { cn } from "../../lib/utils";

export interface PortalNavEntry {
  label: string;
  to: string;
  icon: React.ElementType;
  capability?: string;
}

export interface PortalNavGroup {
  label: string;
  items: PortalNavEntry[];
}

/** Mirrors the operator sidebar's grouping so the two read as one product. */
export const PORTAL_GROUPS: PortalNavGroup[] = [
  {
    label: "Operations",
    items: [
      { label: "Dashboard",          to: "/portal",           icon: LayoutDashboard },
      { label: "Validated Findings", to: "/portal/findings",  icon: AlertTriangle, capability: "view_findings" },
      { label: "All Incidents",      to: "/portal/incidents", icon: Layers,        capability: "view_findings" },
    ],
  },
  {
    label: "Attack Terrain",
    items: [
      { label: "Origin",   to: "/portal/terrain/origin",   icon: PackageOpen, capability: "view_findings" },
      { label: "Vector",   to: "/portal/terrain/vector",   icon: Globe,       capability: "view_findings" },
      { label: "Citadels", to: "/portal/terrain/citadels", icon: Terminal,    capability: "view_findings" },
      { label: "Mesh",     to: "/portal/terrain/mesh",     icon: Radio,       capability: "view_findings" },
      { label: "Identity", to: "/portal/terrain/identity", icon: ShieldCheck, capability: "view_findings" },
      { label: "Posture",  to: "/portal/terrain/posture",  icon: ShieldAlert, capability: "view_posture" },
    ],
  },
  {
    label: "Intelligence",
    items: [
      { label: "Threat Intelligence", to: "/portal/intelligence", icon: Crosshair, capability: "view_reports" },
    ],
  },
  {
    label: "Inventory & Analysis",
    items: [
      { label: "Timeline & History", to: "/portal/timeline", icon: BarChart3, capability: "view_findings" },
      { label: "Deep Analysis",      to: "/portal/analysis", icon: Database,  capability: "view_raw_telemetry" },
      { label: "DeepMesh",           to: "/portal/deepmesh", icon: Radio,     capability: "view_raw_telemetry" },
      { label: "Asset Registry",     to: "/portal/agents",   icon: Monitor,   capability: "view_findings" },
    ],
  },
  {
    label: "Configuration",
    items: [
      { label: "Settings", to: "/portal/settings", icon: Settings, capability: "configure_dashboard" },
    ],
  },
];

/**
 * Groups filtered by the server's capability map, with empty groups dropped.
 * An undefined map means /auth/me has not answered — offer only the dashboard
 * rather than flashing links the customer may not be allowed to use.
 */
export function visibleGroups(
  capabilities: Record<string, boolean> | undefined,
): PortalNavGroup[] {
  return PORTAL_GROUPS
    .map(group => ({
      ...group,
      items: group.items.filter(
        item => !item.capability || Boolean(capabilities?.[item.capability]),
      ),
    }))
    .filter(group => group.items.length > 0);
}

export function PortalSidebar({
  capabilities, orgName, collapsed = false, mobileOpen = true, onNavigate,
}: {
  capabilities: Record<string, boolean> | undefined;
  orgName: string;
  collapsed?: boolean;
  mobileOpen?: boolean;
  onNavigate?: () => void;
}) {
  const groups = visibleGroups(capabilities);

  return (
    <aside
      className={cn(
        "flex flex-col bg-[#12131A] text-white flex-shrink-0 transition-all duration-200 z-50",
        collapsed ? "w-[64px]" : "w-[232px]",
        "max-md:fixed max-md:inset-y-0 max-md:left-0",
        mobileOpen ? "max-md:translate-x-0" : "max-md:-translate-x-full",
      )}
    >
      <div className={cn("flex items-center gap-2.5 px-4 py-4 border-b border-white/5", collapsed && "justify-center px-2")}>
        <div className="w-8 h-8 rounded-xl flex items-center justify-center flex-shrink-0"
          style={{
            background: "linear-gradient(135deg,rgba(124,58,237,0.25),rgba(139,92,246,0.35))",
            border: "1px solid rgba(139,92,246,0.4)",
          }}>
          <ShieldCheck className="w-4 h-4 text-purple-300" />
        </div>
        {!collapsed && (
          <div className="min-w-0">
            <div className="text-[12px] font-bold truncate">{orgName}</div>
            <div className="text-[8px] text-white/40 uppercase tracking-[0.14em]">Security Portal</div>
          </div>
        )}
      </div>

      <nav className="flex-1 overflow-y-auto py-3">
        {groups.map(group => (
          <div key={group.label} className="mb-3">
            {!collapsed && (
              <div className="px-4 pb-1.5 text-[8px] font-bold text-white/30 uppercase tracking-[0.14em]">
                {group.label}
              </div>
            )}
            {group.items.map(item => (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.to === "/portal"}
                onClick={onNavigate}
                className={({ isActive }) => cn(
                  "flex items-center gap-2.5 mx-2 px-2.5 py-2 rounded-xl text-[11.5px] font-medium transition-all",
                  collapsed && "justify-center",
                  isActive
                    ? "bg-purple-600/25 text-white border border-purple-500/40"
                    : "text-white/55 hover:text-white hover:bg-white/5 border border-transparent",
                )}
                title={collapsed ? item.label : undefined}
              >
                <item.icon className="w-4 h-4 flex-shrink-0" />
                {!collapsed && <span className="truncate">{item.label}</span>}
              </NavLink>
            ))}
          </div>
        ))}
      </nav>

      {!collapsed && (
        <div className="px-4 py-3 border-t border-white/5">
          <div className="text-[8px] text-white/30 leading-relaxed">
            Read-only view of your own endpoints
          </div>
        </div>
      )}
    </aside>
  );
}
