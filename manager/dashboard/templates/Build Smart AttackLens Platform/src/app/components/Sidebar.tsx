import {
  Home, AlertTriangle, Terminal, Globe, PackageOpen, Anchor, Users,
  ShieldCheck, GitBranch, Crosshair, Bot, BarChart3, Monitor, Database,
  ClipboardList,
} from "lucide-react";
import { cn } from "../../lib/utils";

export type PageId =
  | "command-center"
  | "threat-queue"
  | "execution"
  | "network"
  | "vulnerabilities"
  | "persistence"
  | "identity"
  | "security-posture"
  | "compliance"
  | "attack-chains"
  | "threat-intel"
  | "ai-analyst"
  | "timeline"
  | "assets"
  | "raw-data";

interface NavItem {
  id: PageId;
  label: string;
  icon: React.ElementType;
  badge?: string | number;
  badgeColor?: "red" | "amber" | "green";
}

interface NavGroup {
  label: string;
  items: NavItem[];
}

const GROUPS: NavGroup[] = [
  {
    label: "Operations",
    items: [
      { id: "command-center", label: "Command Center", icon: Home },
      { id: "threat-queue",   label: "Threat Queue",   icon: AlertTriangle, badge: 7, badgeColor: "red" },
    ],
  },
  {
    label: "Detections",
    items: [
      { id: "execution",      label: "Execution & Malware",     icon: Terminal,    badge: 3, badgeColor: "red"   },
      { id: "network",        label: "Network Threats",         icon: Globe,       badge: 2, badgeColor: "red"   },
      { id: "vulnerabilities",label: "Vulnerability Surface",   icon: PackageOpen, badge: 8, badgeColor: "amber" },
      { id: "persistence",    label: "Persistence & Backdoors", icon: Anchor,      badge: 4, badgeColor: "amber" },
      { id: "identity",       label: "Identity & Access",       icon: Users,       badge: 3, badgeColor: "amber" },
    ],
  },
  {
    label: "Posture",
    items: [
      { id: "security-posture", label: "Security Posture", icon: ShieldCheck, badge: 4, badgeColor: "red"   },
      { id: "compliance",       label: "CIS Compliance",   icon: ClipboardList },
    ],
  },
  {
    label: "Intelligence",
    items: [
      { id: "attack-chains", label: "Attack Chains",      icon: GitBranch,  badge: 4, badgeColor: "red"  },
      { id: "threat-intel",  label: "Threat Intelligence",icon: Crosshair                                 },
      { id: "ai-analyst",    label: "AI Analyst",         icon: Bot                                       },
    ],
  },
  {
    label: "Management",
    items: [
      { id: "timeline",  label: "Timeline & History", icon: BarChart3 },
      { id: "assets",    label: "Asset Registry",     icon: Monitor   },
      { id: "raw-data",  label: "Raw Data",            icon: Database  },
    ],
  },
];

const BADGE_COLORS = {
  red:   "bg-[--red-600] text-white",
  amber: "bg-[--amber-500] text-white",
  green: "bg-[--green-600] text-white",
};

interface SidebarProps {
  activePage: PageId;
  onNavigate: (page: PageId) => void;
}

export function Sidebar({ activePage, onNavigate }: SidebarProps) {
  return (
    <div className="w-56 h-screen bg-gradient-to-b from-[--gray-25] to-[--gray-50] border-r border-[--gray-200] flex flex-col shadow-lg flex-shrink-0">

      {/* Logo */}
      <div className="p-4 pb-3 border-b border-[--gray-200]/50">
        <div className="flex items-center gap-2">
          <div className="w-7 h-7 bg-gradient-orange rounded-md flex items-center justify-center shadow-md">
            <div className="text-white font-bold text-sm">A</div>
          </div>
          <div className="text-sm">
            <span className="font-bold text-[--gray-900]">attack</span>
            <span className="font-bold text-[--brand-orange]">lens</span>
            <span className="text-[--gray-400]">.ai</span>
          </div>
        </div>
        <div className="mt-3 flex items-center gap-2 px-2 py-1.5 bg-white rounded-md border border-[--gray-200] shadow-sm">
          <div className="w-2 h-2 rounded-full bg-[--green-600] animate-pulse shadow-sm" />
          <span className="text-[10px] font-medium text-[--gray-600] truncate">endpoint-macpro-01</span>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 overflow-y-auto px-2 py-3 space-y-3">
        {GROUPS.map(group => (
          <div key={group.label}>
            <div className="px-2 mb-1 text-[9px] font-bold text-[--gray-400] uppercase tracking-widest">
              {group.label}
            </div>
            {group.items.map(item => {
              const Icon = item.icon;
              const isActive = activePage === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => onNavigate(item.id)}
                  className={cn(
                    "w-full flex items-center justify-between gap-2 px-2.5 py-2 rounded-lg mb-0.5 cursor-pointer transition-all duration-150 text-left",
                    isActive
                      ? "bg-gradient-to-r from-[--brand-orange-50] to-[--brand-orange-100] text-[--brand-orange-700] border border-[--brand-orange-700]/20 shadow-sm"
                      : "text-[--gray-600] hover:bg-white hover:shadow-sm border border-transparent hover:border-[--gray-200]"
                  )}
                >
                  <div className="flex items-center gap-2">
                    <Icon className={cn("w-4 h-4 flex-shrink-0", isActive ? "text-[--brand-orange]" : "text-[--gray-400]")} />
                    <span className="text-[12px] font-medium leading-tight">{item.label}</span>
                  </div>
                  {item.badge !== undefined && (
                    <span className={cn("px-1.5 py-0.5 text-[9px] font-bold rounded-full flex-shrink-0 min-w-[18px] text-center", BADGE_COLORS[item.badgeColor ?? "amber"])}>
                      {item.badge}
                    </span>
                  )}
                </button>
              );
            })}
          </div>
        ))}
      </nav>

      {/* Footer */}
      <div className="p-3 border-t border-[--gray-200] bg-white">
        <div className="flex items-center gap-2 p-1.5 hover:bg-[--gray-50] rounded-lg cursor-pointer transition-colors">
          <div className="w-7 h-7 rounded-full bg-gradient-to-br from-[--blue-500] to-[--indigo-600] flex items-center justify-center text-[10px] font-bold text-white shadow-md flex-shrink-0">
            RM
          </div>
          <div>
            <div className="text-xs font-semibold text-[--gray-700]">Rutik M.</div>
            <div className="text-[9px] text-[--gray-400]">SOC Analyst</div>
          </div>
        </div>
      </div>
    </div>
  );
}
