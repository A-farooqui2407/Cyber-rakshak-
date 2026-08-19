import React from "react";
import {
  ShieldAlert,
  LayoutDashboard,
  Terminal,
  BellRing,
  AlertOctagon,
  Cpu,
  Activity,
  Bot,
  Settings,
  Flame,
  ChevronRight,
} from "lucide-react";
import { useAuth } from "../../context/AuthContext";

interface SidebarProps {
  currentTab: string;
  onSelectTab: (tab: string) => void;
  onOpenSimulation: () => void;
}

export const Sidebar: React.FC<SidebarProps> = ({
  currentTab,
  onSelectTab,
  onOpenSimulation,
}) => {
  const { role, organization } = useAuth();

  const navItems = [
    { id: "dashboard", label: "SOC Dashboard", icon: LayoutDashboard },
    { id: "logs", label: "Live Logs Stream", icon: Terminal },
    { id: "alerts", label: "Security Alerts", icon: BellRing },
    { id: "incidents", label: "Incidents Queue", icon: AlertOctagon },
    { id: "detection", label: "Detection Engine", icon: Cpu },
    { id: "risk", label: "Risk Analysis", icon: Activity },
    { id: "ai", label: "AI SOC Assistant", icon: Bot, badge: "Gemini 3.7" },
    { id: "settings", label: "SOC Settings", icon: Settings },
  ];

  return (
    <aside className="w-64 bg-slate-950 border-r border-slate-800/80 flex flex-col h-screen select-none shrink-0">
      {/* Brand Header */}
      <div className="p-4 border-b border-slate-800/80 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-cyan-500 via-blue-600 to-indigo-700 flex items-center justify-center shadow-[0_0_15px_rgba(6,182,212,0.3)]">
            <ShieldAlert className="w-5 h-5 text-white" />
          </div>
          <div>
            <div className="flex items-center gap-1.5">
              <span className="font-bold text-base text-slate-100 tracking-tight">CyberRakshak</span>
            </div>
            <span className="text-[10px] uppercase tracking-wider text-cyan-400 font-mono">SOC-in-a-Box</span>
          </div>
        </div>
      </div>

      {/* Organization Badge */}
      <div className="px-4 py-2.5 bg-slate-900/60 border-b border-slate-800/50 flex items-center justify-between text-xs">
        <div className="truncate">
          <span className="text-slate-400 text-[10px] block">MONITORED ORG</span>
          <span className="text-slate-200 font-medium truncate">{organization}</span>
        </div>
        <div className="flex items-center gap-1">
          <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse shadow-[0_0_8px_#10b981]" />
          <span className="text-[10px] text-emerald-400 font-mono">LIVE</span>
        </div>
      </div>

      {/* Navigation Links */}
      <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto">
        <div className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider px-3 mb-2">
          Operations
        </div>
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = currentTab === item.id;
          return (
            <button
              key={item.id}
              onClick={() => onSelectTab(item.id)}
              className={`w-full flex items-center justify-between px-3 py-2.5 rounded-lg text-xs font-medium transition-all ${
                isActive
                  ? "bg-cyan-500/15 text-cyan-300 border border-cyan-500/30 shadow-[0_0_12px_rgba(6,182,212,0.15)] font-semibold"
                  : "text-slate-400 hover:text-slate-200 hover:bg-slate-900/60"
              }`}
            >
              <div className="flex items-center gap-3">
                <Icon
                  className={`w-4 h-4 ${
                    isActive ? "text-cyan-400" : "text-slate-400 group-hover:text-slate-300"
                  }`}
                />
                <span>{item.label}</span>
              </div>
              {item.badge && (
                <span className="px-1.5 py-0.5 text-[9px] font-mono font-bold uppercase rounded bg-cyan-950 text-cyan-300 border border-cyan-800/60">
                  {item.badge}
                </span>
              )}
            </button>
          );
        })}
      </nav>

      {/* Attack Simulation Call to Action */}
      <div className="p-3 border-t border-slate-800/80 bg-slate-950/90">
        <button
          onClick={onOpenSimulation}
          disabled={role !== "ADMIN"}
          title={role !== "ADMIN" ? "Only ADMIN can run attack simulations" : "Simulate Multi-Stage Attack"}
          className={`w-full relative group overflow-hidden rounded-lg p-3 text-left transition-all border ${
            role !== "ADMIN"
              ? "opacity-50 cursor-not-allowed bg-slate-900 border-slate-800"
              : "bg-gradient-to-r from-red-950/70 via-orange-950/60 to-red-950/70 hover:from-red-900/80 hover:to-orange-900/80 border-red-700/60 hover:border-red-500/80 shadow-[0_0_15px_rgba(239,68,68,0.2)]"
          }`}
        >
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="p-1.5 rounded-md bg-red-600/30 text-red-400">
                <Flame className="w-4 h-4 text-red-400 animate-pulse" />
              </span>
              <div>
                <div className="text-xs font-bold text-red-200 group-hover:text-white">Run Attack Demo</div>
                <div className="text-[10px] text-red-400/80">20 Fails → Breach → 95 Risk</div>
              </div>
            </div>
            <ChevronRight className="w-4 h-4 text-red-400 group-hover:translate-x-0.5 transition-transform" />
          </div>
        </button>
      </div>
    </aside>
  );
};
