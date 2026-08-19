import React, { useState } from "react";
import { Bell, Search, User, LogOut, Building, RefreshCw } from "lucide-react";
import { useAuth } from "../../context/AuthContext";
import { RoleBadge } from "../ui/Badge";

interface NavbarProps {
  onSearch?: (query: string) => void;
  onRefresh?: () => void;
  criticalAlertCount?: number;
  searchValue?: string;
}

export const Navbar: React.FC<NavbarProps> = ({
  onSearch,
  onRefresh,
  criticalAlertCount = 0,
  searchValue = "",
}) => {
  const { user, role, organization, logout } = useAuth();

  return (
    <header className="h-16 bg-slate-950/90 backdrop-blur-md border-b border-slate-800/80 px-6 flex items-center justify-between sticky top-0 z-30">
      <div className="flex items-center gap-6">
        <div className="flex items-center gap-2 px-3 py-1 rounded-full bg-emerald-950/50 border border-emerald-800/40">
          <span className="w-2 h-2 rounded-full bg-emerald-400 animate-ping" />
          <span className="text-xs font-semibold text-emerald-300 tracking-wide">Monitoring Active</span>
        </div>

        <div className="relative w-80">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={searchValue}
            placeholder="Search IPs, users, logs, alerts..."
            onChange={(e) => onSearch && onSearch(e.target.value)}
            className="w-full bg-slate-900/80 border border-slate-800 rounded-lg pl-9 pr-4 py-1.5 text-xs text-slate-200 placeholder-slate-400 focus:outline-none focus:border-cyan-500/60"
          />
        </div>
      </div>

      <div className="flex items-center gap-3">
        {onRefresh && (
          <button
            onClick={onRefresh}
            title="Refresh SOC Telemetry"
            className="p-2 rounded-lg bg-slate-900 text-slate-400 hover:text-slate-200 hover:bg-slate-800 border border-slate-800"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
        )}

        <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-xs text-slate-300">
          <Building className="w-3.5 h-3.5 text-cyan-400" />
          <span className="truncate max-w-[160px] font-medium">{organization}</span>
        </div>

        <div className="relative">
          <button className="p-2 rounded-lg bg-slate-900 text-slate-300 hover:text-white hover:bg-slate-800 border border-slate-800 relative">
            <Bell className="w-4 h-4" />
            {criticalAlertCount > 0 && (
              <span className="absolute -top-1 -right-1 min-w-4 h-4 px-1 rounded-full bg-red-500 text-white text-[10px] font-bold flex items-center justify-center">
                {criticalAlertCount}
              </span>
            )}
          </button>
        </div>

        <div className="flex items-center gap-3 pl-3 border-l border-slate-800">
          <div className="w-8 h-8 rounded-full bg-slate-800 border border-cyan-500/40 flex items-center justify-center text-cyan-400 font-bold text-xs">
            {user?.name.charAt(0) || "U"}
          </div>
          <div className="text-left hidden sm:block">
            <div className="text-xs font-semibold text-slate-200 flex items-center gap-2">
              {user?.name}
              <RoleBadge role={role} />
            </div>
            <div className="text-[10px] text-slate-400 truncate max-w-[160px]">{user?.email}</div>
          </div>
          <button onClick={logout} title="Sign out of SOC" className="p-1.5 rounded text-slate-400 hover:text-red-400">
            <LogOut className="w-4 h-4" />
          </button>
        </div>
      </div>
    </header>
  );
};
