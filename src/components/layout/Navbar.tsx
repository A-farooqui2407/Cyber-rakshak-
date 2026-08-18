import React, { useState } from "react";
import {
  Bell,
  Search,
  Shield,
  User,
  LogOut,
  ChevronDown,
  Building,
  RefreshCw,
} from "lucide-react";
import { useAuth } from "../../context/AuthContext";
import { RoleBadge } from "../ui/Badge";
import { UserRole } from "../../types";

interface NavbarProps {
  onSearch?: (query: string) => void;
  onRefresh?: () => void;
  criticalAlertCount?: number;
}

export const Navbar: React.FC<NavbarProps> = ({
  onSearch,
  onRefresh,
  criticalAlertCount = 0,
}) => {
  const { user, role, switchRole, organization, switchOrganization, logout } = useAuth();
  const [showRoleDropdown, setShowRoleDropdown] = useState(false);
  const [showOrgDropdown, setShowOrgDropdown] = useState(false);

  const orgs = ["LexGuard Law Associates", "St. Jude Memorial Hospital", "Apex Financial Partners"];

  return (
    <header className="h-16 bg-slate-950/90 backdrop-blur-md border-b border-slate-800/80 px-6 flex items-center justify-between sticky top-0 z-30">
      {/* Left: Search & Live SOC Indicator */}
      <div className="flex items-center gap-6">
        <div className="flex items-center gap-2 px-3 py-1 rounded-full bg-emerald-950/50 border border-emerald-800/40">
          <span className="w-2 h-2 rounded-full bg-emerald-400 animate-ping" />
          <span className="text-xs font-semibold text-emerald-300 tracking-wide">Monitoring Active</span>
        </div>

        <div className="relative w-80">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Search IPs, users, logs, alert rules..."
            onChange={(e) => onSearch && onSearch(e.target.value)}
            className="w-full bg-slate-900/80 border border-slate-800 rounded-lg pl-9 pr-4 py-1.5 text-xs text-slate-200 placeholder-slate-400 focus:outline-none focus:border-cyan-500/60 focus:ring-1 focus:ring-cyan-500/30 transition-all"
          />
        </div>
      </div>

      {/* Right Controls: Org Switcher, Role Tester, Refresh, Notifications, Profile */}
      <div className="flex items-center gap-3">
        {/* Quick Refresh */}
        {onRefresh && (
          <button
            onClick={onRefresh}
            title="Refresh SOC Telemetry"
            className="p-2 rounded-lg bg-slate-900 text-slate-400 hover:text-slate-200 hover:bg-slate-800 border border-slate-800 transition-colors"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
        )}

        {/* Organization Switcher */}
        <div className="relative">
          <button
            onClick={() => setShowOrgDropdown(!showOrgDropdown)}
            className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-850 border border-slate-800 text-xs text-slate-300 transition-colors"
          >
            <Building className="w-3.5 h-3.5 text-cyan-400" />
            <span className="truncate max-w-[140px] font-medium">{organization}</span>
            <ChevronDown className="w-3 h-3 text-slate-400" />
          </button>

          {showOrgDropdown && (
            <div className="absolute right-0 mt-2 w-56 bg-slate-900 border border-slate-800 rounded-lg shadow-2xl p-1 z-50">
              <div className="text-[10px] text-slate-400 px-3 py-1.5 uppercase tracking-wider font-semibold">
                Switch Monitored Tenant
              </div>
              {orgs.map((org) => (
                <button
                  key={org}
                  onClick={() => {
                    switchOrganization(org);
                    setShowOrgDropdown(false);
                  }}
                  className={`w-full text-left px-3 py-1.5 rounded text-xs transition-colors ${
                    organization === org
                      ? "bg-cyan-500/20 text-cyan-300 font-semibold"
                      : "text-slate-300 hover:bg-slate-800"
                  }`}
                >
                  {org}
                </button>
              ))}
            </div>
          )}
        </div>

        {/* Role Switcher (For Demo & Testing RBAC) */}
        <div className="relative">
          <button
            onClick={() => setShowRoleDropdown(!showRoleDropdown)}
            className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-850 border border-slate-800 text-xs text-slate-200 transition-colors"
          >
            <Shield className="w-3.5 h-3.5 text-purple-400" />
            <RoleBadge role={role} />
            <ChevronDown className="w-3 h-3 text-slate-400" />
          </button>

          {showRoleDropdown && (
            <div className="absolute right-0 mt-2 w-48 bg-slate-900 border border-slate-800 rounded-lg shadow-2xl p-1 z-50">
              <div className="text-[10px] text-slate-400 px-3 py-1.5 uppercase tracking-wider font-semibold">
                Test RBAC Permissions
              </div>
              {(["ADMIN", "ANALYST", "VIEWER"] as UserRole[]).map((r) => (
                <button
                  key={r}
                  onClick={() => {
                    switchRole(r);
                    setShowRoleDropdown(false);
                  }}
                  className={`w-full text-left px-3 py-2 rounded text-xs flex items-center justify-between transition-colors ${
                    role === r
                      ? "bg-purple-950/60 text-purple-300 font-semibold"
                      : "text-slate-300 hover:bg-slate-800"
                  }`}
                >
                  <span>{r}</span>
                  <RoleBadge role={r} />
                </button>
              ))}
            </div>
          )}
        </div>

        {/* Critical Alerts Bell */}
        <div className="relative">
          <button className="p-2 rounded-lg bg-slate-900 text-slate-300 hover:text-white hover:bg-slate-800 border border-slate-800 transition-colors relative">
            <Bell className="w-4 h-4" />
            {criticalAlertCount > 0 && (
              <span className="absolute -top-1 -right-1 w-4 h-4 rounded-full bg-red-500 text-white text-[10px] font-bold flex items-center justify-center animate-bounce shadow-[0_0_8px_#ef4444]">
                {criticalAlertCount}
              </span>
            )}
          </button>
        </div>

        {/* User Profile Pill */}
        <div className="flex items-center gap-3 pl-3 border-l border-slate-800">
          <div className="w-8 h-8 rounded-full bg-slate-800 border border-cyan-500/40 flex items-center justify-center text-cyan-400 font-bold text-xs">
            {user?.name.charAt(0) || "U"}
          </div>
          <div className="text-left hidden sm:block">
            <div className="text-xs font-semibold text-slate-200">{user?.name || "Rahul Sharma"}</div>
            <div className="text-[10px] text-slate-400 truncate max-w-[120px]">{user?.email}</div>
          </div>
          <button
            onClick={logout}
            title="Sign out of SOC"
            className="p-1.5 rounded text-slate-400 hover:text-red-400 hover:bg-slate-900 transition-colors"
          >
            <LogOut className="w-4 h-4" />
          </button>
        </div>
      </div>
    </header>
  );
};
