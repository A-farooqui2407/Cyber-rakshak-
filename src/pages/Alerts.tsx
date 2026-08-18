import React, { useState, useEffect } from "react";
import {
  BellRing,
  Search,
  Filter,
  RefreshCw,
  Eye,
  CheckCircle,
  Clock,
  Sparkles,
  Bot,
  AlertTriangle,
} from "lucide-react";
import { Alert } from "../types";
import { SeverityBadge, StatusBadge } from "../components/ui/Badge";
import { api } from "../services/api";
import { useAuth } from "../context/AuthContext";

interface AlertsPageProps {
  onSelectAlert: (alert: Alert) => void;
}

export const Alerts: React.FC<AlertsPageProps> = ({ onSelectAlert }) => {
  const { role, user } = useAuth();
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState("");
  const [severityFilter, setSeverityFilter] = useState("");

  const fetchAlerts = async () => {
    setIsLoading(true);
    try {
      const data = await api.getAlerts({
        status: statusFilter || undefined,
        severity: severityFilter || undefined,
      });
      setAlerts(data);
    } catch (err) {
      console.error("Failed to load alerts", err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchAlerts();
  }, [statusFilter, severityFilter]);

  const handleQuickStatusChange = async (
    e: React.MouseEvent,
    alertId: string,
    newStatus: string
  ) => {
    e.stopPropagation();
    try {
      await api.updateAlertStatus(alertId, newStatus, user?.email);
      fetchAlerts();
    } catch (err) {
      console.error("Failed to update alert", err);
    }
  };

  const filteredAlerts = alerts.filter((a) => {
    if (!search) return true;
    const s = search.toLowerCase();
    return (
      a.title.toLowerCase().includes(s) ||
      a.username.toLowerCase().includes(s) ||
      a.source_ip.includes(s) ||
      a.threat_type.toLowerCase().includes(s)
    );
  });

  return (
    <div className="space-y-5">
      {/* Header Controls */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 p-4 rounded-xl bg-slate-900/60 border border-slate-800/80">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-red-950 text-red-400 border border-red-800/50">
            <BellRing className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-sm font-bold text-slate-100 flex items-center gap-2">
              Security Alert Triage Center
              <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-red-950 text-red-300 border border-red-800/50">
                {filteredAlerts.length} Active Alerts
              </span>
            </h2>
            <p className="text-xs text-slate-400">
              Correlated threats requiring SOC analyst investigation & response
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={fetchAlerts}
            className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors"
            title="Refresh"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Filter Bar */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
        <div className="relative">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Search alerts by title, user, IP, or threat rule..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full bg-slate-900/80 border border-slate-800 rounded-lg pl-9 pr-3 py-2 text-xs text-slate-200 placeholder-slate-400 focus:outline-none focus:border-cyan-500"
          />
        </div>

        <div>
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="w-full bg-slate-900/80 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
          >
            <option value="">All Alert Statuses</option>
            <option value="NEW">NEW</option>
            <option value="INVESTIGATING">INVESTIGATING</option>
            <option value="RESOLVED">RESOLVED</option>
            <option value="FALSE_POSITIVE">FALSE POSITIVE</option>
          </select>
        </div>

        <div>
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="w-full bg-slate-900/80 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
          >
            <option value="">All Severities</option>
            <option value="CRITICAL">CRITICAL</option>
            <option value="HIGH">HIGH</option>
            <option value="MEDIUM">MEDIUM</option>
            <option value="LOW">LOW</option>
          </select>
        </div>
      </div>

      {/* Alerts Table */}
      <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800/80 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400 font-mono text-[10px] uppercase">
                <th className="pb-2.5 font-semibold">Detected</th>
                <th className="pb-2.5 font-semibold">Threat Classification</th>
                <th className="pb-2.5 font-semibold">Affected Entity</th>
                <th className="pb-2.5 font-semibold">Source IP</th>
                <th className="pb-2.5 font-semibold">Severity</th>
                <th className="pb-2.5 font-semibold">Risk Score</th>
                <th className="pb-2.5 font-semibold">Status</th>
                <th className="pb-2.5 font-semibold text-right">Triage Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-850">
              {filteredAlerts.length > 0 ? (
                filteredAlerts.map((alert) => (
                  <tr
                    key={alert.id}
                    onClick={() => onSelectAlert(alert)}
                    className="hover:bg-slate-850/60 cursor-pointer transition-colors group"
                  >
                    <td className="py-3 text-slate-400 font-mono text-[11px]">
                      {new Date(alert.created_at).toLocaleTimeString([], {
                        hour: "2-digit",
                        minute: "2-digit",
                        second: "2-digit",
                      })}
                    </td>
                    <td className="py-3">
                      <div className="font-semibold text-slate-200 group-hover:text-cyan-300 flex items-center gap-1.5">
                        {alert.severity === "CRITICAL" && (
                          <AlertTriangle className="w-3.5 h-3.5 text-red-400 shrink-0 animate-pulse" />
                        )}
                        <span>{alert.title}</span>
                      </div>
                      <div className="text-[10px] text-slate-400 font-mono mt-0.5 truncate max-w-sm">
                        Rule: {alert.detection_rule}
                      </div>
                    </td>
                    <td className="py-3 text-slate-300 font-medium">{alert.username}</td>
                    <td className="py-3 font-mono text-amber-400">{alert.source_ip}</td>
                    <td className="py-3">
                      <SeverityBadge severity={alert.severity} />
                    </td>
                    <td className="py-3 font-mono font-bold text-red-400">
                      {alert.risk_score}/100
                    </td>
                    <td className="py-3">
                      <StatusBadge status={alert.status} />
                    </td>
                    <td className="py-3 text-right" onClick={(e) => e.stopPropagation()}>
                      <div className="flex items-center justify-end gap-1.5">
                        <select
                          value={alert.status}
                          disabled={role === "VIEWER"}
                          onChange={(e) => handleQuickStatusChange(e as any, alert.id, e.target.value)}
                          className="bg-slate-950 border border-slate-700 text-slate-200 text-[11px] rounded px-2 py-1 focus:outline-none focus:border-cyan-500 disabled:opacity-50"
                        >
                          <option value="NEW">NEW</option>
                          <option value="INVESTIGATING">INVESTIGATE</option>
                          <option value="RESOLVED">RESOLVE</option>
                          <option value="FALSE_POSITIVE">FALSE POSITIVE</option>
                        </select>
                        <button
                          onClick={() => onSelectAlert(alert)}
                          className="px-2 py-1 rounded bg-slate-800 hover:bg-cyan-950 text-slate-300 hover:text-cyan-300 border border-slate-700 text-[11px] transition-colors"
                        >
                          Inspect
                        </button>
                      </div>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={8} className="py-8 text-center text-slate-500 font-mono">
                    No security alerts found. All systems within normal operating thresholds.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
