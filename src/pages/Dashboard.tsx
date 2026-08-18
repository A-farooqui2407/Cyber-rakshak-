import React, { useState, useEffect } from "react";
import {
  ShieldAlert,
  AlertTriangle,
  Flame,
  Activity,
  Terminal,
  Clock,
  ArrowUpRight,
  TrendingUp,
  Layers,
  CheckCircle,
  Eye,
  RefreshCw,
} from "lucide-react";
import {
  AreaChart,
  Area,
  BarChart,
  Bar,
  PieChart,
  Pie,
  Cell,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
} from "recharts";
import { DashboardMetrics, Alert } from "../types";
import { SeverityBadge, StatusBadge } from "../components/ui/Badge";
import { api } from "../services/api";

interface DashboardProps {
  onSelectAlert: (alert: Alert) => void;
  onOpenSimulation: () => void;
  onNavigateTab: (tab: string) => void;
}

export const Dashboard: React.FC<DashboardProps> = ({
  onSelectAlert,
  onOpenSimulation,
  onNavigateTab,
}) => {
  const [metrics, setMetrics] = useState<DashboardMetrics | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchMetrics = async () => {
    setIsLoading(true);
    try {
      const data = await api.getDashboard();
      setMetrics(data);
      setError(null);
    } catch (err: any) {
      setError(err.message || "Failed to load SOC dashboard metrics");
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchMetrics();
    const interval = setInterval(fetchMetrics, 12000);
    return () => clearInterval(interval);
  }, []);

  // Time series mock generation based on real data
  const timeSeriesData = [
    { time: "06:00", events: 12, alerts: 0 },
    { time: "08:00", events: 25, alerts: 1 },
    { time: "10:00", events: 45, alerts: 0 },
    { time: "12:00", events: 60, alerts: 1 },
    { time: "14:00", events: 88, alerts: 2 },
    { time: "16:00", events: 110, alerts: metrics?.critical_alerts ? 3 : 1 },
    { time: "Now", events: metrics?.total_events || 135, alerts: metrics?.alerts_last_24h || 2 },
  ];

  const severityPieData = [
    { name: "CRITICAL", value: metrics?.alerts_by_severity?.CRITICAL || 0, color: "#ef4444" },
    { name: "HIGH", value: metrics?.alerts_by_severity?.HIGH || 0, color: "#f97316" },
    { name: "MEDIUM", value: metrics?.alerts_by_severity?.MEDIUM || 0, color: "#f59e0b" },
    { name: "LOW", value: metrics?.alerts_by_severity?.LOW || 1, color: "#10b981" },
  ].filter((item) => item.value > 0);

  const eventCategoryData = Object.entries(metrics?.events_by_type || { LOGIN_SUCCESS: 20, LOGIN_FAILED: 5, FILE_ACCESS: 8 }).map(
    ([key, count]) => ({
      name: key.replace(/_/g, " "),
      count,
    })
  );

  return (
    <div className="space-y-6">
      {/* Top Banner Alert if Critical Attack Simulated */}
      {metrics && metrics.critical_alerts > 0 && (
        <div className="p-4 rounded-xl bg-gradient-to-r from-red-950 via-slate-900 to-red-950 border border-red-700/80 shadow-[0_0_20px_rgba(239,68,68,0.25)] flex items-center justify-between animate-pulse">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-red-600/30 text-red-400">
              <Flame className="w-5 h-5 text-red-400" />
            </div>
            <div>
              <div className="text-sm font-bold text-white flex items-center gap-2">
                CRITICAL THREAT ACTIVE: Potential Account Compromise
                <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-red-900 text-red-200 border border-red-500 font-bold">
                  RISK 95/100
                </span>
              </div>
              <p className="text-xs text-red-200/80">
                Multi-signal correlation detected 20 failed logins → successful login → anomalous IP → privilege escalation.
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => onNavigateTab("alerts")}
              className="px-3.5 py-1.5 rounded-lg bg-red-600 hover:bg-red-500 text-white text-xs font-semibold shadow-lg transition-all"
            >
              Investigate Alerts
            </button>
          </div>
        </div>
      )}

      {/* 5 Key Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
        {/* Metric 1: Total Events */}
        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800/80 backdrop-blur-sm relative overflow-hidden group hover:border-slate-700 transition-all">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-medium uppercase tracking-wider font-mono">Total Events Logged</span>
            <Terminal className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="mt-3 flex items-baseline justify-between">
            <span className="text-2xl font-bold font-mono text-slate-100">{metrics?.total_events || 0}</span>
            <span className="text-[11px] text-emerald-400 font-medium flex items-center gap-0.5">
              <TrendingUp className="w-3 h-3" /> Live
            </span>
          </div>
          <div className="mt-2 text-[10px] text-slate-400">Normalized real-time stream</div>
        </div>

        {/* Metric 2: Critical Alerts */}
        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800/80 backdrop-blur-sm relative overflow-hidden group hover:border-slate-700 transition-all">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-medium uppercase tracking-wider font-mono">Critical Alerts</span>
            <ShieldAlert className="w-4 h-4 text-red-400" />
          </div>
          <div className="mt-3 flex items-baseline justify-between">
            <span className="text-2xl font-bold font-mono text-red-400">{metrics?.critical_alerts || 0}</span>
            {metrics && metrics.critical_alerts > 0 ? (
              <span className="text-[10px] px-1.5 py-0.5 rounded bg-red-950 text-red-300 font-bold animate-pulse">
                ACTION REQ
              </span>
            ) : (
              <span className="text-[11px] text-emerald-400 font-medium">None</span>
            )}
          </div>
          <div className="mt-2 text-[10px] text-slate-400">Score &ge; 80 threshold</div>
        </div>

        {/* Metric 3: Active Incidents */}
        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800/80 backdrop-blur-sm relative overflow-hidden group hover:border-slate-700 transition-all">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-medium uppercase tracking-wider font-mono">Active Incidents</span>
            <AlertTriangle className="w-4 h-4 text-amber-400" />
          </div>
          <div className="mt-3 flex items-baseline justify-between">
            <span className="text-2xl font-bold font-mono text-amber-400">{metrics?.active_incidents || 0}</span>
            <span className="text-[10px] text-slate-400">Tier-2 Queue</span>
          </div>
          <div className="mt-2 text-[10px] text-slate-400">Escalated for triage</div>
        </div>

        {/* Metric 4: High Risk Events */}
        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800/80 backdrop-blur-sm relative overflow-hidden group hover:border-slate-700 transition-all">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-medium uppercase tracking-wider font-mono">High Risk Events</span>
            <Layers className="w-4 h-4 text-orange-400" />
          </div>
          <div className="mt-3 flex items-baseline justify-between">
            <span className="text-2xl font-bold font-mono text-orange-400">{metrics?.high_risk_events || 0}</span>
            <span className="text-[10px] text-slate-400">Suspicious</span>
          </div>
          <div className="mt-2 text-[10px] text-slate-400">Severity &ge; HIGH</div>
        </div>

        {/* Metric 5: Overall Risk Score Gauge */}
        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800/80 backdrop-blur-sm relative overflow-hidden group hover:border-slate-700 transition-all">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-medium uppercase tracking-wider font-mono">Overall Risk Score</span>
            <Activity className="w-4 h-4 text-purple-400" />
          </div>
          <div className="mt-3 flex items-baseline justify-between">
            <span
              className={`text-2xl font-bold font-mono ${
                (metrics?.overall_risk_score || 0) >= 80
                  ? "text-red-400"
                  : (metrics?.overall_risk_score || 0) >= 60
                  ? "text-orange-400"
                  : "text-emerald-400"
              }`}
            >
              {metrics?.overall_risk_score || 18}
              <span className="text-xs text-slate-400 font-normal">/100</span>
            </span>
            <SeverityBadge
              severity={
                (metrics?.overall_risk_score || 0) >= 80
                  ? "CRITICAL"
                  : (metrics?.overall_risk_score || 0) >= 60
                  ? "HIGH"
                  : (metrics?.overall_risk_score || 0) >= 30
                  ? "MEDIUM"
                  : "LOW"
              }
            />
          </div>
          <div className="mt-2 text-[10px] text-slate-400">Deterministic algorithm</div>
        </div>
      </div>

      {/* Analytics Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Chart 1: Events & Alerts Volume Timeline */}
        <div className="lg:col-span-2 p-5 rounded-xl bg-slate-900/60 border border-slate-800/80 space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider font-mono">
                Telemetry & Anomaly Ingestion Stream
              </h3>
              <p className="text-[11px] text-slate-400">Real-time event frequency correlated over time</p>
            </div>
            <div className="flex items-center gap-4 text-xs font-mono">
              <span className="flex items-center gap-1.5 text-cyan-400">
                <span className="w-2.5 h-2.5 rounded-sm bg-cyan-500" /> Events
              </span>
              <span className="flex items-center gap-1.5 text-red-400">
                <span className="w-2.5 h-2.5 rounded-sm bg-red-500" /> Alerts
              </span>
            </div>
          </div>

          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={timeSeriesData}>
                <defs>
                  <linearGradient id="colorEvents" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.4} />
                    <stop offset="95%" stopColor="#06b6d4" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="colorAlerts" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#ef4444" stopOpacity={0.6} />
                    <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <XAxis dataKey="time" stroke="#64748b" fontSize={11} tickLine={false} />
                <YAxis stroke="#64748b" fontSize={11} tickLine={false} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: "#020617",
                    borderColor: "#334155",
                    borderRadius: "8px",
                    fontSize: "11px",
                  }}
                />
                <Area
                  type="monotone"
                  dataKey="events"
                  stroke="#06b6d4"
                  strokeWidth={2}
                  fillOpacity={1}
                  fill="url(#colorEvents)"
                />
                <Area
                  type="monotone"
                  dataKey="alerts"
                  stroke="#ef4444"
                  strokeWidth={2}
                  fillOpacity={1}
                  fill="url(#colorAlerts)"
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Chart 2: Alert Severity Breakdown */}
        <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800/80 space-y-4 flex flex-col justify-between">
          <div>
            <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider font-mono">
              Alert Severity Distribution
            </h3>
            <p className="text-[11px] text-slate-400">Proportion of security alerts by triage level</p>
          </div>

          <div className="h-44 w-full flex items-center justify-center">
            {severityPieData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={severityPieData}
                    cx="50%"
                    cy="50%"
                    innerRadius={45}
                    outerRadius={70}
                    paddingAngle={4}
                    dataKey="value"
                  >
                    {severityPieData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{
                      backgroundColor: "#020617",
                      borderColor: "#334155",
                      borderRadius: "8px",
                      fontSize: "11px",
                    }}
                  />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div className="text-xs text-slate-500 font-mono">No alerts active</div>
            )}
          </div>

          <div className="grid grid-cols-2 gap-2 pt-2 border-t border-slate-800/80 text-xs">
            <div className="flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-red-500" />
              <span className="text-slate-400 text-[11px]">Critical: {metrics?.alerts_by_severity?.CRITICAL || 0}</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-orange-500" />
              <span className="text-slate-400 text-[11px]">High: {metrics?.alerts_by_severity?.HIGH || 0}</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-amber-500" />
              <span className="text-slate-400 text-[11px]">Medium: {metrics?.alerts_by_severity?.MEDIUM || 0}</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-emerald-500" />
              <span className="text-slate-400 text-[11px]">Low: {metrics?.alerts_by_severity?.LOW || 0}</span>
            </div>
          </div>
        </div>
      </div>

      {/* Recent Alerts Queue */}
      <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800/80 space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider font-mono">
              Live Correlated Threat Alerts
            </h3>
            <p className="text-[11px] text-slate-400">Alerts ranked by deterministic risk score</p>
          </div>
          <button
            onClick={() => onNavigateTab("alerts")}
            className="text-xs text-cyan-400 hover:text-cyan-300 flex items-center gap-1 font-medium"
          >
            <span>View Full Queue</span>
            <ArrowUpRight className="w-3.5 h-3.5" />
          </button>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400 font-mono text-[10px] uppercase">
                <th className="pb-2.5 font-semibold">Timestamp</th>
                <th className="pb-2.5 font-semibold">Threat Detection</th>
                <th className="pb-2.5 font-semibold">Affected Entity</th>
                <th className="pb-2.5 font-semibold">Source IP</th>
                <th className="pb-2.5 font-semibold">Severity</th>
                <th className="pb-2.5 font-semibold">Risk Score</th>
                <th className="pb-2.5 font-semibold">Status</th>
                <th className="pb-2.5 font-semibold text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-850">
              {metrics?.recent_alerts && metrics.recent_alerts.length > 0 ? (
                metrics.recent_alerts.map((alert) => (
                  <tr
                    key={alert.id}
                    onClick={() => onSelectAlert(alert)}
                    className="hover:bg-slate-850/50 cursor-pointer transition-colors group"
                  >
                    <td className="py-3 text-slate-400 font-mono text-[11px]">
                      {new Date(alert.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                    </td>
                    <td className="py-3 font-semibold text-slate-200 group-hover:text-cyan-300">
                      {alert.title}
                    </td>
                    <td className="py-3 text-slate-300">{alert.username}</td>
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
                    <td className="py-3 text-right">
                      <button className="px-2.5 py-1 rounded bg-slate-800 hover:bg-cyan-950 text-slate-300 hover:text-cyan-300 border border-slate-700 hover:border-cyan-800 transition-colors text-[11px]">
                        Inspect
                      </button>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={8} className="py-8 text-center text-slate-500 font-mono">
                    No active threat alerts detected. Perimeter baseline normal.
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
