import React, { useState, useEffect } from "react";
import {
  Terminal,
  Search,
  Filter,
  RefreshCw,
  Plus,
  Eye,
  X,
  Play,
  ArrowUpDown,
} from "lucide-react";
import { LogEvent } from "../types";
import { SeverityBadge } from "../components/ui/Badge";
import { api } from "../services/api";
import { useAuth } from "../context/AuthContext";

export const LiveLogs: React.FC<{ initialSearch?: string }> = ({ initialSearch = "" }) => {
  const { role } = useAuth();
  const [logs, setLogs] = useState<LogEvent[]>([]);
  const [total, setTotal] = useState(0);
  const [isLoading, setIsLoading] = useState(true);
  const [autoRefresh, setAutoRefresh] = useState(true);

  // Filters
  const [search, setSearch] = useState(initialSearch);
  const [severityFilter, setSeverityFilter] = useState("");
  const [typeFilter, setTypeFilter] = useState("");

  // Modals
  const [selectedLog, setSelectedLog] = useState<LogEvent | null>(null);
  const [showInjectModal, setShowInjectModal] = useState(false);

  // New Log Injection Form State
  const [newLogData, setNewLogData] = useState({
    username: "rahul.sharma",
    ip_address: "198.51.100.42",
    event_type: "LOGIN_FAILED",
    action: "login_attempt",
    severity: "MEDIUM",
    source: "auth_service",
  });

  const fetchLogs = async () => {
    try {
      const res = await api.getLogs({
        search: search || undefined,
        severity: severityFilter || undefined,
        event_type: typeFilter || undefined,
        limit: 100,
      });
      setLogs(res.logs);
      setTotal(res.total);
    } catch (err) {
      console.error("Failed to load logs", err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchLogs();
  }, [search, severityFilter, typeFilter]);

  useEffect(() => {
    if (!autoRefresh) return;
    const interval = setInterval(fetchLogs, 5000);
    return () => clearInterval(interval);
  }, [autoRefresh, search, severityFilter, typeFilter]);

  const handleInjectLog = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await api.createLog({
        ...newLogData,
        status: newLogData.event_type.includes("FAILED") ? "FAILED" : "SUCCESS",
        severity: newLogData.severity as any,
      });
      setShowInjectModal(false);
      fetchLogs();
    } catch (err) {
      console.error("Failed to inject log", err);
    }
  };

  return (
    <div className="space-y-5">
      {/* Header Controls */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 p-4 rounded-xl bg-slate-900/60 border border-slate-800/80">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-cyan-950 text-cyan-400 border border-cyan-800/50">
            <Terminal className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-sm font-bold text-slate-100 flex items-center gap-2">
              Live Security Telemetry Stream
              <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-cyan-950 text-cyan-300 border border-cyan-800/50">
                {total} Events Ingested
              </span>
            </h2>
            <p className="text-xs text-slate-400">Normalized SIEM log pipeline with instant correlation matching</p>
          </div>
        </div>

        <div className="flex items-center gap-2.5 w-full sm:w-auto">
          <button
            onClick={() => setAutoRefresh(!autoRefresh)}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono transition-colors border ${
              autoRefresh
                ? "bg-emerald-950/60 text-emerald-300 border-emerald-800/60"
                : "bg-slate-850 text-slate-400 border-slate-700"
            }`}
          >
            <span className={`w-2 h-2 rounded-full ${autoRefresh ? "bg-emerald-400 animate-ping" : "bg-slate-500"}`} />
            <span>{autoRefresh ? "STREAMING (5s)" : "PAUSED"}</span>
          </button>

          <button
            onClick={fetchLogs}
            className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors"
            title="Refresh"
          >
            <RefreshCw className="w-4 h-4" />
          </button>

          <button
            onClick={() => setShowInjectModal(true)}
            disabled={role === "VIEWER"}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold shadow-md transition-all disabled:opacity-50"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>Ingest Test Log</span>
          </button>
        </div>
      </div>

      {/* Filter Bar */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
        <div className="relative">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Search by user, IP, action, payload..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full bg-slate-900/80 border border-slate-800 rounded-lg pl-9 pr-3 py-2 text-xs text-slate-200 placeholder-slate-400 focus:outline-none focus:border-cyan-500"
          />
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
            <option value="INFO">INFO</option>
          </select>
        </div>

        <div>
          <select
            value={typeFilter}
            onChange={(e) => setTypeFilter(e.target.value)}
            className="w-full bg-slate-900/80 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
          >
            <option value="">All Event Types</option>
            <option value="LOGIN_FAILED">LOGIN_FAILED</option>
            <option value="LOGIN_SUCCESS">LOGIN_SUCCESS</option>
            <option value="PRIVILEGE_ESCALATION">PRIVILEGE_ESCALATION</option>
            <option value="SUSPICIOUS_IP">SUSPICIOUS_IP</option>
            <option value="FILE_ACCESS">FILE_ACCESS</option>
            <option value="DATABASE_ACCESS">DATABASE_ACCESS</option>
          </select>
        </div>
      </div>

      {/* Logs Table */}
      <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800/80 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400 text-[10px] uppercase">
                <th className="pb-2.5 font-semibold">Timestamp</th>
                <th className="pb-2.5 font-semibold">Source</th>
                <th className="pb-2.5 font-semibold">Event Type</th>
                <th className="pb-2.5 font-semibold">Username</th>
                <th className="pb-2.5 font-semibold">Source IP</th>
                <th className="pb-2.5 font-semibold">Action</th>
                <th className="pb-2.5 font-semibold">Severity</th>
                <th className="pb-2.5 font-semibold text-right">Inspect</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-850">
              {logs.length > 0 ? (
                logs.map((log) => (
                  <tr
                    key={log.id}
                    onClick={() => setSelectedLog(log)}
                    className="hover:bg-slate-850/60 cursor-pointer transition-colors"
                  >
                    <td className="py-2.5 text-slate-400 text-[11px]">
                      {new Date(log.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                    </td>
                    <td className="py-2.5 text-slate-300 text-[11px]">{log.source}</td>
                    <td className="py-2.5 font-semibold text-cyan-300 text-[11px]">{log.event_type}</td>
                    <td className="py-2.5 text-slate-200 text-[11px]">{log.username}</td>
                    <td className="py-2.5 text-amber-400 text-[11px]">{log.ip_address}</td>
                    <td className="py-2.5 text-slate-300 text-[11px]">{log.action}</td>
                    <td className="py-2.5">
                      <SeverityBadge severity={log.severity} />
                    </td>
                    <td className="py-2.5 text-right">
                      <button className="p-1 rounded hover:bg-slate-800 text-slate-400 hover:text-cyan-300">
                        <Eye className="w-3.5 h-3.5" />
                      </button>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={8} className="py-8 text-center text-slate-500">
                    No security events matched current filter parameters.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Raw JSON Modal */}
      {selectedLog && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-xs p-4">
          <div className="bg-slate-950 border border-slate-800 rounded-xl w-full max-w-lg overflow-hidden shadow-2xl p-5 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2 font-mono text-xs text-slate-200 font-semibold">
                <Terminal className="w-4 h-4 text-cyan-400" />
                Raw Security Event Payload
              </div>
              <button
                onClick={() => setSelectedLog(null)}
                className="p-1 rounded text-slate-400 hover:text-slate-200"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <pre className="p-3.5 rounded-lg bg-slate-900 text-cyan-300 font-mono text-[11px] overflow-x-auto max-h-80 border border-slate-800">
              {JSON.stringify(selectedLog, null, 2)}
            </pre>

            <div className="flex justify-end">
              <button
                onClick={() => setSelectedLog(null)}
                className="px-4 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs text-slate-200"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Ingest Test Log Modal */}
      {showInjectModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-xs p-4">
          <div className="bg-slate-950 border border-slate-800 rounded-xl w-full max-w-md overflow-hidden shadow-2xl p-5 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="font-bold text-sm text-slate-100">Ingest Custom Security Log</h3>
              <button onClick={() => setShowInjectModal(false)} className="text-slate-400 hover:text-slate-200">
                <X className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleInjectLog} className="space-y-3 text-xs">
              <div>
                <label className="text-slate-400 block mb-1">Username</label>
                <input
                  type="text"
                  value={newLogData.username}
                  onChange={(e) => setNewLogData({ ...newLogData, username: e.target.value })}
                  className="w-full bg-slate-900 border border-slate-800 rounded px-3 py-1.5 text-slate-200"
                  required
                />
              </div>

              <div>
                <label className="text-slate-400 block mb-1">Source IP Address</label>
                <input
                  type="text"
                  value={newLogData.ip_address}
                  onChange={(e) => setNewLogData({ ...newLogData, ip_address: e.target.value })}
                  className="w-full bg-slate-900 border border-slate-800 rounded px-3 py-1.5 text-slate-200"
                  required
                />
              </div>

              <div>
                <label className="text-slate-400 block mb-1">Event Type</label>
                <select
                  value={newLogData.event_type}
                  onChange={(e) => setNewLogData({ ...newLogData, event_type: e.target.value })}
                  className="w-full bg-slate-900 border border-slate-800 rounded px-3 py-1.5 text-slate-200"
                >
                  <option value="LOGIN_FAILED">LOGIN_FAILED</option>
                  <option value="LOGIN_SUCCESS">LOGIN_SUCCESS</option>
                  <option value="PRIVILEGE_ESCALATION">PRIVILEGE_ESCALATION</option>
                  <option value="SUSPICIOUS_IP">SUSPICIOUS_IP</option>
                  <option value="FILE_ACCESS">FILE_ACCESS</option>
                  <option value="DATABASE_ACCESS">DATABASE_ACCESS</option>
                </select>
              </div>

              <div>
                <label className="text-slate-400 block mb-1">Action Description</label>
                <input
                  type="text"
                  value={newLogData.action}
                  onChange={(e) => setNewLogData({ ...newLogData, action: e.target.value })}
                  className="w-full bg-slate-900 border border-slate-800 rounded px-3 py-1.5 text-slate-200"
                  required
                />
              </div>

              <div>
                <label className="text-slate-400 block mb-1">Severity</label>
                <select
                  value={newLogData.severity}
                  onChange={(e) => setNewLogData({ ...newLogData, severity: e.target.value })}
                  className="w-full bg-slate-900 border border-slate-800 rounded px-3 py-1.5 text-slate-200"
                >
                  <option value="CRITICAL">CRITICAL</option>
                  <option value="HIGH">HIGH</option>
                  <option value="MEDIUM">MEDIUM</option>
                  <option value="LOW">LOW</option>
                  <option value="INFO">INFO</option>
                </select>
              </div>

              <div className="pt-2 flex justify-end gap-2">
                <button
                  type="button"
                  onClick={() => setShowInjectModal(false)}
                  className="px-3 py-1.5 rounded bg-slate-800 text-slate-300"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 text-white font-semibold"
                >
                  Submit to Telemetry
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
