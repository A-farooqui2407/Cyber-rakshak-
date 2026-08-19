import React, { useState, useEffect } from "react";
import {
  Settings as SettingsIcon,
  Shield,
  FileText,
  Download,
  Database,
  Cpu,
  RefreshCw,
  CheckCircle2,
  Lock,
} from "lucide-react";
import { AuditLog } from "../types";
import { api } from "../services/api";
import { useAuth } from "../context/AuthContext";
import { RoleBadge } from "../components/ui/Badge";

export const Settings: React.FC = () => {
  const { user, role, organization } = useAuth();
  const [auditLogs, setAuditLogs] = useState<AuditLog[]>([]);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    const fetchAudits = async () => {
      try {
        const data = await api.getAuditLogs();
        setAuditLogs(data);
      } catch (err) {
        console.error("Failed to load audit logs", err);
      } finally {
        setIsLoading(false);
      }
    };
    fetchAudits();
  }, []);

  const handleExportData = async () => {
    try {
      const exportBundle = await api.exportBundle();
      const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(exportBundle, null, 2));
      const downloadAnchor = document.createElement("a");
      downloadAnchor.setAttribute("href", dataStr);
      downloadAnchor.setAttribute("download", `cyberrakshak-export-${Date.now()}.json`);
      document.body.appendChild(downloadAnchor);
      downloadAnchor.click();
      downloadAnchor.remove();
    } catch (err) {
      console.error("Export error", err);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800/80 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-slate-800 text-cyan-400 border border-slate-700">
            <SettingsIcon className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-sm font-bold text-slate-100 flex items-center gap-2">
              SOC Platform Settings & Audit Trail
            </h2>
            <p className="text-xs text-slate-400">System parameters, RBAC enforcement, and compliance audit logs</p>
          </div>
        </div>

        <button
          onClick={handleExportData}
          disabled={role !== "ADMIN"}
          className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-750 text-slate-200 text-xs font-semibold border border-slate-700 transition-colors disabled:opacity-40"
        >
          <Download className="w-4 h-4 text-cyan-400" />
          <span>Export SOC Bundle (.JSON)</span>
        </button>
      </div>

      {/* Grid of Configuration Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* Card 1: Monitored Tenant */}
        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800/80 space-y-2">
          <span className="text-[10px] text-slate-400 block uppercase font-mono">Organization Tenant</span>
          <div className="font-bold text-slate-100 text-sm">{organization}</div>
          <p className="text-[11px] text-slate-400">Single-tenant isolated telemetry stream with strict data fencing.</p>
        </div>

        {/* Card 2: AI Engine Status */}
        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800/80 space-y-2">
          <span className="text-[10px] text-slate-400 block uppercase font-mono">AI Threat Engine</span>
          <div className="font-bold text-cyan-300 text-sm flex items-center gap-1.5">
            <Cpu className="w-4 h-4 text-cyan-400" />
            Gemini 3.7 Flash + Fallback Rules
          </div>
          <p className="text-[11px] text-slate-400">Zero-data-leakage architecture. Server-side key isolation active.</p>
        </div>

        {/* Card 3: RBAC Session */}
        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800/80 space-y-2">
          <span className="text-[10px] text-slate-400 block uppercase font-mono">Active Session Role</span>
          <div className="flex items-center gap-2">
            <RoleBadge role={role} />
            <span className="text-xs text-slate-300">{user?.name}</span>
          </div>
          <p className="text-[11px] text-slate-400">
            {role === "ADMIN"
              ? "Full system authority. Simulations, triage, and rules enabled."
              : role === "ANALYST"
              ? "Triage authority. Can update alerts and incident workflows."
              : "Read-only auditor view. Actions restricted."}
          </p>
        </div>
      </div>

      {/* SOC Compliance Audit Trail */}
      <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800/80 space-y-4">
        <div>
          <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider font-mono">
            Immutable SOC Analyst Audit Trail
          </h3>
          <p className="text-[11px] text-slate-400">
            Tracks all alert triage events, status updates, simulations, and investigations for compliance
          </p>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400 text-[10px] uppercase">
                <th className="pb-2.5 font-semibold">Timestamp</th>
                <th className="pb-2.5 font-semibold">Actor Email</th>
                <th className="pb-2.5 font-semibold">Action Performed</th>
                <th className="pb-2.5 font-semibold">Target Resource</th>
                <th className="pb-2.5 font-semibold text-right">Resource ID</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-850">
              {auditLogs.length > 0 ? (
                auditLogs.map((log) => (
                  <tr key={log.id} className="hover:bg-slate-850/50 transition-colors">
                    <td className="py-2.5 text-slate-400 text-[11px]">
                      {new Date(log.created_at).toLocaleString()}
                    </td>
                    <td className="py-2.5 text-slate-200 font-sans font-medium">{log.actor_email}</td>
                    <td className="py-2.5 font-semibold text-cyan-300">{log.action}</td>
                    <td className="py-2.5 text-slate-300">{log.resource_type}</td>
                    <td className="py-2.5 text-right text-slate-400">{log.resource_id.substring(0, 10)}...</td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={5} className="py-8 text-center text-slate-500 font-mono">
                    No audit records registered yet.
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
