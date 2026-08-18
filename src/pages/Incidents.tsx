import React, { useState, useEffect } from "react";
import {
  AlertOctagon,
  Search,
  RefreshCw,
  Plus,
  Eye,
  User,
  CheckCircle,
  Clock,
  X,
} from "lucide-react";
import { Incident } from "../types";
import { SeverityBadge, StatusBadge } from "../components/ui/Badge";
import { api } from "../services/api";
import { useAuth } from "../context/AuthContext";

interface IncidentsProps {
  onSelectIncident: (inc: Incident) => void;
}

export const Incidents: React.FC<IncidentsProps> = ({ onSelectIncident }) => {
  const { role, user } = useAuth();
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState("");
  const [showCreateModal, setShowCreateModal] = useState(false);

  // New Incident Form State
  const [newIncidentData, setNewIncidentData] = useState({
    title: "Anomalous Credential Access Investigation",
    description: "Manual escalation by Tier-1 SOC analyst for deeper forensic review.",
    severity: "HIGH",
    risk_score: 75,
    affected_user: "rahul.sharma@lexguard.com",
    source_ip: "198.51.100.42",
    assigned_analyst: "Ananya Patel (Tier-2 SOC)",
  });

  const fetchIncidents = async () => {
    setIsLoading(true);
    try {
      const data = await api.getIncidents({ status: statusFilter || undefined });
      setIncidents(data);
    } catch (err) {
      console.error("Failed to load incidents", err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchIncidents();
  }, [statusFilter]);

  const handleCreateIncident = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await api.createIncident(newIncidentData as any);
      setShowCreateModal(false);
      fetchIncidents();
    } catch (err) {
      console.error("Failed to create incident", err);
    }
  };

  const filtered = incidents.filter((inc) => {
    if (!search) return true;
    const s = search.toLowerCase();
    return (
      inc.title.toLowerCase().includes(s) ||
      inc.affected_user.toLowerCase().includes(s) ||
      inc.source_ip.includes(s) ||
      inc.assigned_analyst.toLowerCase().includes(s)
    );
  });

  return (
    <div className="space-y-5">
      {/* Header Controls */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 p-4 rounded-xl bg-slate-900/60 border border-slate-800/80">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-orange-950 text-orange-400 border border-orange-800/50">
            <AlertOctagon className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-sm font-bold text-slate-100 flex items-center gap-2">
              SOC Incident Management Queue
              <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-orange-950 text-orange-300 border border-orange-800/50">
                {filtered.length} Incidents
              </span>
            </h2>
            <p className="text-xs text-slate-400">Formal response cases with containment tracking and analyst assignment</p>
          </div>
        </div>

        <div className="flex items-center gap-2.5">
          <button
            onClick={fetchIncidents}
            className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors"
            title="Refresh"
          >
            <RefreshCw className="w-4 h-4" />
          </button>

          <button
            onClick={() => setShowCreateModal(true)}
            disabled={role === "VIEWER"}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-orange-600 hover:bg-orange-500 text-white text-xs font-semibold shadow-md transition-all disabled:opacity-50"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>Create Incident</span>
          </button>
        </div>
      </div>

      {/* Filter Bar */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        <div className="relative">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Search incidents by title, user, IP, or assigned analyst..."
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
            <option value="">All Incident Statuses</option>
            <option value="OPEN">OPEN</option>
            <option value="INVESTIGATING">INVESTIGATING</option>
            <option value="RESOLVED">RESOLVED</option>
          </select>
        </div>
      </div>

      {/* Incidents Table */}
      <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800/80 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400 font-mono text-[10px] uppercase">
                <th className="pb-2.5 font-semibold">Incident ID</th>
                <th className="pb-2.5 font-semibold">Title & Context</th>
                <th className="pb-2.5 font-semibold">Target Entity</th>
                <th className="pb-2.5 font-semibold">Attacker IP</th>
                <th className="pb-2.5 font-semibold">Assigned Analyst</th>
                <th className="pb-2.5 font-semibold">Severity</th>
                <th className="pb-2.5 font-semibold">Risk Score</th>
                <th className="pb-2.5 font-semibold">Status</th>
                <th className="pb-2.5 font-semibold text-right">Inspect</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-850">
              {filtered.length > 0 ? (
                filtered.map((inc) => (
                  <tr
                    key={inc.id}
                    onClick={() => onSelectIncident(inc)}
                    className="hover:bg-slate-850/60 cursor-pointer transition-colors group"
                  >
                    <td className="py-3 font-mono text-[11px] text-cyan-400">
                      {inc.id.substring(0, 10).toUpperCase()}
                    </td>
                    <td className="py-3 font-semibold text-slate-200 group-hover:text-orange-300">
                      {inc.title}
                    </td>
                    <td className="py-3 text-slate-300">{inc.affected_user}</td>
                    <td className="py-3 font-mono text-amber-400">{inc.source_ip}</td>
                    <td className="py-3 text-slate-300 flex items-center gap-1.5 mt-1">
                      <User className="w-3.5 h-3.5 text-cyan-400" />
                      <span>{inc.assigned_analyst}</span>
                    </td>
                    <td className="py-3">
                      <SeverityBadge severity={inc.severity} />
                    </td>
                    <td className="py-3 font-mono font-bold text-red-400">
                      {inc.risk_score}/100
                    </td>
                    <td className="py-3">
                      <StatusBadge status={inc.status} />
                    </td>
                    <td className="py-3 text-right">
                      <button className="px-2.5 py-1 rounded bg-slate-800 hover:bg-orange-950 text-slate-300 hover:text-orange-300 border border-slate-700 text-[11px] transition-colors">
                        Manage
                      </button>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={9} className="py-8 text-center text-slate-500 font-mono">
                    No open security incidents. Perimeter status secure.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Manual Create Incident Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-xs p-4">
          <div className="bg-slate-950 border border-slate-800 rounded-xl w-full max-w-lg overflow-hidden shadow-2xl p-5 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="font-bold text-sm text-slate-100">Escalate New Security Incident</h3>
              <button onClick={() => setShowCreateModal(false)} className="text-slate-400 hover:text-slate-200">
                <X className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleCreateIncident} className="space-y-3 text-xs">
              <div>
                <label className="text-slate-400 block mb-1">Incident Title</label>
                <input
                  type="text"
                  value={newIncidentData.title}
                  onChange={(e) => setNewIncidentData({ ...newIncidentData, title: e.target.value })}
                  className="w-full bg-slate-900 border border-slate-800 rounded px-3 py-1.5 text-slate-200"
                  required
                />
              </div>

              <div>
                <label className="text-slate-400 block mb-1">Description & Scope</label>
                <textarea
                  rows={3}
                  value={newIncidentData.description}
                  onChange={(e) => setNewIncidentData({ ...newIncidentData, description: e.target.value })}
                  className="w-full bg-slate-900 border border-slate-800 rounded px-3 py-1.5 text-slate-200"
                  required
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-slate-400 block mb-1">Target Account</label>
                  <input
                    type="text"
                    value={newIncidentData.affected_user}
                    onChange={(e) => setNewIncidentData({ ...newIncidentData, affected_user: e.target.value })}
                    className="w-full bg-slate-900 border border-slate-800 rounded px-3 py-1.5 text-slate-200"
                    required
                  />
                </div>
                <div>
                  <label className="text-slate-400 block mb-1">Attacker Remote IP</label>
                  <input
                    type="text"
                    value={newIncidentData.source_ip}
                    onChange={(e) => setNewIncidentData({ ...newIncidentData, source_ip: e.target.value })}
                    className="w-full bg-slate-900 border border-slate-800 rounded px-3 py-1.5 text-slate-200"
                    required
                  />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-slate-400 block mb-1">Assigned SOC Analyst</label>
                  <input
                    type="text"
                    value={newIncidentData.assigned_analyst}
                    onChange={(e) => setNewIncidentData({ ...newIncidentData, assigned_analyst: e.target.value })}
                    className="w-full bg-slate-900 border border-slate-800 rounded px-3 py-1.5 text-slate-200"
                    required
                  />
                </div>
                <div>
                  <label className="text-slate-400 block mb-1">Severity</label>
                  <select
                    value={newIncidentData.severity}
                    onChange={(e) => setNewIncidentData({ ...newIncidentData, severity: e.target.value })}
                    className="w-full bg-slate-900 border border-slate-800 rounded px-3 py-1.5 text-slate-200"
                  >
                    <option value="CRITICAL">CRITICAL</option>
                    <option value="HIGH">HIGH</option>
                    <option value="MEDIUM">MEDIUM</option>
                    <option value="LOW">LOW</option>
                  </select>
                </div>
              </div>

              <div className="pt-2 flex justify-end gap-2">
                <button
                  type="button"
                  onClick={() => setShowCreateModal(false)}
                  className="px-3 py-1.5 rounded bg-slate-800 text-slate-300"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-1.5 rounded bg-orange-600 hover:bg-orange-500 text-white font-semibold"
                >
                  Create Incident Ticket
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
