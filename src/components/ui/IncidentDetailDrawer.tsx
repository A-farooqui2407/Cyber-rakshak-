import React from "react";
import {
  X,
  AlertOctagon,
  User,
  Shield,
  Clock,
  CheckCircle2,
  AlertTriangle,
} from "lucide-react";
import { Incident } from "../../types";
import { SeverityBadge, StatusBadge } from "./Badge";
import { useAuth } from "../../context/AuthContext";

interface IncidentDetailDrawerProps {
  incident: Incident | null;
  onClose: () => void;
  onStatusChange: (id: string, newStatus: string) => void;
}

export const IncidentDetailDrawer: React.FC<IncidentDetailDrawerProps> = ({
  incident,
  onClose,
  onStatusChange,
}) => {
  const { role } = useAuth();

  if (!incident) return null;

  return (
    <div className="fixed inset-0 z-50 overflow-hidden bg-black/60 backdrop-blur-xs flex justify-end">
      <div className="w-full max-w-xl bg-slate-950 border-l border-slate-800 h-full flex flex-col shadow-2xl overflow-hidden">
        {/* Top bar */}
        <div className="p-5 border-b border-slate-800 flex items-center justify-between bg-slate-900/60">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-orange-950/80 border border-orange-800/60 text-orange-400">
              <AlertOctagon className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-xs font-mono text-slate-400">{incident.id.toUpperCase()}</span>
                <SeverityBadge severity={incident.severity} />
                <StatusBadge status={incident.status} />
              </div>
              <h2 className="text-sm font-bold text-slate-100 mt-0.5 truncate max-w-md">{incident.title}</h2>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-2 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Body */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6 text-xs">
          {/* Metadata Cards */}
          <div className="grid grid-cols-2 gap-3">
            <div className="p-3.5 rounded-xl bg-slate-900/60 border border-slate-800">
              <span className="text-[10px] text-slate-400 block uppercase font-mono">Assigned SOC Analyst</span>
              <span className="font-semibold text-slate-200 flex items-center gap-1.5 mt-1">
                <User className="w-3.5 h-3.5 text-cyan-400" />
                {incident.assigned_analyst}
              </span>
            </div>
            <div className="p-3.5 rounded-xl bg-slate-900/60 border border-slate-800">
              <span className="text-[10px] text-slate-400 block uppercase font-mono">Risk Level</span>
              <span className="font-mono font-bold text-red-400 text-sm mt-1 block">
                {incident.risk_score}/100 ({incident.severity})
              </span>
            </div>
            <div className="p-3.5 rounded-xl bg-slate-900/60 border border-slate-800">
              <span className="text-[10px] text-slate-400 block uppercase font-mono">Compromised User Target</span>
              <span className="font-semibold text-slate-200 mt-1 block">{incident.affected_user}</span>
            </div>
            <div className="p-3.5 rounded-xl bg-slate-900/60 border border-slate-800">
              <span className="text-[10px] text-slate-400 block uppercase font-mono">Attacker Remote IP</span>
              <span className="font-mono font-semibold text-amber-400 mt-1 block">{incident.source_ip}</span>
            </div>
          </div>

          {/* Description */}
          <div className="space-y-2">
            <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Incident Summary</div>
            <div className="p-3.5 rounded-lg bg-slate-900/40 border border-slate-800 text-slate-300 leading-relaxed">
              {incident.description}
            </div>
          </div>

          {/* Incident Response Checklist */}
          <div className="space-y-2">
            <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Incident Response Checklist</div>
            <div className="space-y-2">
              <label className="flex items-center gap-3 p-3 rounded-lg bg-slate-900/60 border border-slate-800 text-slate-300 cursor-pointer hover:bg-slate-900">
                <input type="checkbox" defaultChecked className="rounded border-slate-700 text-cyan-500" />
                <span>1. Isolate compromised user endpoint & terminate active sessions</span>
              </label>
              <label className="flex items-center gap-3 p-3 rounded-lg bg-slate-900/60 border border-slate-800 text-slate-300 cursor-pointer hover:bg-slate-900">
                <input type="checkbox" defaultChecked className="rounded border-slate-700 text-cyan-500" />
                <span>2. Block adversary IP address 198.51.100.42 at gateway router</span>
              </label>
              <label className="flex items-center gap-3 p-3 rounded-lg bg-slate-900/60 border border-slate-800 text-slate-300 cursor-pointer hover:bg-slate-900">
                <input type="checkbox" className="rounded border-slate-700 text-cyan-500" />
                <span>3. Invalidate credentials and issue out-of-band MFA secret</span>
              </label>
              <label className="flex items-center gap-3 p-3 rounded-lg bg-slate-900/60 border border-slate-800 text-slate-300 cursor-pointer hover:bg-slate-900">
                <input type="checkbox" className="rounded border-slate-700 text-cyan-500" />
                <span>4. Complete post-incident forensic log export for compliance</span>
              </label>
            </div>
          </div>

          <div className="text-[11px] text-slate-400 flex items-center justify-between p-3 rounded-lg bg-slate-900/30 border border-slate-800/50">
            <span>Created: {new Date(incident.created_at).toLocaleString()}</span>
            <span>Updated: {new Date(incident.updated_at).toLocaleString()}</span>
          </div>
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-slate-800 bg-slate-900/80 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <span className="text-xs text-slate-400">Incident Status:</span>
            <select
              value={incident.status}
              disabled={role === "VIEWER"}
              onChange={(e) => onStatusChange(incident.id, e.target.value)}
              className="bg-slate-950 border border-slate-700 text-slate-200 text-xs rounded-lg px-2.5 py-1.5 focus:outline-none focus:border-cyan-500 disabled:opacity-50"
            >
              <option value="OPEN">OPEN</option>
              <option value="INVESTIGATING">INVESTIGATING</option>
              <option value="RESOLVED">RESOLVED</option>
            </select>
          </div>

          <button
            onClick={onClose}
            className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-medium text-slate-300 transition-colors"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
