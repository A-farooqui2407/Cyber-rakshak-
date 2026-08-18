import React, { useState, useEffect } from "react";
import {
  Activity,
  ShieldCheck,
  AlertTriangle,
  UserCheck,
  Flame,
  ArrowRight,
  TrendingDown,
  Lock,
  Layers,
} from "lucide-react";
import { RiskSummary } from "../types";
import { SeverityBadge } from "../components/ui/Badge";
import { api } from "../services/api";

export const RiskAnalysis: React.FC = () => {
  const [summary, setSummary] = useState<RiskSummary | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    const fetchRisk = async () => {
      try {
        const res = await api.getRiskSummary();
        setSummary(res);
      } catch (err) {
        console.error("Failed to load risk summary", err);
      } finally {
        setIsLoading(false);
      }
    };
    fetchRisk();
  }, []);

  const formulaFactors = [
    { name: "Brute Force Multiplier", weight: "+25", desc: "Triggered on >= 5 failed logins within 5-min threshold", active: (summary?.overall_risk_score || 0) > 40 },
    { name: "Credential Breach Factor", weight: "+45", desc: "Triggered on successful login following repeated failures", active: (summary?.overall_risk_score || 0) > 60 },
    { name: "Adversary IP Reputation Match", weight: "+20", desc: "Flagged proxy node or threat intelligence match", active: (summary?.overall_risk_score || 0) > 30 },
    { name: "Privilege Elevation Sudo Abuse", weight: "+30", desc: "Unauthorized admin role change post-authentication", active: (summary?.overall_risk_score || 0) > 70 },
  ];

  return (
    <div className="space-y-6">
      {/* Top Overview */}
      <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800/80 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-xl bg-purple-950 text-purple-400 border border-purple-800/50">
            <Activity className="w-6 h-6" />
          </div>
          <div>
            <h2 className="text-sm font-bold text-slate-100 flex items-center gap-2">
              Deterministic Organization Risk Posture
              <SeverityBadge severity={summary?.severity || "MEDIUM"} />
            </h2>
            <p className="text-xs text-slate-400">
              Quantitative risk index calculated deterministically from active correlation triggers
            </p>
          </div>
        </div>

        <div className="flex items-baseline gap-2 bg-slate-950 px-4 py-2 rounded-lg border border-slate-800">
          <span className="text-xs font-mono text-slate-400">Calculated Score:</span>
          <span className="text-2xl font-bold font-mono text-purple-400">
            {summary?.overall_risk_score || 25}/100
          </span>
        </div>
      </div>

      {/* Deterministic Formula Explanation Card */}
      <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800/80 space-y-4">
        <div>
          <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider font-mono">
            Deterministic Risk Score Composition
          </h3>
          <p className="text-[11px] text-slate-400">
            Unlike probabilistic "black-box" models, CyberRakshak computes risk transparently using auditable weights
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {formulaFactors.map((f, i) => (
            <div
              key={i}
              className={`p-3.5 rounded-lg border text-xs transition-all ${
                f.active
                  ? "bg-purple-950/40 border-purple-700/60 text-purple-200 shadow-[0_0_10px_rgba(168,85,247,0.1)]"
                  : "bg-slate-950/60 border-slate-850 text-slate-400"
              }`}
            >
              <div className="flex items-center justify-between font-semibold">
                <span className="text-slate-200">{f.name}</span>
                <span className="font-mono text-purple-400 font-bold">{f.weight}</span>
              </div>
              <div className="text-[11px] text-slate-400 mt-1">{f.desc}</div>
              <div className="mt-2 text-[10px] font-mono">
                {f.active ? (
                  <span className="text-emerald-400 flex items-center gap-1 font-semibold">
                    <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" /> APPLIED TO ACTIVE THREAT
                  </span>
                ) : (
                  <span className="text-slate-500">DORMANT (NO CORRELATION MATCH)</span>
                )}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Top High Risk Entities */}
      <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800/80 space-y-4">
        <div>
          <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider font-mono">
            High-Risk Monitored Identities & IPs
          </h3>
          <p className="text-[11px] text-slate-400">Entities with concentrated anomaly volume in the last 24 hours</p>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400 font-mono text-[10px] uppercase">
                <th className="pb-2.5 font-semibold">User Identity</th>
                <th className="pb-2.5 font-semibold">Associated Remote IP</th>
                <th className="pb-2.5 font-semibold">Threat Vector</th>
                <th className="pb-2.5 font-semibold">Risk Index</th>
                <th className="pb-2.5 font-semibold text-right">Containment Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-850">
              {summary?.top_risk_entities?.map((ent, idx) => (
                <tr key={idx} className="hover:bg-slate-850/50 transition-colors">
                  <td className="py-3 font-semibold text-slate-200">{ent.user}</td>
                  <td className="py-3 font-mono text-amber-400">{ent.ip}</td>
                  <td className="py-3 text-slate-300">{ent.threat_type || "POTENTIAL_ACCOUNT_COMPROMISE"}</td>
                  <td className="py-3 font-mono font-bold text-red-400">{ent.risk}/100</td>
                  <td className="py-3 text-right">
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-red-950 text-red-300 border border-red-800">
                      SESSION RESTRICTED
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
