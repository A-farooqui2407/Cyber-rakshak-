import React from "react";
import { ShieldAlert, Shield, ArrowRight, UserCheck, Lock } from "lucide-react";
import { useAuth } from "../context/AuthContext";
import { UserRole } from "../types";

export const Login: React.FC = () => {
  const { login } = useAuth();

  const demoAccounts: Array<{
    role: UserRole;
    name: string;
    title: string;
    description: string;
  }> = [
    {
      role: "ADMIN",
      name: "Rahul Sharma",
      title: "Lead SOC Admin",
      description: "Full access to telemetry, rule builder, incident queue, and attack simulation trigger.",
    },
    {
      role: "ANALYST",
      name: "Ananya Patel",
      title: "Tier-2 SOC Analyst",
      description: "Triage alerts, create incidents, run AI investigations, and manage mitigation checklists.",
    },
    {
      role: "VIEWER",
      name: "Vikram Singh",
      title: "Compliance & Audit Viewer",
      description: "Read-only auditor access. Inspect dashboard analytics and telemetry streams.",
    },
  ];

  return (
    <div className="min-h-screen bg-slate-950 flex flex-col items-center justify-center p-6 text-slate-100">
      <div className="w-full max-w-xl space-y-6">
        {/* Brand Header */}
        <div className="text-center space-y-3">
          <div className="w-14 h-14 rounded-2xl bg-gradient-to-br from-cyan-500 via-blue-600 to-indigo-700 flex items-center justify-center shadow-[0_0_25px_rgba(6,182,212,0.4)] mx-auto">
            <ShieldAlert className="w-8 h-8 text-white" />
          </div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-100">CyberRakshak SOC-in-a-Box</h1>
          <p className="text-xs text-slate-400 max-w-md mx-auto">
            Affordable, lightweight Security Operations Center with real-time log monitoring, correlation rules, deterministic risk scoring, and AI threat analysis.
          </p>
        </div>

        {/* Quick Role Selection Cards */}
        <div className="space-y-3">
          <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider text-center">
            Select a Demo SOC Operator Profile
          </div>

          {demoAccounts.map((acc) => (
            <button
              key={acc.role}
              onClick={() => login(acc.role)}
              className="w-full p-4 rounded-xl bg-slate-900/80 hover:bg-slate-850 border border-slate-800 hover:border-cyan-500/50 transition-all text-left flex items-center justify-between group shadow-lg"
            >
              <div className="flex items-center gap-3.5">
                <div className="w-10 h-10 rounded-xl bg-slate-950 border border-slate-800 flex items-center justify-center text-cyan-400 group-hover:border-cyan-500/60 transition-colors">
                  <Shield className="w-5 h-5" />
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <span className="font-bold text-sm text-slate-200 group-hover:text-cyan-300">
                      {acc.name}
                    </span>
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase bg-slate-950 border border-slate-800 text-slate-300">
                      {acc.role}
                    </span>
                  </div>
                  <div className="text-[11px] text-slate-400 mt-0.5">{acc.description}</div>
                </div>
              </div>
              <ArrowRight className="w-5 h-5 text-slate-500 group-hover:text-cyan-400 group-hover:translate-x-1 transition-all" />
            </button>
          ))}
        </div>

        <div className="text-center text-[11px] text-slate-500 font-mono">
          Single-tenant isolated sandbox • Zero external data leakage
        </div>
      </div>
    </div>
  );
};
