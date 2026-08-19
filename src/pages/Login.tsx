import React, { useState } from "react";
import { ShieldAlert, Shield, ArrowRight, Lock } from "lucide-react";
import { useAuth } from "../context/AuthContext";
import { UserRole } from "../types";

const DEMO: Array<{ role: UserRole; name: string; email: string; password: string; description: string }> = [
  {
    role: "ADMIN",
    name: "Rahul Sharma",
    email: "rahul.sharma@lexguard.com",
    password: "Admin@LexGuard1",
    description: "Full access: rules, simulation, export, incidents.",
  },
  {
    role: "ANALYST",
    name: "Ananya Patel",
    email: "ananya.p@lexguard.com",
    password: "Analyst@LexGuard1",
    description: "Triage alerts, escalate incidents, run AI investigations.",
  },
  {
    role: "VIEWER",
    name: "Vikram Singh",
    email: "vikram.s@lexguard.com",
    password: "Viewer@LexGuard1",
    description: "Read-only auditor access to dashboards and telemetry.",
  },
];

export const Login: React.FC = () => {
  const { login } = useAuth();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (e?: React.FormEvent, creds?: { email: string; password: string }) => {
    e?.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await login(creds?.email || email, creds?.password || password);
    } catch (err: any) {
      setError(err.message || "Login failed");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 flex flex-col items-center justify-center p-6 text-slate-100">
      <div className="w-full max-w-xl space-y-6">
        <div className="text-center space-y-3">
          <div className="w-14 h-14 rounded-2xl bg-gradient-to-br from-cyan-500 via-blue-600 to-indigo-700 flex items-center justify-center mx-auto">
            <ShieldAlert className="w-8 h-8 text-white" />
          </div>
          <h1 className="text-2xl font-bold tracking-tight">CyberRakshak SOC-in-a-Box</h1>
          <p className="text-xs text-slate-400 max-w-md mx-auto">
            Sign in with your SOC operator account. Roles are enforced on the server.
          </p>
        </div>

        <form onSubmit={(e) => submit(e)} className="space-y-3 p-4 rounded-xl bg-slate-900/80 border border-slate-800">
          <label className="block text-xs text-slate-400">
            Email
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="mt-1 w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-100"
              required
            />
          </label>
          <label className="block text-xs text-slate-400">
            Password
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="mt-1 w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-100"
              required
            />
          </label>
          {error && <div className="text-xs text-red-400">{error}</div>}
          <button
            type="submit"
            disabled={busy}
            className="w-full flex items-center justify-center gap-2 px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-sm font-semibold disabled:opacity-50"
          >
            <Lock className="w-4 h-4" />
            {busy ? "Signing in…" : "Sign in"}
          </button>
        </form>

        <div className="space-y-3">
          <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider text-center">
            Demo operator profiles
          </div>
          {DEMO.map((acc) => (
            <button
              key={acc.role}
              onClick={() => submit(undefined, { email: acc.email, password: acc.password })}
              className="w-full p-4 rounded-xl bg-slate-900/80 hover:bg-slate-850 border border-slate-800 hover:border-cyan-500/50 transition-all text-left flex items-center justify-between group"
            >
              <div className="flex items-center gap-3.5">
                <div className="w-10 h-10 rounded-xl bg-slate-950 border border-slate-800 flex items-center justify-center text-cyan-400">
                  <Shield className="w-5 h-5" />
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <span className="font-bold text-sm">{acc.name}</span>
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase bg-slate-950 border border-slate-800">
                      {acc.role}
                    </span>
                  </div>
                  <div className="text-[11px] text-slate-400 mt-0.5">{acc.description}</div>
                  <div className="text-[10px] font-mono text-slate-500 mt-1">{acc.email}</div>
                </div>
              </div>
              <ArrowRight className="w-5 h-5 text-slate-500 group-hover:text-cyan-400" />
            </button>
          ))}
        </div>
      </div>
    </div>
  );
};
