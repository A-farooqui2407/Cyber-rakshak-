import React, { useState } from "react";
import {
  Cpu,
  Shield,
  Zap,
  Play,
  CheckCircle2,
  AlertTriangle,
  Flame,
  Layers,
  ArrowRight,
  Code,
  Sparkles,
} from "lucide-react";
import { api } from "../services/api";
import { DetectionResult, DetectionRule } from "../types";
import { SeverityBadge } from "../components/ui/Badge";
import { useAuth } from "../context/AuthContext";

export const Detection: React.FC = () => {
  const { role, canPerformAction } = useAuth();
  const [rules, setRules] = useState<DetectionRule[]>([]);
  const [testPayload, setTestPayload] = useState(
    JSON.stringify(
      [
        {
          id: "test-1",
          organization_id: "11111111-1111-1111-1111-111111111111",
          timestamp: new Date().toISOString(),
          source: "auth_service",
          username: "rahul.sharma",
          ip_address: "198.51.100.42",
          event_type: "LOGIN_FAILED",
          action: "login_attempt",
          status: "FAILED",
          severity: "MEDIUM",
        },
        {
          id: "test-2",
          organization_id: "11111111-1111-1111-1111-111111111111",
          timestamp: new Date().toISOString(),
          source: "auth_service",
          username: "rahul.sharma",
          ip_address: "198.51.100.42",
          event_type: "LOGIN_FAILED",
          action: "login_attempt",
          status: "FAILED",
          severity: "MEDIUM",
        },
        {
          id: "test-3",
          organization_id: "11111111-1111-1111-1111-111111111111",
          timestamp: new Date().toISOString(),
          source: "auth_service",
          username: "rahul.sharma",
          ip_address: "198.51.100.42",
          event_type: "LOGIN_SUCCESS",
          action: "login_session_created",
          status: "SUCCESS",
          severity: "INFO",
        },
        {
          id: "test-4",
          organization_id: "11111111-1111-1111-1111-111111111111",
          timestamp: new Date().toISOString(),
          source: "system_kernel",
          username: "rahul.sharma",
          ip_address: "198.51.100.42",
          event_type: "PRIVILEGE_ESCALATION",
          action: "sudo_role_elevate",
          status: "SUCCESS",
          severity: "HIGH",
        },
      ],
      null,
      2
    )
  );

  const [result, setResult] = useState<DetectionResult | null>(null);
  const [isRunning, setIsRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);

  React.useEffect(() => {
    api.getDetectionRules().then(setRules).catch((err) => console.error(err));
  }, []);

  const saveRule = async (id: string, patch: Partial<DetectionRule>) => {
    const updated = await api.updateDetectionRule(id, patch);
    setRules((prev) => prev.map((r) => (r.id === id ? updated : r)));
  };

  const handleRunDetection = async () => {
    setIsRunning(true);
    setError(null);
    try {
      const parsed = JSON.parse(testPayload);
      const res = await api.runDetection(parsed);
      setResult(res);
    } catch (err: any) {
      setError(err.message || "Invalid JSON or detection engine failure");
    } finally {
      setIsRunning(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800/80 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-cyan-950 text-cyan-400 border border-cyan-800/50">
            <Cpu className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-sm font-bold text-slate-100 flex items-center gap-2">
              Deterministic Detection Engine & Rules
              <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-cyan-950 text-cyan-300 border border-cyan-800/50">
                {rules.filter((r) => r.enabled).length} Active Rules • Multi-Signal Correlation
              </span>
            </h2>
            <p className="text-xs text-slate-400">
              Deterministic rule weights prevent false alarms and calculate transparent risk scores
            </p>
          </div>
        </div>
      </div>

      {/* Rules Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {rules.map((rule) => (
          <div
            key={rule.id}
            className="p-4 rounded-xl bg-slate-900/60 border border-slate-800/80 space-y-3 hover:border-slate-700 transition-all"
          >
            <div className="flex items-start justify-between">
              <div>
                <span className="text-[10px] font-mono text-cyan-400 font-semibold">{rule.id}</span>
                <h3 className="text-xs font-bold text-slate-100">{rule.name}</h3>
              </div>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-purple-950 text-purple-300 border border-purple-800">
                +{rule.weight} PTS
              </span>
            </div>

            <p className="text-xs text-slate-400">{rule.description}</p>

            <div className="p-2.5 rounded-lg bg-slate-950 font-mono text-[11px] text-slate-300 border border-slate-850">
              <span className="text-cyan-400 block text-[10px] uppercase">Matching Logic</span>
              {rule.condition}
            </div>

            <div className="flex items-center justify-between text-[11px] text-slate-400 pt-1 border-t border-slate-800/60">
              <span className="font-mono text-amber-400">{rule.mitre}</span>
              {role === "ADMIN" ? (
                <div className="flex items-center gap-2">
                  <input
                    type="number"
                    min={0}
                    max={100}
                    value={rule.weight}
                    onChange={(e) => saveRule(rule.id, { weight: Number(e.target.value) })}
                    className="w-16 bg-slate-950 border border-slate-700 rounded px-1 py-0.5 text-[11px] font-mono"
                  />
                  <button
                    onClick={() => saveRule(rule.id, { enabled: !rule.enabled })}
                    className={`px-2 py-0.5 rounded font-mono text-[10px] border ${
                      rule.enabled
                        ? "bg-emerald-950 text-emerald-300 border-emerald-800"
                        : "bg-slate-900 text-slate-400 border-slate-700"
                    }`}
                  >
                    {rule.enabled ? "ENABLED" : "DISABLED"}
                  </button>
                </div>
              ) : (
                <span className={rule.enabled ? "text-emerald-400 flex items-center gap-1" : "text-slate-500"}>
                  <CheckCircle2 className="w-3 h-3" /> {rule.enabled ? "Active" : "Disabled"}
                </span>
              )}
            </div>
          </div>
        ))}
      </div>

      {/* Interactive Detection Test Workbench */}
      <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800/80 space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider font-mono flex items-center gap-2">
              <Code className="w-4 h-4 text-cyan-400" />
              Live Rule Evaluation Playground
            </h3>
            <p className="text-[11px] text-slate-400">
              Test telemetry vectors against the engine to verify correlation, score weighting, and MITRE categorization
            </p>
          </div>

          <button
            onClick={handleRunDetection}
            disabled={isRunning || !canPerformAction("ANALYST")}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-semibold text-xs transition-all shadow-[0_0_12px_rgba(6,182,212,0.25)]"
          >
            <Play className="w-3.5 h-3.5 fill-white" />
            <span>{isRunning ? "Evaluating..." : "Run Detection Engine"}</span>
          </button>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {/* Left: Input Payload */}
          <div className="space-y-2">
            <label className="text-[11px] text-slate-400 uppercase font-mono block">
              Input Security Events (JSON Array)
            </label>
            <textarea
              rows={12}
              value={testPayload}
              onChange={(e) => setTestPayload(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg p-3 text-cyan-300 font-mono text-[11px] focus:outline-none focus:border-cyan-500"
            />
          </div>

          {/* Right: Evaluated Output */}
          <div className="space-y-2">
            <label className="text-[11px] text-slate-400 uppercase font-mono block">
              Correlation Engine Output
            </label>
            {result ? (
              <div className="p-4 rounded-lg bg-slate-950 border border-slate-800 space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <AlertTriangle className="w-4 h-4 text-red-400" />
                    <span className="text-xs font-bold text-slate-200">
                      {result.threat_type}
                    </span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-sm font-bold text-red-400">
                      Score: {result.risk_score}/100
                    </span>
                    <SeverityBadge severity={result.severity} />
                  </div>
                </div>

                <div className="text-xs space-y-1">
                  <span className="text-slate-400 font-mono block text-[10px] uppercase">
                    Triggered Correlation Reasons:
                  </span>
                  <ul className="list-disc pl-4 space-y-0.5 text-slate-300 text-[11px]">
                    {result.reasons?.map((r, i) => (
                      <li key={i}>{r}</li>
                    ))}
                  </ul>
                </div>

                <div className="pt-2 border-t border-slate-800/80 text-[11px] text-slate-400 space-y-1">
                  <div>Affected Entity: <span className="text-slate-200">{result.affected_user}</span></div>
                  <div>Source IP: <span className="text-amber-400 font-mono">{result.source_ip}</span></div>
                  <div>Matched Rule: <span className="text-cyan-400 font-mono">{result.detection_rule}</span></div>
                </div>
              </div>
            ) : (
              <div className="h-64 rounded-lg bg-slate-950 border border-slate-800/80 flex items-center justify-center text-slate-500 font-mono text-xs p-6 text-center">
                Click "Run Detection Engine" to execute correlation logic on the test payload.
              </div>
            )}

            {error && (
              <div className="p-3 rounded-lg bg-red-950 border border-red-800 text-xs text-red-300">
                {error}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
