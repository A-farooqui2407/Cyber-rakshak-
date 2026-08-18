import React, { useState } from "react";
import {
  Flame,
  CheckCircle2,
  AlertTriangle,
  Loader2,
  X,
  Play,
  ArrowRight,
  ShieldCheck,
  Zap,
} from "lucide-react";
import { api } from "../../services/api";
import { SeverityBadge } from "./Badge";

interface SimulationModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSimulationComplete: (result: any) => void;
}

export const SimulationModal: React.FC<SimulationModalProps> = ({
  isOpen,
  onClose,
  onSimulationComplete,
}) => {
  const [isRunning, setIsRunning] = useState(false);
  const [currentStep, setCurrentStep] = useState(0);
  const [simulationResult, setSimulationResult] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);

  if (!isOpen) return null;

  const steps = [
    { title: "Ingesting Security Telemetry", desc: "Collecting high-velocity authentication stream from edge perimeter" },
    { title: "20 Failed Login Attempts Detected", desc: "Rule 1 Triggered: Consecutive failures targeting Rahul Sharma" },
    { title: "Valid Authentication Logged", desc: "Rule 2 Triggered: Credential validation immediately following brute force" },
    { title: "Anomalous IP Reputation Matched", desc: "Rule 3 Triggered: Traffic from flagged node 198.51.100.42" },
    { title: "Privilege Escalation Intercepted", desc: "Rule 4 Triggered: sudo_role_elevate executed on crypto vault" },
    { title: "Event Correlation & Graph Analysis", desc: "Multi-signal synthesis: Correlating user, IP, timing, and actions" },
    { title: "Deterministic Risk Calculation", desc: "25 (BF) + 20 (Login) + 20 (IP) + 30 (PrivEsc) = 95/100" },
    { title: "Generating Critical Threat Alert", desc: "Threat: POTENTIAL_ACCOUNT_COMPROMISE (Severity: CRITICAL)" },
    { title: "Automated Incident Escalation", desc: "Creating INC-2608 ticket & assigning Tier-2 Analyst" },
    { title: "Synthesizing AI Forensic Guidance", desc: "Generating mitigation playbook & investigation steps" },
  ];

  const handleStartSimulation = async () => {
    setIsRunning(true);
    setCurrentStep(0);
    setError(null);
    setSimulationResult(null);

    // Progressive visual step animation
    for (let i = 0; i < steps.length - 1; i++) {
      setCurrentStep(i);
      await new Promise((resolve) => setTimeout(resolve, 380));
    }

    try {
      const result = await api.simulateAttack();
      setCurrentStep(steps.length - 1);
      await new Promise((resolve) => setTimeout(resolve, 300));
      setSimulationResult(result);
      setIsRunning(false);
      onSimulationComplete(result);
    } catch (err: any) {
      setError(err.message || "Failed to execute security simulation.");
      setIsRunning(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
      <div className="bg-slate-950 border border-slate-800 rounded-2xl w-full max-w-2xl overflow-hidden shadow-2xl flex flex-col max-h-[90vh]">
        {/* Header */}
        <div className="p-5 border-b border-slate-800 flex items-center justify-between bg-slate-900/50">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-red-950/80 text-red-400 border border-red-800/60 shadow-[0_0_15px_rgba(239,68,68,0.25)]">
              <Flame className="w-5 h-5 animate-pulse" />
            </div>
            <div>
              <h2 className="text-base font-bold text-slate-100 flex items-center gap-2">
                Multi-Stage Attack Simulation
                <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-red-950 text-red-300 border border-red-800/60">
                  CRITICAL BREACH DEMO
                </span>
              </h2>
              <p className="text-xs text-slate-400">
                End-to-end verification of CyberRakshak detection, correlation, risk scoring, and AI explanation.
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-2 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Body Content */}
        <div className="p-6 overflow-y-auto space-y-6 flex-1">
          {/* Target Scenario Info */}
          <div className="grid grid-cols-3 gap-3 p-3.5 rounded-xl bg-slate-900/60 border border-slate-800/80 text-xs">
            <div>
              <span className="text-[10px] text-slate-400 block uppercase font-mono">Monitored Entity</span>
              <span className="font-semibold text-slate-200">Rahul Sharma (Admin)</span>
            </div>
            <div>
              <span className="text-[10px] text-slate-400 block uppercase font-mono">Adversary Source IP</span>
              <span className="font-semibold text-amber-400 font-mono">198.51.100.42</span>
            </div>
            <div>
              <span className="text-[10px] text-slate-400 block uppercase font-mono">Expected Outcome</span>
              <span className="font-semibold text-red-400">Score 95 (CRITICAL)</span>
            </div>
          </div>

          {/* 10-Step Execution Pipeline */}
          <div className="space-y-2">
            <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
              Detection Pipeline Execution
            </div>
            <div className="space-y-2 max-h-60 overflow-y-auto pr-1">
              {steps.map((step, idx) => {
                const isComplete = idx < currentStep || (simulationResult && !isRunning);
                const isCurrent = idx === currentStep && isRunning;
                const isPending = idx > currentStep && !simulationResult;

                return (
                  <div
                    key={idx}
                    className={`flex items-start gap-3 p-2.5 rounded-lg border transition-all text-xs ${
                      isComplete
                        ? "bg-slate-900/70 border-cyan-800/40 text-slate-200"
                        : isCurrent
                        ? "bg-cyan-950/40 border-cyan-500 text-cyan-200 shadow-[0_0_10px_rgba(6,182,212,0.15)]"
                        : "bg-slate-950 border-slate-850 text-slate-400"
                    }`}
                  >
                    <div className="mt-0.5">
                      {isComplete ? (
                        <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                      ) : isCurrent ? (
                        <Loader2 className="w-4 h-4 text-cyan-400 animate-spin" />
                      ) : (
                        <div className="w-4 h-4 rounded-full border border-slate-700 flex items-center justify-center text-[9px] font-mono text-slate-400">
                          {idx + 1}
                        </div>
                      )}
                    </div>
                    <div className="flex-1">
                      <div className="font-medium">{step.title}</div>
                      <div className="text-[11px] text-slate-400">{step.desc}</div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Result Card after completion */}
          {simulationResult && (
            <div className="p-4 rounded-xl bg-gradient-to-br from-red-950/80 via-slate-900 to-slate-950 border border-red-700/60 space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <AlertTriangle className="w-5 h-5 text-red-400" />
                  <span className="font-bold text-red-200 text-sm">
                    {simulationResult.threat.replace(/_/g, " ")}
                  </span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-xs font-mono text-slate-400">Risk Score:</span>
                  <span className="px-2 py-0.5 rounded bg-red-900/80 text-red-200 font-bold text-sm border border-red-600 font-mono">
                    {simulationResult.risk_score}/100
                  </span>
                  <SeverityBadge severity="CRITICAL" />
                </div>
              </div>

              <div className="text-xs text-slate-300 space-y-1">
                <div className="font-semibold text-slate-200">Why was this classified as Critical?</div>
                <ul className="list-disc pl-4 space-y-0.5 text-slate-400">
                  {simulationResult.reasons?.map((r: string, idx: number) => (
                    <li key={idx}>{r}</li>
                  ))}
                </ul>
              </div>

              <div className="pt-2 flex items-center justify-between text-xs text-slate-400 border-t border-red-900/40">
                <span>Alert ID: <span className="font-mono text-slate-300">{simulationResult.alert_id.substring(0, 12)}...</span></span>
                <span>Incident: <span className="font-mono text-slate-300">{simulationResult.incident_id.substring(0, 12)}...</span></span>
              </div>
            </div>
          )}

          {error && (
            <div className="p-3 rounded-lg bg-red-950/80 border border-red-800 text-xs text-red-300">
              {error}
            </div>
          )}
        </div>

        {/* Footer Actions */}
        <div className="p-4 border-t border-slate-800 bg-slate-900/80 flex items-center justify-between">
          <div className="text-xs text-slate-400 flex items-center gap-1.5">
            <Zap className="w-4 h-4 text-cyan-400" />
            <span>Deterministic engine calculates exact risk score from real logs</span>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={onClose}
              className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-medium text-slate-300 transition-colors"
            >
              Close
            </button>
            <button
              onClick={handleStartSimulation}
              disabled={isRunning}
              className="flex items-center gap-2 px-5 py-2 rounded-lg bg-red-600 hover:bg-red-500 text-white font-semibold text-xs transition-all shadow-[0_0_15px_rgba(239,68,68,0.3)] disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {isRunning ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  <span>Executing Pipeline...</span>
                </>
              ) : (
                <>
                  <Play className="w-4 h-4 fill-white" />
                  <span>{simulationResult ? "Re-run Attack Simulation" : "Launch Attack Simulation"}</span>
                </>
              )}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
