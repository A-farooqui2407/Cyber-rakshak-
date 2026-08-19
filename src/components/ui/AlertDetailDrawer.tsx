import React, { useState } from "react";
import {
  X,
  ShieldAlert,
  Bot,
  Terminal,
  Activity,
  CheckCircle,
  AlertTriangle,
  Clock,
  Sparkles,
  Loader2,
  ExternalLink,
  ChevronRight,
} from "lucide-react";
import { Alert, AIAnalysisResult } from "../../types";
import { SeverityBadge, StatusBadge } from "./Badge";
import { api } from "../../services/api";
import { useAuth } from "../../context/AuthContext";

interface AlertDetailDrawerProps {
  alert: Alert | null;
  onClose: () => void;
  onStatusChange: (id: string, newStatus: string) => void;
  onEscalated?: (incidentId: string) => void;
}

export const AlertDetailDrawer: React.FC<AlertDetailDrawerProps> = ({
  alert,
  onClose,
  onStatusChange,
  onEscalated,
}) => {
  const { role, user, canPerformAction } = useAuth();
  const [aiAnalysis, setAiAnalysis] = useState<AIAnalysisResult | null>(null);
  const [isAiLoading, setIsAiLoading] = useState(false);
  const [aiError, setAiError] = useState<string | null>(null);
  const [escalating, setEscalating] = useState(false);

  if (!alert) return null;

  const handleFetchAIAnalysis = async () => {
    setIsAiLoading(true);
    setAiError(null);
    try {
      const res = await api.getAIAnalysis({
        threat_type: alert.threat_type,
        severity: alert.severity,
        risk_score: alert.risk_score,
        affected_user: alert.username,
        source_ip: alert.source_ip,
        reasons: alert.reasons || [],
      });
      setAiAnalysis(res);
    } catch (err: any) {
      setAiError(err.message || "Failed to retrieve AI analysis.");
    } finally {
      setIsAiLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 overflow-hidden bg-black/60 backdrop-blur-xs flex justify-end">
      <div className="w-full max-w-2xl bg-slate-950 border-l border-slate-800 h-full flex flex-col shadow-2xl overflow-hidden">
        {/* Top bar */}
        <div className="p-5 border-b border-slate-800 flex items-center justify-between bg-slate-900/60">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-red-950/80 border border-red-800/60 text-red-400">
              <ShieldAlert className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-xs font-mono text-slate-400">ALERT #{alert.id.substring(0, 8)}</span>
                <SeverityBadge severity={alert.severity} />
                <StatusBadge status={alert.status} />
              </div>
              <h2 className="text-sm font-bold text-slate-100 mt-0.5 truncate max-w-md">{alert.title}</h2>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-2 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Scrollable Content */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          {/* Key Metrics Grid */}
          <div className="grid grid-cols-4 gap-3 p-4 rounded-xl bg-slate-900/70 border border-slate-800 text-xs">
            <div>
              <span className="text-[10px] text-slate-400 block uppercase font-mono">Risk Score</span>
              <span className="text-lg font-bold font-mono text-red-400">{alert.risk_score}/100</span>
            </div>
            <div>
              <span className="text-[10px] text-slate-400 block uppercase font-mono">Affected Entity</span>
              <span className="font-semibold text-slate-200 truncate block">{alert.username}</span>
            </div>
            <div>
              <span className="text-[10px] text-slate-400 block uppercase font-mono">Source IP</span>
              <span className="font-mono font-semibold text-amber-400 truncate block">{alert.source_ip}</span>
            </div>
            <div>
              <span className="text-[10px] text-slate-400 block uppercase font-mono">Detection Rule</span>
              <span className="font-mono text-[11px] text-cyan-400 truncate block">{alert.detection_rule}</span>
            </div>
          </div>

          {/* Threat Description */}
          <div className="space-y-2">
            <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Detection Overview</h3>
            <p className="text-xs text-slate-300 bg-slate-900/40 p-3 rounded-lg border border-slate-800/80 leading-relaxed">
              {alert.description}
            </p>
          </div>

          {/* Why Was This Detected? */}
          <div className="space-y-2">
            <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Correlation Evidence</h3>
            <div className="space-y-1.5">
              {alert.reasons?.map((r, i) => (
                <div
                  key={i}
                  className="flex items-start gap-2.5 p-2.5 rounded-lg bg-slate-900/60 border border-slate-800/70 text-xs text-slate-300"
                >
                  <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
                  <span>{r}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Recommended Defensive Actions */}
          <div className="space-y-2">
            <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Standard Remediation Steps</h3>
            <div className="space-y-1.5">
              {alert.recommended_actions?.map((act, i) => (
                <div
                  key={i}
                  className="flex items-start gap-2.5 p-2.5 rounded-lg bg-slate-900/60 border border-slate-800/70 text-xs text-slate-300"
                >
                  <CheckCircle className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                  <span>{act}</span>
                </div>
              ))}
            </div>
          </div>

          {/* AI Threat Explanation Section */}
          <div className="p-4 rounded-xl bg-gradient-to-br from-cyan-950/40 via-slate-900 to-indigo-950/40 border border-cyan-800/40 space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <div className="p-1.5 rounded-md bg-cyan-500/20 text-cyan-400 border border-cyan-500/30">
                  <Bot className="w-4 h-4" />
                </div>
                <div>
                  <div className="text-xs font-bold text-slate-100 flex items-center gap-1.5">
                    CyberRakshak AI Analysis
                    <span className="px-1.5 py-0.2 text-[9px] font-mono rounded bg-cyan-950 text-cyan-300 border border-cyan-800">
                      Gemini 3.7
                    </span>
                  </div>
                  <div className="text-[10px] text-slate-400">Contextual threat breakdown & investigation guidance</div>
                </div>
              </div>

                  {!aiAnalysis && (
                <button
                  onClick={handleFetchAIAnalysis}
                  disabled={isAiLoading || !canPerformAction("ANALYST")}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-medium transition-all shadow-[0_0_12px_rgba(6,182,212,0.25)] disabled:opacity-50"
                >
                  {isAiLoading ? (
                    <>
                      <Loader2 className="w-3.5 h-3.5 animate-spin" />
                      <span>Synthesizing...</span>
                    </>
                  ) : (
                    <>
                      <Sparkles className="w-3.5 h-3.5" />
                      <span>Analyze with AI</span>
                    </>
                  )}
                </button>
              )}
            </div>

            {isAiLoading && (
              <div className="p-6 text-center space-y-2">
                <Loader2 className="w-6 h-6 animate-spin text-cyan-400 mx-auto" />
                <div className="text-xs text-cyan-300 font-mono">Running Gemini 3.7 Threat Reasoning...</div>
              </div>
            )}

            {aiAnalysis && (
              <div className="space-y-4 text-xs">
                {/* Executive Summary */}
                <div className="p-3 rounded-lg bg-slate-950/80 border border-cyan-900/60 text-slate-200 leading-relaxed">
                  <div className="font-semibold text-cyan-300 mb-1 flex items-center gap-1.5">
                    <Sparkles className="w-3.5 h-3.5" />
                    AI Executive Summary
                  </div>
                  {aiAnalysis.summary}
                </div>

                {/* Why Suspicious */}
                <div className="space-y-1">
                  <div className="text-[11px] font-semibold text-slate-300 uppercase font-mono">
                    Why Is This Suspicious?
                  </div>
                  <ul className="list-disc pl-4 space-y-1 text-slate-400">
                    {aiAnalysis.why_suspicious?.map((item, idx) => (
                      <li key={idx}>{item}</li>
                    ))}
                  </ul>
                </div>

                {/* Possible Impact */}
                <div className="space-y-1">
                  <div className="text-[11px] font-semibold text-amber-300 uppercase font-mono">
                    Potential Business Impact
                  </div>
                  <ul className="list-disc pl-4 space-y-1 text-slate-400">
                    {aiAnalysis.possible_impact?.map((item, idx) => (
                      <li key={idx}>{item}</li>
                    ))}
                  </ul>
                </div>

                {/* Forensic Steps */}
                <div className="space-y-1">
                  <div className="text-[11px] font-semibold text-cyan-300 uppercase font-mono">
                    Step-by-Step Investigation Guidance
                  </div>
                  <div className="space-y-1">
                    {aiAnalysis.investigation_steps?.map((step, idx) => (
                      <div key={idx} className="flex items-start gap-2 text-slate-300 text-[11px]">
                        <span className="font-mono text-cyan-400 shrink-0">{idx + 1}.</span>
                        <span>{step}</span>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="text-[10px] text-slate-400 pt-2 border-t border-slate-800 flex justify-between items-center">
                  <span>Confidence: {(aiAnalysis.confidence * 100).toFixed(0)}%</span>
                  <span>
                    {aiAnalysis.fallback_used ? "Offline fallback engine" : aiAnalysis.disclaimer}
                  </span>
                </div>
              </div>
            )}

            {aiError && (
              <div className="p-2.5 rounded bg-red-950/70 border border-red-800 text-xs text-red-300">
                {aiError}
              </div>
            )}
          </div>
        </div>

        {/* Footer Actions */}
        <div className="p-4 border-t border-slate-800 bg-slate-900/80 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <span className="text-xs text-slate-400">Status:</span>
            <select
              value={alert.status}
              disabled={role === "VIEWER"}
              onChange={(e) => onStatusChange(alert.id, e.target.value)}
              className="bg-slate-950 border border-slate-700 text-slate-200 text-xs rounded-lg px-2.5 py-1.5 focus:outline-none focus:border-cyan-500 disabled:opacity-50"
            >
              <option value="NEW">NEW</option>
              <option value="INVESTIGATING">INVESTIGATING</option>
              <option value="RESOLVED">RESOLVED</option>
              <option value="FALSE_POSITIVE">FALSE POSITIVE</option>
            </select>
          </div>

          <div className="flex items-center gap-2">
            {canPerformAction("ANALYST") && (
              <button
                disabled={escalating}
                onClick={async () => {
                  if (!alert) return;
                  setEscalating(true);
                  try {
                    const incident = await api.escalateAlert(alert.id);
                    onEscalated?.(incident.id);
                  } catch (err) {
                    console.error(err);
                  } finally {
                    setEscalating(false);
                  }
                }}
                className="px-4 py-2 rounded-lg bg-orange-600 hover:bg-orange-500 text-xs font-medium text-white"
              >
                {escalating ? "Escalating…" : "Escalate to Incident"}
              </button>
            )}
            <button
              onClick={onClose}
              className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-medium text-slate-300 transition-colors"
            >
              Close
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
