import React, { useState } from "react";
import {
  Bot,
  Sparkles,
  Send,
  Loader2,
  Terminal,
  ShieldAlert,
  HelpCircle,
  CheckCircle,
  Layers,
  ArrowRight,
} from "lucide-react";
import { api } from "../services/api";
import { useAuth } from "../context/AuthContext";

interface Message {
  sender: "user" | "ai";
  text: string;
  indicators?: string[];
  suggested_queries?: string[];
  fallback_used?: boolean;
}

export const AIAssistant: React.FC = () => {
  const { canPerformAction } = useAuth();
  const [query, setQuery] = useState("");
  const [messages, setMessages] = useState<Message[]>([
    {
      sender: "ai",
      text: "Greetings. I am CyberRakshak's AI Threat Copilot powered by Gemini 3.7. I can analyze attack timelines, explain root causes, translate MITRE ATT&CK techniques, and generate remediation commands for your SOC response.",
      suggested_queries: [
        "Explain the attack on rahul.sharma",
        "Generate firewall rule to block 198.51.100.42",
        "What is the MITRE mapping for brute force with privilege escalation?",
        "Draft an incident summary for compliance",
      ],
    },
  ]);
  const [isLoading, setIsLoading] = useState(false);

  const handleSend = async (userPrompt?: string) => {
    const textToSend = userPrompt || query;
    if (!textToSend.trim() || isLoading || !canPerformAction("ANALYST")) return;

    const newMsgs: Message[] = [...messages, { sender: "user", text: textToSend }];
    setMessages(newMsgs);
    setQuery("");
    setIsLoading(true);

    try {
      const res = await api.investigateQuery(textToSend);
      setMessages([
        ...newMsgs,
        {
          sender: "ai",
          text: res.answer,
          indicators: res.relevant_indicators,
          suggested_queries: res.suggested_queries,
          fallback_used: res.fallback_used,
        },
      ]);
    } catch (err: any) {
      setMessages([
        ...newMsgs,
        {
          sender: "ai",
          text: "I was unable to complete the AI investigation query at this moment. Fallback: Check the correlation rule definitions or the incident queue for forensic logs.",
        },
      ]);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="h-[calc(100vh-8.5rem)] flex flex-col p-4 rounded-xl bg-slate-900/60 border border-slate-800/80">
      {/* Header */}
      <div className="pb-3 border-b border-slate-800 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-cyan-950 text-cyan-400 border border-cyan-800/50">
            <Bot className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-sm font-bold text-slate-100 flex items-center gap-2">
              CyberRakshak AI SOC Copilot
              <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-cyan-950 text-cyan-300 border border-cyan-800/50">
                Gemini 3.7 Flash Engine
              </span>
            </h2>
            <p className="text-xs text-slate-400">Contextual natural-language security forensics & triage assistant</p>
          </div>
        </div>
      </div>

      {/* Messages Scroll Area */}
      <div className="flex-1 overflow-y-auto py-4 space-y-4 pr-1">
        {messages.map((m, idx) => (
          <div
            key={idx}
            className={`flex flex-col ${m.sender === "user" ? "items-end" : "items-start"}`}
          >
            <div
              className={`max-w-2xl p-4 rounded-xl text-xs leading-relaxed space-y-2.5 ${
                m.sender === "user"
                  ? "bg-cyan-600 text-white rounded-br-none"
                  : "bg-slate-950 border border-slate-800 text-slate-200 rounded-bl-none shadow-lg"
              }`}
            >
              {m.sender === "ai" && (
                <div className="flex items-center gap-1.5 text-cyan-400 font-mono text-[10px] uppercase font-bold">
                  <Sparkles className="w-3 h-3" />
                  CyberRakshak AI Analyst
                </div>
              )}
              <div className="whitespace-pre-wrap">{m.text}</div>
              {m.fallback_used && (
                <div className="text-[10px] font-mono text-amber-400">Offline fallback — Gemini key not configured or API error.</div>
              )}

              {/* Extracted Indicators */}
              {m.indicators && m.indicators.length > 0 && (
                <div className="pt-2 border-t border-slate-850 space-y-1">
                  <div className="text-[10px] font-mono text-slate-400 uppercase">
                    Correlated Artifacts:
                  </div>
                  <div className="flex flex-wrap gap-1.5">
                    {m.indicators.map((ind, i) => (
                      <span
                        key={i}
                        className="px-2 py-0.5 rounded bg-slate-900 text-amber-400 border border-slate-750 font-mono text-[10px]"
                      >
                        {ind}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>

            {/* Quick suggested follow-up questions */}
            {m.suggested_queries && m.suggested_queries.length > 0 && (
              <div className="mt-2 flex flex-wrap gap-1.5 max-w-2xl">
                {m.suggested_queries.map((q, i) => (
                  <button
                    key={i}
                    onClick={() => handleSend(q)}
                    className="flex items-center gap-1 px-2.5 py-1 rounded-full bg-slate-950 hover:bg-slate-800 border border-slate-800 text-slate-300 text-[11px] transition-colors"
                  >
                    <span>{q}</span>
                    <ArrowRight className="w-3 h-3 text-cyan-400" />
                  </button>
                ))}
              </div>
            )}
          </div>
        ))}

        {isLoading && (
          <div className="flex items-center gap-2 text-cyan-400 text-xs font-mono p-3 bg-slate-950 border border-slate-800 rounded-xl w-fit">
            <Loader2 className="w-4 h-4 animate-spin" />
            <span>Analyzing SOC telemetry with Gemini 3.7...</span>
          </div>
        )}
      </div>

      {/* Input Form */}
      <form
        onSubmit={(e) => {
          e.preventDefault();
          handleSend();
        }}
        className="pt-3 border-t border-slate-800 flex items-center gap-2"
      >
        <input
          type="text"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Ask AI Copilot about any security alert, IP address, MITRE tactic, or log pattern..."
          className="flex-1 bg-slate-950 border border-slate-800 rounded-xl px-4 py-2.5 text-xs text-slate-200 placeholder-slate-400 focus:outline-none focus:border-cyan-500"
        />
        <button
          type="submit"
          disabled={!query.trim() || isLoading || !canPerformAction("ANALYST")}
          className="flex items-center gap-2 px-5 py-2.5 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white font-semibold text-xs shadow-md transition-all disabled:opacity-50 disabled:cursor-not-allowed"
        >
          <Send className="w-3.5 h-3.5" />
          <span>Investigate</span>
        </button>
      </form>
    </div>
  );
};
