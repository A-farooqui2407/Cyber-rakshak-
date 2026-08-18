import {
  DashboardMetrics,
  LogEvent,
  Alert,
  Incident,
  RiskSummary,
  DetectionResult,
  AIAnalysisResult,
  AuditLog,
} from "../types";

const BASE_URL = (import.meta as any).env?.VITE_API_URL || "";

async function fetchJSON<T>(url: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE_URL}${url}`, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(options?.headers || {}),
    },
  });

  if (!res.ok) {
    const errBody = await res.text();
    throw new Error(`API error ${res.status}: ${errBody || res.statusText}`);
  }

  return res.json();
}

export const api = {
  // 1. Health
  getHealth: () => fetchJSON<{ status: string; service: string }>("/api/health"),

  // 2. Dashboard
  getDashboard: () => fetchJSON<DashboardMetrics>("/api/dashboard"),

  // 3. Logs
  getLogs: (params?: {
    search?: string;
    severity?: string;
    event_type?: string;
    username?: string;
    ip?: string;
    limit?: number;
    offset?: number;
  }) => {
    const query = new URLSearchParams();
    if (params?.search) query.append("search", params.search);
    if (params?.severity) query.append("severity", params.severity);
    if (params?.event_type) query.append("event_type", params.event_type);
    if (params?.username) query.append("username", params.username);
    if (params?.ip) query.append("ip", params.ip);
    if (params?.limit) query.append("limit", params.limit.toString());
    if (params?.offset) query.append("offset", params.offset.toString());

    return fetchJSON<{ total: number; limit: number; offset: number; logs: LogEvent[] }>(
      `/api/logs?${query.toString()}`
    );
  },

  getLogById: (id: string) => fetchJSON<LogEvent>(`/api/logs/${id}`),

  createLog: (log: Partial<LogEvent>) =>
    fetchJSON<LogEvent>("/api/logs", {
      method: "POST",
      body: JSON.stringify(log),
    }),

  // 4. Alerts
  getAlerts: (params?: { status?: string; severity?: string }) => {
    const query = new URLSearchParams();
    if (params?.status) query.append("status", params.status);
    if (params?.severity) query.append("severity", params.severity);
    return fetchJSON<Alert[]>(`/api/alerts?${query.toString()}`);
  },

  getAlertById: (id: string) => fetchJSON<Alert>(`/api/alerts/${id}`),

  updateAlertStatus: (id: string, status: string, actor_email?: string) =>
    fetchJSON<Alert>(`/api/alerts/${id}`, {
      method: "PATCH",
      body: JSON.stringify({ status, actor_email }),
    }),

  // 5. Incidents
  getIncidents: (params?: { status?: string }) => {
    const query = new URLSearchParams();
    if (params?.status) query.append("status", params.status);
    return fetchJSON<Incident[]>(`/api/incidents?${query.toString()}`);
  },

  getIncidentById: (id: string) => fetchJSON<Incident>(`/api/incidents/${id}`),

  createIncident: (incident: Partial<Incident>) =>
    fetchJSON<Incident>("/api/incidents", {
      method: "POST",
      body: JSON.stringify(incident),
    }),

  updateIncidentStatus: (id: string, status: string, assigned_analyst?: string) =>
    fetchJSON<Incident>(`/api/incidents/${id}`, {
      method: "PATCH",
      body: JSON.stringify({ status, assigned_analyst }),
    }),

  // 6. Detection & Risk
  runDetection: (events: LogEvent[]) =>
    fetchJSON<DetectionResult>("/api/detection/analyze", {
      method: "POST",
      body: JSON.stringify({ events }),
    }),

  getRiskSummary: () => fetchJSON<RiskSummary>("/api/risk/summary"),

  // 7. AI Threat Analysis
  getAIAnalysis: (data: {
    threat_type: string;
    severity: string;
    risk_score: number;
    affected_user: string;
    source_ip: string;
    reasons: string[];
  }) =>
    fetchJSON<AIAnalysisResult>("/api/ai/analyze", {
      method: "POST",
      body: JSON.stringify(data),
    }),

  investigateQuery: (query: string, context?: string) =>
    fetchJSON<{ answer: string; relevant_indicators: string[]; suggested_queries: string[] }>(
      "/api/ai/investigate",
      {
        method: "POST",
        body: JSON.stringify({ query, context }),
      }
    ),

  // 8. Audit Logs
  getAuditLogs: () => fetchJSON<AuditLog[]>("/api/audit-logs"),

  // 9. Demo Attack Simulation
  simulateAttack: () =>
    fetchJSON<{
      attack_simulated: boolean;
      threat: string;
      risk_score: number;
      severity: string;
      reasons: string[];
      alert_id: string;
      incident_id: string;
      affected_user: string;
      source_ip: string;
      detection_details: DetectionResult;
    }>("/api/demo/simulate-attack", {
      method: "POST",
    }),
};
