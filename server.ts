import express, { Request, Response } from "express";
import path from "path";
import dotenv from "dotenv";
import { randomUUID } from "crypto";
import { GoogleGenAI } from "@google/genai";
import { createServer as createViteServer } from "vite";
import { requireAuth, signToken, verifyPassword } from "./server/auth";
import { defaultChecklistLabels, runDetectionEngine } from "./server/detection";
import { createStore } from "./server/store";
import { Alert, DEMO_ORG_ID, DetectionResult, Incident, LogEvent } from "./server/types";

dotenv.config();

const store = createStore();

let aiClient: GoogleGenAI | null = null;
function getAIClient(): GoogleGenAI | null {
  const apiKey =
    process.env.GEMINI_API_KEY ||
    process.env.GOOGLE_API_KEY ||
    process.env.API_KEY ||
    process.env.LLM_API_KEY;
  if (!aiClient && apiKey) {
    aiClient = new GoogleGenAI({ apiKey });
  }
  return aiClient;
}

function orgId(req: Request): string {
  return req.user?.organization_id || DEMO_ORG_ID;
}

function getDeterministicAIFallback(data: any) {
  const user = data.affected_user || "Rahul Sharma";
  const ip = data.source_ip || "198.51.100.42";
  const threat = data.threat_type || "POTENTIAL_ACCOUNT_COMPROMISE";
  const score = data.risk_score || 95;
  const severity = data.severity || "CRITICAL";

  if (String(threat).includes("ACCOUNT_COMPROMISE") || score >= 80) {
    return {
      summary: `Critical multi-stage account takeover detected for account '${user}'. An adversary executed a brute-force sequence from IP ${ip}, validated credentials, and immediately escalated administrative privileges.`,
      threat_type: threat,
      severity,
      risk_score: score,
      why_suspicious: [
        "High velocity of authentication failures followed by immediate valid login represents systematic credential guessing.",
        `Source IP ${ip} is an unverified external node with no prior history in this tenant.`,
        "Privilege escalation triggered within the correlation window is a high-confidence post-exploitation indicator.",
      ],
      possible_impact: [
        "Unauthorized control over internal records and customer case files.",
        "Elevation to Super Admin granting ability to generate rogue API keys and disable logging.",
        "Potential lateral movement across the internal network.",
      ],
      recommended_actions: [
        "Quarantine account: revoke active session tokens immediately.",
        "Initiate out-of-band password reset requiring a hardware security key.",
        `Apply edge firewall DROP rule for remote IP ${ip}.`,
        "Audit database query logs for confidential document downloads.",
      ],
      investigation_steps: [
        `Correlate all egress network traffic to ${ip} across proxy logs.`,
        "Verify whether the user was travelling or on a known company VPN.",
        "Review IAM role revision history for backdoors created during the session.",
      ],
      confidence: 0.98,
      fallback_used: true,
      disclaimer: "Deterministic Tier-3 SOC Analysis (offline fallback — Gemini key missing or API error).",
    };
  }

  return {
    summary: `Security incident detected: ${threat} involving user '${user}' from ${ip} with risk score ${score}/100.`,
    threat_type: threat,
    severity,
    risk_score: score,
    why_suspicious: ["Activity pattern significantly exceeds baseline threshold."],
    possible_impact: ["Potential unauthorized access or policy non-compliance."],
    recommended_actions: ["Review user access logs and verify validity of recent actions."],
    investigation_steps: ["Cross-check event with host-based EDR telemetry."],
    confidence: 0.92,
    fallback_used: true,
    disclaimer: "CyberRakshak SOC Analysis (offline fallback).",
  };
}

async function persistDetection(
  org: string,
  detection: DetectionResult,
  actorEmail: string,
  actorId?: string
): Promise<{ alert: Alert | null; incident: Incident | null }> {
  if (!detection.detected || detection.risk_score < 30) {
    return { alert: null, incident: null };
  }

  const existing = await store.findOpenAlert(org, detection.affected_user, detection.threat_type);
  if (existing) {
    const merged = await store.updateAlert(org, existing.id, {
      risk_score: Math.max(existing.risk_score, detection.risk_score),
      severity: detection.severity,
      reasons: detection.reasons,
      related_event_ids: [...new Set([...(existing.related_event_ids || []), ...detection.related_event_ids])],
    });
    let incident: Incident | null = await store.findOpenIncidentForAlert(org, existing.id);
    if (!incident && detection.risk_score >= 80) {
      incident = await createIncidentFromAlert(merged || existing, actorEmail);
    }
    return { alert: merged || existing, incident };
  }

  const now = new Date().toISOString();
  const alert: Alert = {
    id: randomUUID(),
    organization_id: org,
    title: `${detection.threat_type.replace(/_/g, " ")} — correlated detection`,
    description: detection.reasons.join(" "),
    threat_type: detection.threat_type,
    severity: detection.severity,
    risk_score: detection.risk_score,
    source_ip: detection.source_ip,
    username: detection.affected_user,
    detection_rule: detection.detection_rule,
    reasons: detection.reasons,
    recommended_actions: detection.recommended_actions,
    related_event_ids: detection.related_event_ids,
    status: "NEW",
    created_at: now,
    updated_at: now,
  };
  await store.insertAlert(alert);
  await store.insertAudit({
    id: randomUUID(),
    organization_id: org,
    actor_user_id: actorId || null,
    actor_email: actorEmail,
    action: "ALERT_CREATED",
    resource_type: "ALERT",
    resource_id: alert.id,
    metadata: { threat_type: detection.threat_type, risk_score: detection.risk_score },
    created_at: now,
  });

  let incident: Incident | null = null;
  if (detection.risk_score >= 80) {
    incident = await createIncidentFromAlert(alert, actorEmail, actorId);
  }
  return { alert, incident };
}

async function createIncidentFromAlert(alert: Alert, actorEmail: string, actorId?: string): Promise<Incident> {
  const now = new Date().toISOString();
  const incident: Incident = {
    id: randomUUID(),
    organization_id: alert.organization_id,
    alert_id: alert.id,
    title: `INC-${new Date().toISOString().slice(2, 7).replace("-", "")}: ${alert.threat_type.replace(/_/g, " ")} on ${alert.username}`,
    description: alert.description,
    severity: alert.severity,
    risk_score: alert.risk_score,
    status: "OPEN",
    affected_user: alert.username,
    source_ip: alert.source_ip,
    assigned_analyst: "Ananya Patel (Tier-2 SOC)",
    created_at: now,
    updated_at: now,
  };
  await store.insertIncident(incident, defaultChecklistLabels(alert.source_ip));
  await store.insertAudit({
    id: randomUUID(),
    organization_id: alert.organization_id,
    actor_user_id: actorId || null,
    actor_email: actorEmail,
    action: "INCIDENT_ESCALATED",
    resource_type: "INCIDENT",
    resource_id: incident.id,
    metadata: { alert_id: alert.id },
    created_at: now,
  });
  return incident;
}

async function correlateIngestedLog(log: LogEvent, actorEmail: string, actorId?: string) {
  const since = new Date(Date.now() - 5 * 60 * 1000).toISOString();
  const related = await store.recentLogsForCorrelation(log.organization_id, log.username, log.ip_address, since);
  const rules = await store.listRules();
  const detection = runDetectionEngine(related.length ? related : [log], rules);
  return persistDetection(log.organization_id, detection, actorEmail, actorId);
}

async function startServer() {
  const app = express();
  const PORT = Number(process.env.PORT || 3000);
  app.use(express.json({ limit: "2mb" }));

  app.get("/health", async (_req, res) => {
    res.json({
      status: "ok",
      service: "CyberRakshak API",
      version: "1.1.0",
      store: store.usingSupabase ? "supabase" : "memory",
      detection_engine: "online",
    });
  });
  app.get("/api/health", async (_req, res) => {
    res.json({
      status: "ok",
      service: "CyberRakshak API",
      version: "1.1.0",
      store: store.usingSupabase ? "supabase" : "memory",
    });
  });

  app.post("/api/auth/login", async (req: Request, res: Response) => {
    const email = String(req.body?.email || "").trim();
    const password = String(req.body?.password || "");
    const user = await store.getUserByEmail(email);
    if (!user || !verifyPassword(password, user.password_hash)) {
      return res.status(401).json({ error: "Invalid email or password" });
    }
    const token = signToken({
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role,
      organization: user.organization,
      organization_id: user.organization_id,
    });
    res.json({
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
        organization: user.organization,
      },
    });
  });

  app.get("/api/auth/me", requireAuth(), (req, res) => {
    res.json({ user: req.user });
  });

  app.get("/api/dashboard", requireAuth(), async (req, res) => {
    const org = orgId(req);
    const logs = await store.listLogs(org, { limit: 5000 });
    const alerts = await store.listAlerts(org);
    const incidents = await store.listIncidents(org);
    const series = await store.hourlySeries(org);
    const criticalAlerts = alerts.filter((a) => a.severity === "CRITICAL" && a.status !== "RESOLVED").length;
    const activeIncidents = incidents.filter((inc) => inc.status !== "RESOLVED").length;
    const highRiskEvents = logs.logs.filter((l) => l.severity === "CRITICAL" || l.severity === "HIGH").length;
    const overallRiskScore = alerts.length > 0 ? Math.max(...alerts.map((a) => a.risk_score)) : 18;
    const severityCounts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    for (const a of alerts) {
      if (severityCounts[a.severity as keyof typeof severityCounts] !== undefined) {
        severityCounts[a.severity as keyof typeof severityCounts]++;
      }
    }
    const eventsByType: Record<string, number> = {};
    for (const l of logs.logs) eventsByType[l.event_type] = (eventsByType[l.event_type] || 0) + 1;
    res.json({
      total_events: logs.total,
      critical_alerts: criticalAlerts,
      active_incidents: activeIncidents,
      high_risk_events: highRiskEvents,
      overall_risk_score: overallRiskScore,
      events_last_24h: logs.total,
      alerts_last_24h: alerts.length,
      alerts_by_severity: severityCounts,
      events_by_type: eventsByType,
      recent_alerts: alerts.slice(0, 6),
      series,
    });
  });

  app.get("/api/logs", requireAuth(), async (req, res) => {
    const { search, severity, event_type, username, ip, limit = 50, offset = 0 } = req.query;
    const result = await store.listLogs(orgId(req), {
      search: typeof search === "string" ? search : undefined,
      severity: typeof severity === "string" ? severity : undefined,
      event_type: typeof event_type === "string" ? event_type : undefined,
      username: typeof username === "string" ? username : undefined,
      ip: typeof ip === "string" ? ip : undefined,
      limit: Number(limit),
      offset: Number(offset),
    });
    res.json(result);
  });

  app.post("/api/logs", requireAuth(["ANALYST"]), async (req, res) => {
    const newLog: LogEvent = {
      id: req.body.id || randomUUID(),
      organization_id: orgId(req),
      timestamp: req.body.timestamp || new Date().toISOString(),
      source: req.body.source || "api_ingest",
      username: req.body.username || "anonymous",
      ip_address: req.body.ip_address || "127.0.0.1",
      event_type: req.body.event_type || "GENERIC_EVENT",
      action: req.body.action || "log_record",
      status: req.body.status || "INFO",
      severity: req.body.severity || "INFO",
      metadata: req.body.metadata || {},
    };
    const saved = await store.insertLog(newLog);
    const correlated = await correlateIngestedLog(saved, req.user!.email, req.user!.id);
    res.status(201).json({ ...saved, detection: correlated });
  });

  app.get("/api/logs/:id", requireAuth(), async (req, res) => {
    const found = await store.getLog(orgId(req), req.params.id);
    if (!found) return res.status(404).json({ error: "Log not found" });
    res.json(found);
  });

  app.get("/api/alerts", requireAuth(), async (req, res) => {
    const { status, severity } = req.query;
    const rows = await store.listAlerts(orgId(req), {
      status: typeof status === "string" ? status : undefined,
      severity: typeof severity === "string" ? severity : undefined,
    });
    res.json(rows);
  });

  app.get("/api/alerts/:id", requireAuth(), async (req, res) => {
    const alert = await store.getAlert(orgId(req), req.params.id);
    if (!alert) return res.status(404).json({ error: "Alert not found" });
    res.json(alert);
  });

  app.patch("/api/alerts/:id", requireAuth(["ANALYST"]), async (req, res) => {
    const alert = await store.updateAlert(orgId(req), req.params.id, {
      status: req.body.status,
    });
    if (!alert) return res.status(404).json({ error: "Alert not found" });
    await store.insertAudit({
      id: randomUUID(),
      organization_id: orgId(req),
      actor_user_id: req.user!.id,
      actor_email: req.user!.email,
      action: "ALERT_STATUS_CHANGED",
      resource_type: "ALERT",
      resource_id: alert.id,
      metadata: { new_status: alert.status },
      created_at: new Date().toISOString(),
    });
    res.json(alert);
  });

  app.post("/api/alerts/:id/escalate", requireAuth(["ANALYST"]), async (req, res) => {
    const alert = await store.getAlert(orgId(req), req.params.id);
    if (!alert) return res.status(404).json({ error: "Alert not found" });
    const existing = await store.findOpenIncidentForAlert(orgId(req), alert.id);
    if (existing) return res.json(existing);
    const incident = await createIncidentFromAlert(alert, req.user!.email, req.user!.id);
    res.status(201).json(incident);
  });

  app.get("/api/incidents", requireAuth(), async (req, res) => {
    const { status } = req.query;
    const rows = await store.listIncidents(orgId(req), typeof status === "string" ? status : undefined);
    res.json(rows);
  });

  app.get("/api/incidents/:id", requireAuth(), async (req, res) => {
    const incident = await store.getIncident(orgId(req), req.params.id);
    if (!incident) return res.status(404).json({ error: "Incident not found" });
    const checklist = await store.listChecklist(incident.id);
    res.json({ ...incident, checklist });
  });

  app.post("/api/incidents", requireAuth(["ANALYST"]), async (req, res) => {
    const now = new Date().toISOString();
    const newInc: Incident = {
      id: randomUUID(),
      organization_id: orgId(req),
      alert_id: req.body.alert_id || undefined,
      title: req.body.title || "Manual Security Incident",
      description: req.body.description || "Escalated by SOC Analyst",
      severity: req.body.severity || "MEDIUM",
      risk_score: req.body.risk_score || 50,
      status: "OPEN",
      affected_user: req.body.affected_user || "Unknown",
      source_ip: req.body.source_ip || "10.0.0.1",
      assigned_analyst: req.body.assigned_analyst || req.user!.name,
      created_at: now,
      updated_at: now,
    };
    await store.insertIncident(newInc, defaultChecklistLabels(newInc.source_ip));
    res.status(201).json(newInc);
  });

  app.patch("/api/incidents/:id", requireAuth(["ANALYST"]), async (req, res) => {
    const incident = await store.updateIncident(orgId(req), req.params.id, {
      status: req.body.status,
      assigned_analyst: req.body.assigned_analyst,
    });
    if (!incident) return res.status(404).json({ error: "Incident not found" });
    await store.insertAudit({
      id: randomUUID(),
      organization_id: orgId(req),
      actor_user_id: req.user!.id,
      actor_email: req.user!.email,
      action: "INCIDENT_STATUS_CHANGED",
      resource_type: "INCIDENT",
      resource_id: incident.id,
      metadata: { new_status: incident.status },
      created_at: new Date().toISOString(),
    });
    res.json(incident);
  });

  app.get("/api/incidents/:id/checklist", requireAuth(), async (req, res) => {
    res.json(await store.listChecklist(req.params.id));
  });

  app.patch("/api/checklist/:id", requireAuth(["ANALYST"]), async (req, res) => {
    const item = await store.updateChecklistItem(req.params.id, Boolean(req.body.completed));
    if (!item) return res.status(404).json({ error: "Checklist item not found" });
    res.json(item);
  });

  app.post("/api/detection/analyze", requireAuth(["ANALYST"]), async (req, res) => {
    const events = req.body.events || req.body || [];
    const rules = await store.listRules();
    res.json(runDetectionEngine(events, rules));
  });

  app.get("/api/detection/rules", requireAuth(), async (_req, res) => {
    res.json(await store.listRules());
  });

  app.patch("/api/detection/rules/:id", requireAuth(["ADMIN"]), async (req, res) => {
    const rule = await store.updateRule(req.params.id, {
      weight: req.body.weight,
      enabled: req.body.enabled,
      condition: req.body.condition,
      description: req.body.description,
    });
    if (!rule) return res.status(404).json({ error: "Rule not found" });
    await store.insertAudit({
      id: randomUUID(),
      organization_id: orgId(req),
      actor_user_id: req.user!.id,
      actor_email: req.user!.email,
      action: "DETECTION_RULE_UPDATED",
      resource_type: "RULE",
      resource_id: rule.id,
      metadata: req.body,
      created_at: new Date().toISOString(),
    });
    res.json(rule);
  });

  app.get("/api/risk/summary", requireAuth(), async (req, res) => {
    const alerts = await store.listAlerts(orgId(req));
    const rules = await store.listRules();
    const highestScore = alerts.length > 0 ? Math.max(...alerts.map((a) => a.risk_score)) : 18;
    let severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" = "LOW";
    if (highestScore >= 80) severity = "CRITICAL";
    else if (highestScore >= 60) severity = "HIGH";
    else if (highestScore >= 30) severity = "MEDIUM";
    const weight = (id: string, fallback: number) => rules.find((r) => r.id === id)?.weight ?? fallback;
    res.json({
      overall_risk_score: highestScore,
      severity,
      risk_factors: [
        {
          factor: "Repeated Failed Logins",
          weight: weight("RULE-BF-001", 25),
          active: alerts.some((a) => a.reasons.some((r) => r.toLowerCase().includes("failed"))),
          description: "High rate of authentication failures indicative of brute force",
        },
        {
          factor: "Successful Login After Failures",
          weight: weight("RULE-ATO-002", 20),
          active: alerts.some((a) => a.reasons.some((r) => r.toLowerCase().includes("successful"))),
          description: "Valid login immediately after brute-force attempts",
        },
        {
          factor: "Suspicious External IP Exposure",
          weight: weight("RULE-IP-003", 20),
          active: alerts.some((a) => a.reasons.some((r) => r.toLowerCase().includes("ip"))),
          description: "Connection originated from unverified remote node",
        },
        {
          factor: "Privilege Escalation Attempts",
          weight: weight("RULE-PRIV-004", 30),
          active: alerts.some((a) => a.reasons.some((r) => r.toLowerCase().includes("privilege"))),
          description: "Adversary attempting administrative takeover",
        },
      ],
      top_risk_entities: alerts.slice(0, 5).map((a) => ({
        user: a.username,
        risk: a.risk_score,
        ip: a.source_ip,
        threat_type: a.threat_type,
      })),
    });
  });

  app.post("/api/ai/analyze", requireAuth(["ANALYST"]), async (req, res) => {
    const data = req.body;
    const ai = getAIClient();
    if (!ai) return res.json(getDeterministicAIFallback(data));
    try {
      const prompt = `Analyze this security incident detected by CyberRakshak:
THREAT TYPE: ${data.threat_type || "POTENTIAL_ACCOUNT_COMPROMISE"}
SEVERITY: ${data.severity || "CRITICAL"}
DETERMINISTIC RISK SCORE: ${data.risk_score || 95}/100
AFFECTED USER: ${data.affected_user || "unknown"}
SOURCE IP: ${data.source_ip || "unknown"}
DETECTION REASONS:
${(data.reasons || []).map((r: string) => "- " + r).join("\n")}

Respond with JSON:
{"summary":"","why_suspicious":[],"possible_impact":[],"recommended_actions":[],"investigation_steps":[],"confidence":0.98}`;
      const response = await ai.models.generateContent({
        model: process.env.LLM_MODEL || "gemini-3.7-flash",
        contents: prompt,
        config: {
          systemInstruction:
            "You are CyberRakshak AI — an expert Tier-3 SOC analyst. Output strictly valid JSON. Do not alter risk scores or severities.",
          responseMimeType: "application/json",
        },
      });
      const parsed = JSON.parse(response.text || "{}");
      res.json({
        summary: parsed.summary || "",
        threat_type: data.threat_type,
        severity: data.severity,
        risk_score: data.risk_score,
        why_suspicious: parsed.why_suspicious || [],
        possible_impact: parsed.possible_impact || [],
        recommended_actions: parsed.recommended_actions || [],
        investigation_steps: parsed.investigation_steps || [],
        confidence: parsed.confidence || 0.95,
        fallback_used: false,
        disclaimer: "AI threat explanation generated by Gemini 3.7 Flash.",
      });
    } catch (err: any) {
      console.warn("Gemini API fallback triggered:", err.message);
      res.json(getDeterministicAIFallback(data));
    }
  });

  app.post("/api/ai/investigate", requireAuth(["ANALYST"]), async (req, res) => {
    const { query, context } = req.body;
    const ai = getAIClient();
    if (!ai) {
      return res.json({
        answer: `SOC Investigation Report for '${query}': Correlated evidence indicates anomalous authentication and possible privilege abuse. Priority: isolate sessions, reset credentials, and block the source IP.`,
        relevant_indicators: ["MULTI_STAGE_ACCOUNT_COMPROMISE"],
        suggested_queries: [
          "Show all active sessions for the affected user",
          "List files accessed in the past 60 minutes",
        ],
        fallback_used: true,
      });
    }
    try {
      const response = await ai.models.generateContent({
        model: process.env.LLM_MODEL || "gemini-3.7-flash",
        contents: `Context: ${context || "LexGuard Law Associates SOC incident queue"}\nAnalyst Question: ${query}`,
        config: {
          systemInstruction:
            "You are CyberRakshak AI SOC Copilot. Answer analyst questions with precise, actionable forensic guidance.",
        },
      });
      res.json({
        answer: response.text,
        relevant_indicators: ["Active Threat Event"],
        suggested_queries: ["Check perimeter firewall drops", "Verify user active sessions"],
        fallback_used: false,
      });
    } catch {
      res.json({
        answer: `Forensic Guidance: Immediate isolation recommended for host associated with '${query}'.`,
        relevant_indicators: [],
        suggested_queries: ["Show recent administrative audit logs"],
        fallback_used: true,
      });
    }
  });

  app.get("/api/audit-logs", requireAuth(), async (req, res) => {
    res.json(await store.listAudit(orgId(req), 100));
  });

  app.get("/api/export", requireAuth(["ADMIN"]), async (req, res) => {
    const org = orgId(req);
    const logs = await store.listLogs(org, { limit: 5000 });
    const alerts = await store.listAlerts(org);
    const incidents = await store.listIncidents(org);
    const audit = await store.listAudit(org, 500);
    await store.insertAudit({
      id: randomUUID(),
      organization_id: org,
      actor_user_id: req.user!.id,
      actor_email: req.user!.email,
      action: "SOC_BUNDLE_EXPORTED",
      resource_type: "EXPORT",
      resource_id: org,
      created_at: new Date().toISOString(),
    });
    res.json({
      organization: req.user!.organization,
      exported_at: new Date().toISOString(),
      exported_by: req.user!.email,
      logs: logs.logs,
      alerts,
      incidents,
      audit,
    });
  });

  app.post("/api/demo/simulate-attack", requireAuth(["ADMIN"]), async (req, res) => {
    const attackUser = "Rahul Sharma";
    const attackIP = "198.51.100.42";
    const now = new Date();
    const org = orgId(req);
    const attackBatch: LogEvent[] = [];

    for (let i = 0; i < 20; i++) {
      attackBatch.push({
        id: randomUUID(),
        organization_id: org,
        timestamp: new Date(now.getTime() - 5 * 60 * 1000 + i * 4 * 1000).toISOString(),
        source: "auth_service",
        username: attackUser,
        ip_address: attackIP,
        event_type: "LOGIN_FAILED",
        action: "login_attempt",
        status: "FAILED",
        severity: "MEDIUM",
        metadata: { attempt_number: i + 1, failure_reason: "INVALID_CREDENTIALS" },
      });
    }
    attackBatch.push({
      id: randomUUID(),
      organization_id: org,
      timestamp: new Date(now.getTime() - 2 * 60 * 1000).toISOString(),
      source: "auth_service",
      username: attackUser,
      ip_address: attackIP,
      event_type: "LOGIN_SUCCESS",
      action: "user_login",
      status: "SUCCESS",
      severity: "HIGH",
      metadata: { session_id: "sess_anom_9921", auth_method: "password_only" },
    });
    attackBatch.push({
      id: randomUUID(),
      organization_id: org,
      timestamp: new Date(now.getTime() - 90 * 1000).toISOString(),
      source: "waf_perimeter",
      username: attackUser,
      ip_address: attackIP,
      event_type: "SUSPICIOUS_IP",
      action: "threat_intel_match",
      status: "FLAGGED",
      severity: "HIGH",
      metadata: { is_anomalous_ip: true, reputation: "Known Brute-Force Botnet" },
    });
    attackBatch.push({
      id: randomUUID(),
      organization_id: org,
      timestamp: new Date(now.getTime() - 30 * 1000).toISOString(),
      source: "iam_control",
      username: attackUser,
      ip_address: attackIP,
      event_type: "PRIVILEGE_ESCALATION",
      action: "sudo_role_elevate_admin",
      status: "DETECTED",
      severity: "CRITICAL",
      metadata: { prior_role: "VIEWER", requested_role: "SUPER_ADMIN" },
    });

    await store.insertLogs(attackBatch);
    const rules = await store.listRules();
    const detectionResult = runDetectionEngine(attackBatch, rules);
    const { alert, incident } = await persistDetection(org, detectionResult, req.user!.email, req.user!.id);

    await store.insertAudit({
      id: randomUUID(),
      organization_id: org,
      actor_user_id: req.user!.id,
      actor_email: req.user!.email,
      action: "DEMO_SIMULATION_STARTED",
      resource_type: "SIMULATION",
      resource_id: alert?.id || "none",
      metadata: { risk_score: detectionResult.risk_score, threat: detectionResult.threat_type },
      created_at: now.toISOString(),
    });

    res.json({
      attack_simulated: true,
      threat: detectionResult.threat_type,
      risk_score: detectionResult.risk_score,
      severity: detectionResult.severity,
      reasons: detectionResult.reasons,
      alert_id: alert?.id,
      incident_id: incident?.id,
      affected_user: detectionResult.affected_user,
      source_ip: detectionResult.source_ip,
      detection_details: detectionResult,
    });
  });

  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));
    app.get("*", (req: Request, res: Response) => {
      if (req.path.startsWith("/api")) return res.status(404).json({ error: "Not found" });
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`CyberRakshak SOC Server active on http://0.0.0.0:${PORT}`);
  });
}

startServer().catch((err) => {
  console.error(err);
  process.exit(1);
});
