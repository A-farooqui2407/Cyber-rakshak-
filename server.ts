import express, { Request, Response } from "express";
import path from "path";
import dotenv from "dotenv";
import { GoogleGenAI } from "@google/genai";
import { createServer as createViteServer } from "vite";

dotenv.config();

// Initialize Google GenAI on the server side with free Gemini API key support
let aiClient: GoogleGenAI | null = null;
function getAIClient(): GoogleGenAI | null {
  const apiKey =
    process.env.GEMINI_API_KEY ||
    process.env.GOOGLE_API_KEY ||
    process.env.API_KEY ||
    process.env.LLM_API_KEY;

  if (!aiClient && apiKey) {
    aiClient = new GoogleGenAI({
      apiKey: apiKey,
      httpOptions: {
        headers: {
          "User-Agent": "aistudio-build",
        },
      },
    });
  }
  return aiClient;
}

// ----------------- INTERFACES & TYPES -----------------
export interface LogEvent {
  id: string;
  organization_id: string;
  timestamp: string;
  source: string;
  username: string;
  ip_address: string;
  event_type: string;
  action: string;
  status: string;
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" | "INFO";
  metadata: Record<string, any>;
}

export interface Alert {
  id: string;
  organization_id: string;
  title: string;
  description: string;
  threat_type: string;
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  risk_score: number;
  source_ip: string;
  username: string;
  detection_rule: string;
  reasons: string[];
  recommended_actions: string[];
  related_event_ids: string[];
  status: "NEW" | "INVESTIGATING" | "RESOLVED" | "FALSE_POSITIVE";
  created_at: string;
  updated_at: string;
}

export interface Incident {
  id: string;
  organization_id: string;
  alert_id: string;
  title: string;
  description: string;
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  risk_score: number;
  status: "OPEN" | "INVESTIGATING" | "RESOLVED";
  affected_user: string;
  source_ip: string;
  assigned_analyst: string;
  created_at: string;
  updated_at: string;
}

export interface DetectionResult {
  detected: boolean;
  threat_type: string;
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  risk_score: number;
  reasons: string[];
  related_event_ids: string[];
  affected_user: string;
  source_ip: string;
  recommended_actions: string[];
  detection_rule: string;
  mitre_attack?: {
    tactic: string;
    technique: string;
  };
}

// ----------------- IN-MEMORY STATE FOR LIVE SOC -----------------
const DEMO_ORG_ID = "11111111-1111-1111-1111-111111111111";
const KNOWN_SUSPICIOUS_IPS = new Set([
  "198.51.100.42",
  "203.0.113.195",
  "185.220.101.5",
  "45.154.255.89",
  "194.26.29.112",
  "103.251.167.20",
]);

let logsDB: LogEvent[] = [];
let alertsDB: Alert[] = [];
let incidentsDB: Incident[] = [];
let auditLogsDB: Array<{
  id: string;
  actor_email: string;
  action: string;
  resource_type: string;
  resource_id: string;
  metadata?: any;
  created_at: string;
}> = [];

// Seed baseline logs for LexGuard Law Associates
function seedInitialStore() {
  if (logsDB.length > 0) return;

  const now = new Date();
  const baselineUsers = ["ananya.p", "vikram.s", "rahul.sharma", "sysadmin_backup", "priya.k"];
  const baselineIPs = ["10.0.4.15", "10.0.4.22", "192.168.1.105", "10.0.8.99"];

  for (let i = 0; i < 28; i++) {
    const timeOffset = (30 - i) * 8 * 60 * 1000;
    const logTime = new Date(now.getTime() - timeOffset).toISOString();
    const user = baselineUsers[i % baselineUsers.length];
    const ip = baselineIPs[i % baselineIPs.length];

    logsDB.push({
      id: `log_seed_${i + 1}`,
      organization_id: DEMO_ORG_ID,
      timestamp: logTime,
      source: i % 3 === 0 ? "vpn_gateway" : (i % 3 === 1 ? "auth_service" : "internal_file_server"),
      username: user,
      ip_address: ip,
      event_type: i % 5 === 0 ? "FILE_ACCESS" : "LOGIN_SUCCESS",
      action: i % 5 === 0 ? "document_read" : "vpn_authenticate",
      status: "SUCCESS",
      severity: "INFO",
      metadata: {
        device: "Corp-Device-Secure",
        mfa_verified: true,
        protocol: "TLSv1.3",
      },
    });
  }

  // Pre-seed an initial low/medium alert so dashboard has context
  const sampleAlertId = "alert_seed_001";
  alertsDB.push({
    id: sampleAlertId,
    organization_id: DEMO_ORG_ID,
    title: "Unusual Off-Hours File Access",
    description: "Multiple document reads recorded outside standard operating hours.",
    threat_type: "SENSITIVE_DATA_ACCESS",
    severity: "LOW",
    risk_score: 20,
    source_ip: "10.0.8.99",
    username: "vikram.s",
    detection_rule: "OFF_HOURS_DATA_ACCESS",
    reasons: ["Access occurred at 02:45 UTC outside standard 08:00-18:00 window"],
    recommended_actions: ["Review access policy compliance with department manager"],
    related_event_ids: ["log_seed_1", "log_seed_5"],
    status: "INVESTIGATING",
    created_at: new Date(now.getTime() - 2 * 3600 * 1000).toISOString(),
    updated_at: new Date(now.getTime() - 1 * 3600 * 1000).toISOString(),
  });
}

seedInitialStore();

// ----------------- DETECTION & RISK SCORING ENGINE -----------------
function runDetectionEngine(events: LogEvent[]): DetectionResult {
  if (!events || events.length === 0) {
    return {
      detected: false,
      threat_type: "NORMAL_ACTIVITY",
      severity: "LOW",
      risk_score: 5,
      reasons: ["No abnormal activity found across evaluated logs."],
      related_event_ids: [],
      affected_user: "none",
      source_ip: "0.0.0.0",
      recommended_actions: ["Maintain standard perimeter monitoring."],
      detection_rule: "BASELINE_SECURITY_CHECK",
    };
  }

  const failedLogins = events.filter((e) => e.event_type === "LOGIN_FAILED");
  const successLogins = events.filter((e) => e.event_type === "LOGIN_SUCCESS");
  const privEscEvents = events.filter(
    (e) =>
      e.event_type === "PRIVILEGE_ESCALATION" ||
      (e.action && e.action.toLowerCase().includes("sudo")) ||
      (e.action && e.action.toLowerCase().includes("role_elevate")) ||
      (e.action && e.action.toLowerCase().includes("admin") && e.metadata?.prior_role === "VIEWER")
  );
  const suspiciousIPEvents = events.filter(
    (e) => KNOWN_SUSPICIOUS_IPS.has(e.ip_address) || e.event_type === "SUSPICIOUS_IP" || e.metadata?.is_anomalous_ip
  );
  const sensitiveAccessEvents = events.filter(
    (e) =>
      (e.event_type === "FILE_ACCESS" || e.event_type === "DATABASE_ACCESS") &&
      (e.metadata?.is_confidential || e.action?.toLowerCase().includes("confidential") || e.action?.toLowerCase().includes("export"))
  );

  const hasRepeatedFailedLogins = failedLogins.length >= 5;
  const hasSuccessfulLoginAfterFailures = failedLogins.length >= 3 && successLogins.length > 0;
  const hasSuspiciousIP = suspiciousIPEvents.length > 0;
  const hasPrivilegeEscalation = privEscEvents.length > 0;
  const hasSensitiveDataAccess = sensitiveAccessEvents.length > 0;

  // Deterministic Risk Scoring Formula
  let score = 0;
  if (hasRepeatedFailedLogins) score += 25;
  if (hasSuccessfulLoginAfterFailures) score += 20;
  if (hasSuspiciousIP) score += 20;
  if (hasPrivilegeEscalation) score += 30;
  if (hasSensitiveDataAccess) score += 20;
  score = Math.min(100, score);

  let severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" = "LOW";
  if (score >= 80) severity = "CRITICAL";
  else if (score >= 60) severity = "HIGH";
  else if (score >= 30) severity = "MEDIUM";

  const targetUser = events.find((e) => e.username !== "anonymous")?.username || "Rahul Sharma";
  const targetIP = events.find((e) => KNOWN_SUSPICIOUS_IPS.has(e.ip_address))?.ip_address || events[0].ip_address;
  const relatedIds = events.map((e) => e.id);

  // Multi-stage Account Compromise Correlation
  if ((hasRepeatedFailedLogins || hasSuccessfulLoginAfterFailures) && hasPrivilegeEscalation) {
    return {
      detected: true,
      threat_type: "POTENTIAL_ACCOUNT_COMPROMISE",
      severity: severity,
      risk_score: score, // Exactly calculated (e.g. 25+20+20+30 = 95)
      reasons: [
        `High volume of failed authentication attempts (${failedLogins.length} events)`,
        `Successful logon immediately verified following brute-force attempts`,
        `Originates from flagged anomalous external IP address (${targetIP})`,
        `Unauthorized privilege escalation executed to acquire administrative access`,
      ],
      related_event_ids: relatedIds,
      affected_user: targetUser,
      source_ip: targetIP,
      recommended_actions: [
        "Terminate active sessions immediately across all identity providers",
        "Force emergency password reset and mandate hardware-token MFA",
        `Add firewall DROP rule for suspicious IP ${targetIP}`,
        "Audit IAM access logs for unauthorized policy modifications",
        "Examine endpoint telemetry for persistence mechanisms",
      ],
      detection_rule: "MULTI_STAGE_ACCOUNT_COMPROMISE",
      mitre_attack: {
        tactic: "Initial Access & Privilege Escalation",
        technique: "T1110 (Brute Force) + T1078 (Valid Accounts) + T1068 (Privilege Escalation)",
      },
    };
  }

  if (hasPrivilegeEscalation) {
    return {
      detected: true,
      threat_type: "PRIVILEGE_ESCALATION",
      severity: severity,
      risk_score: score,
      reasons: ["Unauthorized role elevation attempt detected on internal core subsystem"],
      related_event_ids: relatedIds,
      affected_user: targetUser,
      source_ip: targetIP,
      recommended_actions: [
        "Review administrative command logs",
        "Revoke temporary access tokens",
        "Confirm authorization with system owner",
      ],
      detection_rule: "UNAUTHORIZED_PRIVILEGE_ESCALATION",
      mitre_attack: {
        tactic: "Privilege Escalation",
        technique: "T1068 (Exploitation for Privilege Escalation)",
      },
    };
  }

  if (hasRepeatedFailedLogins && hasSuccessfulLoginAfterFailures) {
    return {
      detected: true,
      threat_type: "SUSPICIOUS_LOGIN",
      severity: severity,
      risk_score: score,
      reasons: ["Authentication success preceded by rapid burst of failed login attempts"],
      related_event_ids: relatedIds,
      affected_user: targetUser,
      source_ip: targetIP,
      recommended_actions: [
        "Verify login validity with user via out-of-band channel",
        "Enable adaptive location-based challenge verification",
      ],
      detection_rule: "SUSPICIOUS_AUTHENTICATION_SEQUENCE",
      mitre_attack: {
        tactic: "Credential Access",
        technique: "T1110.001 (Password Guessing)",
      },
    };
  }

  if (hasRepeatedFailedLogins) {
    return {
      detected: true,
      threat_type: "BRUTE_FORCE",
      severity: severity,
      risk_score: score,
      reasons: [`Detected ${failedLogins.length} failed login attempts in compact time window`],
      related_event_ids: relatedIds,
      affected_user: targetUser,
      source_ip: targetIP,
      recommended_actions: [
        "Temporarily throttle authentication requests for targeted username",
        "Check IP reputation against global threat feeds",
      ],
      detection_rule: "REPEATED_LOGIN_FAILURES",
      mitre_attack: {
        tactic: "Credential Access",
        technique: "T1110 (Brute Force)",
      },
    };
  }

  return {
    detected: false,
    threat_type: "NORMAL_ACTIVITY",
    severity: "LOW",
    risk_score: score || 10,
    reasons: ["Activity patterns remain within standard variance thresholds"],
    related_event_ids: relatedIds,
    affected_user: targetUser,
    source_ip: targetIP,
    recommended_actions: ["Routine SOC monitoring."],
    detection_rule: "BASELINE_SECURITY_CHECK",
  };
}

// ----------------- DETERMINISTIC AI FALLBACK -----------------
function getDeterministicAIFallback(data: any) {
  const user = data.affected_user || "Rahul Sharma";
  const ip = data.source_ip || "198.51.100.42";
  const threat = data.threat_type || "POTENTIAL_ACCOUNT_COMPROMISE";
  const score = data.risk_score || 95;
  const severity = data.severity || "CRITICAL";

  if (threat.includes("ACCOUNT_COMPROMISE") || score >= 80) {
    return {
      summary: `Critical multi-stage account takeover detected for account '${user}'. An adversary executed a 20-attempt brute-force sequence from IP ${ip}, validated credentials, and immediately escalated administrative privileges.`,
      threat_type: threat,
      severity: severity,
      risk_score: score,
      why_suspicious: [
        `High velocity of 20 authentication failures followed by immediate valid login represents systematic credential guessing.`,
        `Source IP ${ip} is an unverified external node with no prior history in LexGuard Law Associates records.`,
        `Privilege escalation triggered within 60 seconds of login is an unequivocal indicator of post-exploitation activity.`,
      ],
      possible_impact: [
        "Complete unauthorized control over internal enterprise legal records and customer case files.",
        "Elevation to Super Admin granting ability to generate rogue API keys and disable logging.",
        "Potential lateral movement across the internal 10.0.0.0/16 private subnet.",
      ],
      recommended_actions: [
        "Quarantine account: revoke active session tokens and terminate identity provider sessions immediately.",
        "Initiate out-of-band password reset requiring hardware security key registration.",
        `Apply edge firewall DROP rule for remote IP address ${ip}.`,
        "Audit database query logs for confidential case document downloads.",
      ],
      investigation_steps: [
        `Correlate all egress network traffic to ${ip} across proxy logs.`,
        "Check if user Rahul Sharma was actively travelling or on known company VPN at the event timestamp.",
        "Review IAM role revision history for any backdoors created during the session.",
      ],
      confidence: 0.98,
      disclaimer: "Deterministic Tier-3 SOC Analysis (CyberRakshak Intelligence Engine).",
    };
  }

  return {
    summary: `Security incident detected: ${threat} involving user '${user}' from ${ip} with risk score ${score}/100.`,
    threat_type: threat,
    severity: severity,
    risk_score: score,
    why_suspicious: [
      "Activity pattern significantly exceeds baseline threshold.",
      "Anomalous telemetry recorded on authentication gateway.",
    ],
    possible_impact: [
      "Potential unauthorized access or policy non-compliance.",
    ],
    recommended_actions: [
      "Review user access logs and verify validity of recent actions.",
      "Ensure MFA is enforced across all endpoints.",
    ],
    investigation_steps: [
      "Cross-check event with host-based EDR telemetry.",
    ],
    confidence: 0.92,
    disclaimer: "CyberRakshak SOC Analysis.",
  };
}

// ----------------- EXPRESS APPLICATION SETUP -----------------
async function startServer() {
  const app = express();
  const PORT = 3000;

  app.use(express.json());

  // 1. Health check
  app.get("/health", (req: Request, res: Response) => {
    res.json({
      status: "ok",
      service: "CyberRakshak API",
      version: "1.0.0",
      detection_engine: "online",
      organization: "LexGuard Law Associates",
    });
  });

  app.get("/api/health", (req: Request, res: Response) => {
    res.json({
      status: "ok",
      service: "CyberRakshak API",
      version: "1.0.0",
    });
  });

  // 2. Dashboard metrics
  app.get("/api/dashboard", (req: Request, res: Response) => {
    const totalEvents = logsDB.length;
    const criticalAlerts = alertsDB.filter((a) => a.severity === "CRITICAL" && a.status !== "RESOLVED").length;
    const activeIncidents = incidentsDB.filter((inc) => inc.status !== "RESOLVED").length;
    const highRiskEvents = logsDB.filter((l) => l.severity === "CRITICAL" || l.severity === "HIGH").length;

    let overallRiskScore = 18;
    if (alertsDB.length > 0) {
      overallRiskScore = Math.max(...alertsDB.map((a) => a.risk_score));
    }

    const severityCounts: Record<string, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    for (const a of alertsDB) {
      if (severityCounts[a.severity] !== undefined) {
        severityCounts[a.severity]++;
      }
    }

    const eventsByType: Record<string, number> = {};
    for (const l of logsDB) {
      eventsByType[l.event_type] = (eventsByType[l.event_type] || 0) + 1;
    }

    res.json({
      total_events: totalEvents,
      critical_alerts: criticalAlerts,
      active_incidents: activeIncidents,
      high_risk_events: highRiskEvents,
      overall_risk_score: overallRiskScore,
      events_last_24h: totalEvents,
      alerts_last_24h: alertsDB.length,
      alerts_by_severity: severityCounts,
      events_by_type: eventsByType,
      recent_alerts: alertsDB.slice(-6).reverse(),
    });
  });

  // 3. Logs endpoints
  app.get("/api/logs", (req: Request, res: Response) => {
    const { search, severity, event_type, username, ip, limit = 50, offset = 0 } = req.query;
    let filtered = [...logsDB];

    if (search && typeof search === "string") {
      const s = search.toLowerCase();
      filtered = filtered.filter(
        (l) =>
          l.username.toLowerCase().includes(s) ||
          l.ip_address.includes(s) ||
          l.event_type.toLowerCase().includes(s) ||
          l.action.toLowerCase().includes(s)
      );
    }
    if (severity && typeof severity === "string") {
      filtered = filtered.filter((l) => l.severity.toUpperCase() === severity.toUpperCase());
    }
    if (event_type && typeof event_type === "string") {
      filtered = filtered.filter((l) => l.event_type.toUpperCase() === event_type.toUpperCase());
    }
    if (username && typeof username === "string") {
      filtered = filtered.filter((l) => l.username.toLowerCase() === username.toLowerCase());
    }
    if (ip && typeof ip === "string") {
      filtered = filtered.filter((l) => l.ip_address === ip);
    }

    // Newest logs first
    filtered.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());

    const numLimit = Number(limit);
    const numOffset = Number(offset);

    res.json({
      total: filtered.length,
      limit: numLimit,
      offset: numOffset,
      logs: filtered.slice(numOffset, numOffset + numLimit),
    });
  });

  app.post("/api/logs", (req: Request, res: Response) => {
    const newLog: LogEvent = {
      id: req.body.id || `log_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`,
      organization_id: req.body.organization_id || DEMO_ORG_ID,
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

    logsDB.push(newLog);
    res.status(201).json(newLog);
  });

  app.get("/api/logs/:id", (req: Request, res: Response) => {
    const found = logsDB.find((l) => l.id === req.params.id);
    if (!found) return res.status(404).json({ error: "Log not found" });
    res.json(found);
  });

  // 4. Alerts endpoints
  app.get("/api/alerts", (req: Request, res: Response) => {
    const { status, severity } = req.query;
    let filtered = [...alertsDB];
    if (status && typeof status === "string") {
      filtered = filtered.filter((a) => a.status.toUpperCase() === status.toUpperCase());
    }
    if (severity && typeof severity === "string") {
      filtered = filtered.filter((a) => a.severity.toUpperCase() === severity.toUpperCase());
    }
    filtered.sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime());
    res.json(filtered);
  });

  app.get("/api/alerts/:id", (req: Request, res: Response) => {
    const alert = alertsDB.find((a) => a.id === req.params.id);
    if (!alert) return res.status(404).json({ error: "Alert not found" });
    res.json(alert);
  });

  app.patch("/api/alerts/:id", (req: Request, res: Response) => {
    const alert = alertsDB.find((a) => a.id === req.params.id);
    if (!alert) return res.status(404).json({ error: "Alert not found" });

    if (req.body.status) {
      alert.status = req.body.status;
    }
    alert.updated_at = new Date().toISOString();

    auditLogsDB.push({
      id: `audit_${Date.now()}`,
      actor_email: req.body.actor_email || "rahul.sharma@lexguard.com",
      action: "ALERT_STATUS_CHANGED",
      resource_type: "ALERT",
      resource_id: alert.id,
      metadata: { new_status: alert.status },
      created_at: new Date().toISOString(),
    });

    res.json(alert);
  });

  // 5. Incidents endpoints
  app.get("/api/incidents", (req: Request, res: Response) => {
    const { status } = req.query;
    let filtered = [...incidentsDB];
    if (status && typeof status === "string") {
      filtered = filtered.filter((inc) => inc.status.toUpperCase() === status.toUpperCase());
    }
    filtered.sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime());
    res.json(filtered);
  });

  app.get("/api/incidents/:id", (req: Request, res: Response) => {
    const incident = incidentsDB.find((inc) => inc.id === req.params.id);
    if (!incident) return res.status(404).json({ error: "Incident not found" });
    res.json(incident);
  });

  app.post("/api/incidents", (req: Request, res: Response) => {
    const newInc: Incident = {
      id: `inc_${Date.now()}`,
      organization_id: req.body.organization_id || DEMO_ORG_ID,
      alert_id: req.body.alert_id || "",
      title: req.body.title || "Manual Security Incident",
      description: req.body.description || "Escalated by SOC Analyst",
      severity: req.body.severity || "MEDIUM",
      risk_score: req.body.risk_score || 50,
      status: "OPEN",
      affected_user: req.body.affected_user || "Unknown",
      source_ip: req.body.source_ip || "10.0.0.1",
      assigned_analyst: req.body.assigned_analyst || "Ananya Patel (Tier-2 SOC)",
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    };
    incidentsDB.push(newInc);
    res.status(201).json(newInc);
  });

  app.patch("/api/incidents/:id", (req: Request, res: Response) => {
    const incident = incidentsDB.find((inc) => inc.id === req.params.id);
    if (!incident) return res.status(404).json({ error: "Incident not found" });

    if (req.body.status) incident.status = req.body.status;
    if (req.body.assigned_analyst) incident.assigned_analyst = req.body.assigned_analyst;
    incident.updated_at = new Date().toISOString();

    auditLogsDB.push({
      id: `audit_${Date.now()}`,
      actor_email: req.body.actor_email || "rahul.sharma@lexguard.com",
      action: "INCIDENT_STATUS_CHANGED",
      resource_type: "INCIDENT",
      resource_id: incident.id,
      metadata: { new_status: incident.status },
      created_at: new Date().toISOString(),
    });

    res.json(incident);
  });

  // 6. Detection & Risk Analysis endpoints
  app.post("/api/detection/analyze", (req: Request, res: Response) => {
    const events = req.body.events || [];
    const result = runDetectionEngine(events);
    res.json(result);
  });

  app.get("/api/risk/summary", (req: Request, res: Response) => {
    const highestScore = alertsDB.length > 0 ? Math.max(...alertsDB.map((a) => a.risk_score)) : 18;
    let severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" = "LOW";
    if (highestScore >= 80) severity = "CRITICAL";
    else if (highestScore >= 60) severity = "HIGH";
    else if (highestScore >= 30) severity = "MEDIUM";

    res.json({
      overall_risk_score: highestScore,
      severity: severity,
      risk_factors: [
        {
          factor: "Repeated Failed Logins",
          weight: 25,
          active: alertsDB.some((a) => a.reasons.some((r) => r.toLowerCase().includes("failed"))),
          description: "High rate of authentication failures indicative of brute force",
        },
        {
          factor: "Privilege Escalation Attempts",
          weight: 30,
          active: alertsDB.some((a) => a.reasons.some((r) => r.toLowerCase().includes("privilege"))),
          description: "Adversary attempting administrative takeover",
        },
        {
          factor: "Suspicious External IP Exposure",
          weight: 20,
          active: alertsDB.some((a) => a.reasons.some((r) => r.toLowerCase().includes("ip"))),
          description: "Connection originated from unverified remote node",
        },
        {
          factor: "Credential Guessing Sequences",
          weight: 20,
          active: alertsDB.some((a) => a.reasons.some((r) => r.toLowerCase().includes("successful"))),
          description: "Successful login followed consecutive failures",
        },
      ],
      top_risk_entities: [
        {
          user: "Rahul Sharma (Admin)",
          risk: highestScore,
          ip: "198.51.100.42",
          threat_type: alertsDB[0]?.threat_type || "POTENTIAL_ACCOUNT_COMPROMISE",
        },
      ],
    });
  });

  // 7. AI Threat Analysis
  app.post("/api/ai/analyze", async (req: Request, res: Response) => {
    const data = req.body;
    const ai = getAIClient();

    if (!ai) {
      return res.json(getDeterministicAIFallback(data));
    }

    try {
      const prompt = `Analyze this security incident detected by CyberRakshak:
THREAT TYPE: ${data.threat_type || "POTENTIAL_ACCOUNT_COMPROMISE"}
SEVERITY: ${data.severity || "CRITICAL"}
DETERMINISTIC RISK SCORE: ${data.risk_score || 95}/100
AFFECTED USER: ${data.affected_user || "Rahul Sharma"}
SOURCE IP: ${data.source_ip || "198.51.100.42"}
DETECTION REASONS:
${(data.reasons || []).map((r: string) => "- " + r).join("\n")}

Respond with JSON adhering to this schema:
{
  "summary": "Executive summary of the attack",
  "why_suspicious": ["Reason 1", "Reason 2"],
  "possible_impact": ["Impact 1", "Impact 2"],
  "recommended_actions": ["Action 1", "Action 2", "Action 3"],
  "investigation_steps": ["Step 1", "Step 2", "Step 3"],
  "confidence": 0.98
}`;

      const response = await ai.models.generateContent({
        model: "gemini-3.7-flash",
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
        disclaimer: "AI threat explanation generated by Gemini 3.7 Flash.",
      });
    } catch (err: any) {
      console.warn("Gemini API fallback triggered:", err.message);
      res.json(getDeterministicAIFallback(data));
    }
  });

  app.post("/api/ai/investigate", async (req: Request, res: Response) => {
    const { query, context } = req.body;
    const ai = getAIClient();

    if (!ai) {
      return res.json({
        answer: `SOC Investigation Report for '${query}': Based on current correlated evidence for LexGuard Law Associates, anomalous IP 198.51.100.42 systematically executed high-entropy password attacks targeting Rahul Sharma's credentials, followed by an immediate administrative privilege escalation. Priority action: Revoke active session tokens and enforce perimeter IP block.`,
        relevant_indicators: ["198.51.100.42", "Rahul Sharma", "MULTI_STAGE_ACCOUNT_COMPROMISE", "sudo_role_elevate"],
        suggested_queries: [
          "Show all active sessions for Rahul Sharma",
          "What other internal services were queried by 198.51.100.42?",
          "List files accessed in the past 60 minutes",
        ],
      });
    }

    try {
      const response = await ai.models.generateContent({
        model: "gemini-3.7-flash",
        contents: `Context: ${context || "LexGuard Law Associates SOC incident queue"}\nAnalyst Question: ${query}`,
        config: {
          systemInstruction:
            "You are CyberRakshak AI SOC Copilot. Answer analyst questions with precise, actionable forensic guidance, distinguishing fact from possibility.",
        },
      });

      res.json({
        answer: response.text,
        relevant_indicators: ["198.51.100.42", "Rahul Sharma", "Active Threat Event"],
        suggested_queries: [
          "Check perimeter firewall drops",
          "Verify user active sessions",
        ],
      });
    } catch (err) {
      res.json({
        answer: `Forensic Guidance: Immediate isolation recommended for host associated with '${query}'. Revoke OAuth refresh tokens and check SIEM logs.`,
        relevant_indicators: ["198.51.100.42"],
        suggested_queries: ["Show recent administrative audit logs"],
      });
    }
  });

  // 8. Audit Logs
  app.get("/api/audit-logs", (req: Request, res: Response) => {
    res.json(auditLogsDB.slice(-50).reverse());
  });

  // 9. Master Security Demo Simulation Endpoint
  app.post("/api/demo/simulate-attack", (req: Request, res: Response) => {
    const attackUser = "Rahul Sharma";
    const attackIP = "198.51.100.42";
    const now = new Date();

    const attackBatch: LogEvent[] = [];

    // Step 1: 20 Failed Login attempts
    for (let i = 0; i < 20; i++) {
      const logTime = new Date(now.getTime() - (5 * 60 * 1000) + (i * 4 * 1000)).toISOString();
      const failLog: LogEvent = {
        id: `sim_fail_${Date.now()}_${i + 1}`,
        organization_id: DEMO_ORG_ID,
        timestamp: logTime,
        source: "auth_service",
        username: attackUser,
        ip_address: attackIP,
        event_type: "LOGIN_FAILED",
        action: "login_attempt",
        status: "FAILED",
        severity: "MEDIUM",
        metadata: {
          attempt_number: i + 1,
          failure_reason: "INVALID_CREDENTIALS",
          user_agent: "Mozilla/5.0 (Kali Linux; x86_64)",
          geo_city: "Tor Exit Relay 44",
        },
      };
      attackBatch.push(failLog);
      logsDB.push(failLog);
    }

    // Step 2: 1 Successful Login
    const successLog: LogEvent = {
      id: `sim_succ_${Date.now()}`,
      organization_id: DEMO_ORG_ID,
      timestamp: new Date(now.getTime() - 2 * 60 * 1000).toISOString(),
      source: "auth_service",
      username: attackUser,
      ip_address: attackIP,
      event_type: "LOGIN_SUCCESS",
      action: "user_login",
      status: "SUCCESS",
      severity: "HIGH",
      metadata: {
        session_id: "sess_anom_9921",
        auth_method: "password_only",
        mfa_bypassed: true,
      },
    };
    attackBatch.push(successLog);
    logsDB.push(successLog);

    // Step 3: Suspicious IP Telemetry
    const ipLog: LogEvent = {
      id: `sim_ip_${Date.now()}`,
      organization_id: DEMO_ORG_ID,
      timestamp: new Date(now.getTime() - 90 * 1000).toISOString(),
      source: "waf_perimeter",
      username: attackUser,
      ip_address: attackIP,
      event_type: "SUSPICIOUS_IP",
      action: "threat_intel_match",
      status: "FLAGGED",
      severity: "HIGH",
      metadata: {
        is_anomalous_ip: true,
        threat_score: 94,
        reputation: "Known Brute-Force Botnet",
      },
    };
    attackBatch.push(ipLog);
    logsDB.push(ipLog);

    // Step 4: Privilege Escalation
    const privLog: LogEvent = {
      id: `sim_priv_${Date.now()}`,
      organization_id: DEMO_ORG_ID,
      timestamp: new Date(now.getTime() - 30 * 1000).toISOString(),
      source: "iam_control",
      username: attackUser,
      ip_address: attackIP,
      event_type: "PRIVILEGE_ESCALATION",
      action: "sudo_role_elevate_admin",
      status: "DETECTED",
      severity: "CRITICAL",
      metadata: {
        prior_role: "VIEWER",
        requested_role: "SUPER_ADMIN",
        resource: "/api/v1/system/crypto_vault",
      },
    };
    attackBatch.push(privLog);
    logsDB.push(privLog);

    // Step 5: Feed to Detection & Correlation Engine
    const detectionResult = runDetectionEngine(attackBatch);

    // Step 6: Create Critical Alert
    const alertId = `alert_${Date.now()}`;
    const newAlert: Alert = {
      id: alertId,
      organization_id: DEMO_ORG_ID,
      title: "🚨 Potential Account Compromise — Multi-Stage Attack",
      description: `Automated brute force followed by successful logon and unauthorized administrative privilege escalation targeting user '${attackUser}' from malicious IP ${attackIP}.`,
      threat_type: detectionResult.threat_type,
      severity: detectionResult.severity,
      risk_score: detectionResult.risk_score, // 95 CRITICAL
      source_ip: detectionResult.source_ip,
      username: detectionResult.affected_user,
      detection_rule: detectionResult.detection_rule,
      reasons: detectionResult.reasons,
      recommended_actions: detectionResult.recommended_actions,
      related_event_ids: detectionResult.related_event_ids,
      status: "NEW",
      created_at: now.toISOString(),
      updated_at: now.toISOString(),
    };
    alertsDB.unshift(newAlert);

    // Step 7: Create Incident
    const incidentId = `inc_${Date.now()}`;
    const newIncident: Incident = {
      id: incidentId,
      organization_id: DEMO_ORG_ID,
      alert_id: alertId,
      title: `INC-2608-${incidentsDB.length + 101}: Active Account Takeover on ${attackUser}`,
      description: "Multi-stage attack sequence validated by CyberRakshak correlation engine. Mandatory quarantine & credential reset advised.",
      severity: detectionResult.severity,
      risk_score: detectionResult.risk_score,
      status: "OPEN",
      affected_user: detectionResult.affected_user,
      source_ip: detectionResult.source_ip,
      assigned_analyst: "Ananya Patel (Tier-2 SOC)",
      created_at: now.toISOString(),
      updated_at: now.toISOString(),
    };
    incidentsDB.unshift(newIncident);

    // Audit Log
    auditLogsDB.push({
      id: `audit_sim_${Date.now()}`,
      actor_email: "rahul.sharma@lexguard.com",
      action: "DEMO_SIMULATION_STARTED",
      resource_type: "SIMULATION",
      resource_id: alertId,
      metadata: { risk_score: detectionResult.risk_score, threat: detectionResult.threat_type },
      created_at: now.toISOString(),
    });

    res.json({
      attack_simulated: true,
      threat: detectionResult.threat_type,
      risk_score: detectionResult.risk_score,
      severity: detectionResult.severity,
      reasons: detectionResult.reasons,
      alert_id: alertId,
      incident_id: incidentId,
      affected_user: detectionResult.affected_user,
      source_ip: detectionResult.source_ip,
      detection_details: detectionResult,
    });
  });

  // 10. Vite Middleware for live preview
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
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`🛡️ CyberRakshak SOC Server active on http://0.0.0.0:${PORT}`);
  });
}

startServer();
