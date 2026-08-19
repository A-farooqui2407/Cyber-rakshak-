import {
  DetectionResult,
  DetectionRule,
  DEFAULT_RULES,
  KNOWN_SUSPICIOUS_IPS,
  LogEvent,
} from "./types";

const WINDOW_MS = 5 * 60 * 1000;

function ruleWeight(rules: DetectionRule[], id: string, fallback: number): number {
  const rule = rules.find((r) => r.id === id);
  if (!rule || !rule.enabled) return 0;
  return rule.weight;
}

function isEnabled(rules: DetectionRule[], id: string): boolean {
  const rule = rules.find((r) => r.id === id);
  return rule ? rule.enabled : DEFAULT_RULES.find((r) => r.id === id)?.enabled ?? true;
}

function inWindow(ts: string, anchorMs: number): boolean {
  const t = new Date(ts).getTime();
  return Number.isFinite(t) && t <= anchorMs && anchorMs - t <= WINDOW_MS;
}

function isPrivEsc(e: LogEvent): boolean {
  const action = (e.action || "").toLowerCase();
  return (
    e.event_type === "PRIVILEGE_ESCALATION" ||
    action.includes("sudo") ||
    action.includes("role_elevate") ||
    (action.includes("admin") && e.metadata?.prior_role === "VIEWER")
  );
}

function isSuspiciousIp(e: LogEvent): boolean {
  return (
    KNOWN_SUSPICIOUS_IPS.has(e.ip_address) ||
    e.event_type === "SUSPICIOUS_IP" ||
    Boolean(e.metadata?.is_anomalous_ip)
  );
}

function isSensitive(e: LogEvent): boolean {
  const action = (e.action || "").toLowerCase();
  return (
    (e.event_type === "FILE_ACCESS" || e.event_type === "DATABASE_ACCESS") &&
    (Boolean(e.metadata?.is_confidential) || action.includes("confidential") || action.includes("export"))
  );
}

function scoreToSeverity(score: number): DetectionResult["severity"] {
  if (score >= 80) return "CRITICAL";
  if (score >= 60) return "HIGH";
  if (score >= 30) return "MEDIUM";
  return "LOW";
}

/**
 * Correlate events using a 5-minute sliding window keyed by username and source IP.
 */
export function runDetectionEngine(
  events: LogEvent[],
  rules: DetectionRule[] = DEFAULT_RULES
): DetectionResult {
  const empty: DetectionResult = {
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

  if (!events || events.length === 0) return empty;

  const anchor = Math.max(...events.map((e) => new Date(e.timestamp).getTime() || Date.now()));
  const windowed = events.filter((e) => inWindow(e.timestamp, anchor));
  const scope = windowed.length > 0 ? windowed : events;

  const groups = new Map<string, LogEvent[]>();
  for (const e of scope) {
    const userKey = `user:${(e.username || "").toLowerCase()}`;
    const ipKey = `ip:${e.ip_address}`;
    groups.set(userKey, [...(groups.get(userKey) || []), e]);
    groups.set(ipKey, [...(groups.get(ipKey) || []), e]);
  }

  let best: DetectionResult = empty;

  for (const [, group] of groups) {
    const failed = group.filter((e) => e.event_type === "LOGIN_FAILED");
    const success = group.filter((e) => e.event_type === "LOGIN_SUCCESS");
    const priv = group.filter(isPrivEsc);
    const ipHits = group.filter(isSuspiciousIp);
    const sensitive = group.filter(isSensitive);

    const hasBf = isEnabled(rules, "RULE-BF-001") && failed.length >= 5;
    const hasAto = isEnabled(rules, "RULE-ATO-002") && failed.length >= 3 && success.length > 0;
    const hasIp = isEnabled(rules, "RULE-IP-003") && ipHits.length > 0;
    const hasPe = isEnabled(rules, "RULE-PRIV-004") && priv.length > 0;
    const hasSd = isEnabled(rules, "RULE-DATA-005") && sensitive.length > 0;

    if (!hasBf && !hasAto && !hasIp && !hasPe && !hasSd) continue;

    let score = 0;
    if (hasBf) score += ruleWeight(rules, "RULE-BF-001", 25);
    if (hasAto) score += ruleWeight(rules, "RULE-ATO-002", 20);
    if (hasIp) score += ruleWeight(rules, "RULE-IP-003", 20);
    if (hasPe) score += ruleWeight(rules, "RULE-PRIV-004", 30);
    if (hasSd) score += ruleWeight(rules, "RULE-DATA-005", 20);
    score = Math.min(100, score);

    const targetUser = group.find((e) => e.username && e.username !== "anonymous")?.username || "unknown";
    const targetIP =
      group.find((e) => KNOWN_SUSPICIOUS_IPS.has(e.ip_address))?.ip_address || group[0].ip_address;
    const relatedIds = [...new Set(group.map((e) => e.id))];
    const severity = scoreToSeverity(score);

    let result: DetectionResult;

    if ((hasBf || hasAto) && hasPe) {
      result = {
        detected: true,
        threat_type: "POTENTIAL_ACCOUNT_COMPROMISE",
        severity,
        risk_score: score,
        reasons: [
          `High volume of failed authentication attempts (${failed.length} events within 5 minutes)`,
          `Successful logon immediately verified following brute-force attempts`,
          hasIp ? `Originates from flagged anomalous external IP address (${targetIP})` : "Session correlated across authentication and host telemetry",
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
    } else if (hasPe) {
      result = {
        detected: true,
        threat_type: "PRIVILEGE_ESCALATION",
        severity,
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
    } else if (hasBf && hasAto) {
      result = {
        detected: true,
        threat_type: "SUSPICIOUS_LOGIN",
        severity,
        risk_score: score,
        reasons: ["Authentication success preceded by rapid burst of failed login attempts within 5 minutes"],
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
    } else if (hasBf) {
      result = {
        detected: true,
        threat_type: "BRUTE_FORCE",
        severity,
        risk_score: score,
        reasons: [`Detected ${failed.length} failed login attempts in a 5 minute window`],
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
    } else if (hasIp) {
      result = {
        detected: true,
        threat_type: "SUSPICIOUS_IP",
        severity,
        risk_score: score,
        reasons: [`Traffic originates from flagged suspicious IP address: ${targetIP}`],
        related_event_ids: relatedIds,
        affected_user: targetUser,
        source_ip: targetIP,
        recommended_actions: ["Check IP threat intelligence reports", "Challenge connection with step-up MFA"],
        detection_rule: "ANOMALOUS_IP_ACCESS",
        mitre_attack: { tactic: "Initial Access", technique: "T1078 (Valid Accounts from Proxy/TOR)" },
      };
    } else {
      result = {
        detected: true,
        threat_type: "SENSITIVE_DATA_ACCESS",
        severity,
        risk_score: score,
        reasons: [`Sensitive asset access: ${sensitive.length} confidential read/export requests logged`],
        related_event_ids: relatedIds,
        affected_user: targetUser,
        source_ip: targetIP,
        recommended_actions: [
          "Review data classification policy compliance",
          "Ensure least privilege access control",
        ],
        detection_rule: "SENSITIVE_ASSET_ACCESS",
        mitre_attack: { tactic: "Collection", technique: "T1005 (Data from Local System)" },
      };
    }

    if (result.risk_score > best.risk_score || (!best.detected && result.detected)) {
      best = result;
    }
  }

  return best;
}

export function defaultChecklistLabels(sourceIp: string): string[] {
  return [
    "Isolate compromised user endpoint and terminate active sessions",
    `Block adversary IP address ${sourceIp} at the gateway`,
    "Invalidate credentials and issue out-of-band MFA secret",
    "Complete post-incident forensic log export for compliance",
  ];
}
