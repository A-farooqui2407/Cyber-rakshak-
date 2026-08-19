export type SeverityLevel = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" | "INFO";
export type AlertStatus = "NEW" | "INVESTIGATING" | "RESOLVED" | "FALSE_POSITIVE";
export type IncidentStatus = "OPEN" | "INVESTIGATING" | "RESOLVED";
export type UserRole = "ADMIN" | "ANALYST" | "VIEWER";

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
  severity: SeverityLevel;
  metadata?: Record<string, any>;
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
  status: AlertStatus;
  created_at: string;
  updated_at: string;
}

export interface Incident {
  id: string;
  organization_id: string;
  alert_id?: string;
  title: string;
  description: string;
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  risk_score: number;
  status: IncidentStatus;
  affected_user: string;
  source_ip: string;
  assigned_analyst: string;
  created_at: string;
  updated_at: string;
}

export interface ChecklistItem {
  id: string;
  incident_id: string;
  position: number;
  label: string;
  completed: boolean;
  updated_at: string;
}

export interface DetectionRule {
  id: string;
  name: string;
  mitre: string;
  weight: number;
  condition: string;
  description: string;
  enabled: boolean;
  updated_at?: string;
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
  mitre_attack?: { tactic: string; technique: string };
}

export interface AuditLog {
  id: string;
  organization_id?: string;
  actor_user_id?: string | null;
  actor_email: string;
  action: string;
  resource_type: string;
  resource_id: string;
  metadata?: any;
  created_at: string;
}

export interface UserProfile {
  id: string;
  name: string;
  email: string;
  role: UserRole;
  organization: string;
}

export interface StoredUser extends UserProfile {
  organization_id: string;
  password_hash: string;
}

export interface HourlyPoint {
  time: string;
  events: number;
  alerts: number;
}

export const DEMO_ORG_ID = "11111111-1111-1111-1111-111111111111";

export const KNOWN_SUSPICIOUS_IPS = new Set([
  "198.51.100.42",
  "203.0.113.195",
  "185.220.101.5",
  "45.154.255.89",
  "194.26.29.112",
  "103.251.167.20",
]);

export const DEFAULT_RULES: DetectionRule[] = [
  {
    id: "RULE-BF-001",
    name: "Brute Force Authentication Pattern",
    mitre: "T1110.001 - Password Guessing",
    weight: 25,
    condition: ">= 5 LOGIN_FAILED events for the same username or IP within a 5 minute window",
    description: "Detects automated password spraying and dictionary attacks against user credentials.",
    enabled: true,
  },
  {
    id: "RULE-ATO-002",
    name: "Successful Login After Brute Force",
    mitre: "T1078 - Valid Accounts",
    weight: 20,
    condition: "LOGIN_SUCCESS in the same 5 minute window after brute-force failures",
    description: "Indicates an attacker obtained valid credentials after repeated attempts.",
    enabled: true,
  },
  {
    id: "RULE-IP-003",
    name: "Known Malicious / Tor IP Ingress",
    mitre: "T1090 - Proxy Network",
    weight: 20,
    condition: "Source IP matches the threat-intel set or event_type is SUSPICIOUS_IP",
    description: "Flags remote sessions originating from known adversary or Tor-like nodes.",
    enabled: true,
  },
  {
    id: "RULE-PRIV-004",
    name: "Immediate Post-Breach Privilege Escalation",
    mitre: "T1548 - Abuse Elevation Control Mechanism",
    weight: 30,
    condition: "PRIVILEGE_ESCALATION / sudo / role_elevate in the correlation window",
    description: "Intercepts administrative elevation shortly after initial access.",
    enabled: true,
  },
  {
    id: "RULE-DATA-005",
    name: "Sensitive Asset Access",
    mitre: "T1005 - Data from Local System",
    weight: 20,
    condition: "Confidential file or database export in the correlation window",
    description: "Detects access to classified records after a suspicious session.",
    enabled: true,
  },
];
