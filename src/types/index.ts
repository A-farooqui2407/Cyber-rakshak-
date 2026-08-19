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

export interface HourlyPoint {
  time: string;
  events: number;
  alerts: number;
}

export interface DashboardMetrics {
  total_events: number;
  critical_alerts: number;
  active_incidents: number;
  high_risk_events: number;
  overall_risk_score: number;
  events_last_24h: number;
  alerts_last_24h: number;
  alerts_by_severity: {
    CRITICAL: number;
    HIGH: number;
    MEDIUM: number;
    LOW: number;
  };
  events_by_type: Record<string, number>;
  recent_alerts: Alert[];
  series?: HourlyPoint[];
}

export interface RiskFactor {
  factor: string;
  weight: number;
  active: boolean;
  description: string;
}

export interface RiskSummary {
  overall_risk_score: number;
  severity: SeverityLevel;
  risk_factors: RiskFactor[];
  top_risk_entities: Array<{
    user: string;
    risk: number;
    ip: string;
    threat_type?: string;
  }>;
}

export interface DetectionResult {
  detected: boolean;
  threat_type: string;
  severity: SeverityLevel;
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

export interface DetectionRule {
  id: string;
  name: string;
  mitre: string;
  weight: number;
  condition: string;
  description: string;
  enabled: boolean;
}

export interface ChecklistItem {
  id: string;
  incident_id: string;
  position: number;
  label: string;
  completed: boolean;
  updated_at: string;
}

export interface AIAnalysisResult {
  summary: string;
  threat_type: string;
  severity: string;
  risk_score: number;
  why_suspicious: string[];
  possible_impact: string[];
  recommended_actions: string[];
  investigation_steps: string[];
  confidence: number;
  disclaimer: string;
  fallback_used?: boolean;
}

export interface UserProfile {
  id: string;
  name: string;
  email: string;
  role: UserRole;
  organization: string;
}

export interface AuditLog {
  id: string;
  actor_email: string;
  action: string;
  resource_type: string;
  resource_id: string;
  metadata?: any;
  created_at: string;
}
