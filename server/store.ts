import { randomUUID } from "crypto";
import { createClient, type SupabaseClient } from "@supabase/supabase-js";
import { hashPassword } from "./auth";
import { defaultChecklistLabels } from "./detection";
import {
  Alert,
  AuditLog,
  ChecklistItem,
  DEFAULT_RULES,
  DEMO_ORG_ID,
  DetectionRule,
  HourlyPoint,
  Incident,
  LogEvent,
  StoredUser,
} from "./types";

export interface LogQuery {
  search?: string;
  severity?: string;
  event_type?: string;
  username?: string;
  ip?: string;
  limit?: number;
  offset?: number;
  since?: string;
}

export interface Store {
  usingSupabase: boolean;
  getUserByEmail(email: string): Promise<StoredUser | null>;
  listLogs(orgId: string, query: LogQuery): Promise<{ total: number; logs: LogEvent[] }>;
  getLog(orgId: string, id: string): Promise<LogEvent | null>;
  insertLog(log: LogEvent): Promise<LogEvent>;
  insertLogs(logs: LogEvent[]): Promise<void>;
  recentLogsForCorrelation(orgId: string, username: string, ip: string, sinceIso: string): Promise<LogEvent[]>;
  listAlerts(orgId: string, filters?: { status?: string; severity?: string }): Promise<Alert[]>;
  getAlert(orgId: string, id: string): Promise<Alert | null>;
  insertAlert(alert: Alert): Promise<Alert>;
  updateAlert(orgId: string, id: string, patch: Partial<Alert>): Promise<Alert | null>;
  findOpenAlert(orgId: string, username: string, threatType: string): Promise<Alert | null>;
  listIncidents(orgId: string, status?: string): Promise<Incident[]>;
  getIncident(orgId: string, id: string): Promise<Incident | null>;
  insertIncident(incident: Incident, checklistLabels: string[]): Promise<Incident>;
  updateIncident(orgId: string, id: string, patch: Partial<Incident>): Promise<Incident | null>;
  findOpenIncidentForAlert(orgId: string, alertId: string): Promise<Incident | null>;
  listChecklist(incidentId: string): Promise<ChecklistItem[]>;
  updateChecklistItem(id: string, completed: boolean): Promise<ChecklistItem | null>;
  listRules(): Promise<DetectionRule[]>;
  updateRule(id: string, patch: Partial<DetectionRule>): Promise<DetectionRule | null>;
  insertAudit(entry: AuditLog): Promise<void>;
  listAudit(orgId: string, limit?: number): Promise<AuditLog[]>;
  hourlySeries(orgId: string): Promise<HourlyPoint[]>;
}

function asArray<T>(value: T[] | null | undefined): T[] {
  return Array.isArray(value) ? value : [];
}

function normalizeAlert(row: any): Alert {
  return {
    ...row,
    reasons: asArray(row.reasons),
    recommended_actions: asArray(row.recommended_actions),
    related_event_ids: asArray(row.related_event_ids),
  };
}

const DEMO_USERS: StoredUser[] = [
  {
    id: "22222222-2222-2222-2222-222222222221",
    organization_id: DEMO_ORG_ID,
    name: "Rahul Sharma",
    email: "rahul.sharma@lexguard.com",
    role: "ADMIN",
    organization: "LexGuard Law Associates",
    password_hash: hashPassword("Admin@LexGuard1"),
  },
  {
    id: "22222222-2222-2222-2222-222222222222",
    organization_id: DEMO_ORG_ID,
    name: "Ananya Patel",
    email: "ananya.p@lexguard.com",
    role: "ANALYST",
    organization: "LexGuard Law Associates",
    password_hash: hashPassword("Analyst@LexGuard1"),
  },
  {
    id: "22222222-2222-2222-2222-222222222223",
    organization_id: DEMO_ORG_ID,
    name: "Vikram Singh",
    email: "vikram.s@lexguard.com",
    role: "VIEWER",
    organization: "LexGuard Law Associates",
    password_hash: hashPassword("Viewer@LexGuard1"),
  },
];

class MemoryStore implements Store {
  usingSupabase = false;
  users = DEMO_USERS;
  logs: LogEvent[] = [];
  alerts: Alert[] = [];
  incidents: Incident[] = [];
  audit: AuditLog[] = [];
  rules: DetectionRule[] = DEFAULT_RULES.map((r) => ({ ...r }));
  checklists: ChecklistItem[] = [];

  constructor() {
    this.seedBaseline();
  }

  private seedBaseline() {
    const now = Date.now();
    const users = ["ananya.p", "vikram.s", "rahul.sharma", "sysadmin_backup", "priya.k"];
    const ips = ["10.0.4.15", "10.0.4.22", "192.168.1.105", "10.0.8.99"];
    for (let i = 0; i < 28; i++) {
      this.logs.push({
        id: randomUUID(),
        organization_id: DEMO_ORG_ID,
        timestamp: new Date(now - (30 - i) * 8 * 60 * 1000).toISOString(),
        source: i % 3 === 0 ? "vpn_gateway" : i % 3 === 1 ? "auth_service" : "internal_file_server",
        username: users[i % users.length],
        ip_address: ips[i % ips.length],
        event_type: i % 5 === 0 ? "FILE_ACCESS" : "LOGIN_SUCCESS",
        action: i % 5 === 0 ? "document_read" : "vpn_authenticate",
        status: "SUCCESS",
        severity: "INFO",
        metadata: { device: "Corp-Device-Secure", mfa_verified: true },
      });
    }
  }

  async getUserByEmail(email: string) {
    return this.users.find((u) => u.email.toLowerCase() === email.toLowerCase()) || null;
  }

  async listLogs(orgId: string, query: LogQuery) {
    let filtered = this.logs.filter((l) => l.organization_id === orgId);
    if (query.search) {
      const s = query.search.toLowerCase();
      filtered = filtered.filter(
        (l) =>
          l.username.toLowerCase().includes(s) ||
          l.ip_address.includes(s) ||
          l.event_type.toLowerCase().includes(s) ||
          l.action.toLowerCase().includes(s)
      );
    }
    if (query.severity) filtered = filtered.filter((l) => l.severity.toUpperCase() === query.severity!.toUpperCase());
    if (query.event_type) filtered = filtered.filter((l) => l.event_type.toUpperCase() === query.event_type!.toUpperCase());
    if (query.username) filtered = filtered.filter((l) => l.username.toLowerCase() === query.username!.toLowerCase());
    if (query.ip) filtered = filtered.filter((l) => l.ip_address === query.ip);
    if (query.since) {
      const since = new Date(query.since).getTime();
      filtered = filtered.filter((l) => new Date(l.timestamp).getTime() >= since);
    }
    filtered.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
    const limit = query.limit ?? 50;
    const offset = query.offset ?? 0;
    return { total: filtered.length, logs: filtered.slice(offset, offset + limit) };
  }

  async getLog(orgId: string, id: string) {
    return this.logs.find((l) => l.organization_id === orgId && l.id === id) || null;
  }

  async insertLog(log: LogEvent) {
    this.logs.push(log);
    return log;
  }

  async insertLogs(logs: LogEvent[]) {
    this.logs.push(...logs);
  }

  async recentLogsForCorrelation(orgId: string, username: string, ip: string, sinceIso: string) {
    const since = new Date(sinceIso).getTime();
    return this.logs.filter(
      (l) =>
        l.organization_id === orgId &&
        new Date(l.timestamp).getTime() >= since &&
        (l.username.toLowerCase() === username.toLowerCase() || l.ip_address === ip)
    );
  }

  async listAlerts(orgId: string, filters?: { status?: string; severity?: string }) {
    let rows = this.alerts.filter((a) => a.organization_id === orgId);
    if (filters?.status) rows = rows.filter((a) => a.status.toUpperCase() === filters.status!.toUpperCase());
    if (filters?.severity) rows = rows.filter((a) => a.severity.toUpperCase() === filters.severity!.toUpperCase());
    return rows.sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime());
  }

  async getAlert(orgId: string, id: string) {
    return this.alerts.find((a) => a.organization_id === orgId && a.id === id) || null;
  }

  async insertAlert(alert: Alert) {
    this.alerts.unshift(alert);
    return alert;
  }

  async updateAlert(orgId: string, id: string, patch: Partial<Alert>) {
    const alert = await this.getAlert(orgId, id);
    if (!alert) return null;
    Object.assign(alert, patch, { updated_at: new Date().toISOString() });
    return alert;
  }

  async findOpenAlert(orgId: string, username: string, threatType: string) {
    const cutoff = Date.now() - 15 * 60 * 1000;
    return (
      this.alerts.find(
        (a) =>
          a.organization_id === orgId &&
          a.username.toLowerCase() === username.toLowerCase() &&
          a.threat_type === threatType &&
          a.status !== "RESOLVED" &&
          a.status !== "FALSE_POSITIVE" &&
          new Date(a.created_at).getTime() >= cutoff
      ) || null
    );
  }

  async listIncidents(orgId: string, status?: string) {
    let rows = this.incidents.filter((i) => i.organization_id === orgId);
    if (status) rows = rows.filter((i) => i.status.toUpperCase() === status.toUpperCase());
    return rows.sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime());
  }

  async getIncident(orgId: string, id: string) {
    return this.incidents.find((i) => i.organization_id === orgId && i.id === id) || null;
  }

  async insertIncident(incident: Incident, checklistLabels: string[]) {
    this.incidents.unshift(incident);
    checklistLabels.forEach((label, idx) => {
      this.checklists.push({
        id: randomUUID(),
        incident_id: incident.id,
        position: idx + 1,
        label,
        completed: idx < 2,
        updated_at: new Date().toISOString(),
      });
    });
    return incident;
  }

  async updateIncident(orgId: string, id: string, patch: Partial<Incident>) {
    const incident = await this.getIncident(orgId, id);
    if (!incident) return null;
    Object.assign(incident, patch, { updated_at: new Date().toISOString() });
    return incident;
  }

  async findOpenIncidentForAlert(orgId: string, alertId: string) {
    return (
      this.incidents.find(
        (i) => i.organization_id === orgId && i.alert_id === alertId && i.status !== "RESOLVED"
      ) || null
    );
  }

  async listChecklist(incidentId: string) {
    return this.checklists.filter((c) => c.incident_id === incidentId).sort((a, b) => a.position - b.position);
  }

  async updateChecklistItem(id: string, completed: boolean) {
    const item = this.checklists.find((c) => c.id === id);
    if (!item) return null;
    item.completed = completed;
    item.updated_at = new Date().toISOString();
    return item;
  }

  async listRules() {
    return this.rules;
  }

  async updateRule(id: string, patch: Partial<DetectionRule>) {
    const rule = this.rules.find((r) => r.id === id);
    if (!rule) return null;
    if (typeof patch.weight === "number") rule.weight = patch.weight;
    if (typeof patch.enabled === "boolean") rule.enabled = patch.enabled;
    if (patch.condition) rule.condition = patch.condition;
    if (patch.description) rule.description = patch.description;
    rule.updated_at = new Date().toISOString();
    return rule;
  }

  async insertAudit(entry: AuditLog) {
    this.audit.push(entry);
  }

  async listAudit(orgId: string, limit = 50) {
    return this.audit
      .filter((a) => !a.organization_id || a.organization_id === orgId)
      .sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime())
      .slice(0, limit);
  }

  async hourlySeries(orgId: string): Promise<HourlyPoint[]> {
    const now = Date.now();
    const buckets: HourlyPoint[] = [];
    for (let i = 11; i >= 0; i--) {
      const start = now - (i + 1) * 60 * 60 * 1000;
      const end = now - i * 60 * 60 * 1000;
      const label = new Date(end).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
      const events = this.logs.filter(
        (l) => l.organization_id === orgId && new Date(l.timestamp).getTime() >= start && new Date(l.timestamp).getTime() < end
      ).length;
      const alerts = this.alerts.filter(
        (a) => a.organization_id === orgId && new Date(a.created_at).getTime() >= start && new Date(a.created_at).getTime() < end
      ).length;
      buckets.push({ time: i === 0 ? "Now" : label, events, alerts });
    }
    return buckets;
  }
}

class SupabaseStore implements Store {
  usingSupabase = true;
  constructor(private client: SupabaseClient) {}

  async getUserByEmail(email: string) {
    const { data, error } = await this.client
      .from("users")
      .select("id, organization_id, name, email, role, password_hash")
      .ilike("email", email)
      .maybeSingle();
    if (error || !data) return null;
    const { data: org } = await this.client.from("organizations").select("name").eq("id", data.organization_id).maybeSingle();
    return {
      id: data.id,
      organization_id: data.organization_id,
      name: data.name,
      email: data.email,
      role: data.role,
      organization: org?.name || "LexGuard Law Associates",
      password_hash: data.password_hash,
    } as StoredUser;
  }

  async listLogs(orgId: string, query: LogQuery) {
    let q = this.client.from("logs").select("*", { count: "exact" }).eq("organization_id", orgId);
    if (query.severity) q = q.eq("severity", query.severity.toUpperCase());
    if (query.event_type) q = q.eq("event_type", query.event_type.toUpperCase());
    if (query.username) q = q.ilike("username", query.username);
    if (query.ip) q = q.eq("ip_address", query.ip);
    if (query.since) q = q.gte("timestamp", query.since);
    if (query.search) {
      const s = query.search.replace(/%/g, "");
      q = q.or(`username.ilike.%${s}%,ip_address.ilike.%${s}%,event_type.ilike.%${s}%,action.ilike.%${s}%`);
    }
    const limit = query.limit ?? 50;
    const offset = query.offset ?? 0;
    const { data, count, error } = await q.order("timestamp", { ascending: false }).range(offset, offset + limit - 1);
    if (error) throw error;
    return { total: count || 0, logs: (data || []) as LogEvent[] };
  }

  async getLog(orgId: string, id: string) {
    const { data } = await this.client.from("logs").select("*").eq("organization_id", orgId).eq("id", id).maybeSingle();
    return (data as LogEvent) || null;
  }

  async insertLog(log: LogEvent) {
    const { data, error } = await this.client.from("logs").insert(log).select("*").single();
    if (error) throw error;
    return data as LogEvent;
  }

  async insertLogs(logs: LogEvent[]) {
    if (logs.length === 0) return;
    const { error } = await this.client.from("logs").insert(logs);
    if (error) throw error;
  }

  async recentLogsForCorrelation(orgId: string, username: string, ip: string, sinceIso: string) {
    const { data, error } = await this.client
      .from("logs")
      .select("*")
      .eq("organization_id", orgId)
      .gte("timestamp", sinceIso)
      .or(`username.ilike.${username},ip_address.eq.${ip}`);
    if (error) throw error;
    return (data || []) as LogEvent[];
  }

  async listAlerts(orgId: string, filters?: { status?: string; severity?: string }) {
    let q = this.client.from("alerts").select("*").eq("organization_id", orgId);
    if (filters?.status) q = q.eq("status", filters.status.toUpperCase());
    if (filters?.severity) q = q.eq("severity", filters.severity.toUpperCase());
    const { data, error } = await q.order("created_at", { ascending: false });
    if (error) throw error;
    return (data || []).map(normalizeAlert);
  }

  async getAlert(orgId: string, id: string) {
    const { data } = await this.client.from("alerts").select("*").eq("organization_id", orgId).eq("id", id).maybeSingle();
    return data ? normalizeAlert(data) : null;
  }

  async insertAlert(alert: Alert) {
    const { data, error } = await this.client.from("alerts").insert(alert).select("*").single();
    if (error) throw error;
    return normalizeAlert(data);
  }

  async updateAlert(orgId: string, id: string, patch: Partial<Alert>) {
    const { data, error } = await this.client
      .from("alerts")
      .update({ ...patch, updated_at: new Date().toISOString() })
      .eq("organization_id", orgId)
      .eq("id", id)
      .select("*")
      .maybeSingle();
    if (error) throw error;
    return data ? normalizeAlert(data) : null;
  }

  async findOpenAlert(orgId: string, username: string, threatType: string) {
    const cutoff = new Date(Date.now() - 15 * 60 * 1000).toISOString();
    const { data } = await this.client
      .from("alerts")
      .select("*")
      .eq("organization_id", orgId)
      .ilike("username", username)
      .eq("threat_type", threatType)
      .not("status", "in", "(RESOLVED,FALSE_POSITIVE)")
      .gte("created_at", cutoff)
      .order("created_at", { ascending: false })
      .limit(1)
      .maybeSingle();
    return data ? normalizeAlert(data) : null;
  }

  async listIncidents(orgId: string, status?: string) {
    let q = this.client.from("incidents").select("*").eq("organization_id", orgId);
    if (status) q = q.eq("status", status.toUpperCase());
    const { data, error } = await q.order("created_at", { ascending: false });
    if (error) throw error;
    return (data || []) as Incident[];
  }

  async getIncident(orgId: string, id: string) {
    const { data } = await this.client.from("incidents").select("*").eq("organization_id", orgId).eq("id", id).maybeSingle();
    return (data as Incident) || null;
  }

  async insertIncident(incident: Incident, checklistLabels: string[]) {
    const { data, error } = await this.client.from("incidents").insert(incident).select("*").single();
    if (error) throw error;
    const items = (checklistLabels.length ? checklistLabels : defaultChecklistLabels(incident.source_ip)).map(
      (label, idx) => ({
        id: randomUUID(),
        incident_id: incident.id,
        position: idx + 1,
        label,
        completed: idx < 2,
        updated_at: new Date().toISOString(),
      })
    );
    await this.client.from("incident_checklist_items").insert(items);
    return data as Incident;
  }

  async updateIncident(orgId: string, id: string, patch: Partial<Incident>) {
    const { data, error } = await this.client
      .from("incidents")
      .update({ ...patch, updated_at: new Date().toISOString() })
      .eq("organization_id", orgId)
      .eq("id", id)
      .select("*")
      .maybeSingle();
    if (error) throw error;
    return (data as Incident) || null;
  }

  async findOpenIncidentForAlert(orgId: string, alertId: string) {
    const { data } = await this.client
      .from("incidents")
      .select("*")
      .eq("organization_id", orgId)
      .eq("alert_id", alertId)
      .neq("status", "RESOLVED")
      .maybeSingle();
    return (data as Incident) || null;
  }

  async listChecklist(incidentId: string) {
    const { data, error } = await this.client
      .from("incident_checklist_items")
      .select("*")
      .eq("incident_id", incidentId)
      .order("position");
    if (error) throw error;
    return (data || []) as ChecklistItem[];
  }

  async updateChecklistItem(id: string, completed: boolean) {
    const { data, error } = await this.client
      .from("incident_checklist_items")
      .update({ completed, updated_at: new Date().toISOString() })
      .eq("id", id)
      .select("*")
      .maybeSingle();
    if (error) throw error;
    return (data as ChecklistItem) || null;
  }

  async listRules() {
    const { data, error } = await this.client.from("detection_rules").select("*").order("id");
    if (error) throw error;
    if (!data || data.length === 0) return DEFAULT_RULES;
    return data as DetectionRule[];
  }

  async updateRule(id: string, patch: Partial<DetectionRule>) {
    const { data, error } = await this.client
      .from("detection_rules")
      .update({ ...patch, updated_at: new Date().toISOString() })
      .eq("id", id)
      .select("*")
      .maybeSingle();
    if (error) throw error;
    return (data as DetectionRule) || null;
  }

  async insertAudit(entry: AuditLog) {
    const { error } = await this.client.from("audit_logs").insert(entry);
    if (error) throw error;
  }

  async listAudit(orgId: string, limit = 50) {
    const { data, error } = await this.client
      .from("audit_logs")
      .select("*")
      .eq("organization_id", orgId)
      .order("created_at", { ascending: false })
      .limit(limit);
    if (error) throw error;
    return (data || []) as AuditLog[];
  }

  async hourlySeries(orgId: string): Promise<HourlyPoint[]> {
    const since = new Date(Date.now() - 12 * 60 * 60 * 1000).toISOString();
    const { data: logs } = await this.client
      .from("logs")
      .select("timestamp")
      .eq("organization_id", orgId)
      .gte("timestamp", since);
    const { data: alerts } = await this.client
      .from("alerts")
      .select("created_at")
      .eq("organization_id", orgId)
      .gte("created_at", since);
    const now = Date.now();
    const buckets: HourlyPoint[] = [];
    for (let i = 11; i >= 0; i--) {
      const start = now - (i + 1) * 60 * 60 * 1000;
      const end = now - i * 60 * 60 * 1000;
      const label = new Date(end).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
      const events = (logs || []).filter((l: any) => {
        const t = new Date(l.timestamp).getTime();
        return t >= start && t < end;
      }).length;
      const alertCount = (alerts || []).filter((a: any) => {
        const t = new Date(a.created_at).getTime();
        return t >= start && t < end;
      }).length;
      buckets.push({ time: i === 0 ? "Now" : label, events, alerts: alertCount });
    }
    return buckets;
  }
}

export function createStore(): Store {
  const url = process.env.SUPABASE_URL || "";
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY || "";
  const placeholder = /your[_-]?project|your-anon|your-service|change-me/i.test(`${url}${key}`);
  if (url && key && !placeholder) {
    const client = createClient(url, key, { auth: { persistSession: false, autoRefreshToken: false } });
    console.log("CyberRakshak store: Supabase Postgres");
    return new SupabaseStore(client);
  }
  console.warn("CyberRakshak store: in-memory fallback (set SUPABASE_URL + SUPABASE_SERVICE_ROLE_KEY for production)");
  return new MemoryStore();
}
