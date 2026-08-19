-- CyberRakshak production schema for Supabase / PostgreSQL
-- Run this in the Supabase SQL Editor (or psql) before starting the app.

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ---------------------------------------------------------------------------
-- Core tables
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS organizations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    industry VARCHAR(100) DEFAULT 'Legal & Compliance',
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc', now())
);

CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    role VARCHAR(50) NOT NULL CHECK (role IN ('ADMIN', 'ANALYST', 'VIEWER')),
    password_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc', now())
);

CREATE TABLE IF NOT EXISTS logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT timezone('utc', now()),
    source VARCHAR(100) NOT NULL,
    username VARCHAR(100) NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    event_type VARCHAR(100) NOT NULL,
    action VARCHAR(100) NOT NULL,
    status VARCHAR(50) NOT NULL,
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL', 'INFO')),
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc', now())
);

CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_logs_ip_address ON logs (ip_address);
CREATE INDEX IF NOT EXISTS idx_logs_username ON logs (username);
CREATE INDEX IF NOT EXISTS idx_logs_event_type ON logs (event_type);
CREATE INDEX IF NOT EXISTS idx_logs_organization ON logs (organization_id);
CREATE INDEX IF NOT EXISTS idx_logs_org_user_time ON logs (organization_id, username, timestamp DESC);

CREATE TABLE IF NOT EXISTS alerts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    title VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    threat_type VARCHAR(100) NOT NULL DEFAULT 'UNKNOWN',
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    risk_score INTEGER NOT NULL CHECK (risk_score >= 0 AND risk_score <= 100),
    source_ip VARCHAR(45) NOT NULL,
    username VARCHAR(100) NOT NULL,
    detection_rule VARCHAR(100) NOT NULL,
    reasons JSONB NOT NULL DEFAULT '[]'::jsonb,
    recommended_actions JSONB NOT NULL DEFAULT '[]'::jsonb,
    related_event_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
    status VARCHAR(50) NOT NULL DEFAULT 'NEW' CHECK (status IN ('NEW', 'INVESTIGATING', 'RESOLVED', 'FALSE_POSITIVE')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc', now()),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc', now())
);

CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts (severity);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts (status);
CREATE INDEX IF NOT EXISTS idx_alerts_org ON alerts (organization_id);

CREATE TABLE IF NOT EXISTS incidents (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    alert_id UUID REFERENCES alerts(id) ON DELETE SET NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    risk_score INTEGER NOT NULL CHECK (risk_score >= 0 AND risk_score <= 100),
    status VARCHAR(50) NOT NULL DEFAULT 'OPEN' CHECK (status IN ('OPEN', 'INVESTIGATING', 'RESOLVED')),
    affected_user VARCHAR(100) NOT NULL,
    source_ip VARCHAR(45) NOT NULL,
    assigned_analyst VARCHAR(255) NOT NULL DEFAULT 'Unassigned',
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc', now()),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc', now())
);

CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents (status);
CREATE INDEX IF NOT EXISTS idx_incidents_org ON incidents (organization_id);
CREATE INDEX IF NOT EXISTS idx_incidents_alert ON incidents (alert_id);

CREATE TABLE IF NOT EXISTS incident_checklist_items (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    incident_id UUID NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    position INTEGER NOT NULL,
    label TEXT NOT NULL,
    completed BOOLEAN NOT NULL DEFAULT FALSE,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc', now()),
    UNIQUE (incident_id, position)
);

CREATE TABLE IF NOT EXISTS detection_rules (
    id VARCHAR(64) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    mitre VARCHAR(255) NOT NULL,
    weight INTEGER NOT NULL CHECK (weight >= 0 AND weight <= 100),
    condition TEXT NOT NULL,
    description TEXT NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc', now())
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    actor_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    actor_email VARCHAR(255) NOT NULL,
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50) NOT NULL,
    resource_id VARCHAR(100),
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc', now())
);

CREATE INDEX IF NOT EXISTS idx_audit_org_time ON audit_logs (organization_id, created_at DESC);

CREATE TABLE IF NOT EXISTS alert_logs (
    alert_id UUID NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    log_id UUID NOT NULL REFERENCES logs(id) ON DELETE CASCADE,
    PRIMARY KEY (alert_id, log_id)
);

CREATE TABLE IF NOT EXISTS ai_analysis (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    alert_id UUID NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    summary TEXT NOT NULL,
    threat_type VARCHAR(100) NOT NULL,
    why_suspicious JSONB NOT NULL DEFAULT '[]'::jsonb,
    possible_impact JSONB NOT NULL DEFAULT '[]'::jsonb,
    recommended_actions JSONB NOT NULL DEFAULT '[]'::jsonb,
    investigation_steps JSONB NOT NULL DEFAULT '[]'::jsonb,
    confidence NUMERIC(3, 2) DEFAULT 0.95,
    fallback_used BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc', now())
);

-- ---------------------------------------------------------------------------
-- Row Level Security: browser clients cannot hit tables directly.
-- The Node/FastAPI backend uses the service role key, which bypasses RLS.
-- ---------------------------------------------------------------------------

ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE alerts ENABLE ROW LEVEL SECURITY;
ALTER TABLE incidents ENABLE ROW LEVEL SECURITY;
ALTER TABLE incident_checklist_items ENABLE ROW LEVEL SECURITY;
ALTER TABLE detection_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE alert_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE ai_analysis ENABLE ROW LEVEL SECURITY;

REVOKE ALL ON ALL TABLES IN SCHEMA public FROM anon, authenticated;
GRANT USAGE ON SCHEMA public TO service_role;
GRANT ALL ON ALL TABLES IN SCHEMA public TO service_role;
GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO service_role;

-- ---------------------------------------------------------------------------
-- Seed LexGuard demo tenant
-- Password hashes use scrypt (salt:hash) matching the Node verifier.
--   ADMIN    rahul.sharma@lexguard.com / Admin@LexGuard1
--   ANALYST  ananya.p@lexguard.com     / Analyst@LexGuard1
--   VIEWER   vikram.s@lexguard.com     / Viewer@LexGuard1
-- ---------------------------------------------------------------------------

INSERT INTO organizations (id, name, industry)
VALUES ('11111111-1111-1111-1111-111111111111', 'LexGuard Law Associates', 'Legal & Compliance')
ON CONFLICT (id) DO NOTHING;

INSERT INTO users (id, organization_id, name, email, role, password_hash)
VALUES
(
    '22222222-2222-2222-2222-222222222221',
    '11111111-1111-1111-1111-111111111111',
    'Rahul Sharma',
    'rahul.sharma@lexguard.com',
    'ADMIN',
    'e51a0d712c0850563d34808bcde58b76:1b3cbb95f9e470f67af69c0b6aa024ad9c0bd0b2f164e8a025ee69bffd76e01771647d7774065a87d5c06d4485b515f9126e413524d0c3ab05cedc10fcc37f3b'
),
(
    '22222222-2222-2222-2222-222222222222',
    '11111111-1111-1111-1111-111111111111',
    'Ananya Patel',
    'ananya.p@lexguard.com',
    'ANALYST',
    '157060d8476eff15713ccd9e421c3785:1d1d3c61741d1b4a44ac126670a7c2e2fbe109956a84c4ed959bb26b4250af26dcdb215db447e434a201c95681c93b0bedd8e3baa8f42913c56b5c8e8c2410bc'
),
(
    '22222222-2222-2222-2222-222222222223',
    '11111111-1111-1111-1111-111111111111',
    'Vikram Singh',
    'vikram.s@lexguard.com',
    'VIEWER',
    'fbdfe37940758338a4696d401606066c:ace89e8ca79e5f2a141afb7cf4bea6a58f38c9d6f2f7d90b88d8bf9bb130681cbe4eab9eb8627f93cb1b5faa72af76e2173ad3e88fca37aeb7cb4f4b6955d2ae'
)
ON CONFLICT (id) DO UPDATE SET
    password_hash = EXCLUDED.password_hash,
    role = EXCLUDED.role,
    name = EXCLUDED.name;

INSERT INTO detection_rules (id, name, mitre, weight, condition, description, enabled)
VALUES
(
    'RULE-BF-001',
    'Brute Force Authentication Pattern',
    'T1110.001 - Password Guessing',
    25,
    '>= 5 LOGIN_FAILED events for the same username or IP within a 5 minute window',
    'Detects automated password spraying and dictionary attacks against user credentials.',
    TRUE
),
(
    'RULE-ATO-002',
    'Successful Login After Brute Force',
    'T1078 - Valid Accounts',
    20,
    'LOGIN_SUCCESS in the same 5 minute window after brute-force failures',
    'Indicates an attacker obtained valid credentials after repeated attempts.',
    TRUE
),
(
    'RULE-IP-003',
    'Known Malicious / Tor IP Ingress',
    'T1090 - Proxy Network',
    20,
    'Source IP matches the threat-intel set or event_type is SUSPICIOUS_IP',
    'Flags remote sessions originating from known adversary or Tor-like nodes.',
    TRUE
),
(
    'RULE-PRIV-004',
    'Immediate Post-Breach Privilege Escalation',
    'T1548 - Abuse Elevation Control Mechanism',
    30,
    'PRIVILEGE_ESCALATION / sudo / role_elevate in the correlation window',
    'Intercepts administrative elevation shortly after initial access.',
    TRUE
),
(
    'RULE-DATA-005',
    'Sensitive Asset Access',
    'T1005 - Data from Local System',
    20,
    'Confidential file or database export in the correlation window',
    'Detects access to classified records after a suspicious session.',
    TRUE
)
ON CONFLICT (id) DO UPDATE SET
    weight = EXCLUDED.weight,
    condition = EXCLUDED.condition,
    description = EXCLUDED.description;
