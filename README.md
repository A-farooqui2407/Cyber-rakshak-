# CyberRakshak — Affordable AI SOC-in-a-Box

**CyberRakshak** is an open, full-stack Security Operations Center (SOC) platform for SMBs and enterprises: real-time log monitoring, multi-signal correlation, deterministic risk scoring (0–100), automated incident escalation, and contextual AI threat analysis (Google Gemini 3.7 Flash with an offline fallback).

**Operator manual:** see [USER_GUIDE.md](./USER_GUIDE.md) for production setup, Supabase, roles, and day-to-day use.

---

## Key Features

1. **Deterministic Correlation Engine (0–100 Risk Scoring)**
   - Rule 1: Brute Force Authentication Detection (≥ 5 failed logins for the same user or IP within 5 minutes → +25).
   - Rule 2: Successful login after brute force in that window (→ +20).
   - Rule 3: Malicious ingress / Tor-like IP reputation match (→ +20).
   - Rule 4: Immediate post-breach privilege escalation (sudo / IAM → +30).
   - Rule 5: Sensitive file or database export (→ +20).
   - Multi-signal correlation of rules 1–4 scores **95/100 CRITICAL** and opens an incident.

2. **AI SOC Threat Copilot (Gemini 3.7 Flash + Fallback)**
   - Summarization, attack intent, business impact, and forensic checklists.
   - Deterministic fallback if the API key or quota is missing.

3. **Interactive Multi-Stage Attack Simulator**
   - ADMIN-only 10-step pipeline: brute force, valid login, anomalous IP, privilege escalation, live ingest, score, alert, incident.

4. **Multi-Role RBAC (server-enforced JWT)**
   - `ADMIN`: rules, simulations, incidents, export.
   - `ANALYST`: triage, status, AI queries, containment checklists.
   - `VIEWER`: read-only.

5. **SIEM Telemetry & Audit Logs**
   - Live log table (5s refresh), search, severity filters, raw JSON inspect.
   - Append-only analyst audit trail persisted in Supabase.

6. **Supabase Postgres**
   - Organizations, users, logs, alerts, incidents, checklists, detection rules, audit logs, AI cache.
   - Row Level Security enabled; the API uses the service role key.

---

## Quick Start

### Prerequisites
- Node.js 20+ / 22+
- Optional: a Supabase project for persistence

```bash
npm install
cp .env.example .env
npm run dev
```

Open http://localhost:3000 and sign in:

| Role | Email | Password |
|---|---|---|
| ADMIN | rahul.sharma@lexguard.com | Admin@LexGuard1 |
| ANALYST | ananya.p@lexguard.com | Analyst@LexGuard1 |
| VIEWER | vikram.s@lexguard.com | Viewer@LexGuard1 |

Without Supabase credentials the process uses an in-memory store (fine for a local demo).

### Production
```bash
# Apply supabase/schema.sql in the Supabase SQL editor first
npm run build
npm start
```

Or:

```bash
docker compose up --build -d
```

---

## API Endpoints Summary

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/auth/login` | Email/password login, returns JWT |
| `GET` | `/api/health` | Service health and store mode |
| `GET` | `/api/dashboard` | Metrics, hourly series, alert counts |
| `GET` | `/api/logs` | SIEM telemetry with filters |
| `POST` | `/api/logs` | Ingest a log and run correlation |
| `GET` | `/api/alerts` | Security alerts |
| `PATCH` | `/api/alerts/:id` | Triage status |
| `POST` | `/api/alerts/:id/escalate` | Open an incident from an alert |
| `GET` | `/api/incidents` | Incident queue |
| `POST` | `/api/incidents` | Manual incident |
| `PATCH` | `/api/incidents/:id` | Status / assignee |
| `POST` | `/api/detection/analyze` | Run the correlation engine |
| `GET/PATCH` | `/api/detection/rules` | List / update rule weights |
| `GET` | `/api/risk/summary` | Risk posture |
| `POST` | `/api/ai/analyze` | Gemini (or fallback) threat analysis |
| `POST` | `/api/ai/investigate` | Natural-language SOC copilot |
| `POST` | `/api/demo/simulate-attack` | 10-step attack simulation |
| `GET` | `/api/audit-logs` | Compliance audit trail |
| `GET` | `/api/export` | ADMIN JSON export bundle |

---

## License
MIT License. See [LICENSE](./LICENSE).
