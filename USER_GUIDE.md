# CyberRakshak Operator Manual

This is the production guide for running and using CyberRakshak SOC-in-a-Box.

## 1. What you get

CyberRakshak is a single-tenant Security Operations Center:

- Live SIEM log table (search, severity, JSON inspect)
- Deterministic correlation with a 5-minute window and 0–100 risk score
- Automatic alerts; incidents open when score ≥ 80
- Gemini 3.7 Flash threat copilot with an offline fallback
- Role-based access: ADMIN, ANALYST, VIEWER
- Postgres persistence through Supabase

Risk formula (capped at 100):

| Rule | Signal | Points |
|---|---|---|
| RULE-BF-001 | ≥ 5 failed logins for the same user or IP in 5 minutes | +25 |
| RULE-ATO-002 | Successful login in that window after failures | +20 |
| RULE-IP-003 | Known malicious / Tor-like IP | +20 |
| RULE-PRIV-004 | sudo / IAM privilege escalation | +30 |
| RULE-DATA-005 | Confidential file or DB export | +20 |

Four-signal account takeover = **25 + 20 + 20 + 30 = 95 CRITICAL**.

## 2. Production setup (Supabase)

### Create the project

1. Create a project at [supabase.com](https://supabase.com).
2. Open **SQL Editor**.
3. Paste and run `supabase/schema.sql` (same file as `backend/app/database/schema.sql`).
4. Copy these values from **Project Settings → API**:
   - Project URL → `SUPABASE_URL`
   - `anon` `public` key → `SUPABASE_ANON_KEY` (not used by the browser; kept for Compose)
   - `service_role` key → `SUPABASE_SERVICE_ROLE_KEY` (server only — never ship this to the UI)

### Environment

```bash
cp .env.example .env
```

Edit `.env`:

```env
GEMINI_API_KEY=your-gemini-key          # optional
SESSION_SECRET=a-long-random-string     # required in production
PORT=3000
SUPABASE_URL=https://xxxx.supabase.co
SUPABASE_ANON_KEY=eyJ...
SUPABASE_SERVICE_ROLE_KEY=eyJ...
```

If Supabase keys are missing, the app still boots with an in-memory store (data is lost on restart). Health JSON shows `"store": "supabase"` or `"store": "memory"`.

### Install and run (development)

```bash
npm install
npm run dev
```

Open http://localhost:3000. You must sign in. There is no auto-login.

### Production Node process

```bash
npm run build
NODE_ENV=production npm start
```

### Docker

```bash
docker compose up --build -d
```

Console: http://localhost:3000

The optional FastAPI service is off by default. Start it with:

```bash
docker compose --profile fastapi up --build -d
```

API docs then appear at http://localhost:8000/docs.

## 3. Demo operator accounts

These rows are seeded by `schema.sql`. Change the passwords in Supabase after first login in a real deployment.

| Role | Name | Email | Password |
|---|---|---|---|
| ADMIN | Rahul Sharma | rahul.sharma@lexguard.com | Admin@LexGuard1 |
| ANALYST | Ananya Patel | ananya.p@lexguard.com | Analyst@LexGuard1 |
| VIEWER | Vikram Singh | vikram.s@lexguard.com | Viewer@LexGuard1 |

Sign in with email/password, or click a demo profile card (it still posts the password to `/api/auth/login`).

## 4. How to operate the console

### Daily monitoring

1. Sign in as ANALYST or ADMIN.
2. **SOC Dashboard** — events, critical alerts, incidents, live hourly charts, risk score.
3. **Live Logs Stream** — search from the navbar or the log page; open a row for raw JSON.
4. Ingest a test event with **Ingest Test Log** (ADMIN/ANALYST). The engine correlates the last 5 minutes for that user/IP and may create an alert automatically.

### Attack simulation (ADMIN only)

1. Click **Run Attack Demo** in the sidebar.
2. The 10-step pipeline injects 20 failures, a success, a bad IP, and privilege escalation.
3. Expected result: risk **95/100**, CRITICAL alert, open incident.

### Alert triage (ADMIN / ANALYST)

1. Open **Security Alerts**.
2. Change status: NEW → INVESTIGATING → RESOLVED or FALSE POSITIVE.
3. Open an alert → **Analyze with AI** for summary, impact, and investigation steps.
4. **Escalate to Incident** if it is not already ticketed (auto-happens at score ≥ 80).

### Incident response (ADMIN / ANALYST)

1. Open **Incidents Queue**.
2. Work the persisted containment checklist (saved to the database).
3. Update incident status: OPEN → INVESTIGATING → RESOLVED.

### Detection rules (ADMIN)

1. Open **Detection Engine**.
2. Toggle rules on/off and edit weights (0–100).
3. Use the JSON playground to test a payload without waiting for live ingest.

### Export and audit (ADMIN export)

- **SOC Settings → Export SOC Bundle** downloads logs, alerts, incidents, and audit records.
- VIEWER can read the audit table but cannot export.

### AI copilot (ADMIN / ANALYST)

Ask natural-language questions on **AI SOC Assistant**. If `GEMINI_API_KEY` is empty, answers come from the deterministic fallback and are labeled as such.

## 5. Role matrix (enforced on the API)

| Action | ADMIN | ANALYST | VIEWER |
|---|---|---|---|
| View dashboards, logs, alerts, incidents, audit | Yes | Yes | Yes |
| Ingest logs, triage, create/escalate incidents, AI | Yes | Yes | No |
| Run attack simulation | Yes | No | No |
| Edit detection rules | Yes | No | No |
| Export SOC bundle | Yes | No | No |

Role switching from the navbar was removed. Use a different account to change privilege.

## 6. API (Bearer JWT)

After `POST /api/auth/login`:

```http
Authorization: Bearer <token>
```

| Method | Path | Who |
|---|---|---|
| POST | `/api/auth/login` | Public |
| GET | `/api/health` | Public |
| GET | `/api/dashboard` | Any role |
| GET/POST | `/api/logs` | GET any; POST analyst+ |
| GET/PATCH | `/api/alerts/:id` | PATCH analyst+ |
| POST | `/api/alerts/:id/escalate` | Analyst+ |
| GET/POST/PATCH | `/api/incidents` | POST/PATCH analyst+ |
| PATCH | `/api/checklist/:id` | Analyst+ |
| POST | `/api/detection/analyze` | Analyst+ |
| GET/PATCH | `/api/detection/rules` | PATCH admin |
| GET | `/api/risk/summary` | Any role |
| POST | `/api/ai/analyze` `/api/ai/investigate` | Analyst+ |
| GET | `/api/audit-logs` | Any role |
| GET | `/api/export` | Admin |
| POST | `/api/demo/simulate-attack` | Admin |

## 7. Security notes

- The service role key bypasses Row Level Security. Keep it on the server only.
- Rotate `SESSION_SECRET` and demo passwords before any internet-facing deploy.
- Gemini is optional; detection and scoring never depend on it.
- Data is tenant-scoped by `organization_id` on every query.
