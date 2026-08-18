# CyberRakshak — Affordable AI SOC-in-a-Box

**CyberRakshak** is an open, full-stack Security Operations Center (SOC) platform engineered to give SMBs and enterprises real-time security log monitoring, multi-signal correlation, deterministic risk scoring (0–100), automated incident escalation, and contextual AI threat analysis powered by Google Gemini 3.7 Flash.

---

## 🌟 Key Features

1. **Deterministic Correlation Engine (0–100 Risk Scoring)**
   - Rule 1: Brute Force Authentication Detection ($\ge 5$ failed logins within 5 min $\rightarrow$ +25 risk points).
   - Rule 2: Multi-Stage Account Takeover (Immediate valid login after brute force $\rightarrow$ +45 risk points).
   - Rule 3: Malicious Ingress / Tor IP Reputation Match ($\rightarrow$ +20 risk points).
   - Rule 4: Immediate Post-Breach Privilege Escalation (Sudo/IAM elevation $\rightarrow$ +30 risk points).
   - Multi-signal correlation triggers a **CRITICAL** Alert (Risk Score: 95/100) and automatically escalates into an Incident.

2. **AI SOC Threat Copilot (Gemini 3.7 Flash + Fallback)**
   - Contextual threat summarization, attack intent explanation, business impact forecasting, and forensic investigation checklists.
   - Built-in deterministic fallback ensuring 100% uptime even if API quotas or keys are absent.

3. **Interactive Multi-Stage Attack Simulator**
   - 10-step visual pipeline execution simulating high-velocity brute force, successful breach, anomalous IP, and privilege escalation with instant telemetry ingestion.

4. **Multi-Role RBAC (Role-Based Access Control)**
   - `ADMIN`: Full authority (rules, simulations, incident management, export).
   - `ANALYST`: Triage alerts, update statuses, execute AI forensic queries, manage containment checklists.
   - `VIEWER`: Read-only compliance auditor access (restricted from state modifications).

5. **SIEM Telemetry & Audit Logs**
   - Live streaming log table with search, severity filters, and raw JSON payload inspection.
   - Immutable audit logging tracking all analyst triage decisions for compliance.

---

## 🚀 Quick Start Guide

### Prerequisites
- Node.js 20+ / 22+
- npm or yarn

### 1. Installation
```bash
# Clone or extract the repository
git clone https://github.com/your-username/cyberrakshak-soc.git
cd cyberrakshak-soc

# Install all dependencies
npm install
```

### 2. Environment Variables
Create a `.env` file from `.env.example`:
```bash
cp .env.example .env
```
Populate optional keys:
```env
GEMINI_API_KEY="your-gemini-api-key"
PORT=3000
BACKEND_PORT=8000
```
*(Note: If `GEMINI_API_KEY` is not provided, CyberRakshak automatically uses its deterministic expert-system fallback).*

### 3. Running in Development
```bash
npm run dev
```
Open your browser at `http://localhost:3000`.

### 4. Building for Production
```bash
# Compiles React SPA with Vite and bundles server with esbuild
npm run build

# Start production server
npm start
```

---

## 🐳 Docker Deployment

### Run with Docker Compose
```bash
docker-compose up --build -d
```
Access the SOC console at `http://localhost:3000` (or `http://localhost:8000` for backend API).

---

## 📦 How to Download & Push to GitHub

1. In the AI Studio top navigation or settings menu, click **Export / Download ZIP** (or use the GitHub export button).
2. Extract the downloaded `.zip` file on your local machine.
3. Initialize Git and push to your GitHub repository:
   ```bash
   cd cyberrakshak-soc
   git init
   git add .
   git commit -m "Initial commit: CyberRakshak full-stack SOC platform"
   git branch -M main
   git remote add origin https://github.com/<your-username>/cyberrakshak-soc.git
   git push -u origin main
   ```

---

## 🛡️ API Endpoints Summary

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/health` | Service health status |
| `GET` | `/api/dashboard` | Aggregated SOC metrics, chart series, and active alert counts |
| `GET` | `/api/logs` | Query SIEM telemetry with filtering & pagination |
| `POST` | `/api/logs` | Ingest new security log event |
| `GET` | `/api/alerts` | Retrieve security alerts |
| `PATCH` | `/api/alerts/:id` | Update alert triage status (`NEW`, `INVESTIGATING`, `RESOLVED`, `FALSE_POSITIVE`) |
| `GET` | `/api/incidents` | List formal incidents queue |
| `POST` | `/api/incidents` | Escalate new security incident ticket |
| `PATCH` | `/api/incidents/:id` | Update incident status and assigned analyst |
| `POST` | `/api/detection/analyze` | Run deterministic correlation engine on log arrays |
| `GET` | `/api/risk/summary` | Quantitative risk posture and factor breakdown |
| `POST` | `/api/ai/analyze` | Contextual threat analysis with Gemini 3.7 Flash |
| `POST` | `/api/ai/investigate` | Natural language SOC copilot inquiry |
| `POST` | `/api/demo/simulate-attack` | Launch 10-step multi-stage attack simulation |
| `GET` | `/api/audit-logs` | Retrieve compliance analyst audit trail |

---

## 📄 License
MIT License. Built for proactive cyber defense.
