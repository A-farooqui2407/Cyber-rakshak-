# Cyber-rakshak-CyberRakshak

> **Affordable SOC-in-a-Box for small organizations**

CyberRakshak is a cybersecurity monitoring platform designed for colleges, SMEs, small hospitals, and other organizations that may not have a dedicated Security Operations Center (SOC) or security team.

It collects security logs, detects suspicious activity using rule-based detection and event correlation, assigns a risk score, and uses an LLM to explain incidents and suggest response actions.



1. Problem Statement

Small organizations often lack dedicated cybersecurity teams and cannot afford complex enterprise SOC/SIEM solutions.

As a result, security events such as:

	●	Brute-force login attempts
	●	Suspicious logins
	●	Port scanning
	●	Privilege escalation
	●	Suspicious processes

may go unnoticed or be detected too late.

CyberRakshak aims to provide a simpler and more affordable security monitoring layer for these organizations.



2. Proposed Solution

CyberRakshak follows this flow:

```text
Windows / Linux / Security Logs
            ↓
       Log Collector
            ↓
          FastAPI
            ↓
     Detection Engine
            ↓
    Risk Score + Alert
            ↓
        Supabase
            ↓
      AI Explanation
            ↓
     React SOC Dashboard
```

The detection engine is responsible for identifying suspicious behavior. The LLM is used primarily to explain detected incidents and provide human-readable recommendations rather than being the sole detection mechanism.



3. Key Features

MVP

	●	Security log ingestion
	●	Rule-based threat detection
	●	Event correlation
	●	Risk scoring
	●	Alert management
	●	Incident management
	●	SOC-style dashboard
	●	AI-assisted incident explanation

Initial Threat Detections

	1.	Brute-force login attempts
	2.	Possible account compromise
	3.	Port scanning
	4.	Privilege escalation
	5.	Suspicious process activity

Future

	●	Windows event collector
	●	Linux log collector
	●	Threat intelligence integration
	●	More detection rules
	●	Anomaly detection
	●	Controlled automated response



4. Technology Stack

|Layer           |Technology                            |
|----------------|--------------------------------------|
|Frontend        |React + Vite + Tailwind CSS           |
|Backend         |Python + FastAPI                      |
|Database        |Supabase PostgreSQL                   |
|Authentication  |Supabase Auth                         |
|Detection       |Python rule engine + event correlation|
|AI              |LLM API                               |
|Containerization|Docker                                |
|Log Collection  |Python agent                          |
|Version Control |Git + GitHub                          |



5. System Architecture

```text
                 ORGANIZATION
                      │
          ┌───────────┴───────────┐
          ↓                       ↓
    Windows Machine          Linux Machine
          │                       │
          └───────────┬───────────┘
                      ↓
                Log Collector
                      ↓
                   FastAPI
                      ↓
             Detection Engine
                      ↓
              Risk / Alert Engine
                      ↓
                Supabase DB
                      ↓
             ┌────────┴────────┐
             ↓                 ↓
         React UI          LLM API
             │                 │
             └────────┬────────┘
                      ↓
                Admin Dashboard
```



6. How Detection Works

Example: Brute Force

```text
Failed Login
Failed Login
Failed Login
...
10+ failures
within a short time window
        ↓
Brute Force Detected
        ↓
Risk Score: HIGH
```

Example: Possible Account Compromise

```text
Multiple Failed Logins
        +
Successful Login
        +
Same Source
        ↓
Possible Account Compromise
```

The detection engine can produce a structured incident such as:

```json
{
  "threat_type": "BRUTE_FORCE",
  "severity": "HIGH",
  "risk_score": 85,
  "source_ip": "10.20.1.5",
  "reason": "Multiple failed login attempts from the same source"
}
```



7. API Layer

Initial API design:

```text
POST /api/logs
GET  /api/logs
GET  /api/alerts
GET  /api/incidents
GET  /api/dashboard
POST /api/incidents/{id}/acknowledge
POST /api/analyze
```

FastAPI responsibilities:

	1.	Receive logs
	2.	Validate input
	3.	Normalize events
	4.	Store events
	5.	Trigger detection
	6.	Return alerts/incidents



8. Database

Initial tables:

```text
users
organizations
log_sources
logs
alerts
incidents
detection_rules
```

Important security requirements:

	●	Supabase Row Level Security
	●	Organization-level data isolation
	●	Authenticated access
	●	Server-side authorization
	●	Pagination and query limits
	●	Input validation



9. AI Security Analyst

The LLM receives structured incident information instead of unrestricted raw system access.

Example input:

```text
Attack: Possible Account Compromise
Failed Attempts: 47
Successful Login: 1
Source IP: X
Time Window: 3 minutes
```

Expected output:

```text
What happened?
47 failed authentication attempts were followed by a successful login.
Risk:
High
Recommended actions:
1. Investigate the account.
2. Reset credentials if compromise is suspected.
3. Review recent login activity.
4. Investigate the source IP.
```

The AI layer should assist analysts and explain incidents; it should not be treated as the only security detection mechanism.



10. Development Phases

Phase 0 — Setup

	●	React/Vite/Tailwind
	●	FastAPI
	●	Supabase
	●	Docker
	●	GitHub

Phase 1 — Database & Auth

	●	Schema
	●	Authentication
	●	RLS
	●	Organization isolation

Phase 2 — Simulated Log Collector

	●	Generate/read security events
	●	Send events to FastAPI
	●	Validate and store logs

Phase 3 — Backend

	●	API endpoints
	●	Validation
	●	Log processing
	●	Database integration

Phase 4 — Detection Engine

Implement:

	●	Brute force
	●	Account compromise
	●	Port scan
	●	Privilege escalation
	●	Suspicious process

Phase 5 — Risk & Alerts

	●	Severity
	●	Risk score
	●	Alert creation
	●	Incident creation

Phase 6 — Dashboard

	●	Live alerts
	●	Incident list
	●	Threat timeline
	●	Risk distribution
	●	Incident details

Phase 7 — AI

	●	Incident explanation
	●	Summary
	●	Recommended actions

Phase 8 — Real Log Collection

	●	Windows Event Logs
	●	Linux auth/system logs

Phase 9 — Threat Intelligence

	●	IP reputation
	●	Domain/hash intelligence where applicable

Phase 10 — Deployment & Security

	●	Docker
	●	Rate limiting
	●	Input validation
	●	Secure secrets
	●	Monitoring
	●	Production hardening



11. SIH MVP Scope

Must Have

		React dashboard
		FastAPI backend
		Supabase database
		Log ingestion
		Five detection rules
		Risk scoring
		Alerts
		Incident details
		AI explanation

Good to Have

		Windows collector
		Linux collector
		Threat intelligence
		Real-time dashboard updates
		Incident timeline

Not Required for Initial MVP

	●	Full enterprise SIEM
	●	50+ attack detections
	●	Complex ML model
	●	Automatic destructive response
	●	Kubernetes/distributed infrastructure



12. Demo Scenario

A recommended SIH demo:

	1.	Start CyberRakshak dashboard.
	2.	Generate multiple failed login events.
	3.	Generate a successful login from the same source.
	4.	Log Collector sends events to FastAPI.
	5.	Detection Engine correlates the events.
	6.	System creates a HIGH-risk incident.
	7.	Dashboard updates with the alert.
	8.	LLM generates a clear explanation and recommended actions.
	9.	Administrator acknowledges the incident.

This demonstrates the complete pipeline:

```text
Attack Simulation
      ↓
Log Collection
      ↓
API
      ↓
Detection
      ↓
Risk Score
      ↓
Alert
      ↓
AI Explanation
      ↓
Dashboard
```



13. Future Scope

	●	Multi-organization SaaS architecture
	●	Advanced anomaly detection
	●	MITRE ATT&CK mapping
	●	Threat intelligence correlation
	●	Controlled response automation
	●	Email/Slack/SMS alerting
	●	Endpoint isolation integrations
	●	More operating systems and security sources



14. Project Goal

CyberRakshak aims to make essential security monitoring more accessible to organizations that cannot maintain a dedicated SOC.

Tagline:

> Detect early. Understand clearly. Respond faster.
