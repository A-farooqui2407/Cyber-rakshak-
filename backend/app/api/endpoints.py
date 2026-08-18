import uuid
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, HTTPException, Query, Body, Header, Depends
from pydantic import BaseModel

from ..detection.models import LogEvent, DetectionResult
from ..detection.engine import detection_engine
from ..detection.constants import (
    EVENT_LOGIN_FAILED,
    EVENT_LOGIN_SUCCESS,
    EVENT_PRIVILEGE_ESCALATION,
    EVENT_SUSPICIOUS_IP,
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
    SEVERITY_LOW
)
from ..ai.service import ai_service
from ..ai.schemas import (
    AIThreatAnalysisRequest,
    AIThreatAnalysisResponse,
    AIInvestigateRequest,
    AIInvestigateResponse
)

router = APIRouter()

# In-Memory Store for FastAPI (Syncs with PostgreSQL / Demo state)
DEMO_ORG_ID = "11111111-1111-1111-1111-111111111111"

# Initial seed data for LexGuard Law Associates
logs_db: List[Dict[str, Any]] = []
alerts_db: List[Dict[str, Any]] = []
incidents_db: List[Dict[str, Any]] = []
audit_logs_db: List[Dict[str, Any]] = []

def seed_initial_data():
    global logs_db, alerts_db, incidents_db, audit_logs_db
    if logs_db:
        return
        
    base_time = datetime.utcnow() - timedelta(hours=3)
    
    # Normal logs
    for i in range(15):
        logs_db.append({
            "id": str(uuid.uuid4()),
            "organization_id": DEMO_ORG_ID,
            "timestamp": (base_time + timedelta(minutes=i*10)).isoformat(),
            "source": "vpn_gateway",
            "username": "ananya.p",
            "ip_address": "10.0.4.15",
            "event_type": "LOGIN_SUCCESS",
            "action": "vpn_connect",
            "status": "SUCCESS",
            "severity": "INFO",
            "metadata": {"device": "Corp-MacBook-04", "mfa_verified": True}
        })

seed_initial_data()

# ----------------- DASHBOARD -----------------
@router.get("/dashboard")
async def get_dashboard():
    total_events = len(logs_db)
    critical_alerts = sum(1 for a in alerts_db if a.get("severity") == "CRITICAL" and a.get("status") != "RESOLVED")
    active_incidents = sum(1 for inc in incidents_db if inc.get("status") != "RESOLVED")
    high_risk_events = sum(1 for l in logs_db if l.get("severity") in ("CRITICAL", "HIGH"))
    
    # Calculate weighted overall risk score
    if alerts_db:
        overall_risk_score = max([a.get("risk_score", 0) for a in alerts_db])
    else:
        overall_risk_score = 18  # Baseline low risk
        
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for a in alerts_db:
        sev = a.get("severity", "LOW")
        if sev in severity_counts:
            severity_counts[sev] += 1
            
    events_by_type = {}
    for l in logs_db:
        etype = l.get("event_type", "OTHER")
        events_by_type[etype] = events_by_type.get(etype, 0) + 1
        
    return {
        "total_events": total_events,
        "critical_alerts": critical_alerts,
        "active_incidents": active_incidents,
        "high_risk_events": high_risk_events,
        "overall_risk_score": overall_risk_score,
        "events_last_24h": total_events,
        "alerts_last_24h": len(alerts_db),
        "alerts_by_severity": severity_counts,
        "events_by_type": events_by_type,
        "recent_alerts": alerts_db[-5:] if alerts_db else []
    }

# ----------------- LOGS -----------------
@router.get("/logs")
async def get_logs(
    search: Optional[str] = None,
    severity: Optional[str] = None,
    event_type: Optional[str] = None,
    username: Optional[str] = None,
    ip: Optional[str] = None,
    limit: int = 50,
    offset: int = 0
):
    filtered = logs_db
    if search:
        s = search.lower()
        filtered = [l for l in filtered if s in l["username"].lower() or s in l["ip_address"] or s in l["event_type"].lower() or s in l["action"].lower()]
    if severity:
        filtered = [l for l in filtered if l["severity"].upper() == severity.upper()]
    if event_type:
        filtered = [l for l in filtered if l["event_type"].upper() == event_type.upper()]
    if username:
        filtered = [l for l in filtered if l["username"].lower() == username.lower()]
    if ip:
        filtered = [l for l in filtered if l["ip_address"] == ip]
        
    # Sort newest first
    sorted_logs = sorted(filtered, key=lambda x: x["timestamp"], reverse=True)
    return {
        "total": len(sorted_logs),
        "limit": limit,
        "offset": offset,
        "logs": sorted_logs[offset:offset+limit]
    }

@router.post("/logs")
async def create_log(log: LogEvent):
    log_dict = log.dict()
    log_dict["id"] = log_dict.get("id") or str(uuid.uuid4())
    log_dict["timestamp"] = log_dict["timestamp"].isoformat() if hasattr(log_dict["timestamp"], "isoformat") else log_dict["timestamp"]
    logs_db.append(log_dict)
    return log_dict

@router.get("/logs/{log_id}")
async def get_log_by_id(log_id: str):
    for l in logs_db:
        if l["id"] == log_id:
            return l
    raise HTTPException(status_code=404, detail="Log entry not found")

# ----------------- ALERTS -----------------
@router.get("/alerts")
async def get_alerts(status: Optional[str] = None, severity: Optional[str] = None):
    filtered = alerts_db
    if status:
        filtered = [a for a in filtered if a["status"].upper() == status.upper()]
    if severity:
        filtered = [a for a in filtered if a["severity"].upper() == severity.upper()]
    return sorted(filtered, key=lambda x: x.get("created_at", ""), reverse=True)

@router.get("/alerts/{alert_id}")
async def get_alert(alert_id: str):
    for a in alerts_db:
        if a["id"] == alert_id:
            return a
    raise HTTPException(status_code=404, detail="Alert not found")

@router.patch("/alerts/{alert_id}")
async def update_alert_status(alert_id: str, payload: Dict[str, Any] = Body(...)):
    for a in alerts_db:
        if a["id"] == alert_id:
            if "status" in payload:
                a["status"] = payload["status"]
            a["updated_at"] = datetime.utcnow().isoformat()
            
            # Audit log
            audit_logs_db.append({
                "id": str(uuid.uuid4()),
                "action": "ALERT_STATUS_CHANGED",
                "resource_type": "ALERT",
                "resource_id": alert_id,
                "metadata": payload,
                "created_at": datetime.utcnow().isoformat()
            })
            return a
    raise HTTPException(status_code=404, detail="Alert not found")

# ----------------- INCIDENTS -----------------
@router.get("/incidents")
async def get_incidents(status: Optional[str] = None):
    filtered = incidents_db
    if status:
        filtered = [inc for inc in filtered if inc["status"].upper() == status.upper()]
    return sorted(filtered, key=lambda x: x.get("created_at", ""), reverse=True)

@router.get("/incidents/{incident_id}")
async def get_incident(incident_id: str):
    for inc in incidents_db:
        if inc["id"] == incident_id:
            return inc
    raise HTTPException(status_code=404, detail="Incident not found")

@router.patch("/incidents/{incident_id}")
async def update_incident(incident_id: str, payload: Dict[str, Any] = Body(...)):
    for inc in incidents_db:
        if inc["id"] == incident_id:
            if "status" in payload:
                inc["status"] = payload["status"]
            inc["updated_at"] = datetime.utcnow().isoformat()
            return inc
    raise HTTPException(status_code=404, detail="Incident not found")

# ----------------- DETECTION & RISK -----------------
@router.post("/detection/analyze")
async def analyze_events(events: List[LogEvent]):
    res = detection_engine.process_events(events)
    return res

@router.get("/risk/summary")
async def get_risk_summary():
    highest_score = max([a.get("risk_score", 0) for a in alerts_db], default=18)
    severity = "CRITICAL" if highest_score >= 80 else ("HIGH" if highest_score >= 60 else ("MEDIUM" if highest_score >= 30 else "LOW"))
    
    return {
        "overall_risk_score": highest_score,
        "severity": severity,
        "risk_factors": [
            {"factor": "Repeated Failed Logins", "weight": 25, "active": any("Failed" in r for a in alerts_db for r in a.get("reasons", []))},
            {"factor": "Privilege Escalation Attempts", "weight": 30, "active": any("Privilege" in r for a in alerts_db for r in a.get("reasons", []))},
            {"factor": "Suspicious External IP Exposure", "weight": 20, "active": any("IP" in r for a in alerts_db for r in a.get("reasons", []))},
            {"factor": "Credential Guessing Sequences", "weight": 20, "active": any("Successful" in r for a in alerts_db for r in a.get("reasons", []))}
        ],
        "top_risk_entities": [
            {"user": "rahul.sharma@lexguard.com", "risk": highest_score, "ip": "198.51.100.42"}
        ]
    }

# ----------------- AI THREAT ANALYSIS -----------------
@router.post("/ai/analyze")
async def analyze_with_ai(payload: AIThreatAnalysisRequest):
    return await ai_service.analyze_threat(payload)

@router.post("/ai/investigate")
async def investigate_with_ai(payload: AIInvestigateRequest):
    return await ai_service.investigate_query(payload)

# ----------------- DEMO ATTACK SIMULATION -----------------
@router.post("/demo/simulate-attack")
async def simulate_attack():
    """
    Executes the exact multi-stage attack sequence:
    1. 20 Failed Logins
    2. 1 Successful Login
    3. Unusual Suspicious IP (198.51.100.42)
    4. Privilege Escalation (role_elevate / admin takeover)
    5. Feeds to real Detection Engine
    6. Correlates events -> POTENTIAL_ACCOUNT_COMPROMISE
    7. Calculates deterministic risk -> 95/100 (CRITICAL)
    8. Creates Alert & Incident
    """
    attack_user = "Rahul Sharma"
    attack_ip = "198.51.100.42"
    now = datetime.utcnow()
    
    simulated_events: List[LogEvent] = []
    
    # 1. 20 Failed Login attempts
    for i in range(20):
        log_obj = LogEvent(
            id=str(uuid.uuid4()),
            organization_id=DEMO_ORG_ID,
            timestamp=now - timedelta(minutes=5) + timedelta(seconds=i*4),
            source="auth_service",
            username=attack_user,
            ip_address=attack_ip,
            event_type=EVENT_LOGIN_FAILED,
            action="login_attempt",
            status="FAILED",
            severity="MEDIUM",
            metadata={"attempt_number": i + 1, "failure_reason": "INVALID_CREDENTIALS", "user_agent": "Mozilla/5.0 (Kali Linux)"}
        )
        simulated_events.append(log_obj)
        logs_db.append(log_obj.dict())
        
    # 2. 1 Successful Login
    success_log = LogEvent(
        id=str(uuid.uuid4()),
        organization_id=DEMO_ORG_ID,
        timestamp=now - timedelta(minutes=3),
        source="auth_service",
        username=attack_user,
        ip_address=attack_ip,
        event_type=EVENT_LOGIN_SUCCESS,
        action="user_login",
        status="SUCCESS",
        severity="HIGH",
        metadata={"session_id": "sess_malicious_9981", "auth_method": "password_only"}
    )
    simulated_events.append(success_log)
    logs_db.append(success_log.dict())
    
    # 3. Suspicious IP Telemetry
    ip_log = LogEvent(
        id=str(uuid.uuid4()),
        organization_id=DEMO_ORG_ID,
        timestamp=now - timedelta(minutes=2, seconds=30),
        source="waf_perimeter",
        username=attack_user,
        ip_address=attack_ip,
        event_type=EVENT_SUSPICIOUS_IP,
        action="threat_intel_match",
        status="FLAGGED",
        severity="HIGH",
        metadata={"is_anomalous_ip": True, "geo_country": "Unknown Proxy Node"}
    )
    simulated_events.append(ip_log)
    logs_db.append(ip_log.dict())
    
    # 4. Privilege Escalation
    priv_log = LogEvent(
        id=str(uuid.uuid4()),
        organization_id=DEMO_ORG_ID,
        timestamp=now - timedelta(minutes=1),
        source="iam_control",
        username=attack_user,
        ip_address=attack_ip,
        event_type=EVENT_PRIVILEGE_ESCALATION,
        action="sudo_role_elevate_admin",
        status="DETECTED",
        severity="CRITICAL",
        metadata={"prior_role": "VIEWER", "requested_role": "SUPER_ADMIN", "resource": "/api/v1/system/keys"}
    )
    simulated_events.append(priv_log)
    logs_db.append(priv_log.dict())
    
    # 5. Run Detection & Correlation Engine
    detection_res = detection_engine.process_events(simulated_events)
    
    # 6. Create Alert
    alert_id = str(uuid.uuid4())
    alert_obj = {
        "id": alert_id,
        "organization_id": DEMO_ORG_ID,
        "title": "🚨 Potential Account Compromise — Multi-Stage Attack",
        "description": f"Automated brute-force followed by successful logon and administrative privilege escalation targeting user '{attack_user}' from anomalous IP {attack_ip}.",
        "threat_type": detection_res.threat_type,
        "severity": detection_res.severity,
        "risk_score": detection_res.risk_score,
        "source_ip": detection_res.source_ip,
        "username": detection_res.affected_user,
        "detection_rule": detection_res.detection_rule,
        "reasons": detection_res.reasons,
        "recommended_actions": detection_res.recommended_actions,
        "related_event_ids": detection_res.related_event_ids,
        "status": "NEW",
        "created_at": now.isoformat(),
        "updated_at": now.isoformat()
    }
    alerts_db.append(alert_obj)
    
    # 7. Create Incident
    incident_id = str(uuid.uuid4())
    incident_obj = {
        "id": incident_id,
        "organization_id": DEMO_ORG_ID,
        "alert_id": alert_id,
        "title": f"INC-{now.strftime('%y%m')}-{len(incidents_db)+101}: Active Account Takeover on {attack_user}",
        "description": "Multi-stage attack sequence validated by correlation engine. Mandatory quarantine & credential reset advised.",
        "severity": detection_res.severity,
        "risk_score": detection_res.risk_score,
        "status": "OPEN",
        "affected_user": detection_res.affected_user,
        "source_ip": detection_res.source_ip,
        "assigned_analyst": "Ananya Patel (Tier-2 SOC)",
        "created_at": now.isoformat(),
        "updated_at": now.isoformat()
    }
    incidents_db.append(incident_obj)
    
    return {
        "attack_simulated": True,
        "threat": detection_res.threat_type,
        "risk_score": detection_res.risk_score,
        "severity": detection_res.severity,
        "reasons": detection_res.reasons,
        "alert_id": alert_id,
        "incident_id": incident_id,
        "affected_user": detection_res.affected_user,
        "source_ip": detection_res.source_ip,
        "detection_details": detection_res.dict()
    }
