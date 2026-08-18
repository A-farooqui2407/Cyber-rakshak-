from datetime import datetime
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field

class LogEvent(BaseModel):
    id: Optional[str] = None
    organization_id: Optional[str] = "11111111-1111-1111-1111-111111111111"
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    source: str
    username: str
    ip_address: str
    event_type: str
    action: str
    status: str
    severity: str = "INFO"
    metadata: Dict[str, Any] = Field(default_factory=dict)

class DetectionResult(BaseModel):
    detected: bool
    threat_type: str
    severity: str
    risk_score: int
    reasons: List[str]
    related_event_ids: List[str]
    affected_user: str
    source_ip: str
    recommended_actions: List[str]
    detection_rule: str
    mitre_attack: Optional[Dict[str, str]] = None
