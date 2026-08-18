from typing import List, Optional
from pydantic import BaseModel, Field

class AIThreatAnalysisRequest(BaseModel):
    threat_type: str
    severity: str
    risk_score: int
    affected_user: str
    source_ip: str
    reasons: List[str]
    related_logs_summary: Optional[str] = None
    alert_id: Optional[str] = None

class AIThreatAnalysisResponse(BaseModel):
    summary: str
    threat_type: str
    severity: str
    risk_score: int
    why_suspicious: List[str]
    possible_impact: List[str]
    recommended_actions: List[str]
    investigation_steps: List[str]
    confidence: float = 0.95
    disclaimer: str = "AI-generated SOC guidance. Verify facts before taking remediation actions."

class AIInvestigateRequest(BaseModel):
    alert_id: Optional[str] = None
    query: str
    context: Optional[str] = None

class AIInvestigateResponse(BaseModel):
    answer: str
    relevant_indicators: List[str] = Field(default_factory=list)
    suggested_queries: List[str] = Field(default_factory=list)
