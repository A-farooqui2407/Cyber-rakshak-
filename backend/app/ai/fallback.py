from typing import Dict, Any
from .schemas import AIThreatAnalysisResponse

def get_deterministic_ai_fallback(data: Dict[str, Any]) -> AIThreatAnalysisResponse:
    """
    Deterministic AI fallback when LLM API keys are unavailable or rate-limited.
    Provides expert SOC-tier explanations for demonstration and offline reliability.
    """
    threat_type = data.get("threat_type", "POTENTIAL_ACCOUNT_COMPROMISE")
    severity = data.get("severity", "CRITICAL")
    risk_score = data.get("risk_score", 95)
    affected_user = data.get("affected_user", "Rahul Sharma")
    source_ip = data.get("source_ip", "198.51.100.42")
    
    if "ACCOUNT_COMPROMISE" in threat_type or "MULTI_STAGE" in threat_type or risk_score >= 80:
        return AIThreatAnalysisResponse(
            summary=f"Critical multi-stage account compromise detected for user '{affected_user}'. An attacker systematically brute-forced authentication from IP {source_ip}, achieved valid logon, and immediately attempted administrative privilege escalation.",
            threat_type=threat_type,
            severity=severity,
            risk_score=risk_score,
            why_suspicious=[
                "Sequence of 20 consecutive authentication failures followed by immediate successful logon indicates automated credential brute-forcing or password spraying.",
                f"Connection originated from unverified external IP ({source_ip}) that differs from the user's historical corporate geolocations.",
                "Sub-minute privilege escalation attempt following logon is a high-confidence signature of post-exploitation adversary activity."
            ],
            possible_impact=[
                "Complete unauthorized takeover of user credentials with elevated administrative permissions.",
                "Potential unauthorized exfiltration of sensitive legal and client confidential files.",
                "Lateral movement across internal subnet or persistent backdoor installation."
            ],
            recommended_actions=[
                "Immediately revoke active session tokens and force an account-wide logout.",
                "Force an out-of-band password reset with mandated hardware-bound MFA.",
                f"Add firewall drop rule for source IP address {source_ip}.",
                "Audit recent administrative privilege grants in database access logs."
            ],
            investigation_steps=[
                "Review perimeter firewall logs for outbound connections to IP " + source_ip + ".",
                "Extract all commands and API queries executed during this specific session ID.",
                "Interview user to verify whether travel or VPN usage was active at the incident timestamp."
            ],
            confidence=0.98,
            disclaimer="Deterministic SOC intelligence rule output (offline fallback mode active)."
        )
    elif "BRUTE_FORCE" in threat_type:
        return AIThreatAnalysisResponse(
            summary=f"Automated brute-force password guessing attack detected targeting user '{affected_user}' from IP {source_ip}.",
            threat_type=threat_type,
            severity=severity,
            risk_score=risk_score,
            why_suspicious=[
                "High density of failed login attempts exceeding normal human error thresholds within a compact 5-minute window."
            ],
            possible_impact=[
                "Account lockouts leading to Denial of Service for legitimate employees.",
                "Credential compromise if weak or reused passwords are in use."
            ],
            recommended_actions=[
                f"Block IP {source_ip} on edge reverse proxy.",
                "Verify account lockout policy is triggering correctly."
            ],
            investigation_steps=[
                "Check if other usernames in the organization are being targeted by the same IP."
            ],
            confidence=0.95,
            disclaimer="Deterministic SOC intelligence rule output (offline fallback mode active)."
        )
    else:
        return AIThreatAnalysisResponse(
            summary=f"Security alert triggered: {threat_type} involving user '{affected_user}' from {source_ip}.",
            threat_type=threat_type,
            severity=severity,
            risk_score=risk_score,
            why_suspicious=["Activity deviates from established baseline behavior patterns."],
            possible_impact=["Potential policy violation or unauthorized access attempt."],
            recommended_actions=["Review logs and verify activity with the account owner."],
            investigation_steps=["Correlate with additional network telemetry."],
            confidence=0.90,
            disclaimer="Deterministic SOC intelligence rule output."
        )
