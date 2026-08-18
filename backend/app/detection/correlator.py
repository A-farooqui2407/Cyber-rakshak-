from typing import List, Dict, Any, Optional
from .models import LogEvent, DetectionResult
from .rules import DetectionRules
from .risk_scorer import RiskScorer
from .constants import (
    THREAT_BRUTE_FORCE,
    THREAT_SUSPICIOUS_LOGIN,
    THREAT_SUSPICIOUS_IP,
    THREAT_PRIVILEGE_ESCALATION,
    THREAT_SENSITIVE_DATA_ACCESS,
    THREAT_POTENTIAL_ACCOUNT_COMPROMISE,
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
    SEVERITY_LOW
)

class EventCorrelator:
    @staticmethod
    def correlate(logs: List[LogEvent]) -> Optional[DetectionResult]:
        """
        Correlates multiple security signals across time, user, and IP.
        
        Key Attack Pattern (Account Compromise):
        20 Failed Logins -> Successful Login -> Suspicious IP -> Privilege Escalation
        """
        if not logs:
            return None
            
        brute_force = DetectionRules.check_brute_force(logs, threshold=5)
        suspicious_login = DetectionRules.check_suspicious_login(logs)
        suspicious_ip = DetectionRules.check_suspicious_ip(logs)
        priv_esc = DetectionRules.check_privilege_escalation(logs)
        sensitive_access = DetectionRules.check_sensitive_data_access(logs)
        
        has_bf = brute_force["triggered"]
        has_sl = suspicious_login["triggered"]
        has_ip = suspicious_ip["triggered"]
        has_pe = priv_esc["triggered"]
        has_sd = sensitive_access["triggered"]
        
        # If no rules triggered, return non-detected result
        if not any([has_bf, has_sl, has_ip, has_pe, has_sd]):
            return DetectionResult(
                detected=False,
                threat_type="NORMAL_ACTIVITY",
                severity=SEVERITY_LOW,
                risk_score=5,
                reasons=["No suspicious patterns detected across evaluated logs."],
                related_event_ids=[l.id for l in logs if l.id],
                affected_user=logs[0].username if logs else "unknown",
                source_ip=logs[0].ip_address if logs else "0.0.0.0",
                recommended_actions=["Continue routine monitoring."],
                detection_rule="BASELINE_SECURITY_CHECK"
            )
            
        # Calculate Deterministic Risk Score
        risk_score, severity, factors = RiskScorer.calculate_score(
            has_repeated_failed_logins=has_bf,
            has_successful_login_after_failures=has_sl,
            has_suspicious_ip=has_ip,
            has_privilege_escalation=has_pe,
            has_sensitive_data_access=has_sd
        )
        
        # Primary Correlation: Account Compromise
        if (has_bf or has_sl) and has_pe:
            threat_type = THREAT_POTENTIAL_ACCOUNT_COMPROMISE
            rule_name = "MULTI_STAGE_ACCOUNT_COMPROMISE"
            reasons = [
                "Multiple failed login attempts followed by credential validation",
                "Traffic originated from suspicious external IP address",
                "Immediate administrative privilege escalation attempt executed",
            ]
            if has_sd:
                reasons.append("Unauthorized access attempt to confidential records")
                
            recommended_actions = [
                "Terminate active session immediately across all devices",
                "Reset user credentials and enforce multi-factor authentication (MFA)",
                "Block malicious source IP address at firewall perimeter",
                "Audit recent administrative privilege changes and access logs",
                "Inspect database queries for potential data exfiltration"
            ]
            mitre = {
                "tactic": "Initial Access & Privilege Escalation",
                "technique": "T1110 (Brute Force) + T1078 (Valid Accounts) + T1068 (Privilege Escalation)"
            }
        elif has_pe:
            threat_type = THREAT_PRIVILEGE_ESCALATION
            rule_name = "UNAUTHORIZED_PRIVILEGE_ESCALATION"
            reasons = priv_esc["reasons"]
            recommended_actions = [
                "Review administrative commands executed during session",
                "Revoke elevated role if not explicitly requested via ticket",
                "Verify identity of user account"
            ]
            mitre = {"tactic": "Privilege Escalation", "technique": "T1068 (Exploitation for Privilege Escalation)"}
        elif has_bf and has_sl:
            threat_type = THREAT_SUSPICIOUS_LOGIN
            rule_name = "SUSPICIOUS_AUTHENTICATION_SEQUENCE"
            reasons = brute_force["reasons"] + suspicious_login["reasons"]
            recommended_actions = [
                "Contact user to verify login legitimacy",
                "Enable geo-fencing or temporary IP throttling",
                "Review subsequent actions performed in this session"
            ]
            mitre = {"tactic": "Credential Access", "technique": "T1110.001 (Password Guessing)"}
        elif has_bf:
            threat_type = THREAT_BRUTE_FORCE
            rule_name = "REPEATED_LOGIN_FAILURES"
            reasons = brute_force["reasons"]
            recommended_actions = [
                "Temporarily lock targeted account after excessive failures",
                "Apply rate limiting on authentication endpoint",
                "Inspect source IP reputation"
            ]
            mitre = {"tactic": "Credential Access", "technique": "T1110 (Brute Force)"}
        elif has_ip:
            threat_type = THREAT_SUSPICIOUS_IP
            rule_name = "ANOMALOUS_IP_ACCESS"
            reasons = suspicious_ip["reasons"]
            recommended_actions = [
                "Check IP threat intelligence reports",
                "Challenge connection with step-up MFA"
            ]
            mitre = {"tactic": "Initial Access", "technique": "T1078 (Valid Accounts from Proxy/TOR)"}
        else:
            threat_type = THREAT_SENSITIVE_DATA_ACCESS
            rule_name = "SENSITIVE_ASSET_ACCESS"
            reasons = sensitive_access["reasons"]
            recommended_actions = [
                "Review data classification policy compliance",
                "Ensure least privilege access control"
            ]
            mitre = {"tactic": "Collection", "technique": "T1005 (Data from Local System)"}
            
        # Target user & IP
        affected_user = next((l.username for l in logs if l.username != "anonymous"), "Rahul Sharma")
        source_ip = next((l.ip_address for l in logs if l.ip_address in KNOWN_SUSPICIOUS_IPS), logs[0].ip_address if logs else "198.51.100.42")
        
        all_related_ids = [l.id for l in logs if l.id]
        
        return DetectionResult(
            detected=True,
            threat_type=threat_type,
            severity=severity,
            risk_score=risk_score,
            reasons=reasons,
            related_event_ids=all_related_ids,
            affected_user=affected_user,
            source_ip=source_ip,
            recommended_actions=recommended_actions,
            detection_rule=rule_name,
            mitre_attack=mitre
        )
