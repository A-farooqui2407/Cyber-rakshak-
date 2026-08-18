from typing import List, Dict, Any, Tuple
from .constants import (
    RISK_WEIGHT_REPEATED_FAILED_LOGIN,
    RISK_WEIGHT_SUCCESSFUL_LOGIN_AFTER_FAILURES,
    RISK_WEIGHT_SUSPICIOUS_IP,
    RISK_WEIGHT_PRIVILEGE_ESCALATION,
    RISK_WEIGHT_SENSITIVE_DATA_ACCESS,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    SEVERITY_HIGH,
    SEVERITY_CRITICAL
)

class RiskScorer:
    @staticmethod
    def calculate_score(
        has_repeated_failed_logins: bool,
        has_successful_login_after_failures: bool,
        has_suspicious_ip: bool,
        has_privilege_escalation: bool,
        has_sensitive_data_access: bool
    ) -> Tuple[int, str, List[Dict[str, Any]]]:
        """
        Deterministic Risk Calculation:
        - Repeated failed login:       +25
        - Successful login afterward:  +20
        - Suspicious IP:               +20
        - Privilege escalation:        +30
        - Sensitive data access:       +20
        Capped at 100.
        
        Severity Mapping:
        0 - 29   -> LOW
        30 - 59  -> MEDIUM
        60 - 79  -> HIGH
        80 - 100 -> CRITICAL
        """
        score = 0
        factors = []
        
        if has_repeated_failed_logins:
            score += RISK_WEIGHT_REPEATED_FAILED_LOGIN
            factors.append({
                "factor": "Repeated Failed Login Attempts",
                "weight": RISK_WEIGHT_REPEATED_FAILED_LOGIN,
                "description": "High frequency of failed authentication attempts indicative of brute force."
            })
            
        if has_successful_login_after_failures:
            score += RISK_WEIGHT_SUCCESSFUL_LOGIN_AFTER_FAILURES
            factors.append({
                "factor": "Successful Login After Repeated Failures",
                "weight": RISK_WEIGHT_SUCCESSFUL_LOGIN_AFTER_FAILURES,
                "description": "Attacker successfully obtained or guessed valid credentials."
            })
            
        if has_suspicious_ip:
            score += RISK_WEIGHT_SUSPICIOUS_IP
            factors.append({
                "factor": "Suspicious / Anomalous Source IP",
                "weight": RISK_WEIGHT_SUSPICIOUS_IP,
                "description": "Connection originated from unverified, proxy, or flagged threat IP address."
            })
            
        if has_privilege_escalation:
            score += RISK_WEIGHT_PRIVILEGE_ESCALATION
            factors.append({
                "factor": "Privilege Escalation Attempt",
                "weight": RISK_WEIGHT_PRIVILEGE_ESCALATION,
                "description": "Unauthorized attempt to acquire administrative privileges or elevate access."
            })
            
        if has_sensitive_data_access:
            score += RISK_WEIGHT_SENSITIVE_DATA_ACCESS
            factors.append({
                "factor": "Sensitive Asset / Database Access",
                "weight": RISK_WEIGHT_SENSITIVE_DATA_ACCESS,
                "description": "Access or exfiltration request directed at restricted database files."
            })
            
        score = min(100, score)
        
        if score >= 80:
            severity = SEVERITY_CRITICAL
        elif score >= 60:
            severity = SEVERITY_HIGH
        elif score >= 30:
            severity = SEVERITY_MEDIUM
        else:
            severity = SEVERITY_LOW
            
        return score, severity, factors
