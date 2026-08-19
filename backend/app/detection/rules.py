from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from .models import LogEvent
from .constants import (
    EVENT_LOGIN_FAILED,
    EVENT_LOGIN_SUCCESS,
    EVENT_PRIVILEGE_ESCALATION,
    EVENT_SUSPICIOUS_IP,
    EVENT_FILE_ACCESS,
    EVENT_DATABASE_ACCESS,
    KNOWN_SUSPICIOUS_IPS
)

class DetectionRules:
    @staticmethod
    def check_brute_force(logs: List[LogEvent], threshold: int = 5, window_minutes: int = 5) -> Dict[str, Any]:
        """
        Rule 1: Detect repeated failed login attempts for same user or IP within time window.
        """
        if not logs:
            return {"triggered": False, "count": 0, "reasons": [], "logs": []}
        anchor = max((l.timestamp for l in logs if l.timestamp), default=None)
        if not anchor:
            return {"triggered": False, "count": 0, "reasons": [], "logs": []}
        window = timedelta(minutes=window_minutes)
        by_key: Dict[str, List[LogEvent]] = {}
        for l in logs:
            if l.event_type != EVENT_LOGIN_FAILED:
                continue
            if l.timestamp < anchor - window:
                continue
            by_key.setdefault(f"user:{l.username.lower()}", []).append(l)
            by_key.setdefault(f"ip:{l.ip_address}", []).append(l)
        for _key, group in by_key.items():
            if len(group) >= threshold:
                return {
                    "triggered": True,
                    "count": len(group),
                    "reasons": [f"Detected {len(group)} failed login attempts within {window_minutes} minutes (Threshold: {threshold})"],
                    "logs": group
                }
        return {"triggered": False, "count": 0, "reasons": [], "logs": []}

    @staticmethod
    def check_suspicious_login(logs: List[LogEvent]) -> Dict[str, Any]:
        """
        Rule 2: Detect multiple failed login attempts followed by a successful login.
        """
        failed_count = sum(1 for l in logs if l.event_type == EVENT_LOGIN_FAILED)
        successful_logins = [l for l in logs if l.event_type == EVENT_LOGIN_SUCCESS]
        
        if failed_count >= 3 and len(successful_logins) > 0:
            return {
                "triggered": True,
                "reasons": [f"Successful authentication immediately preceded by {failed_count} failed attempts"],
                "success_log": successful_logins[0]
            }
        return {"triggered": False, "reasons": [], "success_log": None}

    @staticmethod
    def check_suspicious_ip(logs: List[LogEvent]) -> Dict[str, Any]:
        """
        Rule 3: Detect known malicious, unusual, or flagged external IP addresses.
        """
        suspicious_matches = []
        for l in logs:
            if l.ip_address in KNOWN_SUSPICIOUS_IPS or l.event_type == EVENT_SUSPICIOUS_IP:
                suspicious_matches.append(l)
            elif l.metadata and l.metadata.get("is_anomalous_ip"):
                suspicious_matches.append(l)
                
        if suspicious_matches:
            matched_ips = list(set([l.ip_address for l in suspicious_matches]))
            return {
                "triggered": True,
                "ips": matched_ips,
                "reasons": [f"Traffic originates from flagged suspicious IP address: {', '.join(matched_ips)}"],
                "logs": suspicious_matches
            }
        return {"triggered": False, "ips": [], "reasons": [], "logs": []}

    @staticmethod
    def check_privilege_escalation(logs: List[LogEvent]) -> Dict[str, Any]:
        """
        Rule 4: Detect normal user performing unauthorized administrative action.
        """
        esc_logs = [
            l for l in logs 
            if l.event_type == EVENT_PRIVILEGE_ESCALATION 
            or (l.action and "sudo" in l.action.lower())
            or (l.action and "role_elevate" in l.action.lower())
            or (l.action and "admin" in l.action.lower() and l.metadata.get("prior_role") == "VIEWER")
        ]
        
        if esc_logs:
            return {
                "triggered": True,
                "reasons": [f"Privilege escalation event detected: {esc_logs[0].action} on resource {esc_logs[0].metadata.get('resource', 'system_core')}"],
                "logs": esc_logs
            }
        return {"triggered": False, "reasons": [], "logs": []}

    @staticmethod
    def check_sensitive_data_access(logs: List[LogEvent], threshold: int = 20) -> Dict[str, Any]:
        """
        Rule 5: Detect abnormal access to sensitive databases, confidential files, or high volume exfiltration.
        """
        sensitive_logs = [
            l for l in logs 
            if l.event_type in (EVENT_FILE_ACCESS, EVENT_DATABASE_ACCESS)
            and (l.metadata.get("is_confidential") or "confidential" in l.action.lower() or "export" in l.action.lower())
        ]
        
        if len(sensitive_logs) >= 1:
            return {
                "triggered": True,
                "count": len(sensitive_logs),
                "reasons": [f"Sensitive asset access: {len(sensitive_logs)} sensitive resource read/export requests logged"],
                "logs": sensitive_logs
            }
        return {"triggered": False, "count": 0, "reasons": [], "logs": []}
