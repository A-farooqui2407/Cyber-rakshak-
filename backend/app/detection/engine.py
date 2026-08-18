from typing import List, Dict, Any
from .models import LogEvent, DetectionResult
from .correlator import EventCorrelator

class DetectionEngine:
    def __init__(self):
        self.correlator = EventCorrelator()

    def process_events(self, events: List[LogEvent]) -> DetectionResult:
        """
        Main entrypoint: Accepts security events, runs rule evaluation,
        performs multi-signal correlation, deterministically calculates risk,
        and outputs the DetectionResult.
        """
        return self.correlator.correlate(events)

# Singleton instance
detection_engine = DetectionEngine()
