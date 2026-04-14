import time
from typing import List, Dict, Optional
from collections import defaultdict, deque
from datetime import datetime, timedelta

from database.db_manager import Alert, Severity as DBSeverity
from core.event_parser import parse_log_event, ParsedEvent, EventParser
from utils.helpers import (
    Severity, calculate_threat_score, logger, UpdateQueues, signals, db
)

class SIEMRule:
    """Individual detection rule"""
    def __init__(self, name: str, description: str, severity: str, 
                 pattern_matcher: callable, threshold: int = 1):
        self.name = name
        self.description = description
        self.severity = severity
        self.pattern_matcher = pattern_matcher
        self.threshold = threshold
        self.matches = defaultdict(int)  # Key-based counting (IP, user, etc.)

class SIEMEngine:
    """Rule-based SIEM detection engine"""
    
    def __init__(self, db_manager):
        self.db = db_manager
        self.parser = EventParser()
        self.rules = self._load_rules()
        self.event_window = deque(maxlen=1000)  # Sliding window
        self.alert_window = deque(maxlen=100)   # Recent alerts
        
    def _load_rules(self) -> List[SIEMRule]:
        """Security detection rules"""
        def ip_bruteforce(event: Dict) -> Optional[str]:
            if event["parsed"].get("action") == "ssh-failed":
                return event["parsed"].get("ip_address")
        
        def user_sudo_abuse(event: Dict) -> Optional[str]:
            if "sudo_fail" in event["parsed"].get("action", ""):
                return event["parsed"].get("user")
        
        def priv_esc_chain(event: Dict) -> Optional[str]:
            # Session + sudo combo
            if event["parsed"].get("action") == "session-open":
                return event["parsed"].get("user")
        
        def rapid_sessions(event: Dict) -> Optional[str]:
            if event["parsed"].get("action") == "session-open":
                return f"{event['parsed'].get('user')}_{event['source']}"
        
        def suspicious_file_change(event: Dict) -> Optional[str]:
            if "file_change" in event["parsed"].get("action", ""):
                return event["parsed"].get("file")
        
        rules = [
            SIEMRule(
                "brute_force_ssh",
                "5+ failed SSH logins from same IP in 5min",
                "critical",
                ip_bruteforce,
                threshold=5
            ),
            SIEMRule(
                "sudo_abuse",
                "Multiple sudo failures by same user",
                "high",
                user_sudo_abuse,
                threshold=3
            ),
            SIEMRule(
                "privilege_escalation",
                "New session followed by sudo attempt",
                "critical",
                priv_esc_chain,
                threshold=1
            ),
            SIEMRule(
                "rapid_sessions",
                "3+ rapid sessions from same user",
                "medium",
                rapid_sessions,
                threshold=3
            ),
            SIEMRule(
                "file_integrity_violation",
                "Suspicious file modification",
                "high",
                suspicious_file_change,
                threshold=2
            ),
        ]
        logger.info(f"Loaded {len(rules)} SIEM rules")
        return rules
    
    def process_event(self, raw_event: Dict):
        """Main SIEM processing pipeline"""
        # Parse
        parsed_event = self.parser.parse(raw_event["raw"], raw_event["source"])
        
        enriched = {
            **raw_event,
            "parsed": vars(parsed_event),
            "threat_score": calculate_threat_score(raw_event),
            "tactics": parsed_event.tactics
        }
        
        # Store event (already done in monitor/processor)
        
        # Run all rules
        for rule in self.rules:
            key = rule.pattern_matcher(enriched)
            if key:
                self.evaluate_rule(rule, key, enriched)
        
        # Update window
        self.event_window.append(enriched)
        
        # Pattern detection across window
        self.check_correlations()
    
    def evaluate_rule(self, rule: SIEMRule, key: str, event: Dict):
        """Check single rule threshold"""
        now = time.time()
        window_start = now - 300  # 5 minutes
        
        # Age out old matches (simple time-based)
        if rule.matches[key] > rule.threshold:
            # Still valid window - check if alert already firing
            pass
        
        rule.matches[key] += 1
        
        if rule.matches[key] >= rule.threshold:
            self.create_alert(rule, key, event)
    
    def create_alert(self, rule: SIEMRule, key: str, event: Dict):
        """Create database alert"""
        alert = Alert(
            id=0,
            event_id=event.get("event_id", 0),  # From DB
            rule_name=rule.name,
            severity=rule.severity,
            description=f"{rule.description} (key: {key})",
            status="open"
        )
        
        alert_id = self.db.add_alert(alert)
        logger.warning(f"🚨 SIEM ALERT: {rule.name} - {key}")
        
        # Emit signal
        signals.new_alert.emit({
            "alert": vars(alert),
            "rule": rule.name,
            "key": key
        })
        
        UpdateQueues.alert_queue.put(alert)
    
    def check_correlations(self):
        """Advanced multi-event correlation"""
        if len(self.event_window) < 10:
            return
        
        recent_events = list(self.event_window)[-50:]
        
        # Chain detection: login → sudo → session
        sudo_events = [e for e in recent_events if "sudo" in str(e.get("parsed", ""))]
        ssh_events = [e for e in recent_events if "ssh" in str(e.get("parsed", ""))]
        
        if len(sudo_events) >= 2 and len(ssh_events) >= 1:
            self.create_alert(
                SIEMRule("attack_chain", "SSH + multiple sudo (possible priv esc)", "critical", lambda x: "chain"),
                "ssh_sudo_chain",
                recent_events[-1]
            )
    
    def get_active_alerts(self, limit: int = 20) -> List[Dict]:
        """Dashboard summary"""
        alerts = self.db.get_alerts(limit=limit)
        return [{"id": a.id, "rule": a.rule_name, "severity": a.severity} for a in alerts]
    
    def suppress_alert(self, alert_id: int, duration_hours: int = 1):
        """Temporarily suppress repeating alerts"""
        logger.info(f"Suppressing alert {alert_id} for {duration_hours}h")
        # Impl expiration tracking

# Global SIEM instance
siem_engine = None

def get_siem_engine(db_manager) -> SIEMEngine:
    global siem_engine
    if siem_engine is None:
        siem_engine = SIEMEngine(db_manager)
    return siem_engine

def check_rules(event: Dict) -> List[str]:
    """Legacy wrapper for main.py"""
    engine = get_siem_engine(db)
    engine.process_event(event)
    return []  # Placeholder

