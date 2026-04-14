import time
from typing import List, Dict, Optional
from collections import defaultdict
from datetime import datetime

from database.db_manager import Incident, Severity as DBSeverity, Status, Alert
from core.siem_engine import SIEMEngine, get_siem_engine
from utils.helpers import logger, signals, db, calculate_threat_score, UpdateQueues

class IncidentManager:
    """Correlates alerts into incidents, manages lifecycle"""
    
    def __init__(self, db_manager, siem_engine: SIEMEngine):
        self.db = db_manager
        self.siem = siem_engine
        self.open_incidents: Dict[int, Incident] = {}
        self.alert_correlation_window = 3600  # 1 hour
        self.auto_resolve_timer = {}
    
    def process_alert(self, alert: Alert):
        """Correlate new alert to existing incident or create new"""
        # Check if matches existing open incident
        matching_incident = self.find_correlated_incident(alert)
        
        if matching_incident:
            self.link_alert_to_incident(matching_incident.id, alert.id)
            self.update_incident_threat_score(matching_incident.id)
            logger.info(f"Alert {alert.id} linked to incident {matching_incident.id}")
        else:
            # Create new incident
            incident = self.create_incident_from_alert(alert)
            self.link_alert_to_incident(incident.id, alert.id)
            self.open_incidents[incident.id] = incident
            signals.new_incident.emit(vars(incident))
            logger.warning(f"🎯 NEW INCIDENT: {incident.title}")
        
        # Trigger auto-response evaluation
        self.evaluate_auto_response(alert)
    
    def find_correlated_incident(self, alert: Alert) -> Optional[Incident]:
        """Find existing incident by similarity"""
        # Same rule family, same target (IP/user/file), recent time
        for inc_id, incident in self.open_incidents.items():
            if (self.is_same_rule_family(alert.rule_name, incident.title) and
                self.time_in_window(incident.created, self.alert_correlation_window)):
                return incident
        
        # Query DB for open incidents
        incidents = self.db.get_incidents(status=Status.OPEN.value)
        for inc in incidents:
            # Simplified matching logic
            if alert.rule_name in inc.title.lower():
                return inc
        
        return None
    
    def create_incident_from_alert(self, alert: Alert) -> Incident:
        """Auto-generate incident from single alert"""
        threat_score = self.calculate_incident_score([alert])
        title = f"{alert.rule_name.upper().replace('_', ' ')} - {alert.description[:50]}"
        
        incident = Incident(
            id=0,
            alert_ids=[],  # Filled later
            title=title,
            severity=alert.severity,
            status=Status.OPEN.value,
            created=datetime.now().isoformat(),
            threat_score=threat_score
        )
        
        inc_id = self.db.create_incident(incident)
        incident.id = inc_id
        
        return incident
    
    def link_alert_to_incident(self, incident_id: int, alert_id: int):
        """DB link"""
        self.db.link_alert_to_incident(incident_id, alert_id)
    
    def update_incident_threat_score(self, incident_id: int):
        """Recalculate based on all linked alerts"""
        # Simplified - average scores
        # Full impl would weight by severity/recency
        pass
    
    def calculate_incident_score(self, alerts: List[Alert]) -> float:
        """MITRE-inspired scoring"""
        scores = []
        for alert in alerts:
            score = {
                "low": 2.0,
                "medium": 5.0,
                "high": 8.0,
                "critical": 10.0
            }.get(alert.severity, 1.0)
            scores.append(score)
        return sum(scores) / len(scores) if scores else 0.0
    
    def evaluate_auto_response(self, alert: Alert):
        """Decide if auto-response needed"""
        threat_threshold = 7.0
        if self.calculate_incident_score([alert]) > threat_threshold:
            from responders.auto_response import get_responder
            responder = get_responder()
            responder.trigger_response(alert)
    
    def auto_resolve_low_risk(self):
        """Background task to auto-resolve low-risk incidents"""
        low_incidents = self.db.get_incidents(status=Status.OPEN.value)
        for inc in low_incidents:
            if inc.threat_score < 3.0 and time.time() - datetime.fromisoformat(inc.created).timestamp() > 3600:
                self.db.update_incident_status(inc.id, Status.RESOLVED.value)
                logger.info(f"Auto-resolved low-risk incident {inc.id}")
    
    def get_open_incidents(self, limit: int = 20) -> List[Dict]:
        """Dashboard data"""
        incidents = self.db.get_incidents(status=Status.OPEN.value, limit=limit)
        return [{"id": i.id, "title": i.title, "severity": i.severity, "score": i.threat_score} 
                for i in incidents]

# Global manager
incident_mgr = None

def get_incident_manager(db_manager, siem_engine) -> IncidentManager:
    global incident_mgr
    if incident_mgr is None:
        incident_mgr = IncidentManager(db_manager, siem_engine)
    return incident_mgr

def correlate_alerts():
    """Process pending alerts"""
    try:
        alert = UpdateQueues.alert_queue.get_nowait()
        mgr = get_incident_manager(db, get_siem_engine(db))
        mgr.process_alert(alert)
    except:
        pass  # No alerts

