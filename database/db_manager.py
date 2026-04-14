import sqlite3
import json
import datetime
from typing import List, Dict, Optional
from dataclasses import dataclass
from enum import Enum

class Severity(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class Status(Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"

@dataclass
class Event:
    id: int
    timestamp: str
    source: str
    message: str
    parsed_data: Dict
    severity: str

@dataclass
class Alert:
    id: int
    event_id: int
    rule_name: str
    severity: str
    description: str
    status: str

@dataclass
class Incident:
    id: int
    alert_ids: List[int]
    title: str
    severity: str
    status: str
    created: str
    threat_score: float

@dataclass
class ResponseAction:
    id: int
    incident_id: int
    action_type: str
    target: str
    success: bool
    timestamp: str

class DBManager:
    def __init__(self, db_path: str = "soc_database.db"):
        self.db_path = db_path
        self.init_db()

    def init_db(self):
        """Initialize database schema"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Events table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                source TEXT NOT NULL,
                message TEXT NOT NULL,
                parsed_data TEXT,
                severity TEXT DEFAULT 'low'
            )
        ''')
        
        # Alerts table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id INTEGER,
                rule_name TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT,
                status TEXT DEFAULT 'open',
                FOREIGN KEY(event_id) REFERENCES events(id)
            )
        ''')
        
        # Incidents table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                status TEXT DEFAULT 'open',
                created TEXT NOT NULL,
                threat_score REAL DEFAULT 0.0,
                resolved TEXT
            )
        ''')
        
        # Incident-alert mapping
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS incident_alerts (
                incident_id INTEGER,
                alert_id INTEGER,
                PRIMARY KEY(incident_id, alert_id),
                FOREIGN KEY(incident_id) REFERENCES incidents(id),
                FOREIGN KEY(alert_id) REFERENCES alerts(id)
            )
        ''')
        
        # Response actions
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS responses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id INTEGER,
                action_type TEXT NOT NULL,
                target TEXT,
                success INTEGER NOT NULL,
                timestamp TEXT NOT NULL,
                FOREIGN KEY(incident_id) REFERENCES incidents(id)
            )
        ''')
        
        # ML anomalies
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS anomalies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id INTEGER,
                anomaly_score REAL NOT NULL,
                features TEXT,
                timestamp TEXT NOT NULL,
                FOREIGN KEY(event_id) REFERENCES events(id)
            )
        ''')
        
        conn.commit()
        conn.close()

    def add_event(self, event: Event) -> int:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO events (timestamp, source, message, parsed_data, severity)
            VALUES (?, ?, ?, ?, ?)
        ''', (event.timestamp, event.source, event.message, 
              json.dumps(event.parsed_data), event.severity))
        event_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return event_id

    def add_alert(self, alert: Alert) -> int:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO alerts (event_id, rule_name, severity, description, status)
            VALUES (?, ?, ?, ?, ?)
        ''', (alert.event_id, alert.rule_name, alert.severity, alert.description, alert.status))
        alert_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return alert_id

    def create_incident(self, incident: Incident) -> int:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO incidents (title, severity, status, created, threat_score)
            VALUES (?, ?, ?, ?, ?)
        ''', (incident.title, incident.severity, incident.status, incident.created, incident.threat_score))
        inc_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return inc_id

    def link_alert_to_incident(self, incident_id: int, alert_id: int):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT OR IGNORE INTO incident_alerts (incident_id, alert_id)
            VALUES (?, ?)
        ''', (incident_id, alert_id))
        conn.commit()
        conn.close()

    def add_response(self, response: ResponseAction) -> int:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO responses (incident_id, action_type, target, success, timestamp)
            VALUES (?, ?, ?, ?, ?)
        ''', (response.incident_id, response.action_type, response.target, 
              int(response.success), response.timestamp))
        resp_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return resp_id

    def add_anomaly(self, event_id: int, score: float, features: Dict):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO anomalies (event_id, anomaly_score, features, timestamp)
            VALUES (?, ?, ?, ?)
        ''', (event_id, score, json.dumps(features), datetime.datetime.now().isoformat()))
        conn.commit()
        conn.close()

    def get_recent_events(self, limit: int = 100) -> List[Event]:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id, timestamp, source, message, parsed_data, severity
            FROM events ORDER BY timestamp DESC LIMIT ?
        ''', (limit,))
        rows = cursor.fetchall()
        events = []
        for row in rows:
            events.append(Event(row[0], row[1], row[2], row[3], 
                               json.loads(row[4]) if row[4] else {}, row[5]))
        conn.close()
        return events

    def get_alerts(self, status: str = None, limit: int = 50) -> List[Alert]:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        if status:
            cursor.execute('''
                SELECT id, event_id, rule_name, severity, description, status
                FROM alerts WHERE status = ? ORDER BY id DESC LIMIT ?
            ''', (status, limit))
        else:
            cursor.execute('''
                SELECT id, event_id, rule_name, severity, description, status
                FROM alerts ORDER BY id DESC LIMIT ?
            ''', (limit,))
        rows = cursor.fetchall()
        alerts = [Alert(row[0], row[1], row[2], row[3], row[4], row[5]) for row in rows]
        conn.close()
        return alerts

    def get_incidents(self, status: str = None, limit: int = 20) -> List[Incident]:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        if status:
            cursor.execute('''
                SELECT id, title, severity, status, created, threat_score
                FROM incidents WHERE status = ? ORDER BY created DESC LIMIT ?
            ''', (status, limit))
        else:
            cursor.execute('''
                SELECT id, title, severity, status, created, threat_score
                FROM incidents ORDER BY created DESC LIMIT ?
            ''', (limit,))
        rows = cursor.fetchall()
        incidents = []
        for row in rows:
            # Fetch linked alert count for display
            incidents.append(Incident(row[0], [], row[1], row[2], row[3], row[4], row[5]))
        conn.close()
        return incidents

    def update_incident_status(self, incident_id: int, status: str, resolved: str = None):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        if resolved:
            cursor.execute('''
                UPDATE incidents SET status = ?, resolved = ? WHERE id = ?
            ''', (status, resolved, incident_id))
        else:
            cursor.execute('UPDATE incidents SET status = ? WHERE id = ?', (status, incident_id))
        conn.commit()
        conn.close()

    def get_stats(self) -> Dict:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT COUNT(*) FROM events")
        total_events = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM alerts WHERE status = 'open'")
        open_alerts = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM incidents WHERE status = 'open'")
        open_incidents = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM incidents WHERE severity = 'critical'")
        critical_incidents = cursor.fetchone()[0]
        
        conn.close()
        return {
            'total_events': total_events,
            'open_alerts': open_alerts,
            'open_incidents': open_incidents,
            'critical_incidents': critical_incidents
        }

    def clear_demo_data(self):
        """Clear all tables for demo reset"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM responses")
        cursor.execute("DELETE FROM anomalies")
        cursor.execute("DELETE FROM incident_alerts")
        cursor.execute("DELETE FROM incidents")
        cursor.execute("DELETE FROM alerts")
        cursor.execute("DELETE FROM events")
        conn.commit()
        conn.close()

