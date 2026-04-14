import logging
import threading
import queue
import time
import random
import datetime
from typing import Dict, List, Callable, Any
from enum import Enum
import colorsys
import json

# Colors for GUI (Dark theme)
class Colors:
    BG_PRIMARY = "#1e1e2e"
    BG_SECONDARY = "#2a2a3a"
    BG_ACCENT = "#3b3b4b"
    
    TEXT_PRIMARY = "#ffffff"
    TEXT_SECONDARY = "#b0b0b0"
    
    SEVERITY = {
        "low": "#4ade80",      # green
        "medium": "#facc15",   # yellow
        "high": "#f97316",     # orange
        "critical": "#ef4444"  # red
    }
    
    MITRE_ATTACK = "#3b82f6"  # blue

# Severity levels
class Severity(Enum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

SEVERITY_NAMES = {v: k.name.lower() for k, v in Severity.__members__.items()}

# Thread-safe queues for real-time updates
class UpdateQueues:
    event_queue = queue.Queue()
    alert_queue = queue.Queue()
    incident_queue = queue.Queue()

# Logging setup
def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('soc.log'),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger(__name__)

# Safe threaded worker
class BackgroundWorker(threading.Thread):
    def __init__(self, name: str, target: Callable, interval: float = 1.0):
        super().__init__(daemon=True, name=name)
        self.target = target
        self.interval = interval
        self.running = True
        self.lock = threading.Lock()

    def run(self):
        while self.running:
            try:
                self.target()
                time.sleep(self.interval)
            except Exception as e:
                logging = setup_logging()
                logging.error(f"Worker {self.name} error: {e}")

    def stop(self):
        self.running = False

# Generate fake security events for demo (Linux-like)
def generate_demo_event(source: str = "auth.log") -> Dict:
    """Generate realistic fake Linux security events"""
    templates = {
        "auth.log": [
            {"user": "root", "action": "failed-password", "ip": f"192.168.1.{random.randint(1,255)}", "service": "sshd"},
            {"user": "ubuntu", "action": "accepted-password", "ip": "192.168.1.100", "service": "sshd"},
            {"user": "admin", "action": "sudo-failure", "command": "rm -rf /"},
            {"user": "root", "action": "session-opened", "tty": "pts/0", "pid": random.randint(1000,9999)},
        ],
        "syslog": [
            {"process": "cron", "message": "user denied cron access"},
            {"process": "kernel", "message": "suspicious module load attempt"},
            {"process": "systemd", "message": "service restart after crash"},
        ],
        "kern.log": [
            {"event": "netfilter", "action": "dropped packet", "src_ip": f"10.0.0.{random.randint(1,255)}"},
            {"event": "integrity", "file": "/bin/suspicious", "action": "modified"},
        ]
    }
    
    template = random.choice(templates.get(source, templates["syslog"]))
    severity = random.choices(
        ["low", "medium", "high", "critical"], 
        weights=[50, 30, 15, 5]
    )[0]
    
    event = {
        "timestamp": datetime.datetime.now().isoformat(),
        "source": source,
        "raw": f"Sample event from {source}",
        "parsed": template,
        "severity": severity,
        "anomaly_score": round(random.uniform(0, 1), 3)
    }
    return event

# Demo event generator thread
def demo_event_generator():
    """Background thread generating fake events for demo"""
    while True:
        event = generate_demo_event(random.choice(["auth.log", "syslog", "kern.log"]))
        UpdateQueues.event_queue.put(event)
        time.sleep(random.uniform(1, 5))  # 1-5 sec intervals

# Threat score calculation
def calculate_threat_score(event: Dict, anomaly_score: float = 0) -> float:
    """Calculate MITRE ATT&CK inspired threat score"""
    base_score = {
        "low": 2.0,
        "medium": 5.0,
        "high": 8.0,
        "critical": 10.0
    }.get(event["severity"], 1.0)
    
    multipliers = {
        "brute_force": 1.5,
        "privilege_escalation": 2.0,
        "persistence": 1.8,
        "lateral_movement": 2.2
    }
    
    score = base_score + (anomaly_score * 5)
    for tactic in multipliers:
        if tactic in str(event.get("parsed", "")).lower():
            score *= multipliers[tactic]
    
    return min(score, 10.0)

# GUI update signal (emulate Qt signals)
class Signal:
    def __init__(self):
        self.callbacks = []
    
    def connect(self, callback: Callable):
        self.callbacks.append(callback)
    
    def emit(self, data: Any):
        for cb in self.callbacks:
            try:
                cb(data)
            except:
                pass

# Global signals
signals = {
    "new_event": Signal(),
    "new_alert": Signal(),
    "new_incident": Signal(),
    "stats_updated": Signal()
}

# File tail utility (for real logs)
class LogTailer:
    def __init__(self, filepath: str):
        self.filepath = filepath
        self.position = 0
        
    def read_new_lines(self) -> List[str]:
        try:
            with open(self.filepath, 'r') as f:
                f.seek(0, 2)  # End of file
                new_pos = f.tell()
                if self.position < new_pos:
                    f.seek(self.position)
                    lines = f.readlines()
                    self.position = new_pos
                    return [line.strip() for line in lines if line.strip()]
        except FileNotFoundError:
            pass
        return []

# Constants
LOG_PATHS = {
    "auth": "/var/log/auth.log",
    "syslog": "/var/log/syslog",
    "kern": "/var/log/kern.log",
}

DEMO_MODE = True  # Set False for real Linux monitoring

def json_dumps(obj):
    """Safe JSON dumps"""
    return json.dumps(obj, default=str)

if __name__ == "__main__":
    # Test helpers
    print("Testing demo event:", generate_demo_event())
    logging.info("Helpers module loaded")

