import re
from typing import Dict, Optional, List
import datetime
from dataclasses import dataclass

from utils.helpers import logger, Severity

@dataclass
class ParsedEvent:
    """Structured parsed security event"""
    timestamp: str
    user: Optional[str]
    ip_address: Optional[str]
    action: str
    service: Optional[str]
    command: Optional[str]
    tty: Optional[str]
    pid: Optional[int]
    severity: str
    tactics: List[str]  # MITRE ATT&CK tactics

class EventParser:
    """Advanced Linux log parser for SOC"""
    
    def __init__(self):
        self.patterns = self._build_patterns()
    
    def _build_patterns(self) -> Dict[str, re.Pattern]:
        """Regex patterns for Linux security logs"""
        return {
            # auth.log - SSH failed login
            "ssh_failed": re.compile(
                r'(?P<time>\w+\s+\d+\s+\d+:\d+:\d+)\s+'
                r'(?P<host>\S+)\s+'
                r'(sshd|sudo):\s+'
                r'(?P<user>\S+)\s+'
                r'Failed password|authentication failure'
                r'(?:\s+for\s+(?P<ip>\S+)(?::\d+)?)?',
                re.IGNORECASE
            ),
            
            # auth.log - successful login
            "ssh_success": re.compile(
                r'(?P<time>\w+\s+\d+\s+\d+:\d+:\d+)\s+'
                r'(?P<host>\S+)\s+'
                r'(sshd):\s+'
                r'(?P<user>\S+)\s+'
                r'Accepted password|publickey'
                r'\s+for\s+(?P<ip>\S+)(?::\d+)?',
                re.IGNORECASE
            ),
            
            # sudo failure
            "sudo_fail": re.compile(
                r'(?P<time>\w+\s+\d+\s+\d+:\d+:\d+)\s+'
                r'(?P<user>\S+)\s+:'
                r'\s+\d+:\s+Sorry,\s+user\s+(?P<target>\S+)\s+'
                r'may not run sudo on\s+(?P<host>\S+)',
                re.IGNORECASE
            ),
            
            # session open
            "session_open": re.compile(
                r'New session\s+(?P<id>\d+)\s+for\s+(?P<user>\S+)',
                re.IGNORECASE
            ),
            
            # syslog - suspicious process
            "suspicious_proc": re.compile(
                r'(?P<time>\w+\s+\d+\s+\d+:\d+:\d+)\s+'
                r'(?P<proc>\S+):\s+'
                r'(suspicious|unknown|unauthorized)',
                re.IGNORECASE
            ),
            
            # kernel - file integrity
            "file_change": re.compile(
                r'(IN_MODIFY|IN_CREATE|IN_DELETE_SELF)\s+(?P<file>.+)',
                re.IGNORECASE
            ),
            
            # Brute force pattern (time window)
            "bruteforce": re.compile(r'Failed password.*for invalid user|Failed password'),
        }
    
    def parse(self, line: str, source: str = "unknown") -> Optional[ParsedEvent]:
        """Parse log line → structured event"""
        timestamp = datetime.datetime.now().isoformat()
        
        # Try specific patterns first
        for name, pattern in self.patterns.items():
            match = pattern.search(line)
            if match:
                return self._create_parsed_event(match, source, name, timestamp)
        
        # Generic fallback
        return ParsedEvent(
            timestamp=timestamp,
            user=None, ip_address=None, action="generic",
            service=source, command=None, tty=None, pid=None,
            severity="low",
            tactics=[]
        )
    
    def _create_parsed_event(self, match: re.Match, source: str, pattern_name: str, 
                           timestamp: str) -> ParsedEvent:
        """Create ParsedEvent from regex match"""
        data = match.groupdict()
        
        # Determine severity and tactics
        severity_map = {
            "ssh_failed": "high" if "Failed password" in match.string else "medium",
            "sudo_fail": "high",
            "bruteforce": "critical",
            "session_open": "low",
            "suspicious_proc": "high",
            "file_change": "medium",
        }
        
        severity = severity_map.get(pattern_name, "medium")
        tactics = self._get_tactics(pattern_name, data)
        
        # Fill defaults
        parsed_event = ParsedEvent(
            timestamp=timestamp,
            user=data.get("user"),
            ip_address=data.get("ip"),
            action=pattern_name.replace("_", "-"),
            service=data.get("service", source),
            command=data.get("command"),
            tty=data.get("tty"),
            pid=data.get("pid") and int(data.get("pid")),
            severity=severity,
            tactics=tactics
        )
        
        logger.debug(f"Parsed {pattern_name}: {parsed_event.user}@{parsed_event.ip_address}")
        return parsed_event
    
    def _get_tactics(self, pattern: str, data: Dict) -> List[str]:
        """Map to MITRE ATT&CK tactics"""
        tactics_map = {
            "ssh_failed": ["TA0008", "T1110"],  # Lateral Movement, Brute Force
            "sudo_fail": ["TA0004", "T1068"],   # Privilege Escalation
            "session_open": ["TA0003"],         # Persistence
            "suspicious_proc": ["TA0002"],      # Execution
            "file_change": ["TA0006"],          # Defense Evasion
        }
        return tactics_map.get(pattern, [])
    
    def detect_patterns(self, events: List[Dict], window: int = 60) -> List[str]:
        """Multi-event correlation (brute force, etc.)"""
        detections = []
        
        # Simple brute force: >5 failed logins same IP in window
        ip_fails = {}
        for event in events:
            if event.get("action") == "ssh-failed":
                ip = event.get("ip_address")
                if ip:
                    ip_fails[ip] = ip_fails.get(ip, 0) + 1
                    if ip_fails[ip] > 5:
                        detections.append(f"BRUTE_FORCE:{ip}")
        
        return detections

# Global parser
parser = EventParser()

def parse_log_event(line: str, source: str = "auth.log") -> Dict:
    """Convenience wrapper"""
    parsed = parser.parse(line, source)
    return {
        "timestamp": parsed.timestamp,
        "source": source,
        "parsed": vars(parsed),
        "severity": parsed.severity,
        "raw": line,
        "anomaly_score": 0.1  # Placeholder
    }

if __name__ == "__main__":
    # Test parser
    test_lines = [
        "Oct 10 14:23:45 ubuntu sshd[1234]: Failed password for root from 192.168.1.100",
        "Oct 10 14:24:00 ubuntu sudo: john : TTY=pts/0 ; PWD=/home ; USER=root ; COMMAND=/bin/bash",
    ]
    
    for line in test_lines:
        result = parse_log_event(line)
        print(result)

