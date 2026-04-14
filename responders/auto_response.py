import subprocess
import os
import time
from typing import Dict, Optional
from enum import Enum

from database.db_manager import ResponseAction
from utils.helpers import logger, db, DEMO_MODE, signals
from core.siem_engine import Alert

class ResponseType(Enum):
    BLOCK_IP = "block_ip"
    KILL_PROCESS = "kill_process"
    QUARANTINE_FILE = "quarantine_file"
    DISABLE_USER = "disable_user"
    ALERT_ONLY = "alert_only"

class AutoResponder:
    """Automated incident response engine"""
    
    def __init__(self):
        self.mode = "simulation" if DEMO_MODE else "production"
        self.blocked_ips = set()
        self.quarantined_files = set()
    
    def trigger_response(self, alert: Alert, incident_id: Optional[int] = None):
        """Main response dispatcher"""
        responses = self._get_response_actions(alert)
        
        for resp_type, target in responses:
            success = self._execute_response(resp_type, target)
            
            action = ResponseAction(
                id=0,
                incident_id=incident_id or 0,
                action_type=resp_type.value,
                target=target,
                success=success,
                timestamp=time.strftime("%Y-%m-%dT%H:%M:%S")
            )
            
            resp_id = self.db.add_response(action)
            logger.info(f"Response {resp_type.value} on {target}: {'✅' if success else '❌'}")
            
            signals.new_response.emit({
                "action": vars(action),
                "mode": self.mode
            })
    
    def _get_response_actions(self, alert: Alert) -> List[tuple]:
        """Rule-based response selection"""
        actions = []
        
        rule_responses = {
            "brute_force_ssh": [(ResponseType.BLOCK_IP, alert.description.split()[-1])],
            "sudo_abuse": [(ResponseType.DISABLE_USER, "temp_user")],
            "privilege_escalation": [(ResponseType.KILL_PROCESS, "suspicious_pid")],
            "file_integrity_violation": [(ResponseType.QUARANTINE_FILE, "/path/to/file")],
        }
        
        actions = rule_responses.get(alert.rule_name, [(ResponseType.ALERT_ONLY, "none")])
        return actions
    
    def _execute_response(self, resp_type: ResponseType, target: str) -> bool:
        """Execute response action"""
        if self.mode == "simulation":
            time.sleep(0.5)  # Simulate work
            return True
        
        try:
            if resp_type == ResponseType.BLOCK_IP:
                # iptables -A INPUT -s {target} -j DROP
                cmd = ["iptables", "-A", "INPUT", "-s", target, "-j", "DROP"]
                result = subprocess.run(cmd, capture_output=True)
                return result.returncode == 0
            
            elif resp_type == ResponseType.KILL_PROCESS:
                # kill -9 {target}
                subprocess.run(["kill", "-9", target], capture_output=True)
                return True
            
            elif resp_type == ResponseType.QUARANTINE_FILE:
                # mv {target} /quarantine/
                os.makedirs("/quarantine", exist_ok=True)
                os.rename(target, f"/quarantine/{os.path.basename(target)}")
                return True
            
            elif resp_type == ResponseType.DISABLE_USER:
                # passwd -l {target}
                subprocess.run(["passwd", "-l", target], capture_output=True)
                return True
            
        except Exception as e:
            logger.error(f"Response failed: {e}")
            return False
        
        return True
    
    def get_response_history(self, limit: int = 20) -> List[Dict]:
        """Dashboard data"""
        # Query DB responses table
        conn = self.db.conn  # Assume accessor
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM responses ORDER BY timestamp DESC LIMIT ?", (limit,))
        return [{"type": row[2], "target": row[3], "success": bool(row[4])} for row in cursor.fetchall()]
    
    def clear_blocklist(self):
        """Manual unblock (operator intervention)"""
        if self.mode == "production":
            subprocess.run(["iptables", "-F"], capture_output=True)
        self.blocked_ips.clear()

# Global responder
responder = None

def get_responder() -> AutoResponder:
    global responder
    if responder is None:
        responder = AutoResponder()
    return responder

if __name__ == "__main__":
    # Demo
    from database.db_manager import Alert
    alert = Alert(0, 0, "brute_force_ssh", "critical", "IP 192.168.1.100 brute force", "open")
    r = get_responder()
    r.trigger_response(alert)

