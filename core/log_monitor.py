import time
import threading
from typing import List, Dict
import random

from utils.helpers import (
    BackgroundWorker, UpdateQueues, LOG_PATHS, DEMO_MODE,
    generate_demo_event, LogTailer, logger
)
from database.db_manager import DBManager, Event

class LogMonitor:
    def __init__(self, db: DBManager):
        self.db = db
        self.tailers: List[LogTailer] = []
        self.workers: List[BackgroundWorker] = []
        self.init_monitors()
    
    def init_monitors(self):
        """Initialize log tailers for Linux paths"""
        if DEMO_MODE:
            # Demo mode uses generator (already in helpers)
            pass
        else:
            # Real mode
            for name, path in LOG_PATHS.items():
                tailer = LogTailer(path)
                self.tailers.append(tailer)
                worker = BackgroundWorker(
                    f"LogTail-{name}", 
                    lambda t=tailer: self.process_tailer(t),
                    interval=0.5
                )
                worker.start()
                self.workers.append(worker)
        
        logger.info(f"LogMonitor initialized with {len(self.tailers)} tailers")
    
    def process_tailer(self, tailer: LogTailer):
        """Process new lines from tailer"""
        new_lines = tailer.read_new_lines()
        for line in new_lines:
            event = self.parse_raw_line(line, tailer.filepath)
            UpdateQueues.event_queue.put(event)
    
    def parse_raw_line(self, line: str, source: str) -> Dict:
        """Basic line parser - enhanced in event_parser later"""
        event = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "source": source.split('/')[-1],
            "raw": line,
            "parsed": {"message": line},
            "severity": "medium",
            "anomaly_score": random.uniform(0, 0.3)
        }
        return event
    
    def generate_demo_loop(self):
        """Alternative demo generator - calls helpers"""
        while True:
            event = generate_demo_event()
            # Simulate processing
            event_id = self.db.add_event(Event(
                0, event["timestamp"], event["source"], 
                event["raw"], event["parsed"], event["severity"]
            ))
            logger.debug(f"Demo event {event_id} queued")
            time.sleep(random.uniform(2, 8))

    def stop(self):
        for worker in self.workers:
            worker.stop()
        logger.info("LogMonitor stopped")

# Global monitor instance
monitor = None

def get_monitor(db: DBManager) -> LogMonitor:
    global monitor
    if monitor is None:
        monitor = LogMonitor(db)
    return monitor

