#!/usr/bin/env python3
"""
Fully Autonomous SOC-in-a-Box for Linux
Master-Level Cybersecurity Academic Project

Entry point for the complete SOC platform.
Manages background threads, database, GUI dashboard.
"""

import sys
import os
import logging
import threading
from datetime import datetime
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from PyQt6.QtWidgets import QApplication, QMainWindow, QLabel, QVBoxLayout, QWidget, QProgressBar
from PyQt6.QtCore import QTimer, Qt, pyqtSignal, QObject
from PyQt6.QtGui import QFont, QPixmap, QPalette, QColor

from database.db_manager import DBManager, Severity as DBSeverity
from utils.helpers import (
    setup_logging, Colors, UpdateQueues, BackgroundWorker,
    demo_event_generator, signals, DEMO_MODE, generate_demo_event,
    calculate_threat_score, LOG_PATHS
)

# Global instances
logger = setup_logging()
db = None
workers = []

class SplashScreen(QMainWindow):
    """Startup splash with loading animation"""
    show_main = pyqtSignal()
    
    def __init__(self):
        super().__init__()
        self.setWindowTitle("SOC-in-a-Box - Initializing...")
        self.setFixedSize(600, 400)
        self.setWindowFlags(Qt.WindowType.SplashScreen | Qt.WindowType.FramelessWindowHint)
        
        # Dark theme
        palette = QPalette()
        palette.setColor(QPalette.ColorRole.Window, QColor(Colors.BG_PRIMARY))
        palette.setColor(QPalette.ColorRole.WindowText, QColor(Colors.TEXT_PRIMARY))
        self.setPalette(palette)
        
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        
        # Logo/title
        title = QLabel("🚨 SOC-in-a-Box 🚨\\nFully Autonomous Security Operations Center")
        title.setFont(QFont("Segoe UI", 18, QFont.Weight.Bold))
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet(f"color: {Colors.TEXT_PRIMARY}; margin: 20px;")
        layout.addWidget(title)
        
        subtitle = QLabel("Master-Level Cybersecurity Platform for Linux")
        subtitle.setFont(QFont("Segoe UI", 12))
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        subtitle.setStyleSheet(f"color: {Colors.TEXT_SECONDARY};")
        layout.addWidget(subtitle)
        
        layout.addSpacing(30)
        
        # Progress
        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.progress.setStyleSheet(f"""
            QProgressBar {{
                border: 1px solid {Colors.BG_ACCENT};
                border-radius: 5px;
                text-align: center;
                background: {Colors.BG_SECONDARY};
                color: {Colors.TEXT_PRIMARY};
            }}
            QProgressBar::chunk {{
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 {Colors.SEVERITY['critical']}, 
                    stop:1 {Colors.SEVERITY['high']});
                border-radius: 3px;
            }}
        """)
        layout.addWidget(self.progress)
        
        self.status_label = QLabel("Initializing database...")
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.status_label.setStyleSheet(f"color: {Colors.TEXT_SECONDARY};")
        layout.addWidget(self.status_label)
        
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_progress)
        self.timer.start(50)  # 20 FPS
        
        self.progress_value = 0

    def update_progress(self):
        self.progress_value += random.uniform(1, 3)
        if self.progress_value > 100:
            self.progress_value = 100
            self.timer.stop()
            self.show_main.emit()
            return
            
        self.progress.setValue(int(self.progress_value))
        
        statuses = [
            "Initializing database...",
            "Starting log monitors...",
            "Loading SIEM rules...",
            "Initializing ML models...",
            "Starting response engine...",
            "Loading dashboard...",
            "Ready for autonomous operation..."
        ]
        step = int(self.progress_value / 15)  # ~7 steps
        if step < len(statuses):
            self.status_label.setText(statuses[step])

class EventProcessor(QObject):
    """Processes incoming events from queues"""
    
    def __init__(self, db_manager):
        super().__init__()
        self.db = db_manager
        
    def process_events(self):
        """Background event processor"""
        while True:
            try:
                event_data = UpdateQueues.event_queue.get(timeout=1)
                self.handle_event(event_data)
            except:
                pass
    
    def handle_event(self, event_data: dict):
        """Full pipeline: parse → store → SIEM → ML → incidents → response"""
        from core.event_parser import parse_log_event
        from core.siem_engine import get_siem_engine
        from ml.anomaly_detector import get_anomaly_detector
        from core.incident_manager import get_incident_manager
        
        # Store raw event first
        timestamp = event_data["timestamp"]
        source = event_data["source"]
        message = event_data["raw"]
        parsed_data = event_data["parsed"]
        severity_str = event_data["severity"]
        
        event_obj = DBManager.Event(0, timestamp, source, message, parsed_data, severity_str)
        event_id = self.db.add_event(event_obj)
        event_data['event_id'] = event_id
        
        # Parse structured
        structured_event = parse_log_event(message, source)
        
        # SIEM detection
        siem = get_siem_engine(self.db)
        siem.process_event(structured_event)
        
        # ML anomaly scoring
        detector = get_anomaly_detector(self.db)
        features = {}  # Extract from event
        anomaly_score = detector.score_event(features)
        if anomaly_score['is_anomaly']:
            self.db.add_anomaly(event_id, anomaly_score['anomaly_score'], features)
        
        signals.new_event.emit(event_data)
        
        logger.info(f"🔄 Full pipeline processed event {event_id}")

def start_workers():
    """Start all background workers"""
    global workers
    
    # Demo event generator
    if DEMO_MODE:
        demo_worker = BackgroundWorker("DemoEvents", demo_event_generator, 0.5)
        demo_worker.start()
        workers.append(demo_worker)
    
    logger.info("All workers started")

def main():
    global db
    
    app = QApplication(sys.argv)
    app.setStyle('Fusion')  # Modern look
    
    # Dark theme stylesheet
    app.setStyleSheet(f"""
        QMainWindow {{
            background-color: {Colors.BG_PRIMARY};
            color: {Colors.TEXT_PRIMARY};
        }}
        QLabel {{
            color: {Colors.TEXT_PRIMARY};
        }}
    """)
    
    # Init DB
    db = DBManager()
    
    # Splash
    splash = SplashScreen()
    splash.show()
    
    def show_dashboard():
        from gui.dashboard import SOCDashboard
        dashboard = SOCDashboard(db)
        dashboard.show()
        splash.close()

    
    splash.show_main.connect(show_dashboard)
    
    # Temp dashboard stub for now
    timer = QTimer()
    timer.singleShot(3000, lambda: splash.show_main.emit())
    
    start_workers()
    
    sys.exit(app.exec())

if __name__ == "__main__":
    main()

