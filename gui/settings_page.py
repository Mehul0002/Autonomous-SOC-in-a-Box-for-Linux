from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                               QCheckBox, QComboBox, QSlider, QPushButton, 
                               QGroupBox, QSpinBox, QTextEdit)
from PyQt6.QtCore import Qt

from utils.helpers import Colors, DEMO_MODE, LOG_PATHS
from database.db_manager import DBManager

class SettingsPage(QWidget):
    """SOC Configuration Panel"""
    
    def __init__(self, db: DBManager):
        super().__init__()
        self.db = db
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(20)
        layout.setContentsMargins(30, 30, 30, 30)
        
        self.setStyleSheet(f"""
            QWidget {{
                background: {Colors.BG_PRIMARY};
                color: {Colors.TEXT_PRIMARY};
            }}
            QGroupBox {{
                font-weight: bold;
                border: 1px solid {Colors.BG_ACCENT};
                border-radius: 8px;
                margin-top: 15px;
                padding-top: 10px;
            }}
            QGroupBox::title {{
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
                background: {Colors.BG_SECONDARY};
            }}
            QPushButton {{
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 {Colors.SEVERITY['medium']},
                    stop:1 {Colors.SEVERITY['high']});
                border: none;
                border-radius: 6px;
                padding: 10px 20px;
                color: white;
                font-weight: bold;
            }}
            QPushButton:hover {{
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 {Colors.SEVERITY['high']},
                    stop:1 {Colors.SEVERITY['critical']});
            }}
        """)
        
        # Operation Mode
        mode_group = QGroupBox("Operation Mode")
        mode_layout = QVBoxLayout(mode_group)
        
        self.demo_mode_cb = QCheckBox("Demo/Simulation Mode (Safe for Windows)")
        self.demo_mode_cb.setChecked(DEMO_MODE)
        self.demo_mode_cb.stateChanged.connect(self.toggle_demo_mode)
        mode_layout.addWidget(self.demo_mode_cb)
        
        self.production_mode_label = QLabel("⚠️ PRODUCTION MODE DISABLED - Linux only")
        self.production_mode_label.setStyleSheet("color: orange;")
        mode_layout.addWidget(self.production_mode_label)
        
        layout.addWidget(mode_group)
        
        # Monitoring Config
        monitor_group = QGroupBox("Log Monitoring")
        monitor_layout = QVBoxLayout(monitor_group)
        
        path_layout = QHBoxLayout()
        self.auth_log_path = QComboBox()
        self.auth_log_path.addItems([f"{name}: {path}" for name, path in LOG_PATHS.items()])
        path_layout.addWidget(QLabel("Auth Log:"))
        path_layout.addWidget(self.auth_log_path)
        monitor_layout.addLayout(path_layout)
        
        self.monitor_interval = QSpinBox()
        self.monitor_interval.setRange(100, 5000)
        self.monitor_interval.setValue(500)
        self.monitor_interval.setSuffix(" ms")
        monitor_layout.addWidget(QLabel("Poll Interval:"))
        monitor_layout.addWidget(self.monitor_interval)
        
        layout.addWidget(monitor_group)
        
        # SIEM Thresholds
        siem_group = QGroupBox("SIEM Detection")
        siem_layout = QVBoxLayout(siem_group)
        
        self.bruteforce_threshold = QSpinBox()
        self.bruteforce_threshold.setRange(3, 20)
        self.bruteforce_threshold.setValue(5)
        siem_layout.addWidget(QLabel("Brute-force threshold:"))
        siem_layout.addWidget(self.bruteforce_threshold)
        
        layout.addWidget(siem_group)
        
        # ML Sensitivity
        ml_group = QGroupBox("ML Anomaly Detection")
        ml_layout = QVBoxLayout(ml_group)
        
        self.ml_sensitivity = QSlider(Qt.Orientation.Horizontal)
        self.ml_sensitivity.setRange(10, 90)
        self.ml_sensitivity.setValue(60)
        self.ml_sensitivity.setSuffix("%")
        ml_layout.addWidget(QLabel("Anomaly sensitivity:"))
        ml_layout.addWidget(self.ml_sensitivity)
        
        self.retrain_ml_btn = QPushButton("Retrain ML Model")
        self.retrain_ml_btn.clicked.connect(self.retrain_model)
        ml_layout.addWidget(self.retrain_ml_btn)
        
        layout.addWidget(ml_group)
        
        # Database & Reports
        db_group = QGroupBox("Database & Reports")
        db_layout = QVBoxLayout(db_group)
        
        self.clear_db_btn = QPushButton("🗑️ Clear Demo Data")
        self.clear_db_btn.clicked.connect(self.clear_demo_data)
        db_layout.addWidget(self.clear_db_btn)
        
        self.generate_report_btn = QPushButton("📊 Generate Daily Report")
        self.generate_report_btn.clicked.connect(self.generate_report)
        db_layout.addWidget(self.generate_report_btn)
        
        layout.addWidget(db_group)
        
        layout.addStretch()
    
    def toggle_demo_mode(self, state):
        global DEMO_MODE
        DEMO_MODE = bool(state)
        logger.info(f"Demo mode: {'ON' if DEMO_MODE else 'OFF'}")
    
    def retrain_model(self):
        from ml.anomaly_detector import get_anomaly_detector
        detector = get_anomaly_detector(self.db)
        detector._train_model()
    
    def clear_demo_data(self):
        self.db.clear_demo_data()
        logger.info("Demo data cleared")
    
    def generate_report(self):
        from reports.report_generator import get_report_generator
        gen = get_report_generator(self.db)
        filename = gen.generate_daily_summary()
        logger.info(f"Report saved: {filename}")

