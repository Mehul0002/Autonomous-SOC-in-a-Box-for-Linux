import sys
from PyQt6.QtWidgets import (QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                             QGridLayout, QLabel, QPushButton, QTableWidget, 
                             QTableWidgetItem, QHeaderView, QFrame, QSplitter,
                             QScrollArea, QSizePolicy)
from PyQt6.QtCore import QTimer, Qt, pyqtSignal
from PyQt6.QtGui import QFont, QPalette, QColor, QPainter

from PyQt6.QtCharts import QChart, QChartView, QBarSeries, QBarSet, QValueAxis, QBarCategoryAxis
from PyQt6.QtCharts import QPieSeries

from database.db_manager import Event, Alert
from utils.helpers import Colors, signals, db, UpdateQueues, generate_demo_event, setup_logging
from utils.helpers import Severity as HelperSeverity

logger = setup_logging()

class KPIWidget(QFrame):
    """Modern KPI card"""
    def __init__(self, title: str, value: str, color: str, icon: str = ""):
        super().__init__()
        self.setFixedHeight(120)
        self.setStyleSheet(f"""
            KPIWidget {{
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 {Colors.BG_SECONDARY}, stop:1 {Colors.BG_ACCENT});
                border-radius: 12px;
                border: 1px solid {Colors.BG_ACCENT};
                margin: 8px;
            }}
        """)
        
        layout = QHBoxLayout(self)
        layout.setContentsMargins(20, 15, 20, 15)
        
        # Icon
        icon_label = QLabel(icon or "📊")
        icon_label.setFont(QFont("Segoe UI Emoji", 24))
        icon_label.setStyleSheet(f"color: {color};")
        layout.addWidget(icon_label)
        
        # Value and title
        right_layout = QVBoxLayout()
        value_label = QLabel(value)
        value_label.setFont(QFont("Segoe UI", 24, QFont.Weight.Bold))
        value_label.setStyleSheet(f"color: {Colors.TEXT_PRIMARY};")
        
        title_label = QLabel(title)
        title_label.setFont(QFont("Segoe UI", 10))
        title_label.setStyleSheet(f"color: {Colors.TEXT_SECONDARY};")
        
        right_layout.addWidget(value_label)
        right_layout.addWidget(title_label)
        layout.addLayout(right_layout)
        layout.addStretch()

class RealTimeFeed(QFrame):
    """Live event feed table"""
    def __init__(self):
        super().__init__()
        self.setStyleSheet(f"""
            RealTimeFeed {{
                background: {Colors.BG_SECONDARY};
                border-radius: 8px;
                border: 1px solid {Colors.BG_ACCENT};
            }}
        """)
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["Time", "Source", "Severity", "Message", "Score"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table.setAlternatingRowColors(True)
        self.table.setStyleSheet(f"""
            QTableWidget {{
                background: transparent;
                gridline-color: {Colors.BG_ACCENT};
                alternate-background-color: {Colors.BG_PRIMARY};
            }}
            QHeaderView::section {{
                background: {Colors.BG_ACCENT};
                color: {Colors.TEXT_PRIMARY};
                padding: 8px;
                border: none;
            }}
        """)
        layout.addWidget(self.table)
        
        # Auto-scroll timer
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_feed)
        self.timer.start(1000)

    def update_feed(self):
        """Live events from DB"""
        recent_events = self.parent().db.get_recent_events(limit=20)  # Access parent DB
        
        # Clear and repopulate
        self.table.setRowCount(0)
        for event in recent_events[-10:]:  # Last 10
            row_data = {
                'timestamp': event.timestamp[-8:],
                'source': event.source,
                'severity': event.severity.upper(),
                'message': event.message[:40] + '...' if len(event.message) > 40 else event.message,
                'score': str(event.parsed_data.get('anomaly_score', 0.0))[:4]
            }
            self.add_event_row(row_data)
        
        if self.table.rowCount() == 0:
            # Fallback demo
            event = generate_demo_event()
            self.add_event_row(event)

    def add_event_row(self, event: dict):
        row = self.table.rowCount()
        self.table.insertRow(row)
        
        # Color severity cell
        severity_color = Colors.SEVERITY.get(event["severity"], Colors.SEVERITY["low"])
        self.table.setItem(row, 0, QTableWidgetItem(event["timestamp"][-8:]))  # Time only
        self.table.setItem(row, 1, QTableWidgetItem(event["source"]))
        sev_item = QTableWidgetItem(event["severity"].upper())
        sev_item.setBackground(QColor(severity_color))
        sev_item.setForeground(QColor(Colors.TEXT_PRIMARY))
        self.table.setItem(row, 2, sev_item)
        self.table.setItem(row, 3, QTableWidgetItem(event["raw"][:50] + "..."))
        self.table.setItem(row, 4, QTableWidgetItem(str(event["anomaly_score"])))

class SOCDashboard(QMainWindow):
    def __init__(self, database):
        super().__init__()
        self.db = database
        self.setWindowTitle("SOC-in-a-Box - Main Dashboard")
        self.setGeometry(100, 100, 1400, 900)
        
        # Dark theme
        palette = QPalette()
        palette.setColor(QPalette.ColorRole.Window, QColor(Colors.BG_PRIMARY))
        palette.setColor(QPalette.ColorRole.WindowText, QColor(Colors.TEXT_PRIMARY))
        self.setPalette(palette)
        
        self.init_ui()
        self.start_timers()
        self.connect_signals()
        self.update_stats()
        
        logger.info("SOC Dashboard loaded")

    def init_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QHBoxLayout(central)
        
        # Left sidebar
        sidebar = QFrame()
        sidebar.setFixedWidth(220)
        sidebar.setStyleSheet(f"background: {Colors.BG_ACCENT}; border-radius: 0 12px 12px 0;")
        sidebar_layout = QVBoxLayout(sidebar)
        sidebar_layout.setContentsMargins(20, 20, 10, 20)
        
        nav_buttons = [
            ("🏠 Dashboard", self.show_dashboard),
            ("🚨 Alerts", lambda: print("Alerts")),
            ("🎯 Incidents", lambda: print("Incidents")),
            ("📋 Logs", lambda: print("Logs")),
            ("📈 Analytics", lambda: print("Analytics")),
            ("⚡ Response", lambda: print("Response")),
            ("⚙️ Settings", lambda: print("Settings")),
        ]
        
        for text, callback in nav_buttons:
            btn = QPushButton(text)
            btn.setStyleSheet(f"""
                QPushButton {{
                    background: transparent;
                    border: none;
                    color: {Colors.TEXT_SECONDARY};
                    padding: 12px;
                    text-align: left;
                    font-size: 14px;
                    border-radius: 8px;
                }}
                QPushButton:hover {{
                    background: {Colors.BG_PRIMARY};
                    color: {Colors.TEXT_PRIMARY};
                }}
            """)
            btn.clicked.connect(callback)
            sidebar_layout.addWidget(btn)
        
        sidebar_layout.addStretch()
        main_layout.addWidget(sidebar)
        
        # Main content area
        content = QSplitter(Qt.Orientation.Vertical)
        main_layout.addWidget(content, 1)
        
        # Top: KPIs and charts
        top_panel = QFrame()
        top_layout = QVBoxLayout(top_panel)
        
        # KPI grid
        kpi_grid = QGridLayout()
        kpis = [
            ("Total Events", "1,247", Colors.SEVERITY["low"]),
            ("Open Alerts", "23", Colors.SEVERITY["high"]),
            ("Active Incidents", "5", Colors.SEVERITY["critical"]),
            ("Blocked IPs", "12", Colors.SEVERITY["medium"]),
        ]
        for i, (title, value, color) in enumerate(kpis):
            kpi = KPIWidget(title, value, color)
            kpi_grid.addWidget(kpi, i // 2, i % 2)
        top_layout.addLayout(kpi_grid)
        
        # Charts row
        charts_layout = QHBoxLayout()
        
        # Live stats from DB
        stats = self.db.get_stats()
        severity_label = QLabel(f"Open Alerts: {stats['open_alerts']} | Critical: {stats['critical_incidents']}")
        severity_label.setStyleSheet(f"color: {Colors.TEXT_PRIMARY}; font-size: 14px;")
        charts_layout.addWidget(severity_label)
        
        # Alerts table preview
        from PyQt6.QtWidgets import QTableWidget, QTableWidgetItem, QHeaderView
        alerts_table = QTableWidget(5, 3)
        alerts_table.setHorizontalHeaderLabels(["Rule", "Severity", "Status"])
        alerts_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        alerts_table.setMaximumHeight(150)
        alerts_table.setStyleSheet(f"""
            background: {Colors.BG_SECONDARY};
            alternate-background-color: {Colors.BG_PRIMARY};
            color: {Colors.TEXT_PRIMARY};
        """)
        charts_layout.addWidget(alerts_table)
        
        self.refresh_alerts_table(alerts_table)
        
        top_layout.addLayout(charts_layout)
        content.addWidget(top_panel)
        
        # Bottom: Real-time feed
        self.feed = RealTimeFeed()
        content.addWidget(self.feed)
        
        content.setSizes([400, 500])

    def start_timers(self):
        self.stats_timer = QTimer()
        self.stats_timer.timeout.connect(self.update_stats)
        self.stats_timer.start(5000)  # 5s

    def connect_signals(self):
        signals.new_event.connect(self.on_new_event)

    def update_stats(self):
        stats = self.db.get_stats()
        logger.info(f"Dashboard stats: {stats}")
        # Update KPI values in full impl

    def on_new_event(self, event):
        logger.info(f"Dashboard received new event: {event['source']}")

    def show_dashboard(self):
        print("Dashboard active")

if __name__ == "__main__":
    from database.db_manager import DBManager
    app = QApplication(sys.argv)
    db = DBManager()
    window = SOCDashboard(db)
    window.show()
    sys.exit(app.exec())

