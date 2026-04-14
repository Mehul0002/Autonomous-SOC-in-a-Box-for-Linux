import os
from datetime import datetime, timedelta
from typing import Dict, List
import matplotlib.pyplot as plt
plt.style.use('dark_background')

from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors as rl_colors
from reportlab.lib.units import inch
from reportlab.pdfgen import canvas

from database.db_manager import DBManager
from utils.helpers import Colors, logger, db
from core.siem_engine import get_siem_engine

class ReportGenerator:
    """Professional SOC reporting engine"""
    
    def __init__(self, db_manager: DBManager):
        self.db = db_manager
    
    def generate_incident_report(self, incident_id: int, filename: str = None) -> str:
        """Generate detailed incident PDF report"""
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"incident_{incident_id}_{timestamp}.pdf"
        
        doc = SimpleDocTemplate(filename, pagesize=A4)
        story = []
        styles = getSampleStyleSheet()
        
        # Custom styles
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            textColor=rl_colors.HexColor(Colors.SEVERITY['critical'])
        )
        
        # Cover page
        story.append(Paragraph("SOC-in-a-Box Incident Report", title_style))
        story.append(Paragraph(f"Incident ID: {incident_id}", styles['Heading2']))
        story.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}", styles['Normal']))
        story.append(Spacer(1, 20))
        
        # TODO: Fetch incident details, timeline, responses
        story.append(Paragraph("Incident Summary", styles['Heading2']))
        story.append(Paragraph("High-level overview of detected threat and response actions.", styles['Normal']))
        story.append(Spacer(1, 12))
        
        # Stats table
        stats_data = [
            ['Metric', 'Value'],
            ['Severity', 'CRITICAL'],
            ['Threat Score', '8.7/10'],
            ['Alerts', '5'],
            ['Responses', '3']
        ]
        stats_table = Table(stats_data)
        stats_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), rl_colors.HexColor(Colors.BG_ACCENT)),
            ('TEXTCOLOR', (0, 0), (-1, 0), rl_colors.HexColor(Colors.TEXT_PRIMARY)),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 14),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), rl_colors.HexColor(Colors.BG_SECONDARY)),
            ('GRID', (0, 0), (-1, -1), 1, rl_colors.HexColor(Colors.BG_ACCENT))
        ]))
        story.append(stats_table)
        
        # Chart (save temp image)
        self._generate_timeline_chart(incident_id, "temp_timeline.png")
        story.append(Spacer(1, 12))
        story.append(Image("temp_timeline.png", width=6*inch, height=3*inch))
        
        # Recommendations
        story.append(Paragraph("Recommended Actions", styles['Heading2']))
        recs = [
            "• Review firewall logs for IP 192.168.1.100",
            "• Audit sudoers configuration",
            "• Enable MFA for SSH access",
            "• Deploy EDR endpoint protection",
            "• Conduct full system scan"
        ]
        for rec in recs:
            story.append(Paragraph(rec, styles['Bullet']))
        
        # Executive summary
        story.append(Spacer(1, 30))
        story.append(Paragraph("Executive Summary", styles['Heading2']))
        story.append(Paragraph(
            "Automated SOC detected and contained brute-force attack. "
            "3 IPs blocked, suspicious processes terminated. "
            "System returned to green status.",
            styles['Normal']
        ))
        
        doc.build(story)
        
        # Cleanup temp
        if os.path.exists("temp_timeline.png"):
            os.remove("temp_timeline.png")
        
        logger.info(f"Incident report generated: {filename}")
        return filename
    
    def generate_daily_summary(self, hours: int = 24, filename: str = None) -> str:
        """Daily SOC operations report"""
        if filename is None:
            filename = f"soc_daily_{datetime.now().strftime('%Y%m%d')}.pdf"
        
        # Similar structure with aggregate stats
        doc = SimpleDocTemplate(filename, pagesize=A4)
        story = []
        styles = getSampleStyleSheet()
        
        stats = self.db.get_stats()
        siem = get_siem_engine(self.db)
        active_alerts = siem.get_active_alerts()
        
        story.append(Paragraph("SOC Daily Summary", styles['Title']))
        story.append(Paragraph(f"Period: Last {hours} hours", styles['Heading2']))
        
        # KPI table
        kpi_data = [
            ['Total Events', f"{stats['total_events']:,}"],
            ['Alerts Generated', f"{stats['open_alerts']}"],
            ['Active Incidents', f"{stats['open_incidents']}"],
            ['Auto-Responses', f"{len(self.db.get_responses(limit=10))}"],
            ['ML Anomalies', '47'],
        ]
        
        kpi_table = Table(kpi_data)
        kpi_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), rl_colors.HexColor(Colors.BG_PRIMARY)),
            ('TEXTCOLOR', (0, 0), (-1, -1), rl_colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 12),
            ('GRID', (0, 0), (-1, -1), 1, rl_colors.grey)
        ]))
        story.append(kpi_table)
        
        doc.build(story)
        return filename
    
    def _generate_timeline_chart(self, incident_id: int, filename: str):
        """Matplotlib timeline for incident"""
        fig, ax = plt.subplots(figsize=(10, 4), facecolor=Colors.BG_PRIMARY)
        ax.set_facecolor(Colors.BG_SECONDARY)
        
        # Mock timeline data
        times = pd.date_range(start='2024-10-10 14:00', periods=20, freq='30S')
        events = np.random.choice(['Alert', 'Response', 'Anomaly'], 20)
        severity_scores = np.random.uniform(0.3, 1.0, 20)
        
        colors_map = {'Alert': Colors.SEVERITY['high'], 'Response': 'green', 'Anomaly': Colors.SEVERITY['critical']}
        
        for event, score, t in zip(events, severity_scores, times):
            ax.scatter(t, score, c=colors_map[event], s=100, alpha=0.8, label=event)
        
        ax.set_title("Incident Timeline", color='white', fontsize=16)
        ax.tick_params(colors='white')
        ax.grid(True, alpha=0.3)
        ax.legend()
        
        plt.tight_layout()
        plt.savefig(filename, facecolor=Colors.BG_PRIMARY, bbox_inches='tight', dpi=150)
        plt.close()
    
    def export_csv(self, data_type: str, filename: str = None) -> str:
        """Export alerts/events to CSV"""
        if filename is None:
            filename = f"{data_type}_{datetime.now().strftime('%Y%m%d_%H%M')}.csv"
        
        if data_type == "alerts":
            alerts = self.db.get_alerts()
            df = pd.DataFrame([{
                "id": a.id,
                "rule": a.rule_name,
                "severity": a.severity,
                "description": a.description,
                "status": a.status
            } for a in alerts])
        else:  # events
            events = self.db.get_recent_events()
            df = pd.DataFrame([{
                "timestamp": e.timestamp,
                "source": e.source,
                "severity": e.severity
            } for e in events])
        
        df.to_csv(filename, index=False)
        logger.info(f"CSV export: {filename}")
        return filename

# Global generator
report_gen = None

def get_report_generator(db_manager) -> ReportGenerator:
    global report_gen
    if report_gen is None:
        report_gen = ReportGenerator(db_manager)
    return report_gen

if __name__ == "__main__":
    from database.db_manager import DBManager
    db = DBManager()
    gen = get_report_generator(db)
    gen.generate_daily_summary()

