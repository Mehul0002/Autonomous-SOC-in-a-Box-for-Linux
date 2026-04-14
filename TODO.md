# SOC-in-a-Box Development Plan & Progress Tracker

## Information Gathered
- New greenfield Python project in `soc-in-a-box/` subdirectory
- Target: Linux log monitoring (/var/log/auth.log, syslog, kern.log, journalctl)
- Tech: PyQt6 GUI, SQLite DB, scikit-learn ML, threading for real-time
- Existing dir clean, no conflicts

## Overall Plan
1. **Core Infrastructure** (DB, utils, threading backbone)
2. **Log Monitoring** (tail logs, parse events)
3. **SIEM Engine** (rules, correlation, alerting)
4. **ML Anomaly Detection** (IsolationForest on features)
5. **Incident Management** (auto-create, track)
6. **Auto-Response** (simulate/block/kill)
7. **GUI Dashboard** (main + 6 pages, real-time updates)
8. **Reporting** (PDF/HTML generation)
9. **Polish** (themes, charts, demo data)

## Detailed File-Level Plan

### Phase 1: Foundation (✅ Started)
- [x] `requirements.txt` - Dependencies (PyQt6, sklearn, etc.)
- [x] `README.md` - Documentation
- [ ] `database/db_manager.py` - SQLite schema (events, alerts, incidents)
- [ ] `utils/helpers.py` - Logging, constants, threading utils
- [ ] `main.py` - App entry, thread manager, GUI launch

### Phase 2: Monitoring & Parsing
- [ ] `core/log_monitor.py` - Tail /var/log/* files, journalctl
- [ ] `core/event_parser.py` - Parse auth.log, syslog → normalized events

### Phase 3: Detection
- [ ] `core/siem_engine.py` - Rule-based detection (brute-force, sudo abuse)
- [ ] `ml/anomaly_detector.py` - Train IsolationForest, score events

### Phase 4: Response & Incidents
- [ ] `core/incident_manager.py` - Correlate → create incidents
- [ ] `responders/auto_response.py` - Block IP, kill process (simulation mode)

### Phase 5: GUI (Multi-page PyQt6)
- [ ] `gui/dashboard.py` - Main page (KPI cards, charts, feed)
- [ ] `gui/alerts_page.py` - Alert table/filter
- [ ] `gui/incidents_page.py` - Incident management
- [ ] `gui/log_explorer.py` - Searchable logs
- [ ] `gui/analytics_page.py` - ML charts, trends
- [ ] `gui/response_center.py` - Response logs
- [ ] `gui/settings_page.py` - Config

### Phase 6: Reporting
- [ ] `reports/report_generator.py` - PDF/CSV reports

### Dependent Files
All files interdependent via imports → implement in order above.

## Follow-up Steps After Edits
1. Install: `pip install -r requirements.txt`
2. Test: `python main.py`
3. Demo: Generate fake events, view dashboard
4. Linux test: Run on Ubuntu VM for real logs

## Current Progress
- [x] Project structure initiated
- Next: database/db_manager.py → utils/helpers.py → main.py

**Awaiting approval to proceed with Phase 1 files.**

