import sys
import os

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../"))
sys.path.append(BASE_DIR)

import threading
import logging
from config import settings
from db.database import SessionLocal
from db import crud
from services.risk_engine import compute_risk_scores

logger = logging.getLogger(__name__)

def start_scan_task(scan_id: str, target: str, scan_type: str):
    thread = threading.Thread(
        target=_run_scan,
        args=(scan_id, target, scan_type),
        daemon=True
    )
    thread.start()
    logger.info(f"Scan thread started for scan_id={scan_id}")

def _run_scan(scan_id: str, target: str, scan_type: str):
    db = SessionLocal()
    try:
        logger.info(f"Running scan for ID: {scan_id}")

        crud.update_scan_status(db, scan_id, "running")

        raw_findings = _execute_scanners(target, scan_type)

        if not raw_findings:
            logger.warning("No findings from scanners")

        scored_findings = compute_risk_scores(raw_findings)

        #Merging original + scored data
        final_findings = []
        for i in range(len(raw_findings)):
            merged = {**raw_findings[i], **scored_findings[i]}
            final_findings.append(merged)

        for finding in final_findings:
            # remove scanner before saving to DB
            finding_copy = finding.copy()
            finding_copy.pop("scanner", None)

            crud.create_vulnerability(db, scan_id=scan_id, **finding_copy)
        
        generate_report_for_scan(scan_id, db)

        crud.update_scan_status(db, scan_id, "completed")

    except Exception as e:
        logger.error(f"Scan {scan_id} failed: {str(e)}", exc_info=True)
        crud.update_scan_status(db, scan_id, "failed")

    finally:
        db.close()

def safe_run(func, *args, retries=2):
    for i in range(retries):
        try:
            return func(*args)
        except Exception as e:
            logger.warning(f"Retry {i+1} failed: {e}")
    return []


def _execute_scanners(target: str, scan_type: str) -> list:
    try:
        from scanner.scanner_manager import ScannerManager

        manager = ScannerManager(target)
        findings = manager.run()

        return findings

    except Exception as e:
        logger.error(f"Scanner execution failed: {e}")
        return []


def generate_report_for_scan(scan_id: str, db):
    from db import crud
    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas
    import datetime
    os.makedirs(settings.REPORT_OUTPUT_DIR, exist_ok=True)
    report_path = os.path.join(settings.REPORT_OUTPUT_DIR, f"{scan_id}.pdf")
    scan = crud.get_scan_by_id(db, scan_id)
    vulns = crud.get_vulnerabilities_by_scan(db, scan_id)
    c = canvas.Canvas(report_path, pagesize=letter)
    width, height = letter
    c.setFont("Helvetica-Bold", 18)
    c.drawString(50, height - 50, "Vulnerability Scan Report")
    c.setFont("Helvetica", 11)
    c.drawString(50, height - 80, f"Scan ID: {scan_id}")
    c.drawString(50, height - 100, f"Target: {scan.target if scan else 'N/A'}")
    c.drawString(50, height - 120, f"Generated: {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}")
    c.drawString(50, height - 150, f"Total Vulnerabilities: {len(vulns)}")
    y = height - 180
    for v in vulns:
        if y < 100:
            c.showPage()
            y = height - 50
        c.setFont("Helvetica-Bold", 11)
        c.drawString(50, y, f"[{v.severity.upper()}] {v.name}")
        y -= 18
        c.setFont("Helvetica", 10)
        c.drawString(60, y, f"Description: {v.description[:100]}")
        y -= 15
        c.drawString(60, y, f"Recommendation: {v.recommendation[:100]}")
        y -= 20
    c.save()
    logger.info(f"Report generated at {report_path}")
    from db.database import SessionLocal
    from db import crud

    db = SessionLocal()

    try:
        scan = crud.get_scan_by_id(db, scan_id)
        if scan:
            scan.status = "completed"   # ✅ IMPORTANT
            db.commit()
    finally:
        db.close()
# This file is responsible for scan orchestration and report generation, used for managing scan lifecycle in background threads and coordinating scanner modules, and contains start_scan_task, _run_scan, _execute_scanners, and generate_report_for_scan functions.