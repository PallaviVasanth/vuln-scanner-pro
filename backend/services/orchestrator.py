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

def _get_recommendation(vuln_type: str) -> str:
    recommendations = {
        "Security Misconfiguration": "Add missing security headers to your web server configuration.",
        "Open Port": "Close unnecessary open ports and restrict access with firewall rules.",
        "Port Scan": "Ensure firewall rules are properly configured.",
        "SQL Injection": "Use parameterized queries and input validation.",
        "Cross-Site Scripting (XSS)": "Sanitize user input and implement Content Security Policy.",
        "CSRF Vulnerability": "Implement CSRF tokens on all state-changing requests.",
        "Open Redirect": "Validate and whitelist redirect URLs.",
        "Directory Traversal": "Sanitize file path inputs and restrict directory access.",
    }
    for key in recommendations:
        if key.lower() in vuln_type.lower():
            return recommendations[key]
    return "Review and remediate this vulnerability following security best practices."

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
    # Map scanner's 'type' field to 'name' since scanner doesn't set 'name'
            vuln_name = (
                finding.get("name")
                or finding.get("type")
                or "Unknown Vulnerability"
            )

    # Build description from available fields
            description = finding.get("description") or (
                f"{vuln_name} detected at {finding.get('endpoint', 'unknown endpoint')}"
            )

    # Build recommendation from vuln type
            recommendation = finding.get("recommendation") or _get_recommendation(vuln_name)

            crud.create_vulnerability(
                db,
                scan_id=scan_id,
                name=str(vuln_name),
                description=str(description),
                severity=str(finding.get("severity", "low")),
                evidence=str(finding.get("evidence", "")),
                recommendation=str(recommendation),
                cvss_score=float(finding.get("cvss_score", 0.0)),
                ml_prediction=str(finding.get("prediction", "Unknown")),
                ml_confidence=float(finding.get("confidence", 0.0)),
            )
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