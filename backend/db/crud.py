import logging
from datetime import datetime
from sqlalchemy.orm import Session
from sqlalchemy import func
from db.models import Scan, Vulnerability
from db import models

logger = logging.getLogger(__name__)

def create_scan(db: Session, target: str, scan_type: str = "web") -> Scan:
    scan = Scan(target=target, scan_type=scan_type, status="pending")
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan

def get_scan_by_id(db: Session, scan_id: str):
    return db.query(Scan).filter(Scan.id == scan_id).first()

def update_scan_status(db, scan_id: str, status: str):
    scan = db.query(models.Scan).filter(models.Scan.id == scan_id).first()
    if scan:
        scan.status = status
        db.commit()
        db.refresh(scan)
    return scan

def create_vulnerability(db: Session, scan_id: str, name: str, description: str,
                          severity: str, evidence: str, recommendation: str, 
                          cvss_score: float,
                          ml_prediction: str = "Unknown",
                          ml_confidence: float = 0.0):
    vuln = Vulnerability(
        scan_id=scan_id,
        name=name,
        description=description,
        severity=severity,
        evidence=evidence,
        recommendation=recommendation,
        cvss_score=cvss_score,
        ml_prediction=ml_prediction,
        ml_confidence=ml_confidence,
    )
    db.add(vuln)
    db.commit()
    db.refresh(vuln)
    return vuln

def get_vulnerabilities_by_scan(db: Session, scan_id: str):
    return db.query(Vulnerability).filter(Vulnerability.scan_id == scan_id).all()

def get_risk_summary(db: Session, scan_id: str) -> dict:
    rows = (
        db.query(Vulnerability.severity, func.count(Vulnerability.id))
        .filter(Vulnerability.scan_id == scan_id)
        .group_by(Vulnerability.severity)
        .all()
    )
    return {severity: count for severity, count in rows}

def get_dashboard_summary(db: Session) -> dict:
    total_scans = db.query(func.count(Scan.id)).scalar()
    completed = db.query(func.count(Scan.id)).filter(Scan.status == "completed").scalar()
    running = db.query(func.count(Scan.id)).filter(Scan.status == "running").scalar()
    failed = db.query(func.count(Scan.id)).filter(Scan.status == "failed").scalar()
    total_vulns = db.query(func.count(Vulnerability.id)).scalar()
    severity_breakdown = (
        db.query(Vulnerability.severity, func.count(Vulnerability.id))
        .group_by(Vulnerability.severity)
        .all()
    )
    recent_scans = (
        db.query(Scan)
        .order_by(Scan.created_at.desc())
        .limit(5)
        .all()
    )
    return {
        "total_scans": total_scans,
        "completed_scans": completed,
        "running_scans": running,
        "failed_scans": failed,
        "total_vulnerabilities": total_vulns,
        "severity_breakdown": {s: c for s, c in severity_breakdown},
        "recent_scans": [
            {"scan_id": s.id, "target": s.target, "status": s.status, "created_at": str(s.created_at)}
            for s in recent_scans
        ]
    }

# This file is responsible for all database CRUD operations, used for abstracting all read/write interactions with Scan and Vulnerability tables, and contains create_scan, get_scan_by_id, update_scan_status, create_vulnerability, get_vulnerabilities_by_scan, get_risk_summary, and get_dashboard_summary functions.