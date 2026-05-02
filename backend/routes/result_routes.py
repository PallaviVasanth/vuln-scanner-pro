import logging
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from backend.db.database import get_db
from backend.db import crud
from backend.schemas.response_schemas import ScanResultResponse

logger = logging.getLogger(__name__)
router = APIRouter()

@router.get("/result/{scan_id}", response_model=ScanResultResponse)
def get_scan_result(scan_id: str, db: Session = Depends(get_db)):
    scan = crud.get_scan_by_id(db, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found.")
    if scan.status not in ("completed", "failed"):
        raise HTTPException(status_code=202, detail="Scan still in progress.")
    vulnerabilities = crud.get_vulnerabilities_by_scan(db, scan_id)
    vuln_list = [
        {
            "id": str(v.id),
            "name": v.name,
            "description": v.description,
            "severity": v.severity,
            "evidence": v.evidence,
            "recommendation": v.recommendation,
            "cvss_score": v.cvss_score,
        }
        for v in vulnerabilities
    ]
    return ScanResultResponse(
        scan_id=scan_id,
        target=scan.target,
        status=scan.status,
        total_vulnerabilities=len(vuln_list),
        vulnerabilities=vuln_list,
        risk_summary=crud.get_risk_summary(db, scan_id)
    )

# This file is responsible for scan result retrieval routes, used for handling GET /scan/result/{scan_id} endpoint, and contains get_scan_result handler that fetches vulnerabilities and risk summary from the database.