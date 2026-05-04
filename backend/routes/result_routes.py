import logging
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from db.database import get_db
from db import crud
from schemas.response_schemas import ScanResultResponse

logger = logging.getLogger(__name__)
router = APIRouter()

@router.get("/result/{scan_id}")
def get_result(scan_id: str, db: Session = Depends(get_db)):
    try:
        scan = crud.get_scan_by_id(db, scan_id)
        if not scan:
            return {"status": "not_found", "vulnerabilities": []}

        vulnerabilities = crud.get_vulnerabilities_by_scan(db, scan_id)

        vuln_list = [
            {
                "type":           v.name,
                "severity":       v.severity,
                "description":    v.description,
                "evidence":       v.evidence,
                "recommendation": v.recommendation,
                "cvss_score":     v.cvss_score,
                "ml_prediction":  v.ml_prediction,
                "ml_confidence":  round(v.ml_confidence * 100, 1),
            }
            for v in vulnerabilities
        ]

        return {
            "status": scan.status,
            "vulnerabilities": vuln_list
        }
    except Exception as e:
        print("ERROR in result API:", str(e))
        return {"status": "error", "vulnerabilities": []}
# This file is responsible for scan result retrieval routes, used for handling GET /scan/result/{scan_id} endpoint, and contains get_scan_result handler that fetches vulnerabilities and risk summary from the database.