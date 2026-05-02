import os
import logging
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from backend.db.database import get_db
from backend.db import crud
from backend.config import settings

logger = logging.getLogger(__name__)
router = APIRouter()

@router.get("/download/{scan_id}")
def download_report(scan_id: str, db: Session = Depends(get_db)):
    scan = crud.get_scan_by_id(db, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found.")
    if scan.status != "completed":
        raise HTTPException(status_code=400, detail="Report not available until scan completes.")
    report_path = os.path.join(settings.REPORT_OUTPUT_DIR, f"{scan_id}.pdf")
    if not os.path.exists(report_path):
        from services.orchestrator import generate_report_for_scan
        generate_report_for_scan(scan_id, db)
    if not os.path.exists(report_path):
        raise HTTPException(status_code=500, detail="Report generation failed.")
    logger.info(f"Serving report for scan {scan_id}")
    return FileResponse(
        path=report_path,
        media_type="application/pdf",
        filename=f"vulnerability_report_{scan_id}.pdf"
    )

# This file is responsible for report download routes, used for handling GET /report/download/{scan_id} endpoint, and contains download_report handler that serves generated PDF reports or triggers on-demand generation.