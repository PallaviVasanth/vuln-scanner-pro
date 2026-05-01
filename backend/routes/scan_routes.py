import logging
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from db.database import get_db
from db import crud
from schemas.request_schemas import ScanRequest
from schemas.response_schemas import ScanStartResponse, ScanStatusResponse
from services.orchestrator import start_scan_task
from services.validator import validate_target

logger = logging.getLogger(__name__)
router = APIRouter()

@router.post("/start", response_model=ScanStartResponse)
def start_scan(payload: ScanRequest, db: Session = Depends(get_db)):
    if not validate_target(payload.target):
        raise HTTPException(status_code=400, detail="Invalid target format.")
    scan = crud.create_scan(db, target=payload.target, scan_type=payload.scan_type)
    logger.info(f"Scan created: {scan.id} for target {payload.target}")
    start_scan_task(scan.id, payload.target, payload.scan_type)
    return ScanStartResponse(scan_id=scan.id, status=scan.status, message="Scan started successfully.")

@router.get("/status/{scan_id}", response_model=ScanStatusResponse)
def get_scan_status(scan_id: str, db: Session = Depends(get_db)):
    scan = crud.get_scan_by_id(db, scan_id)

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    return ScanStatusResponse(
        scan_id=scan.id,
        status=scan.status,
        target=scan.target,
        created_at=str(scan.created_at),
        completed_at=str(scan.completed_at) if scan.completed_at else None
    )
# This file is responsible for scan management routes, used for handling POST /scan/start and GET /scan/status/{scan_id} endpoints, and contains start_scan and get_scan_status route handlers with DB interaction and orchestrator trigger.