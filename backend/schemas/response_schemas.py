from pydantic import BaseModel
from typing import Optional, List, Dict, Any

class ScanStartResponse(BaseModel):
    scan_id: str
    status: str
    message: str

class ScanStatusResponse(BaseModel):
    scan_id: str
    status: str
    target: str
    created_at: str
    completed_at: Optional[str] = None

class VulnerabilityItem(BaseModel):
    id: str
    name: str
    description: str
    severity: str
    evidence: str
    recommendation: str
    cvss_score: float

class ScanResultResponse(BaseModel):
    scan_id: str
    target: str
    status: str
    total_vulnerabilities: int
    vulnerabilities: List[Dict[str, Any]]
    risk_summary: Dict[str, int]

# This file is responsible for outgoing response schema definitions, used for structuring and serializing API responses consistently using Pydantic, and contains ScanStartResponse, ScanStatusResponse, VulnerabilityItem, and ScanResultResponse models.