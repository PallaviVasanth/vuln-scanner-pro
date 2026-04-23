from pydantic import BaseModel, field_validator
from typing import Literal

class ScanRequest(BaseModel):
    target: str
    scan_type: Literal["web", "network", "full"] = "web"

    @field_validator("target")
    @classmethod
    def target_must_not_be_empty(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Target must not be empty.")
        return v

    @field_validator("scan_type")
    @classmethod
    def scan_type_must_be_valid(cls, v: str) -> str:
        allowed = {"web", "network", "full"}
        if v not in allowed:
            raise ValueError(f"scan_type must be one of {allowed}")
        return v

# This file is responsible for incoming request schema definitions, used for validating and parsing API request payloads using Pydantic, and contains ScanRequest model with target and scan_type fields and their validators.