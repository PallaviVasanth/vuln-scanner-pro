import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import uvicorn

from model import threat_model


# ─────────────────────────────────────────────
# Lifespan (replaces deprecated on_event)
# ─────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    # startup
    threat_model.load()
    print("🚀 ML Service ready on http://localhost:8001")
    yield
    # shutdown (nothing to clean up)


# ─────────────────────────────────────────────
# App setup
# ─────────────────────────────────────────────

app = FastAPI(
    title="ML Threat Prediction Service",
    description="AI layer for the Automated Vulnerability Scanner",
    version="1.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ─────────────────────────────────────────────
# Schemas — Pydantic V2 compatible
# ─────────────────────────────────────────────

class Features(BaseModel):
    payload:              str
    response_time:        int
    status_code:          int
    payload_reflected:    bool
    error_detected:       bool
    response_length_diff: int

    model_config = {
        "json_schema_extra": {
            "example": {
                "payload": "<script>alert(1)</script>",
                "response_time": 180,
                "status_code": 200,
                "payload_reflected": True,
                "error_detected": False,
                "response_length_diff": 120
            }
        }
    }

class PredictRequest(BaseModel):
    features: Features

class PredictResponse(BaseModel):
    prediction:    str
    confidence:    float
    is_vulnerable: bool


# ─────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────

@app.get("/health")
def health_check():
    """Dev 1 pings this to confirm ML service is up before a scan."""
    return {
        "status":       "healthy",
        "service":      "ml_service",
        "model_loaded": threat_model._loaded
    }


@app.post("/ml/predict", response_model=PredictResponse)
def predict(request: PredictRequest):
    """
    Main prediction endpoint — called by Dev 1 once per finding.

    POST /ml/predict
    {
        "features": {
            "payload": "...",
            "response_time": 180,
            "status_code": 200,
            "payload_reflected": true,
            "error_detected": false,
            "response_length_diff": 120
        }
    }
    """
    try:
        raw_finding = {
            "payload":              request.features.payload,
            "response_time":        request.features.response_time,
            "status_code":          request.features.status_code,
            "payload_reflected":    request.features.payload_reflected,
            "error_detected":       request.features.error_detected,
            "response_length_diff": request.features.response_length_diff,
        }

        result = threat_model.predict(raw_finding)
        return PredictResponse(**result)

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail={
                "error":         str(e),
                "prediction":    "Clean",
                "confidence":    0.0,
                "is_vulnerable": False
            }
        )


# ─────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────

if __name__ == "__main__":
    uvicorn.run(
        "api:app",
        host="0.0.0.0",
        port=8001,
        reload=True
    )