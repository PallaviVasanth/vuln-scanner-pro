from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.routes.scan_routes import router as scan_router
from backend.routes.result_routes import router as result_router
from backend.routes.report_routes import router as report_router

from backend.db.database import engine, SessionLocal
from backend.db import models
from backend.db.crud import get_dashboard_summary

from backend.logging_config import setup_logging

setup_logging()
models.Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Automated Vulnerability Scanner API",
    version="1.0.0",
    description="AI-powered vulnerability scanner backend"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(scan_router, prefix="/scan", tags=["Scan"])
app.include_router(result_router, prefix="/scan", tags=["Results"])
app.include_router(report_router, prefix="/report", tags=["Report"])

@app.get("/dashboard/summary", tags=["Dashboard"])
def dashboard_summary():
    db = SessionLocal()
    try:
        return get_dashboard_summary(db)
    finally:
        db.close()

# This file is responsible for application entry point, used for initializing FastAPI app with all routers and middleware, and contains app setup, CORS config, router registration, and DB table creation.