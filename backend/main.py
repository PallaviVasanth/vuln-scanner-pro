from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from routes.scan_routes import router as scan_router
from routes.result_routes import router as result_router
from routes.report_routes import router as report_router

from db.database import engine, SessionLocal
from db import models
from db.crud import get_dashboard_summary

from logging_config import setup_logging

setup_logging()
models.Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Automated Vulnerability Scanner API",
    version="1.0.0",
    description="AI-powered vulnerability scanner backend"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # allow frontend
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
        
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True
    )
# This file is responsible for application entry point, used for initializing FastAPI app with all routers and middleware, and contains app setup, CORS config, router registration, and DB table creation.