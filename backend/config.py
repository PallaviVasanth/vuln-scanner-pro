from pydantic_settings import BaseSettings
from typing import Optional

class Settings(BaseSettings):
    APP_NAME: str = "Automated Vulnerability Scanner"
    DEBUG: bool = False
    DATABASE_URL: str = "postgresql://vuln_user:secure123@localhost:5432/vuln_scanner"
    SECRET_KEY: str = "supersecretkey"
    MAX_SCAN_TIMEOUT: int = 300
    REPORT_OUTPUT_DIR: str = "reports"
    ML_MODEL_PATH: Optional[str] = "models/threat_model.pkl"
    ALLOWED_SCAN_PORTS: str = "22,80,443,8080,8443,3306,5432"
    LOG_LEVEL: str = "INFO"

    class Config:
        env_file = ".env"

settings = Settings()

# This file is responsible for application configuration management, used for centralizing all environment-based settings via Pydantic BaseSettings, and contains database URL, app metadata, ML model path, scan limits, and log level.