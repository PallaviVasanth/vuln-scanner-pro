import uuid
from datetime import datetime
from sqlalchemy import Column, String, Float, DateTime, Text, ForeignKey
from sqlalchemy.orm import relationship
from db.database import Base

def generate_uuid():
    return str(uuid.uuid4())

class Scan(Base):
    __tablename__ = "scans"

    id = Column(String, primary_key=True, default=generate_uuid)
    target = Column(String, nullable=False)
    scan_type = Column(String, default="web")
    status = Column(String, default="pending")
    created_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    vulnerabilities = relationship("Vulnerability", back_populates="scan", cascade="all, delete-orphan")

class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(String, primary_key=True, default=generate_uuid)
    scan_id = Column(String, ForeignKey("scans.id"), nullable=False)
    name = Column(String, nullable=False)
    description = Column(Text, default="")
    severity = Column(String, default="low")
    evidence = Column(Text, default="")
    recommendation = Column(Text, default="")
    cvss_score = Column(Float, default=0.0)
    created_at = Column(DateTime, default=datetime.utcnow)
    scan = relationship("Scan", back_populates="vulnerabilities")

# This file is responsible for ORM model definitions, used for mapping Scan and Vulnerability entities to PostgreSQL tables via SQLAlchemy, and contains Scan and Vulnerability model classes with all columns and relationships.