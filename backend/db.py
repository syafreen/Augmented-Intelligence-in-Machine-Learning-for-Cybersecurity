import os
from datetime import datetime

from sqlalchemy import (
    create_engine,
    Column,
    String,
    DateTime,
    Boolean,
    Float,
    JSON,
    func,
)
from sqlalchemy.orm import declarative_base, sessionmaker

from config import logger, config


"""
Database layer.
Provides SQLAlchemy engine/session and models for detections, feedback, and login attempts.
"""


DATABASE_URL = os.getenv(
    "IDS_DATABASE_URL",
    (
        config.get("database", {}) or {}
    ).get(
        "url",
        # Default local development DSN – override in env or config.yaml for real deployments
        "postgresql+psycopg2://ids_user:ids_password@localhost:5432/ids_db",
    ),
)


engine = create_engine(DATABASE_URL, future=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)

Base = declarative_base()


class DetectionModel(Base):
    __tablename__ = "detections"

    id = Column(String, primary_key=True, index=True)  # detection_id (UUID string)
    timestamp = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)
    prediction = Column(String, nullable=False, index=True)
    attack_type = Column(String, nullable=True, index=True)
    severity = Column(String, nullable=True, index=True)
    risk_score = Column(Float, nullable=True)
    combined_risk_score = Column(Float, nullable=True)
    ip_address = Column(String, nullable=True, index=True)

    # Full detection payload as JSON for maximum flexibility
    payload = Column(JSON, nullable=False)


class FeedbackModel(Base):
    __tablename__ = "feedback"

    id = Column(String, primary_key=True, index=True)  # feedback_id (UUID string)
    detection_id = Column(String, nullable=False, index=True)
    timestamp = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)
    label = Column(String, nullable=False)
    user = Column(String, nullable=True)

    payload = Column(JSON, nullable=False)


class LoginAttemptModel(Base):
    __tablename__ = "login_attempts"

    id = Column(String, primary_key=True, index=True)
    timestamp = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)
    username = Column(String, nullable=False, index=True)
    ip_address = Column(String, nullable=False, index=True)
    success = Column(Boolean, nullable=False, index=True)

    payload = Column(JSON, nullable=False)


def init_db() -> None:
    """Create database tables if they do not exist."""
    try:
        Base.metadata.create_all(bind=engine)
        logger.info("Database tables ensured/created successfully.")
    except Exception as exc:
        logger.error(f"Failed to initialize database: {exc}")


def get_session():
    """Return a new SQLAlchemy session."""
    return SessionLocal()

