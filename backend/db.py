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

from config import logger, config, ADMIN_USERNAME, ADMIN_PASSWORD
from werkzeug.security import generate_password_hash
import uuid


"""
Database layer.
Provides SQLAlchemy engine/session and models for detections, feedback, and login attempts.
"""


_DB_DIR = os.path.dirname(os.path.abspath(__file__))
_DEFAULT_DB = f"sqlite:///{os.path.join(_DB_DIR, 'ids_local.db')}"

# Environment-driven database connection (Professional pattern instead of hardcoding)
DATABASE_URL = os.getenv("IDS_DATABASE_URL", _DEFAULT_DB)

_engine_kwargs = {"future": True}
if DATABASE_URL.startswith("sqlite"):
    _engine_kwargs["connect_args"] = {"check_same_thread": False}

engine = create_engine(DATABASE_URL, **_engine_kwargs)
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


class UserModel(Base):
    __tablename__ = "users"
    
    id = Column(String, primary_key=True, index=True)
    username = Column(String, unique=True, nullable=False, index=True)
    password_hash = Column(String, nullable=False)


def init_db() -> None:
    """Create database tables if they do not exist."""
    try:
        Base.metadata.create_all(bind=engine)
        logger.info("Database tables ensured/created successfully.")
        
        session = SessionLocal()
        admin_user = session.query(UserModel).filter(UserModel.username == ADMIN_USERNAME).first()
        if not admin_user:
            logger.info("Creating default admin user from config environment variables.")
            new_user = UserModel(
                id=str(uuid.uuid4()), 
                username=ADMIN_USERNAME, 
                password_hash=generate_password_hash(ADMIN_PASSWORD)
            )
            session.add(new_user)
            session.commit()
        session.close()

    except Exception as exc:
        logger.error(f"Failed to initialize database: {exc}")


def get_session():
    """Return a new SQLAlchemy session."""
    return SessionLocal()

