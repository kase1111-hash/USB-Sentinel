"""
Audit database models.

SQLAlchemy ORM models for device and event tracking.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any


def _utc_now() -> datetime:
    """Get current UTC time (timezone-aware)."""
    return datetime.now(timezone.utc)

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    create_engine,
)
from sqlalchemy.orm import DeclarativeBase, relationship


class Base(DeclarativeBase):
    """Base class for all models."""

    pass


class TrustLevel(str, Enum):
    """Device trust levels."""

    UNKNOWN = "unknown"
    TRUSTED = "trusted"
    BLOCKED = "blocked"
    REVIEW = "review"


class EventType(str, Enum):
    """Event types for audit log."""

    CONNECT = "connect"
    DISCONNECT = "disconnect"
    ALLOWED = "allowed"
    BLOCKED = "blocked"
    SANDBOXED = "sandboxed"
    REVIEWED = "reviewed"


class Device(Base):
    """
    Known USB device record.

    Tracks devices by fingerprint with trust level and history.
    """

    __tablename__ = "devices"

    id = Column(Integer, primary_key=True)
    fingerprint = Column(String(64), unique=True, nullable=False, index=True)
    vid = Column(String(4), nullable=False)
    pid = Column(String(4), nullable=False)
    manufacturer = Column(String(256), nullable=True)
    product = Column(String(256), nullable=True)
    serial = Column(String(256), nullable=True)
    first_seen = Column(DateTime, default=_utc_now, nullable=False)
    last_seen = Column(DateTime, default=_utc_now, onupdate=_utc_now)
    trust_level = Column(String(16), default=TrustLevel.UNKNOWN.value, nullable=False)
    notes = Column(Text, nullable=True)

    # Relationships
    events = relationship("Event", back_populates="device")

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "fingerprint": self.fingerprint,
            "vid": self.vid,
            "pid": self.pid,
            "manufacturer": self.manufacturer,
            "product": self.product,
            "serial": self.serial,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "trust_level": self.trust_level,
            "notes": self.notes,
        }


class Event(Base):
    """
    Audit log event.

    Records all USB device events with full context.
    Append-only: no updates or deletes allowed.
    """

    __tablename__ = "events"

    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=_utc_now, nullable=False, index=True)
    device_fingerprint = Column(
        String(64),
        ForeignKey("devices.fingerprint"),
        nullable=False,
        index=True,
    )
    event_type = Column(String(16), nullable=False)
    policy_rule = Column(String(256), nullable=True)
    llm_analysis = Column(Text, nullable=True)
    risk_score = Column(Integer, nullable=True)
    verdict = Column(String(16), nullable=True)
    raw_descriptor = Column(Text, nullable=True)  # JSON blob

    # Relationships
    device = relationship("Device", back_populates="events")

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "device_fingerprint": self.device_fingerprint,
            "event_type": self.event_type,
            "policy_rule": self.policy_rule,
            "llm_analysis": self.llm_analysis,
            "risk_score": self.risk_score,
            "verdict": self.verdict,
        }


# SQL for append-only trigger (to be executed separately)
APPEND_ONLY_TRIGGER = """
CREATE TRIGGER IF NOT EXISTS no_delete_events
BEFORE DELETE ON events
BEGIN
    SELECT RAISE(ABORT, 'Deletion not permitted on audit log');
END;

CREATE TRIGGER IF NOT EXISTS no_update_events
BEFORE UPDATE ON events
BEGIN
    SELECT RAISE(ABORT, 'Updates not permitted on audit log');
END;
"""


def init_db(db_path: str) -> None:
    """
    Initialize database with schema.

    Args:
        db_path: Path to SQLite database file
    """
    engine = create_engine(f"sqlite:///{db_path}")
    Base.metadata.create_all(engine)

    # Add append-only triggers
    with engine.connect() as conn:
        for statement in APPEND_ONLY_TRIGGER.split(";"):
            statement = statement.strip()
            if statement:
                conn.execute(statement)
