"""
Audit Database Operations.

Provides high-level database operations for device and event management.
Implements append-only audit logging with integrity verification.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Generator, Sequence

from sqlalchemy import create_engine, event, func, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from sentinel.audit.models import (
    APPEND_ONLY_TRIGGER,
    Base,
    Device,
    Event,
    EventType,
    TrustLevel,
)


logger = logging.getLogger(__name__)


# Enable SQLite foreign keys
@event.listens_for(Engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    """Enable foreign key support for SQLite."""
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


class AuditDatabase:
    """
    High-level interface for audit database operations.

    Provides CRUD operations for devices and events, with support
    for querying, filtering, and maintaining audit integrity.
    """

    def __init__(
        self,
        db_path: str | Path,
        wal_mode: bool = True,
        create_if_missing: bool = True,
    ) -> None:
        """
        Initialize the audit database.

        Args:
            db_path: Path to SQLite database file
            wal_mode: Enable WAL mode for better concurrency
            create_if_missing: Create database if it doesn't exist
        """
        self.db_path = Path(db_path)

        # Ensure parent directory exists
        if create_if_missing:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)

        # Create engine
        self.engine = create_engine(
            f"sqlite:///{self.db_path}",
            echo=False,
            pool_pre_ping=True,
        )

        # Create session factory
        self.Session = sessionmaker(bind=self.engine)

        # Initialize schema if needed
        if create_if_missing or not self.db_path.exists():
            self._init_schema()

        # Enable WAL mode
        if wal_mode:
            with self.engine.connect() as conn:
                conn.execute(text("PRAGMA journal_mode=WAL"))
                conn.commit()

    def _init_schema(self) -> None:
        """Initialize database schema and triggers."""
        Base.metadata.create_all(self.engine)

        # Add append-only triggers
        with self.engine.connect() as conn:
            for statement in APPEND_ONLY_TRIGGER.split(";"):
                statement = statement.strip()
                if statement:
                    try:
                        conn.execute(text(statement))
                    except Exception as e:
                        # Trigger may already exist
                        logger.debug("Trigger creation: %s", e)
            conn.commit()

        logger.info("Database schema initialized: %s", self.db_path)

    @contextmanager
    def session(self) -> Generator[Session, None, None]:
        """
        Get a database session context manager.

        Yields:
            SQLAlchemy Session object
        """
        session = self.Session()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    # =========================================================================
    # Device Operations
    # =========================================================================

    def get_device(self, fingerprint: str) -> Device | None:
        """
        Get a device by fingerprint.

        Args:
            fingerprint: Device fingerprint

        Returns:
            Device or None if not found
        """
        with self.session() as session:
            device = session.query(Device).filter(
                Device.fingerprint == fingerprint
            ).first()
            if device:
                session.expunge(device)
            return device

    def get_device_by_vid_pid(self, vid: str, pid: str) -> list[Device]:
        """
        Get all devices matching VID:PID.

        Args:
            vid: Vendor ID
            pid: Product ID

        Returns:
            List of matching devices
        """
        with self.session() as session:
            devices = session.query(Device).filter(
                Device.vid == vid.lower(),
                Device.pid == pid.lower(),
            ).all()
            for d in devices:
                session.expunge(d)
            return devices

    def get_all_devices(
        self,
        trust_level: TrustLevel | str | None = None,
        limit: int | None = None,
        offset: int = 0,
    ) -> list[Device]:
        """
        Get all devices, optionally filtered by trust level.

        Args:
            trust_level: Filter by trust level
            limit: Maximum number of results
            offset: Number of results to skip

        Returns:
            List of devices
        """
        with self.session() as session:
            query = session.query(Device)

            if trust_level is not None:
                if isinstance(trust_level, TrustLevel):
                    trust_level = trust_level.value
                query = query.filter(Device.trust_level == trust_level)

            query = query.order_by(Device.last_seen.desc())

            if offset:
                query = query.offset(offset)
            if limit:
                query = query.limit(limit)

            devices = query.all()
            for d in devices:
                session.expunge(d)
            return devices

    def add_device(
        self,
        fingerprint: str,
        vid: str,
        pid: str,
        manufacturer: str | None = None,
        product: str | None = None,
        serial: str | None = None,
        trust_level: TrustLevel | str = TrustLevel.UNKNOWN,
        notes: str | None = None,
    ) -> Device:
        """
        Add a new device or update existing.

        Args:
            fingerprint: Device fingerprint
            vid: Vendor ID
            pid: Product ID
            manufacturer: Manufacturer string
            product: Product string
            serial: Serial number
            trust_level: Initial trust level
            notes: Optional notes

        Returns:
            Created or updated Device
        """
        if isinstance(trust_level, TrustLevel):
            trust_level = trust_level.value

        with self.session() as session:
            device = session.query(Device).filter(
                Device.fingerprint == fingerprint
            ).first()

            if device is None:
                device = Device(
                    fingerprint=fingerprint,
                    vid=vid.lower(),
                    pid=pid.lower(),
                    manufacturer=manufacturer,
                    product=product,
                    serial=serial,
                    trust_level=trust_level,
                    notes=notes,
                )
                session.add(device)
                logger.info("Added new device: %s", fingerprint)
            else:
                # Update last seen
                device.last_seen = datetime.now(timezone.utc)
                if manufacturer and not device.manufacturer:
                    device.manufacturer = manufacturer
                if product and not device.product:
                    device.product = product
                if serial and not device.serial:
                    device.serial = serial
                logger.debug("Updated device: %s", fingerprint)

            session.commit()
            session.refresh(device)
            session.expunge(device)
            return device

    def update_trust_level(
        self,
        fingerprint: str,
        trust_level: TrustLevel | str,
    ) -> bool:
        """
        Update device trust level.

        Args:
            fingerprint: Device fingerprint
            trust_level: New trust level

        Returns:
            True if device was found and updated
        """
        if isinstance(trust_level, TrustLevel):
            trust_level = trust_level.value

        with self.session() as session:
            device = session.query(Device).filter(
                Device.fingerprint == fingerprint
            ).first()

            if device is None:
                return False

            device.trust_level = trust_level
            logger.info(
                "Updated trust level for %s: %s",
                fingerprint, trust_level
            )
            return True

    def device_exists(self, fingerprint: str) -> bool:
        """Check if device exists in database."""
        with self.session() as session:
            return session.query(Device).filter(
                Device.fingerprint == fingerprint
            ).count() > 0

    def count_devices(self, trust_level: TrustLevel | str | None = None) -> int:
        """
        Count devices in database.

        Args:
            trust_level: Optional filter by trust level

        Returns:
            Number of devices
        """
        with self.session() as session:
            query = session.query(func.count(Device.id))
            if trust_level is not None:
                if isinstance(trust_level, TrustLevel):
                    trust_level = trust_level.value
                query = query.filter(Device.trust_level == trust_level)
            return query.scalar()

    def list_devices(
        self,
        filters: dict[str, Any] | None = None,
        offset: int = 0,
        limit: int | None = 50,
    ) -> tuple[list[Device], int]:
        """
        List devices with filters and pagination.

        Args:
            filters: Dictionary of filter conditions (trust_level, etc.)
            offset: Number of results to skip
            limit: Maximum number of results

        Returns:
            Tuple of (list of devices, total count)
        """
        filters = filters or {}

        with self.session() as session:
            query = session.query(Device)

            # Apply filters
            if "trust_level" in filters:
                query = query.filter(Device.trust_level == filters["trust_level"])
            if "vid" in filters:
                query = query.filter(Device.vid == filters["vid"].lower())
            if "pid" in filters:
                query = query.filter(Device.pid == filters["pid"].lower())
            if "manufacturer" in filters:
                query = query.filter(
                    Device.manufacturer.ilike(f"%{filters['manufacturer']}%")
                )
            if "product" in filters:
                query = query.filter(
                    Device.product.ilike(f"%{filters['product']}%")
                )

            # Get total count before pagination
            total = query.count()

            # Apply ordering and pagination
            query = query.order_by(Device.last_seen.desc())
            if offset:
                query = query.offset(offset)
            if limit:
                query = query.limit(limit)

            devices = query.all()
            for d in devices:
                session.expunge(d)

            return devices, total

    def update_device_notes(self, fingerprint: str, notes: str | None) -> bool:
        """
        Update device notes.

        Args:
            fingerprint: Device fingerprint
            notes: New notes value

        Returns:
            True if device was found and updated
        """
        with self.session() as session:
            device = session.query(Device).filter(
                Device.fingerprint == fingerprint
            ).first()

            if device is None:
                return False

            device.notes = notes
            logger.info("Updated notes for device %s", fingerprint)
            return True

    # =========================================================================
    # Event Operations
    # =========================================================================

    def log_event(
        self,
        device_fingerprint: str,
        event_type: EventType | str,
        policy_rule: str | None = None,
        llm_analysis: str | None = None,
        risk_score: int | None = None,
        verdict: str | None = None,
        raw_descriptor: dict | str | None = None,
    ) -> Event:
        """
        Log a new event (append-only).

        Args:
            device_fingerprint: Associated device fingerprint
            event_type: Type of event
            policy_rule: Policy rule that triggered
            llm_analysis: LLM analysis text
            risk_score: Risk score (0-100)
            verdict: Final verdict
            raw_descriptor: Raw descriptor data (dict or JSON string)

        Returns:
            Created Event
        """
        if isinstance(event_type, EventType):
            event_type = event_type.value

        if isinstance(raw_descriptor, dict):
            raw_descriptor = json.dumps(raw_descriptor)

        with self.session() as session:
            # Ensure device exists
            device = session.query(Device).filter(
                Device.fingerprint == device_fingerprint
            ).first()

            if device is None:
                raise ValueError(f"Device not found: {device_fingerprint}")

            # Update device last_seen
            device.last_seen = datetime.now(timezone.utc)

            event = Event(
                device_fingerprint=device_fingerprint,
                event_type=event_type,
                policy_rule=policy_rule,
                llm_analysis=llm_analysis,
                risk_score=risk_score,
                verdict=verdict,
                raw_descriptor=raw_descriptor,
            )
            session.add(event)
            session.commit()
            session.refresh(event)

            logger.debug(
                "Logged event: %s %s (verdict=%s)",
                event_type, device_fingerprint, verdict
            )

            session.expunge(event)
            return event

    def get_events(
        self,
        device_fingerprint: str | None = None,
        event_type: EventType | str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int | None = 100,
        offset: int = 0,
    ) -> list[Event]:
        """
        Query events with filters.

        Args:
            device_fingerprint: Filter by device
            event_type: Filter by event type
            since: Events after this time
            until: Events before this time
            limit: Maximum results
            offset: Skip results

        Returns:
            List of matching events
        """
        with self.session() as session:
            query = session.query(Event)

            if device_fingerprint:
                query = query.filter(Event.device_fingerprint == device_fingerprint)
            if event_type:
                if isinstance(event_type, EventType):
                    event_type = event_type.value
                query = query.filter(Event.event_type == event_type)
            if since:
                query = query.filter(Event.timestamp >= since)
            if until:
                query = query.filter(Event.timestamp <= until)

            query = query.order_by(Event.timestamp.desc())

            if offset:
                query = query.offset(offset)
            if limit:
                query = query.limit(limit)

            events = query.all()
            for e in events:
                session.expunge(e)
            return events

    def get_recent_events(
        self,
        hours: int = 24,
        limit: int = 100,
    ) -> list[Event]:
        """
        Get events from the last N hours.

        Args:
            hours: Number of hours to look back
            limit: Maximum results

        Returns:
            List of recent events
        """
        since = datetime.now(timezone.utc) - timedelta(hours=hours)
        return self.get_events(since=since, limit=limit)

    def count_events(
        self,
        device_fingerprint: str | None = None,
        event_type: EventType | str | None = None,
        since: datetime | None = None,
    ) -> int:
        """
        Count events with optional filters.

        Args:
            device_fingerprint: Filter by device
            event_type: Filter by event type
            since: Events after this time

        Returns:
            Number of matching events
        """
        with self.session() as session:
            query = session.query(func.count(Event.id))

            if device_fingerprint:
                query = query.filter(Event.device_fingerprint == device_fingerprint)
            if event_type:
                if isinstance(event_type, EventType):
                    event_type = event_type.value
                query = query.filter(Event.event_type == event_type)
            if since:
                query = query.filter(Event.timestamp >= since)

            return query.scalar()

    def list_events(
        self,
        filters: dict[str, Any] | None = None,
        offset: int = 0,
        limit: int | None = 50,
    ) -> tuple[list[Event], int]:
        """
        List events with filters and pagination.

        Args:
            filters: Dictionary of filter conditions
            offset: Number of results to skip
            limit: Maximum number of results

        Returns:
            Tuple of (list of events, total count)
        """
        filters = filters or {}

        with self.session() as session:
            query = session.query(Event)

            # Apply filters
            if "device_fingerprint" in filters:
                query = query.filter(
                    Event.device_fingerprint == filters["device_fingerprint"]
                )
            if "event_type" in filters:
                query = query.filter(Event.event_type == filters["event_type"])
            if "since" in filters:
                query = query.filter(Event.timestamp >= filters["since"])
            if "until" in filters:
                query = query.filter(Event.timestamp <= filters["until"])
            if "min_risk_score" in filters:
                query = query.filter(Event.risk_score >= filters["min_risk_score"])
            if "verdict" in filters:
                query = query.filter(Event.verdict == filters["verdict"])

            # Get total count before pagination
            total = query.count()

            # Apply ordering and pagination
            query = query.order_by(Event.timestamp.desc())
            if offset:
                query = query.offset(offset)
            if limit:
                query = query.limit(limit)

            events = query.all()
            for e in events:
                session.expunge(e)

            return events, total

    def get_event(self, event_id: int) -> Event | None:
        """
        Get a single event by ID.

        Args:
            event_id: Event ID

        Returns:
            Event or None if not found
        """
        with self.session() as session:
            event = session.query(Event).filter(Event.id == event_id).first()
            if event:
                session.expunge(event)
            return event

    def get_device_events(
        self,
        fingerprint: str,
        limit: int = 10,
    ) -> list[dict[str, Any]]:
        """
        Get recent events for a specific device.

        Args:
            fingerprint: Device fingerprint
            limit: Maximum number of events

        Returns:
            List of event dictionaries with relevant fields
        """
        with self.session() as session:
            events = (
                session.query(Event)
                .filter(Event.device_fingerprint == fingerprint)
                .order_by(Event.timestamp.desc())
                .limit(limit)
                .all()
            )

            return [
                {
                    "timestamp": e.timestamp.isoformat() if e.timestamp else None,
                    "event_type": e.event_type,
                    "verdict": e.verdict,
                    "risk_score": e.risk_score,
                }
                for e in events
            ]

    def get_events_by_vid_pid(
        self,
        vid: str,
        pid: str,
        limit: int = 5,
    ) -> list[dict[str, Any]]:
        """
        Get recent events for devices matching VID:PID.

        Args:
            vid: Vendor ID
            pid: Product ID
            limit: Maximum number of events

        Returns:
            List of event dictionaries
        """
        with self.session() as session:
            # Get fingerprints for matching devices
            devices = (
                session.query(Device.fingerprint)
                .filter(Device.vid == vid.lower(), Device.pid == pid.lower())
                .all()
            )
            fingerprints = [d.fingerprint for d in devices]

            if not fingerprints:
                return []

            events = (
                session.query(Event)
                .filter(Event.device_fingerprint.in_(fingerprints))
                .order_by(Event.timestamp.desc())
                .limit(limit)
                .all()
            )

            return [
                {
                    "timestamp": e.timestamp.isoformat() if e.timestamp else None,
                    "event_type": e.event_type,
                    "verdict": e.verdict,
                    "risk_score": e.risk_score,
                    "device_fingerprint": e.device_fingerprint,
                }
                for e in events
            ]

    # =========================================================================
    # Statistics
    # =========================================================================

    def get_statistics(self) -> dict[str, Any]:
        """
        Get database statistics.

        Returns:
            Dictionary with statistics
        """
        with self.session() as session:
            total_devices = session.query(func.count(Device.id)).scalar()
            total_events = session.query(func.count(Event.id)).scalar()

            # Trust level breakdown
            trust_counts = {}
            for level in TrustLevel:
                count = session.query(func.count(Device.id)).filter(
                    Device.trust_level == level.value
                ).scalar()
                trust_counts[level.value] = count

            # Event type breakdown
            event_counts = {}
            for etype in EventType:
                count = session.query(func.count(Event.id)).filter(
                    Event.event_type == etype.value
                ).scalar()
                event_counts[etype.value] = count

            # Recent activity
            last_24h = datetime.now(timezone.utc) - timedelta(hours=24)
            recent_events = session.query(func.count(Event.id)).filter(
                Event.timestamp >= last_24h
            ).scalar()

            # Blocked in last 24h
            blocked_24h = session.query(func.count(Event.id)).filter(
                Event.timestamp >= last_24h,
                Event.event_type == EventType.BLOCKED.value,
            ).scalar()

            return {
                "total_devices": total_devices,
                "total_events": total_events,
                "trust_levels": trust_counts,
                "event_types": event_counts,
                "events_last_24h": recent_events,
                "blocked_last_24h": blocked_24h,
                "database_size_bytes": self.db_path.stat().st_size if self.db_path.exists() else 0,
            }

    def get_system_statistics(self) -> dict[str, Any]:
        """
        Get system-wide statistics for API.

        Returns:
            Dictionary with system statistics
        """
        with self.session() as session:
            total_devices = session.query(func.count(Device.id)).scalar()
            total_events = session.query(func.count(Event.id)).scalar()

            # Trust level counts
            trusted_devices = session.query(func.count(Device.id)).filter(
                Device.trust_level == TrustLevel.TRUSTED.value
            ).scalar()
            blocked_devices = session.query(func.count(Device.id)).filter(
                Device.trust_level == TrustLevel.BLOCKED.value
            ).scalar()
            unknown_devices = session.query(func.count(Device.id)).filter(
                Device.trust_level == TrustLevel.UNKNOWN.value
            ).scalar()

            # Time-based statistics
            now = datetime.now(timezone.utc)
            today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
            week_start = today_start - timedelta(days=now.weekday())

            events_today = session.query(func.count(Event.id)).filter(
                Event.timestamp >= today_start
            ).scalar()

            events_this_week = session.query(func.count(Event.id)).filter(
                Event.timestamp >= week_start
            ).scalar()

            blocked_today = session.query(func.count(Event.id)).filter(
                Event.timestamp >= today_start,
                Event.event_type == EventType.BLOCKED.value,
            ).scalar()

            allowed_today = session.query(func.count(Event.id)).filter(
                Event.timestamp >= today_start,
                Event.event_type == EventType.ALLOWED.value,
            ).scalar()

            # Average risk score
            avg_risk = session.query(func.avg(Event.risk_score)).filter(
                Event.risk_score.isnot(None)
            ).scalar()

            return {
                "total_devices": total_devices,
                "trusted_devices": trusted_devices,
                "blocked_devices": blocked_devices,
                "unknown_devices": unknown_devices,
                "total_events": total_events,
                "events_today": events_today,
                "events_this_week": events_this_week,
                "average_risk_score": round(avg_risk, 1) if avg_risk else None,
                "blocked_today": blocked_today,
                "allowed_today": allowed_today,
            }

    def get_device_statistics(self, fingerprint: str) -> dict[str, Any]:
        """
        Get statistics for a specific device.

        Args:
            fingerprint: Device fingerprint

        Returns:
            Dictionary with device statistics
        """
        with self.session() as session:
            device = session.query(Device).filter(
                Device.fingerprint == fingerprint
            ).first()

            if device is None:
                return {}

            # Count events by type
            event_count = session.query(func.count(Event.id)).filter(
                Event.device_fingerprint == fingerprint
            ).scalar()

            times_blocked = session.query(func.count(Event.id)).filter(
                Event.device_fingerprint == fingerprint,
                Event.event_type == EventType.BLOCKED.value,
            ).scalar()

            times_allowed = session.query(func.count(Event.id)).filter(
                Event.device_fingerprint == fingerprint,
                Event.event_type == EventType.ALLOWED.value,
            ).scalar()

            # Average risk score for this device
            avg_risk = session.query(func.avg(Event.risk_score)).filter(
                Event.device_fingerprint == fingerprint,
                Event.risk_score.isnot(None),
            ).scalar()

            return {
                "event_count": event_count,
                "times_blocked": times_blocked,
                "times_allowed": times_allowed,
                "average_risk_score": round(avg_risk, 1) if avg_risk else None,
            }

    # =========================================================================
    # Export & Backup
    # =========================================================================

    def export_to_json(self, output_path: str | Path) -> None:
        """
        Export database to JSON file.

        Args:
            output_path: Path to output file
        """
        with self.session() as session:
            devices = session.query(Device).all()
            events = session.query(Event).all()

            data = {
                "exported_at": datetime.now(timezone.utc).isoformat(),
                "devices": [d.to_dict() for d in devices],
                "events": [e.to_dict() for e in events],
            }

        with open(output_path, "w") as f:
            json.dump(data, f, indent=2)

        logger.info("Exported database to %s", output_path)

    def backup(self, backup_path: str | Path | None = None) -> Path:
        """
        Create a backup of the database.

        Args:
            backup_path: Path for backup file (auto-generated if None)

        Returns:
            Path to backup file
        """
        if backup_path is None:
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            backup_path = self.db_path.parent / f"{self.db_path.stem}_backup_{timestamp}.db"

        backup_path = Path(backup_path)

        # Use SQLite backup API for consistency
        with self.engine.connect() as conn:
            conn.execute(text("PRAGMA wal_checkpoint(TRUNCATE)"))
            conn.commit()

        shutil.copy2(self.db_path, backup_path)
        logger.info("Created backup: %s", backup_path)

        return backup_path

    def vacuum(self) -> None:
        """Optimize database by running VACUUM."""
        with self.engine.connect() as conn:
            conn.execute(text("VACUUM"))
            conn.commit()
        logger.info("Database vacuumed")

    # =========================================================================
    # Integrity Verification
    # =========================================================================

    def compute_integrity_hash(self) -> str:
        """
        Compute integrity hash of all events.

        Returns:
            SHA-256 hash of event data
        """
        with self.session() as session:
            events = session.query(Event).order_by(Event.id).all()

            hasher = hashlib.sha256()
            for event in events:
                data = f"{event.id}|{event.timestamp}|{event.device_fingerprint}|{event.event_type}"
                hasher.update(data.encode())

            return hasher.hexdigest()

    def verify_integrity(self, expected_hash: str | None = None) -> bool:
        """
        Verify database integrity.

        Args:
            expected_hash: Expected hash (if known)

        Returns:
            True if integrity check passes
        """
        # Run SQLite integrity check
        with self.engine.connect() as conn:
            result = conn.execute(text("PRAGMA integrity_check")).fetchone()
            if result[0] != "ok":
                logger.error("SQLite integrity check failed: %s", result[0])
                return False

        # Check event hash if provided
        if expected_hash:
            current_hash = self.compute_integrity_hash()
            if current_hash != expected_hash:
                logger.error("Event hash mismatch")
                return False

        return True

    def close(self) -> None:
        """Close database connections."""
        self.engine.dispose()


def create_database(db_path: str | Path) -> AuditDatabase:
    """
    Create and initialize a new audit database.

    Args:
        db_path: Path for database file

    Returns:
        Initialized AuditDatabase
    """
    return AuditDatabase(db_path, create_if_missing=True)
