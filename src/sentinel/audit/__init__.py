"""
Audit System - Layer 5.

Provides comprehensive logging, forensic data retention,
and persistent storage for devices and events.
"""

from sentinel.audit.database import AuditDatabase, create_database
from sentinel.audit.models import (
    Base,
    Device,
    Event,
    EventType,
    TrustLevel,
    init_db,
)
from sentinel.audit.schemas import (
    AnalysisRequest,
    AnalysisResponse,
    DatabaseStats,
    DeviceCreate,
    DeviceListResponse,
    DeviceResponse,
    DeviceUpdate,
    EventCreate,
    EventDetailResponse,
    EventListResponse,
    EventResponse,
    Verdict,
    device_to_response,
    event_to_response,
)

__all__ = [
    # Database
    "AuditDatabase",
    "create_database",
    # Models
    "Base",
    "Device",
    "Event",
    "EventType",
    "TrustLevel",
    "init_db",
    # Schemas
    "AnalysisRequest",
    "AnalysisResponse",
    "DatabaseStats",
    "DeviceCreate",
    "DeviceListResponse",
    "DeviceResponse",
    "DeviceUpdate",
    "EventCreate",
    "EventDetailResponse",
    "EventListResponse",
    "EventResponse",
    "Verdict",
    "device_to_response",
    "event_to_response",
]
