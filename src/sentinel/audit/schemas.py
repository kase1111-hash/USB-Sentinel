"""
Pydantic Schemas for Audit Data.

Defines request/response models for API validation and serialization.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


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


class Verdict(str, Enum):
    """Analysis verdicts."""

    ALLOW = "allow"
    BLOCK = "block"
    SANDBOX = "sandbox"
    REVIEW = "review"


# =============================================================================
# Device Schemas
# =============================================================================


class DeviceBase(BaseModel):
    """Base device schema."""

    vid: str = Field(..., min_length=4, max_length=4, pattern=r"^[0-9a-fA-F]{4}$")
    pid: str = Field(..., min_length=4, max_length=4, pattern=r"^[0-9a-fA-F]{4}$")
    manufacturer: str | None = Field(None, max_length=256)
    product: str | None = Field(None, max_length=256)
    serial: str | None = Field(None, max_length=256)

    @field_validator("vid", "pid", mode="before")
    @classmethod
    def lowercase_hex(cls, v: str) -> str:
        """Normalize VID/PID to lowercase."""
        return v.lower() if v else v


class DeviceCreate(DeviceBase):
    """Schema for creating a new device."""

    fingerprint: str = Field(..., min_length=16, max_length=64)
    trust_level: TrustLevel = TrustLevel.UNKNOWN
    notes: str | None = None


class DeviceUpdate(BaseModel):
    """Schema for updating a device."""

    trust_level: TrustLevel | None = None
    notes: str | None = None
    manufacturer: str | None = None
    product: str | None = None


class DeviceResponse(DeviceBase):
    """Schema for device response."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    fingerprint: str
    first_seen: datetime
    last_seen: datetime | None
    trust_level: TrustLevel
    notes: str | None = None
    event_count: int | None = None

    @property
    def vid_pid(self) -> str:
        """Get VID:PID string."""
        return f"{self.vid}:{self.pid}"

    @property
    def display_name(self) -> str:
        """Get display name for device."""
        if self.product:
            return self.product
        if self.manufacturer:
            return f"{self.manufacturer} Device"
        return f"USB Device {self.vid}:{self.pid}"


class DeviceListResponse(BaseModel):
    """Schema for device list response."""

    devices: list[DeviceResponse]
    total: int
    limit: int
    offset: int


# =============================================================================
# Event Schemas
# =============================================================================


class EventBase(BaseModel):
    """Base event schema."""

    device_fingerprint: str = Field(..., min_length=16, max_length=64)
    event_type: EventType
    policy_rule: str | None = None
    verdict: Verdict | None = None


class EventCreate(EventBase):
    """Schema for creating a new event."""

    llm_analysis: str | None = None
    risk_score: int | None = Field(None, ge=0, le=100)
    raw_descriptor: dict[str, Any] | None = None


class EventResponse(EventBase):
    """Schema for event response."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    timestamp: datetime
    llm_analysis: str | None = None
    risk_score: int | None = None


class EventDetailResponse(EventResponse):
    """Schema for detailed event response."""

    raw_descriptor: dict[str, Any] | None = None
    device: DeviceResponse | None = None


class EventListResponse(BaseModel):
    """Schema for event list response."""

    events: list[EventResponse]
    total: int
    limit: int
    offset: int


# =============================================================================
# Analysis Schemas
# =============================================================================


class AnalysisRequest(BaseModel):
    """Schema for LLM analysis request."""

    device_fingerprint: str | None = None
    descriptor: dict[str, Any] | None = None

    @field_validator("descriptor", "device_fingerprint")
    @classmethod
    def require_one(cls, v, info):
        """Validate that at least one field is provided."""
        return v


class AnalysisResponse(BaseModel):
    """Schema for LLM analysis response."""

    risk_score: int = Field(..., ge=0, le=100)
    verdict: Verdict
    analysis: str
    confidence: float = Field(..., ge=0, le=1)
    anomalies: list[dict[str, Any]] = []


# =============================================================================
# Statistics Schemas
# =============================================================================


class TrustLevelStats(BaseModel):
    """Trust level statistics."""

    unknown: int = 0
    trusted: int = 0
    blocked: int = 0
    review: int = 0


class EventTypeStats(BaseModel):
    """Event type statistics."""

    connect: int = 0
    disconnect: int = 0
    allowed: int = 0
    blocked: int = 0
    sandboxed: int = 0
    reviewed: int = 0


class DatabaseStats(BaseModel):
    """Database statistics response."""

    total_devices: int
    total_events: int
    trust_levels: TrustLevelStats
    event_types: EventTypeStats
    events_last_24h: int
    blocked_last_24h: int
    database_size_bytes: int


# =============================================================================
# Policy Schemas
# =============================================================================


class PolicyRuleBase(BaseModel):
    """Base policy rule schema."""

    action: str = Field(..., pattern=r"^(allow|block|review)$")
    comment: str | None = None


class PolicyMatchCondition(BaseModel):
    """Policy match condition schema."""

    vid: str | None = None
    pid: str | None = None
    device_class: str | int | None = Field(None, alias="class")
    manufacturer: str | None = None
    product: str | None = None
    serial: str | None = None
    has_storage_endpoint: bool | None = None
    has_hid_endpoint: bool | None = None
    endpoint_count_gt: int | None = None
    first_seen: bool | None = None

    model_config = ConfigDict(populate_by_name=True)


class PolicyRuleCreate(PolicyRuleBase):
    """Schema for creating a policy rule."""

    match: PolicyMatchCondition | str  # str for wildcard "*"


class PolicyRuleResponse(PolicyRuleBase):
    """Schema for policy rule response."""

    id: int | None = None
    match: PolicyMatchCondition | str
    priority: int = 0


class PolicyResponse(BaseModel):
    """Schema for full policy response."""

    rules: list[PolicyRuleResponse]
    version: str | None = None
    last_modified: datetime | None = None


# =============================================================================
# WebSocket Schemas
# =============================================================================


class WebSocketMessage(BaseModel):
    """WebSocket message schema."""

    type: str
    data: dict[str, Any]
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class DeviceEventMessage(BaseModel):
    """Real-time device event message."""

    type: str = "device_event"
    event: EventResponse
    device: DeviceResponse


class AlertMessage(BaseModel):
    """Alert message for high-risk events."""

    type: str = "alert"
    severity: str  # "info", "warning", "critical"
    message: str
    device_fingerprint: str | None = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)


# =============================================================================
# Utility Functions
# =============================================================================


def device_to_response(device: Any, event_count: int | None = None) -> DeviceResponse:
    """
    Convert SQLAlchemy Device model to response schema.

    Args:
        device: Device model instance
        event_count: Optional event count

    Returns:
        DeviceResponse schema
    """
    return DeviceResponse(
        id=device.id,
        fingerprint=device.fingerprint,
        vid=device.vid,
        pid=device.pid,
        manufacturer=device.manufacturer,
        product=device.product,
        serial=device.serial,
        first_seen=device.first_seen,
        last_seen=device.last_seen,
        trust_level=TrustLevel(device.trust_level),
        notes=device.notes,
        event_count=event_count,
    )


def event_to_response(event: Any) -> EventResponse:
    """
    Convert SQLAlchemy Event model to response schema.

    Args:
        event: Event model instance

    Returns:
        EventResponse schema
    """
    return EventResponse(
        id=event.id,
        timestamp=event.timestamp,
        device_fingerprint=event.device_fingerprint,
        event_type=EventType(event.event_type),
        policy_rule=event.policy_rule,
        verdict=Verdict(event.verdict) if event.verdict else None,
        llm_analysis=event.llm_analysis,
        risk_score=event.risk_score,
    )
