"""
Pydantic schemas for API request/response validation.

Provides type-safe models for all API endpoints.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator


# ============================================================================
# Enums
# ============================================================================


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


class ActionType(str, Enum):
    """Policy action types."""

    ALLOW = "allow"
    BLOCK = "block"
    REVIEW = "review"


# ============================================================================
# Device Schemas
# ============================================================================


class DeviceBase(BaseModel):
    """Base device fields."""

    vid: str = Field(..., min_length=4, max_length=4, pattern=r"^[0-9a-fA-F]{4}$")
    pid: str = Field(..., min_length=4, max_length=4, pattern=r"^[0-9a-fA-F]{4}$")
    manufacturer: str | None = None
    product: str | None = None
    serial: str | None = None


class DeviceResponse(DeviceBase):
    """Device response model."""

    id: int
    fingerprint: str = Field(..., min_length=16, max_length=64)
    trust_level: TrustLevel = TrustLevel.UNKNOWN
    first_seen: datetime
    last_seen: datetime | None = None
    notes: str | None = None
    event_count: int = 0

    model_config = {"from_attributes": True}


class DeviceListResponse(BaseModel):
    """Paginated device list response."""

    items: list[DeviceResponse]
    total: int
    page: int = 1
    page_size: int = 50


class DeviceUpdateRequest(BaseModel):
    """Request to update device properties."""

    trust_level: TrustLevel | None = None
    notes: str | None = None

    @field_validator("notes")
    @classmethod
    def sanitize_notes(cls, v: str | None) -> str | None:
        """Sanitize notes field to prevent XSS."""
        if v is None:
            return v
        # Basic HTML entity escaping
        return (
            v.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#x27;")
        )


# ============================================================================
# Event Schemas
# ============================================================================


class EventResponse(BaseModel):
    """Event response model."""

    id: int
    timestamp: datetime
    device_fingerprint: str
    event_type: EventType
    policy_rule: str | None = None
    llm_analysis: str | None = None
    risk_score: int | None = Field(None, ge=0, le=100)
    verdict: str | None = None

    model_config = {"from_attributes": True}


class EventListResponse(BaseModel):
    """Paginated event list response."""

    items: list[EventResponse]
    total: int
    page: int = 1
    page_size: int = 50


class EventQuery(BaseModel):
    """Event query parameters."""

    device_fingerprint: str | None = None
    event_type: EventType | None = None
    since: datetime | None = None
    until: datetime | None = None
    min_risk_score: int | None = Field(None, ge=0, le=100)
    page: int = Field(1, ge=1)
    page_size: int = Field(50, ge=1, le=1000)


# ============================================================================
# Policy Schemas
# ============================================================================


class MatchConditionSchema(BaseModel):
    """Policy match condition schema."""

    vid: str | None = None
    pid: str | None = None
    vid_list: list[str] | None = None
    pid_list: list[str] | None = None
    device_class: int | str | None = None
    interface_class: int | str | None = None
    manufacturer: str | None = None
    product: str | None = None
    serial: str | None = None
    has_storage_endpoint: bool | None = None
    has_hid_endpoint: bool | None = None
    is_composite: bool | None = None
    first_seen: bool | None = None
    trust_level: str | None = None
    match_all: bool = False


class PolicyRuleSchema(BaseModel):
    """Policy rule schema."""

    match: MatchConditionSchema | str
    action: ActionType
    comment: str = ""
    priority: int = 0

    @field_validator("match", mode="before")
    @classmethod
    def validate_match(cls, v: Any) -> MatchConditionSchema | str:
        """Allow '*' as wildcard match."""
        if v == "*":
            return MatchConditionSchema(match_all=True)
        if isinstance(v, dict):
            return MatchConditionSchema(**v)
        return v


class PolicySchema(BaseModel):
    """Complete policy schema."""

    rules: list[PolicyRuleSchema]


class PolicyResponse(BaseModel):
    """Policy response with metadata."""

    rules: list[PolicyRuleSchema]
    rule_count: int
    last_modified: datetime | None = None


class PolicyValidationResult(BaseModel):
    """Result of policy validation."""

    valid: bool
    errors: list[str] = []
    warnings: list[str] = []


# ============================================================================
# Analysis Schemas
# ============================================================================


class AnalysisRequest(BaseModel):
    """Request for manual LLM analysis."""

    vid: str = Field(..., min_length=4, max_length=4, pattern=r"^[0-9a-fA-F]{4}$")
    pid: str = Field(..., min_length=4, max_length=4, pattern=r"^[0-9a-fA-F]{4}$")
    device_class: int = Field(0, ge=0, le=255)
    device_subclass: int = Field(0, ge=0, le=255)
    device_protocol: int = Field(0, ge=0, le=255)
    manufacturer: str | None = None
    product: str | None = None
    serial: str | None = None
    interfaces: list[dict[str, Any]] = []


class AnalysisResponse(BaseModel):
    """LLM analysis response."""

    risk_score: int = Field(..., ge=0, le=100)
    verdict: str
    analysis: str
    confidence: float = Field(..., ge=0.0, le=1.0)
    processing_time_ms: float


# ============================================================================
# WebSocket Event Schemas
# ============================================================================


class WebSocketEvent(BaseModel):
    """WebSocket event message."""

    event_type: str
    timestamp: datetime
    data: dict[str, Any]


class DeviceConnectEvent(BaseModel):
    """Device connection event."""

    fingerprint: str
    vid: str
    pid: str
    manufacturer: str | None = None
    product: str | None = None
    risk_score: int | None = None
    verdict: str | None = None
    is_new: bool = False


class DeviceDisconnectEvent(BaseModel):
    """Device disconnection event."""

    fingerprint: str
    vid: str
    pid: str


# ============================================================================
# Statistics Schemas
# ============================================================================


class SystemStatistics(BaseModel):
    """System statistics response."""

    total_devices: int
    trusted_devices: int
    blocked_devices: int
    unknown_devices: int
    total_events: int
    events_today: int
    events_this_week: int
    average_risk_score: float | None = None
    blocked_today: int = 0
    allowed_today: int = 0


class DeviceStatistics(BaseModel):
    """Device-specific statistics."""

    fingerprint: str
    event_count: int
    first_seen: datetime
    last_seen: datetime | None = None
    average_risk_score: float | None = None
    times_blocked: int = 0
    times_allowed: int = 0


# ============================================================================
# Health Check Schemas
# ============================================================================


class HealthCheck(BaseModel):
    """Health check response."""

    status: str = "healthy"
    version: str
    uptime_seconds: float
    database_connected: bool
    llm_available: bool
    interceptor_active: bool


class ComponentStatus(BaseModel):
    """Individual component status."""

    name: str
    status: str
    last_activity: datetime | None = None
    error: str | None = None


# ============================================================================
# Error Schemas
# ============================================================================


class ErrorResponse(BaseModel):
    """Standard error response."""

    error: str
    detail: str | None = None
    code: str | None = None


class ValidationError(BaseModel):
    """Validation error detail."""

    loc: list[str | int]
    msg: str
    type: str
