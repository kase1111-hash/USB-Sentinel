"""
REST API routes for USB Sentinel.

Provides endpoints for device management, event queries, policy
configuration, and manual analysis triggering.
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from sentinel.api.auth import (
    APIKey,
    check_rate_limit,
    get_api_key,
    require_permission,
)
from sentinel.api.schemas import (
    ActionType,
    AnalysisRequest,
    AnalysisResponse,
    DeviceListResponse,
    DeviceResponse,
    DeviceStatistics,
    DeviceUpdateRequest,
    ErrorResponse,
    EventListResponse,
    EventResponse,
    EventType,
    HealthCheck,
    PolicyResponse,
    PolicyRuleSchema,
    PolicySchema,
    PolicyValidationResult,
    SystemStatistics,
    TrustLevel,
)

logger = logging.getLogger(__name__)

# API Router with prefix
router = APIRouter(prefix="/api")


# ============================================================================
# Dependencies
# ============================================================================


class ServiceDependencies:
    """
    Container for service dependencies.

    Set these after app initialization to inject database, policy engine, etc.
    """

    db = None  # AuditDatabase instance
    policy_engine = None  # PolicyEngine instance
    analyzer = None  # LLMAnalyzer instance
    start_time: float = time.time()


deps = ServiceDependencies()


def get_db():
    """Get database instance."""
    if deps.db is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database not initialized",
        )
    return deps.db


def get_policy_engine():
    """Get policy engine instance."""
    if deps.policy_engine is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Policy engine not initialized",
        )
    return deps.policy_engine


def get_analyzer():
    """Get LLM analyzer instance."""
    if deps.analyzer is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="LLM analyzer not initialized",
        )
    return deps.analyzer


# ============================================================================
# Health Check Endpoints
# ============================================================================


@router.get("/health", response_model=HealthCheck, tags=["Health"])
async def health_check() -> HealthCheck:
    """
    Check system health status.

    Returns component status and uptime information.
    """
    return HealthCheck(
        status="healthy",
        version="1.0.0",
        uptime_seconds=time.time() - deps.start_time,
        database_connected=deps.db is not None,
        llm_available=deps.analyzer is not None,
        interceptor_active=True,  # Would check actual interceptor status
    )


@router.get("/health/ready", tags=["Health"])
async def readiness_check() -> dict[str, bool]:
    """
    Kubernetes readiness probe.

    Returns 200 if service is ready to accept traffic.
    """
    ready = deps.db is not None
    if not ready:
        raise HTTPException(status_code=503, detail="Service not ready")
    return {"ready": True}


@router.get("/health/live", tags=["Health"])
async def liveness_check() -> dict[str, bool]:
    """
    Kubernetes liveness probe.

    Returns 200 if service is alive.
    """
    return {"alive": True}


# ============================================================================
# Device Endpoints
# ============================================================================


@router.get(
    "/devices",
    response_model=DeviceListResponse,
    tags=["Devices"],
    responses={401: {"model": ErrorResponse}},
)
async def list_devices(
    request: Request,
    trust_level: TrustLevel | None = Query(None, description="Filter by trust level"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(50, ge=1, le=1000, description="Items per page"),
    api_key: APIKey = Depends(get_api_key),
) -> DeviceListResponse:
    """
    List all known devices.

    Supports filtering by trust level and pagination.
    """
    await check_rate_limit(request, api_key)
    db = get_db()

    # Build query filters
    filters = {}
    if trust_level:
        filters["trust_level"] = trust_level.value

    # Get devices from database
    devices, total = db.list_devices(
        filters=filters,
        offset=(page - 1) * page_size,
        limit=page_size,
    )

    # Convert to response models
    items = []
    for device in devices:
        event_count = db.count_events(device_fingerprint=device.fingerprint)
        items.append(
            DeviceResponse(
                id=device.id,
                fingerprint=device.fingerprint,
                vid=device.vid,
                pid=device.pid,
                manufacturer=device.manufacturer,
                product=device.product,
                serial=device.serial,
                trust_level=TrustLevel(device.trust_level),
                first_seen=device.first_seen,
                last_seen=device.last_seen,
                notes=device.notes,
                event_count=event_count,
            )
        )

    return DeviceListResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get(
    "/devices/{fingerprint}",
    response_model=DeviceResponse,
    tags=["Devices"],
    responses={404: {"model": ErrorResponse}},
)
async def get_device(
    request: Request,
    fingerprint: str,
    api_key: APIKey = Depends(get_api_key),
) -> DeviceResponse:
    """
    Get device details by fingerprint.

    Returns full device information and event history.
    """
    await check_rate_limit(request, api_key)
    db = get_db()

    device = db.get_device(fingerprint)
    if device is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Device not found: {fingerprint}",
        )

    event_count = db.count_events(device_fingerprint=fingerprint)

    return DeviceResponse(
        id=device.id,
        fingerprint=device.fingerprint,
        vid=device.vid,
        pid=device.pid,
        manufacturer=device.manufacturer,
        product=device.product,
        serial=device.serial,
        trust_level=TrustLevel(device.trust_level),
        first_seen=device.first_seen,
        last_seen=device.last_seen,
        notes=device.notes,
        event_count=event_count,
    )


@router.put(
    "/devices/{fingerprint}",
    response_model=DeviceResponse,
    tags=["Devices"],
    responses={404: {"model": ErrorResponse}},
)
async def update_device(
    request: Request,
    fingerprint: str,
    update: DeviceUpdateRequest,
    api_key: APIKey = Depends(require_permission("write")),
) -> DeviceResponse:
    """
    Update device properties.

    Allows changing trust level and notes.
    """
    await check_rate_limit(request, api_key)
    db = get_db()

    device = db.get_device(fingerprint)
    if device is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Device not found: {fingerprint}",
        )

    # Update fields
    if update.trust_level is not None:
        db.update_trust_level(fingerprint, update.trust_level.value)
        logger.info(
            f"Trust level updated: {fingerprint} -> {update.trust_level.value}"
        )

    if update.notes is not None:
        db.update_device_notes(fingerprint, update.notes)

    # Get updated device
    device = db.get_device(fingerprint)
    event_count = db.count_events(device_fingerprint=fingerprint)

    return DeviceResponse(
        id=device.id,
        fingerprint=device.fingerprint,
        vid=device.vid,
        pid=device.pid,
        manufacturer=device.manufacturer,
        product=device.product,
        serial=device.serial,
        trust_level=TrustLevel(device.trust_level),
        first_seen=device.first_seen,
        last_seen=device.last_seen,
        notes=device.notes,
        event_count=event_count,
    )


@router.get(
    "/devices/{fingerprint}/statistics",
    response_model=DeviceStatistics,
    tags=["Devices"],
)
async def get_device_statistics(
    request: Request,
    fingerprint: str,
    api_key: APIKey = Depends(get_api_key),
) -> DeviceStatistics:
    """
    Get statistics for a specific device.

    Returns event counts, risk scores, and activity history.
    """
    await check_rate_limit(request, api_key)
    db = get_db()

    device = db.get_device(fingerprint)
    if device is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Device not found: {fingerprint}",
        )

    stats = db.get_device_statistics(fingerprint)

    return DeviceStatistics(
        fingerprint=fingerprint,
        event_count=stats.get("event_count", 0),
        first_seen=device.first_seen,
        last_seen=device.last_seen,
        average_risk_score=stats.get("average_risk_score"),
        times_blocked=stats.get("times_blocked", 0),
        times_allowed=stats.get("times_allowed", 0),
    )


# ============================================================================
# Event Endpoints
# ============================================================================


@router.get(
    "/events",
    response_model=EventListResponse,
    tags=["Events"],
)
async def list_events(
    request: Request,
    device_fingerprint: str | None = Query(None, description="Filter by device"),
    event_type: EventType | None = Query(None, description="Filter by event type"),
    since: datetime | None = Query(None, description="Events after this time"),
    until: datetime | None = Query(None, description="Events before this time"),
    min_risk_score: int | None = Query(None, ge=0, le=100, description="Minimum risk score"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=1000),
    api_key: APIKey = Depends(get_api_key),
) -> EventListResponse:
    """
    Query event log.

    Supports filtering by device, event type, time range, and risk score.
    """
    await check_rate_limit(request, api_key)
    db = get_db()

    # Build filters
    filters = {}
    if device_fingerprint:
        filters["device_fingerprint"] = device_fingerprint
    if event_type:
        filters["event_type"] = event_type.value
    if since:
        filters["since"] = since
    if until:
        filters["until"] = until
    if min_risk_score is not None:
        filters["min_risk_score"] = min_risk_score

    # Get events
    events, total = db.list_events(
        filters=filters,
        offset=(page - 1) * page_size,
        limit=page_size,
    )

    items = [
        EventResponse(
            id=event.id,
            timestamp=event.timestamp,
            device_fingerprint=event.device_fingerprint,
            event_type=EventType(event.event_type),
            policy_rule=event.policy_rule,
            llm_analysis=event.llm_analysis,
            risk_score=event.risk_score,
            verdict=event.verdict,
        )
        for event in events
    ]

    return EventListResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get(
    "/events/{event_id}",
    response_model=EventResponse,
    tags=["Events"],
)
async def get_event(
    request: Request,
    event_id: int,
    api_key: APIKey = Depends(get_api_key),
) -> EventResponse:
    """
    Get event details by ID.
    """
    await check_rate_limit(request, api_key)
    db = get_db()

    event = db.get_event(event_id)
    if event is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Event not found: {event_id}",
        )

    return EventResponse(
        id=event.id,
        timestamp=event.timestamp,
        device_fingerprint=event.device_fingerprint,
        event_type=EventType(event.event_type),
        policy_rule=event.policy_rule,
        llm_analysis=event.llm_analysis,
        risk_score=event.risk_score,
        verdict=event.verdict,
    )


# ============================================================================
# Policy Endpoints
# ============================================================================


@router.get(
    "/policy",
    response_model=PolicyResponse,
    tags=["Policy"],
)
async def get_policy(
    request: Request,
    api_key: APIKey = Depends(get_api_key),
) -> PolicyResponse:
    """
    Get current policy configuration.

    Returns all policy rules with metadata.
    """
    await check_rate_limit(request, api_key)
    engine = get_policy_engine()

    rules = []
    for rule in engine.policy.rules:
        match_dict = rule.match.to_dict()
        if rule.match.is_wildcard():
            match_schema = "*"
        else:
            from sentinel.api.schemas import MatchConditionSchema
            match_schema = MatchConditionSchema(**match_dict)

        rules.append(
            PolicyRuleSchema(
                match=match_schema,
                action=ActionType(rule.action.value),
                comment=rule.comment,
                priority=rule.priority,
            )
        )

    return PolicyResponse(
        rules=rules,
        rule_count=len(rules),
        last_modified=engine.last_modified if hasattr(engine, "last_modified") else None,
    )


@router.put(
    "/policy",
    response_model=PolicyResponse,
    tags=["Policy"],
)
async def update_policy(
    request: Request,
    policy: PolicySchema,
    api_key: APIKey = Depends(require_permission("admin")),
) -> PolicyResponse:
    """
    Update policy configuration.

    Replaces all existing rules with the provided rules.
    Requires admin permission.
    """
    await check_rate_limit(request, api_key)
    engine = get_policy_engine()

    # Convert to internal format
    from sentinel.policy.models import Action, MatchCondition, PolicyRule

    new_rules = []
    for rule_schema in policy.rules:
        if isinstance(rule_schema.match, str) and rule_schema.match == "*":
            match = MatchCondition(match_all=True)
        else:
            match_dict = (
                rule_schema.match.model_dump()
                if hasattr(rule_schema.match, "model_dump")
                else rule_schema.match
            )
            match = MatchCondition.from_dict(match_dict)

        new_rules.append(
            PolicyRule(
                match=match,
                action=Action(rule_schema.action.value),
                comment=rule_schema.comment,
                priority=rule_schema.priority,
            )
        )

    # Update engine
    engine.update_rules(new_rules)
    logger.info("Policy updated: %d rules by %s", len(new_rules), api_key.name)

    # Return updated policy
    return await get_policy(request, api_key)


@router.post(
    "/policy/validate",
    response_model=PolicyValidationResult,
    tags=["Policy"],
)
async def validate_policy(
    request: Request,
    policy: PolicySchema,
    api_key: APIKey = Depends(get_api_key),
) -> PolicyValidationResult:
    """
    Validate policy configuration without applying it.

    Returns validation errors and warnings.
    """
    await check_rate_limit(request, api_key)

    errors = []
    warnings = []

    # Check for duplicate rules
    seen_matches = set()
    for i, rule in enumerate(policy.rules):
        match_key = str(rule.match)
        if match_key in seen_matches:
            warnings.append(f"Rule {i + 1}: Duplicate match condition")
        seen_matches.add(match_key)

        # Validate action
        if rule.action not in ActionType:
            errors.append(f"Rule {i + 1}: Invalid action '{rule.action}'")

    # Check for wildcard not at end
    for i, rule in enumerate(policy.rules[:-1]):
        if isinstance(rule.match, str) and rule.match == "*":
            warnings.append(
                f"Rule {i + 1}: Wildcard rule not at end - subsequent rules unreachable"
            )

    return PolicyValidationResult(
        valid=len(errors) == 0,
        errors=errors,
        warnings=warnings,
    )


# ============================================================================
# Analysis Endpoints
# ============================================================================


@router.post(
    "/analyze",
    response_model=AnalysisResponse,
    tags=["Analysis"],
)
async def manual_analyze(
    request: Request,
    device_info: AnalysisRequest,
    api_key: APIKey = Depends(require_permission("write")),
) -> AnalysisResponse:
    """
    Manually trigger LLM analysis for a device.

    Useful for testing or re-analyzing devices.
    """
    await check_rate_limit(request, api_key)
    analyzer = get_analyzer()

    start_time = time.time()

    # Build device descriptor
    from sentinel.interceptor.descriptors import DeviceDescriptor, InterfaceDescriptor

    interfaces = []
    for iface_data in device_info.interfaces:
        interfaces.append(
            InterfaceDescriptor(
                interface_class=iface_data.get("interface_class", 0),
                interface_subclass=iface_data.get("interface_subclass", 0),
                interface_protocol=iface_data.get("interface_protocol", 0),
                num_endpoints=iface_data.get("num_endpoints", 0),
                endpoints=[],
            )
        )

    descriptor = DeviceDescriptor(
        vid=device_info.vid,
        pid=device_info.pid,
        device_class=device_info.device_class,
        device_subclass=device_info.device_subclass,
        device_protocol=device_info.device_protocol,
        manufacturer=device_info.manufacturer,
        product=device_info.product,
        serial=device_info.serial,
        interfaces=interfaces,
    )

    # Run analysis
    result = await analyzer.analyze_async(descriptor)

    processing_time = (time.time() - start_time) * 1000

    return AnalysisResponse(
        risk_score=result.risk_score,
        verdict=result.verdict,
        analysis=result.analysis,
        confidence=result.confidence,
        processing_time_ms=processing_time,
    )


# ============================================================================
# Statistics Endpoints
# ============================================================================


@router.get(
    "/statistics",
    response_model=SystemStatistics,
    tags=["Statistics"],
)
async def get_statistics(
    request: Request,
    api_key: APIKey = Depends(get_api_key),
) -> SystemStatistics:
    """
    Get system-wide statistics.

    Returns device counts, event statistics, and risk metrics.
    """
    await check_rate_limit(request, api_key)
    db = get_db()

    stats = db.get_system_statistics()

    return SystemStatistics(
        total_devices=stats.get("total_devices", 0),
        trusted_devices=stats.get("trusted_devices", 0),
        blocked_devices=stats.get("blocked_devices", 0),
        unknown_devices=stats.get("unknown_devices", 0),
        total_events=stats.get("total_events", 0),
        events_today=stats.get("events_today", 0),
        events_this_week=stats.get("events_this_week", 0),
        average_risk_score=stats.get("average_risk_score"),
        blocked_today=stats.get("blocked_today", 0),
        allowed_today=stats.get("allowed_today", 0),
    )


# ============================================================================
# Export Endpoints
# ============================================================================


@router.get(
    "/export/events",
    tags=["Export"],
)
async def export_events(
    request: Request,
    format: str = Query("json", pattern="^(json|csv)$"),
    since: datetime | None = None,
    until: datetime | None = None,
    api_key: APIKey = Depends(require_permission("read")),
) -> dict[str, Any]:
    """
    Export events for forensic analysis.

    Supports JSON and CSV formats.
    """
    await check_rate_limit(request, api_key)
    db = get_db()

    filters = {}
    if since:
        filters["since"] = since
    if until:
        filters["until"] = until

    events, _ = db.list_events(filters=filters, limit=10000)

    if format == "csv":
        # Return CSV as string
        import csv
        import io

        output = io.StringIO()
        writer = csv.DictWriter(
            output,
            fieldnames=[
                "id",
                "timestamp",
                "device_fingerprint",
                "event_type",
                "verdict",
                "risk_score",
            ],
        )
        writer.writeheader()
        for event in events:
            writer.writerow(event.to_dict())

        return {
            "format": "csv",
            "data": output.getvalue(),
            "count": len(events),
        }

    return {
        "format": "json",
        "data": [event.to_dict() for event in events],
        "count": len(events),
    }


@router.get(
    "/export/devices",
    tags=["Export"],
)
async def export_devices(
    request: Request,
    format: str = Query("json", pattern="^(json|csv)$"),
    api_key: APIKey = Depends(require_permission("read")),
) -> dict[str, Any]:
    """
    Export device inventory.

    Supports JSON and CSV formats.
    """
    await check_rate_limit(request, api_key)
    db = get_db()

    devices, _ = db.list_devices(limit=10000)

    if format == "csv":
        import csv
        import io

        output = io.StringIO()
        writer = csv.DictWriter(
            output,
            fieldnames=[
                "fingerprint",
                "vid",
                "pid",
                "manufacturer",
                "product",
                "trust_level",
                "first_seen",
            ],
        )
        writer.writeheader()
        for device in devices:
            writer.writerow(device.to_dict())

        return {
            "format": "csv",
            "data": output.getvalue(),
            "count": len(devices),
        }

    return {
        "format": "json",
        "data": [device.to_dict() for device in devices],
        "count": len(devices),
    }
