"""
Tests for the Dashboard Backend API module (Phase 9).

Tests REST endpoints, authentication, WebSocket functionality, and Pydantic schemas.
"""

from __future__ import annotations

import asyncio
import json
import time
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import status
from fastapi.testclient import TestClient

from sentinel.api import (
    APIKey,
    APIKeyManager,
    ActionType,
    AnalysisRequest,
    ConnectionManager,
    DeviceResponse,
    DeviceUpdateRequest,
    EventResponse,
    EventType,
    HealthCheck,
    MatchConditionSchema,
    PolicyRuleSchema,
    PolicySchema,
    PolicyValidationResult,
    RateLimiter,
    SystemStatistics,
    TrustLevel,
    WebSocketEventType,
    WebSocketMessage,
    app,
    configure_services,
    create_app,
    generate_api_key,
    key_manager,
)
from sentinel.api.auth import TokenBucket, hash_api_key, verify_api_key


# ============================================================================
# Test Fixtures
# ============================================================================


@pytest.fixture
def test_app():
    """Create test FastAPI application."""
    return create_app(debug=True)


@pytest.fixture
def client(test_app):
    """Create test client."""
    return TestClient(test_app)


@pytest.fixture
def api_key():
    """Generate test API key."""
    key, key_hash = generate_api_key()
    key_manager.add_key(key, "test_key", permissions=["read", "write", "admin"])
    return key


@pytest.fixture
def mock_db():
    """Create mock database."""
    db = MagicMock()

    # Mock device data
    mock_device = MagicMock()
    mock_device.id = 1
    mock_device.fingerprint = "abc123def456abcd"
    mock_device.vid = "046d"
    mock_device.pid = "c534"
    mock_device.manufacturer = "Logitech"
    mock_device.product = "Unifying Receiver"
    mock_device.serial = "12345"
    mock_device.first_seen = datetime.now(timezone.utc)
    mock_device.last_seen = datetime.now(timezone.utc)
    mock_device.trust_level = "trusted"
    mock_device.notes = None
    mock_device.to_dict.return_value = {
        "id": 1,
        "fingerprint": "abc123def456abcd",
        "vid": "046d",
        "pid": "c534",
        "manufacturer": "Logitech",
        "product": "Unifying Receiver",
        "trust_level": "trusted",
        "first_seen": datetime.now(timezone.utc).isoformat(),
        "last_seen": datetime.now(timezone.utc).isoformat(),
    }

    db.get_device.return_value = mock_device
    db.list_devices.return_value = ([mock_device], 1)
    db.count_events.return_value = 5
    db.get_device_statistics.return_value = {
        "event_count": 5,
        "average_risk_score": 25.0,
        "times_blocked": 0,
        "times_allowed": 5,
    }

    # Mock event data
    mock_event = MagicMock()
    mock_event.id = 1
    mock_event.timestamp = datetime.now(timezone.utc)
    mock_event.device_fingerprint = "abc123def456abcd"
    mock_event.event_type = "connect"
    mock_event.policy_rule = None
    mock_event.llm_analysis = None
    mock_event.risk_score = 15
    mock_event.verdict = "allowed"
    mock_event.to_dict.return_value = {
        "id": 1,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "device_fingerprint": "abc123def456abcd",
        "event_type": "connect",
        "verdict": "allowed",
        "risk_score": 15,
    }

    db.list_events.return_value = ([mock_event], 1)
    db.get_event.return_value = mock_event

    # Mock statistics
    db.get_system_statistics.return_value = {
        "total_devices": 10,
        "trusted_devices": 5,
        "blocked_devices": 2,
        "unknown_devices": 3,
        "total_events": 100,
        "events_today": 10,
        "events_this_week": 50,
        "average_risk_score": 30.0,
        "blocked_today": 1,
        "allowed_today": 9,
    }

    return db


@pytest.fixture
def mock_policy_engine():
    """Create mock policy engine."""
    engine = MagicMock()

    from sentinel.policy.models import Action, MatchCondition, Policy, PolicyRule

    engine.policy = Policy(
        rules=[
            PolicyRule(
                match=MatchCondition(vid="046d"),
                action=Action.ALLOW,
                comment="Logitech devices",
            ),
            PolicyRule(
                match=MatchCondition(match_all=True),
                action=Action.REVIEW,
                comment="Default rule",
            ),
        ]
    )
    engine.last_modified = datetime.now(timezone.utc)
    engine.update_rules = MagicMock()

    return engine


@pytest.fixture
def configured_client(test_app, mock_db, mock_policy_engine, api_key):
    """Create configured test client with mocked services."""
    from sentinel.api.routes import deps

    deps.db = mock_db
    deps.policy_engine = mock_policy_engine
    deps.analyzer = MagicMock()

    return TestClient(test_app), api_key


# ============================================================================
# API Key Tests
# ============================================================================


class TestAPIKeyGeneration:
    """Tests for API key generation."""

    def test_generate_api_key(self):
        """Test API key generation."""
        key, key_hash = generate_api_key()
        assert key.startswith("usk_")
        assert len(key) > 40
        assert len(key_hash) == 64  # SHA-256 hex

    def test_hash_api_key(self):
        """Test API key hashing."""
        key = "test_key_123"
        hash1 = hash_api_key(key)
        hash2 = hash_api_key(key)
        assert hash1 == hash2
        assert len(hash1) == 64

    def test_verify_api_key(self):
        """Test API key verification."""
        key = "test_key_123"
        key_hash = hash_api_key(key)
        assert verify_api_key(key, key_hash)
        assert not verify_api_key("wrong_key", key_hash)


class TestAPIKeyManager:
    """Tests for API key manager."""

    def test_add_and_validate_key(self):
        """Test adding and validating keys."""
        manager = APIKeyManager()
        key = "test_key_456"
        manager.add_key(key, "test", permissions=["read"])

        result = manager.validate_key(key)
        assert result is not None
        assert result.name == "test"
        assert "read" in result.permissions

    def test_expired_key(self):
        """Test expired key validation."""
        manager = APIKeyManager()
        key = "test_key_789"
        manager.add_key(
            key,
            "expired_test",
            expires_at=datetime.now(timezone.utc) - timedelta(hours=1),
        )

        result = manager.validate_key(key)
        assert result is None

    def test_revoke_key(self):
        """Test key revocation."""
        manager = APIKeyManager()
        key = "test_key_revoke"
        manager.add_key(key, "to_revoke")

        assert manager.validate_key(key) is not None
        assert manager.revoke_key(key)
        assert manager.validate_key(key) is None

    def test_has_permission(self):
        """Test permission checking."""
        api_key = APIKey(
            key_hash="test",
            name="test",
            permissions=["read", "write"],
        )
        assert api_key.has_permission("read")
        assert api_key.has_permission("write")
        assert not api_key.has_permission("admin")

    def test_admin_has_all_permissions(self):
        """Test admin has all permissions."""
        api_key = APIKey(
            key_hash="test",
            name="admin_test",
            permissions=["admin"],
        )
        assert api_key.has_permission("read")
        assert api_key.has_permission("write")
        assert api_key.has_permission("anything")


# ============================================================================
# Rate Limiter Tests
# ============================================================================


class TestTokenBucket:
    """Tests for token bucket rate limiter."""

    def test_initial_tokens(self):
        """Test initial token count."""
        bucket = TokenBucket(capacity=10)
        assert bucket.tokens == 10.0

    def test_consume_tokens(self):
        """Test token consumption."""
        bucket = TokenBucket(capacity=10)
        assert bucket.consume(5)
        assert bucket.tokens == 5.0

    def test_consume_too_many(self):
        """Test consuming more tokens than available."""
        bucket = TokenBucket(capacity=5)
        assert not bucket.consume(10)
        assert bucket.tokens == 5.0  # Unchanged

    def test_refill(self):
        """Test token refill over time."""
        bucket = TokenBucket(capacity=60)  # 1 per second
        bucket.tokens = 0
        bucket.last_update = time.time() - 10  # 10 seconds ago
        bucket._refill()
        assert bucket.tokens >= 9.5  # ~10 tokens refilled


class TestRateLimiter:
    """Tests for rate limiter."""

    def test_check_rate_under_limit(self):
        """Test request under rate limit."""
        limiter = RateLimiter(default_rate=60)
        assert limiter.check_rate("client1")

    def test_check_rate_over_limit(self):
        """Test request over rate limit."""
        limiter = RateLimiter(default_rate=2)
        assert limiter.check_rate("client2")
        assert limiter.check_rate("client2")
        assert not limiter.check_rate("client2")

    def test_different_clients(self):
        """Test rate limiting per client."""
        limiter = RateLimiter(default_rate=1)
        assert limiter.check_rate("clientA")
        assert limiter.check_rate("clientB")  # Different client

    def test_get_remaining(self):
        """Test getting remaining requests."""
        limiter = RateLimiter(default_rate=10)
        limiter.check_rate("client3")
        remaining = limiter.get_remaining("client3")
        assert remaining == 9


# ============================================================================
# Pydantic Schema Tests
# ============================================================================


class TestDeviceSchemas:
    """Tests for device schemas."""

    def test_device_response_valid(self):
        """Test valid device response."""
        device = DeviceResponse(
            id=1,
            fingerprint="abc123def456abcd",
            vid="046d",
            pid="c534",
            manufacturer="Logitech",
            product="Mouse",
            serial=None,
            trust_level=TrustLevel.TRUSTED,
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
        )
        assert device.vid == "046d"
        assert device.trust_level == TrustLevel.TRUSTED

    def test_device_response_invalid_vid(self):
        """Test device response with invalid VID."""
        with pytest.raises(ValueError):
            DeviceResponse(
                id=1,
                fingerprint="abc123def456abcd",
                vid="invalid",  # Not 4 hex chars
                pid="c534",
                trust_level=TrustLevel.UNKNOWN,
                first_seen=datetime.now(timezone.utc),
            )

    def test_device_update_sanitizes_notes(self):
        """Test XSS sanitization in notes."""
        update = DeviceUpdateRequest(
            notes="<script>alert('xss')</script>",
        )
        assert "<script>" not in update.notes
        assert "&lt;script&gt;" in update.notes


class TestEventSchemas:
    """Tests for event schemas."""

    def test_event_response_valid(self):
        """Test valid event response."""
        event = EventResponse(
            id=1,
            timestamp=datetime.now(timezone.utc),
            device_fingerprint="abc123",
            event_type=EventType.CONNECT,
            risk_score=25,
            verdict="allowed",
        )
        assert event.event_type == EventType.CONNECT
        assert event.risk_score == 25

    def test_event_response_risk_score_bounds(self):
        """Test risk score validation."""
        with pytest.raises(ValueError):
            EventResponse(
                id=1,
                timestamp=datetime.now(timezone.utc),
                device_fingerprint="abc",
                event_type=EventType.CONNECT,
                risk_score=150,  # > 100
            )


class TestPolicySchemas:
    """Tests for policy schemas."""

    def test_policy_rule_with_match_condition(self):
        """Test policy rule with match condition."""
        rule = PolicyRuleSchema(
            match=MatchConditionSchema(vid="046d"),
            action=ActionType.ALLOW,
            comment="Test rule",
        )
        assert rule.action == ActionType.ALLOW

    def test_policy_rule_with_wildcard(self):
        """Test policy rule with wildcard match."""
        rule = PolicyRuleSchema(
            match="*",
            action=ActionType.REVIEW,
        )
        assert rule.match.match_all

    def test_policy_validation_result(self):
        """Test policy validation result."""
        result = PolicyValidationResult(
            valid=False,
            errors=["Invalid rule at position 1"],
            warnings=["Duplicate match condition"],
        )
        assert not result.valid
        assert len(result.errors) == 1


class TestAnalysisSchemas:
    """Tests for analysis schemas."""

    def test_analysis_request_valid(self):
        """Test valid analysis request."""
        request = AnalysisRequest(
            vid="046d",
            pid="c534",
            device_class=0,
            device_subclass=0,
            device_protocol=0,
            manufacturer="Logitech",
            product="Mouse",
        )
        assert request.vid == "046d"

    def test_analysis_request_invalid_vid(self):
        """Test invalid VID in analysis request."""
        with pytest.raises(ValueError):
            AnalysisRequest(
                vid="gggg",  # Not valid hex
                pid="c534",
            )


# ============================================================================
# Health Check Tests
# ============================================================================


class TestHealthEndpoints:
    """Tests for health check endpoints."""

    def test_health_check(self, client):
        """Test health check endpoint."""
        response = client.get("/api/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "uptime_seconds" in data

    def test_liveness_check(self, client):
        """Test liveness probe."""
        response = client.get("/api/health/live")
        assert response.status_code == 200
        assert response.json()["alive"] is True

    def test_readiness_check_not_ready(self, client):
        """Test readiness probe when not ready."""
        from sentinel.api.routes import deps

        deps.db = None  # Not initialized
        response = client.get("/api/health/ready")
        assert response.status_code == 503


# ============================================================================
# Device Endpoint Tests
# ============================================================================


class TestDeviceEndpoints:
    """Tests for device endpoints."""

    def test_list_devices_unauthorized(self, client):
        """Test listing devices without auth."""
        response = client.get("/api/devices")
        assert response.status_code == 401

    def test_list_devices(self, configured_client):
        """Test listing devices."""
        client, api_key = configured_client
        response = client.get(
            "/api/devices",
            headers={"X-API-Key": api_key},
        )
        assert response.status_code == 200
        data = response.json()
        assert "items" in data
        assert "total" in data

    def test_get_device(self, configured_client):
        """Test getting device by fingerprint."""
        client, api_key = configured_client
        response = client.get(
            "/api/devices/abc123def456abcd",
            headers={"X-API-Key": api_key},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["fingerprint"] == "abc123def456abcd"

    def test_get_device_not_found(self, configured_client):
        """Test getting non-existent device."""
        client, api_key = configured_client
        from sentinel.api.routes import deps

        deps.db.get_device.return_value = None

        response = client.get(
            "/api/devices/nonexistent",
            headers={"X-API-Key": api_key},
        )
        assert response.status_code == 404


# ============================================================================
# Event Endpoint Tests
# ============================================================================


class TestEventEndpoints:
    """Tests for event endpoints."""

    def test_list_events(self, configured_client):
        """Test listing events."""
        client, api_key = configured_client
        response = client.get(
            "/api/events",
            headers={"X-API-Key": api_key},
        )
        assert response.status_code == 200
        data = response.json()
        assert "items" in data

    def test_list_events_with_filters(self, configured_client):
        """Test listing events with filters."""
        client, api_key = configured_client
        response = client.get(
            "/api/events",
            params={
                "device_fingerprint": "abc123",
                "event_type": "connect",
            },
            headers={"X-API-Key": api_key},
        )
        assert response.status_code == 200


# ============================================================================
# Policy Endpoint Tests
# ============================================================================


class TestPolicyEndpoints:
    """Tests for policy endpoints."""

    def test_get_policy(self, configured_client):
        """Test getting policy."""
        client, api_key = configured_client
        response = client.get(
            "/api/policy",
            headers={"X-API-Key": api_key},
        )
        assert response.status_code == 200
        data = response.json()
        assert "rules" in data
        assert data["rule_count"] == 2

    def test_validate_policy(self, configured_client):
        """Test policy validation."""
        client, api_key = configured_client
        policy_data = {
            "rules": [
                {
                    "match": {"vid": "046d"},
                    "action": "allow",
                    "comment": "Logitech",
                }
            ]
        }
        response = client.post(
            "/api/policy/validate",
            json=policy_data,
            headers={"X-API-Key": api_key},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["valid"] is True


# ============================================================================
# Statistics Endpoint Tests
# ============================================================================


class TestStatisticsEndpoints:
    """Tests for statistics endpoints."""

    def test_get_statistics(self, configured_client):
        """Test getting system statistics."""
        client, api_key = configured_client
        response = client.get(
            "/api/statistics",
            headers={"X-API-Key": api_key},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["total_devices"] == 10
        assert data["events_today"] == 10


# ============================================================================
# WebSocket Tests
# ============================================================================


class TestWebSocketMessage:
    """Tests for WebSocket message handling."""

    def test_message_to_json(self):
        """Test message serialization."""
        message = WebSocketMessage(
            event_type=WebSocketEventType.DEVICE_CONNECT,
            data={"fingerprint": "abc123", "vid": "046d"},
        )
        json_str = message.to_json()
        parsed = json.loads(json_str)
        assert parsed["event"] == "device.connect"
        assert parsed["data"]["fingerprint"] == "abc123"

    def test_message_from_json(self):
        """Test message deserialization."""
        json_str = json.dumps(
            {
                "id": "123",
                "event": "device.connect",
                "data": {"fingerprint": "abc"},
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )
        message = WebSocketMessage.from_json(json_str)
        assert message.event_type == "device.connect"
        assert message.data["fingerprint"] == "abc"


class TestConnectionManager:
    """Tests for WebSocket connection manager."""

    def test_manager_start_stop(self):
        """Test starting and stopping connection manager."""
        manager = ConnectionManager()

        async def run_test():
            await manager.start()
            assert manager._running is True
            await manager.stop()
            assert manager._running is False

        asyncio.run(run_test())

    def test_manager_statistics(self):
        """Test connection statistics."""
        manager = ConnectionManager()
        stats = manager.get_statistics()
        assert "total_connections" in stats
        assert "running" in stats


# ============================================================================
# Integration Tests
# ============================================================================


class TestAPIIntegration:
    """Integration tests for API."""

    def test_full_device_workflow(self, configured_client):
        """Test complete device workflow."""
        client, api_key = configured_client
        headers = {"X-API-Key": api_key}

        # List devices
        response = client.get("/api/devices", headers=headers)
        assert response.status_code == 200

        # Get specific device
        response = client.get("/api/devices/abc123def456abcd", headers=headers)
        assert response.status_code == 200

        # Get device statistics
        response = client.get(
            "/api/devices/abc123def456abcd/statistics",
            headers=headers,
        )
        assert response.status_code == 200

    def test_full_event_workflow(self, configured_client):
        """Test complete event workflow."""
        client, api_key = configured_client
        headers = {"X-API-Key": api_key}

        # List events
        response = client.get("/api/events", headers=headers)
        assert response.status_code == 200

        # List events with pagination
        response = client.get(
            "/api/events",
            params={"page": 1, "page_size": 10},
            headers=headers,
        )
        assert response.status_code == 200

    def test_rate_limiting(self, configured_client):
        """Test API rate limiting."""
        client, api_key = configured_client

        # Make many requests quickly
        responses = []
        for _ in range(70):  # More than default 60/min
            response = client.get(
                "/api/health",
            )
            responses.append(response.status_code)

        # All should succeed for unauthenticated health check
        assert all(r == 200 for r in responses)


# ============================================================================
# Export Endpoint Tests
# ============================================================================


class TestExportEndpoints:
    """Tests for data export endpoints."""

    def test_export_events_json(self, configured_client):
        """Test exporting events as JSON."""
        client, api_key = configured_client
        response = client.get(
            "/api/export/events",
            params={"format": "json"},
            headers={"X-API-Key": api_key},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["format"] == "json"
        assert "data" in data

    def test_export_events_csv(self, configured_client):
        """Test exporting events as CSV."""
        client, api_key = configured_client
        response = client.get(
            "/api/export/events",
            params={"format": "csv"},
            headers={"X-API-Key": api_key},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["format"] == "csv"

    def test_export_devices(self, configured_client):
        """Test exporting devices."""
        client, api_key = configured_client
        response = client.get(
            "/api/export/devices",
            headers={"X-API-Key": api_key},
        )
        assert response.status_code == 200
