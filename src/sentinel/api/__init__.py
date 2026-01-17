"""
Dashboard API - Layer 5.

FastAPI-based REST interface for dashboard and external integrations.
Includes WebSocket support for real-time event streaming.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING

from fastapi import FastAPI, Request, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from sentinel.api.auth import (
    APIKey,
    APIKeyManager,
    RateLimiter,
    check_rate_limit,
    generate_api_key,
    get_api_key,
    get_optional_api_key,
    init_auth,
    key_manager,
    rate_limiter,
    require_permission,
)
from sentinel.api.routes import deps, router
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
    MatchConditionSchema,
    PolicyResponse,
    PolicyRuleSchema,
    PolicySchema,
    PolicyValidationResult,
    SystemStatistics,
    TrustLevel,
    ValidationError,
    WebSocketEvent,
)
from sentinel.api.websocket import (
    ConnectionManager,
    WebSocketConnection,
    WebSocketEventType,
    WebSocketMessage,
    broadcast_analysis_event,
    broadcast_device_event,
    broadcast_policy_update,
    init_websocket,
    manager,
    shutdown_websocket,
    websocket_endpoint,
)

if TYPE_CHECKING:
    from sentinel.analyzer.llm import LLMAnalyzer
    from sentinel.audit.database import AuditDatabase
    from sentinel.policy.engine import PolicyEngine

logger = logging.getLogger(__name__)


# ============================================================================
# Application Lifecycle
# ============================================================================


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan handler.

    Initializes and cleans up resources on startup/shutdown.
    """
    # Startup
    logger.info("Starting USB Sentinel API")
    await init_websocket()
    yield
    # Shutdown
    logger.info("Shutting down USB Sentinel API")
    await shutdown_websocket()


# ============================================================================
# FastAPI Application
# ============================================================================


def create_app(
    title: str = "USB Sentinel API",
    version: str = "1.0.0",
    debug: bool = False,
    cors_origins: list[str] | None = None,
) -> FastAPI:
    """
    Create and configure FastAPI application.

    Args:
        title: API title
        version: API version
        debug: Enable debug mode
        cors_origins: Allowed CORS origins

    Returns:
        Configured FastAPI application
    """
    app = FastAPI(
        title=title,
        description="REST API for USB Sentinel USB security firewall",
        version=version,
        debug=debug,
        lifespan=lifespan,
        docs_url="/api/docs",
        redoc_url="/api/redoc",
        openapi_url="/api/openapi.json",
    )

    # CORS middleware
    origins = cors_origins or ["http://localhost:3000", "http://localhost:5173"]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Include REST routes
    app.include_router(router)

    # WebSocket endpoint
    @app.websocket("/api/events/stream")
    async def event_stream(
        websocket: WebSocket,
        client_id: str | None = None,
        api_key: str | None = None,
    ):
        """WebSocket endpoint for real-time event streaming."""
        await websocket_endpoint(websocket, client_id, api_key)

    # Global exception handler
    @app.exception_handler(Exception)
    async def global_exception_handler(request: Request, exc: Exception):
        """Handle unexpected exceptions."""
        logger.error(f"Unhandled exception: {exc}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={
                "error": "Internal server error",
                "detail": str(exc) if debug else None,
            },
        )

    return app


def configure_services(
    app: FastAPI,
    db: "AuditDatabase | None" = None,
    policy_engine: "PolicyEngine | None" = None,
    analyzer: "LLMAnalyzer | None" = None,
    default_api_key: str | None = None,
) -> None:
    """
    Configure application services.

    Args:
        app: FastAPI application
        db: Audit database instance
        policy_engine: Policy engine instance
        analyzer: LLM analyzer instance
        default_api_key: Default API key for development
    """
    deps.db = db
    deps.policy_engine = policy_engine
    deps.analyzer = analyzer

    # Initialize authentication
    init_auth(default_api_key)

    logger.info("API services configured")


# Default app instance
app = create_app()


__all__ = [
    # Application
    "app",
    "create_app",
    "configure_services",
    # Authentication
    "APIKey",
    "APIKeyManager",
    "RateLimiter",
    "check_rate_limit",
    "generate_api_key",
    "get_api_key",
    "get_optional_api_key",
    "init_auth",
    "key_manager",
    "rate_limiter",
    "require_permission",
    # Routes
    "router",
    "deps",
    # Schemas
    "ActionType",
    "AnalysisRequest",
    "AnalysisResponse",
    "DeviceListResponse",
    "DeviceResponse",
    "DeviceStatistics",
    "DeviceUpdateRequest",
    "ErrorResponse",
    "EventListResponse",
    "EventResponse",
    "EventType",
    "HealthCheck",
    "MatchConditionSchema",
    "PolicyResponse",
    "PolicyRuleSchema",
    "PolicySchema",
    "PolicyValidationResult",
    "SystemStatistics",
    "TrustLevel",
    "ValidationError",
    "WebSocketEvent",
    # WebSocket
    "ConnectionManager",
    "WebSocketConnection",
    "WebSocketEventType",
    "WebSocketMessage",
    "broadcast_analysis_event",
    "broadcast_device_event",
    "broadcast_policy_update",
    "init_websocket",
    "manager",
    "shutdown_websocket",
    "websocket_endpoint",
]
