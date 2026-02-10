"""
WebSocket support for real-time event streaming.

Provides live updates for USB device events to connected dashboard clients.
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable
from weakref import WeakSet

from fastapi import WebSocket, WebSocketDisconnect, status

from sentinel.api.auth import key_manager

logger = logging.getLogger(__name__)


# ============================================================================
# Event Types
# ============================================================================


class WebSocketEventType(str, Enum):
    """Types of WebSocket events."""

    # Device events
    DEVICE_CONNECT = "device.connect"
    DEVICE_DISCONNECT = "device.disconnect"
    DEVICE_ALLOWED = "device.allowed"
    DEVICE_BLOCKED = "device.blocked"
    DEVICE_SANDBOXED = "device.sandboxed"
    DEVICE_TRUST_CHANGED = "device.trust_changed"

    # Analysis events
    ANALYSIS_STARTED = "analysis.started"
    ANALYSIS_COMPLETED = "analysis.completed"

    # System events
    POLICY_UPDATED = "policy.updated"
    SYSTEM_STATUS = "system.status"
    HEARTBEAT = "heartbeat"

    # Client events
    SUBSCRIBE = "subscribe"
    UNSUBSCRIBE = "unsubscribe"


@dataclass
class WebSocketMessage:
    """
    WebSocket message structure.

    Attributes:
        event_type: Type of event
        data: Event payload
        timestamp: When the event occurred
        id: Unique message ID
    """

    event_type: WebSocketEventType | str
    data: dict[str, Any]
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    id: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_json(self) -> str:
        """Serialize to JSON string."""
        return json.dumps(
            {
                "id": self.id,
                "event": (
                    self.event_type.value
                    if isinstance(self.event_type, WebSocketEventType)
                    else self.event_type
                ),
                "data": self.data,
                "timestamp": self.timestamp.isoformat(),
            }
        )

    @classmethod
    def from_json(cls, data: str) -> "WebSocketMessage":
        """Deserialize from JSON string."""
        parsed = json.loads(data)
        return cls(
            event_type=parsed.get("event", "unknown"),
            data=parsed.get("data", {}),
            timestamp=datetime.fromisoformat(parsed.get("timestamp", datetime.now(timezone.utc).isoformat())),
            id=parsed.get("id", ""),
        )


# ============================================================================
# Connection Manager
# ============================================================================


@dataclass
class WebSocketConnection:
    """
    Individual WebSocket connection.

    Attributes:
        websocket: The WebSocket instance
        client_id: Unique client identifier
        subscriptions: Event types the client is subscribed to
        authenticated: Whether the connection is authenticated
        connected_at: Connection timestamp
    """

    websocket: WebSocket
    client_id: str
    subscriptions: set[str] = field(default_factory=set)
    authenticated: bool = False
    connected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    async def send(self, message: WebSocketMessage) -> bool:
        """
        Send message to client.

        Args:
            message: Message to send

        Returns:
            True if sent successfully
        """
        try:
            await self.websocket.send_text(message.to_json())
            return True
        except Exception as e:
            logger.debug(f"Failed to send to {self.client_id}: {e}")
            return False

    def is_subscribed(self, event_type: str) -> bool:
        """Check if client is subscribed to event type."""
        if not self.subscriptions:
            return True  # Empty = subscribed to all
        return event_type in self.subscriptions or "*" in self.subscriptions


class ConnectionManager:
    """
    Manages WebSocket connections and message broadcasting.

    Thread-safe connection handling with support for:
    - Authentication
    - Selective subscriptions
    - Automatic cleanup of dead connections
    - Rate limiting per connection
    """

    def __init__(self) -> None:
        """Initialize connection manager."""
        self._connections: dict[str, WebSocketConnection] = {}
        self._lock = asyncio.Lock()
        self._message_queue: asyncio.Queue[WebSocketMessage] = asyncio.Queue()
        self._running = False
        self._broadcast_task: asyncio.Task | None = None
        self._heartbeat_task: asyncio.Task | None = None
        self._event_handlers: dict[str, list[Callable]] = {}

    @property
    def connection_count(self) -> int:
        """Get number of active connections."""
        return len(self._connections)

    async def start(self) -> None:
        """Start background tasks."""
        if self._running:
            return

        self._running = True
        self._broadcast_task = asyncio.create_task(self._broadcast_loop())
        self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())
        logger.info("WebSocket connection manager started")

    async def stop(self) -> None:
        """Stop background tasks and close connections."""
        self._running = False

        if self._broadcast_task:
            self._broadcast_task.cancel()
            try:
                await self._broadcast_task
            except asyncio.CancelledError:
                pass

        if self._heartbeat_task:
            self._heartbeat_task.cancel()
            try:
                await self._heartbeat_task
            except asyncio.CancelledError:
                pass

        # Close all connections
        async with self._lock:
            for conn in list(self._connections.values()):
                try:
                    await conn.websocket.close()
                except Exception:
                    pass
            self._connections.clear()

        logger.info("WebSocket connection manager stopped")

    async def connect(
        self,
        websocket: WebSocket,
        client_id: str,
        api_key: str | None = None,
    ) -> WebSocketConnection:
        """
        Accept new WebSocket connection.

        Args:
            websocket: WebSocket instance
            client_id: Unique client identifier
            api_key: Optional API key for authentication

        Returns:
            Connection object
        """
        await websocket.accept()

        # Validate API key if provided
        authenticated = False
        if api_key:
            key_obj = key_manager.validate_key(api_key)
            authenticated = key_obj is not None

        conn = WebSocketConnection(
            websocket=websocket,
            client_id=client_id,
            authenticated=authenticated,
        )

        async with self._lock:
            # Remove old connection for same client
            if client_id in self._connections:
                old_conn = self._connections[client_id]
                try:
                    await old_conn.websocket.close()
                except Exception:
                    pass

            self._connections[client_id] = conn

        logger.info(f"WebSocket connected: {client_id} (auth={authenticated})")

        # Send welcome message
        await conn.send(
            WebSocketMessage(
                event_type=WebSocketEventType.SYSTEM_STATUS,
                data={
                    "status": "connected",
                    "client_id": client_id,
                    "authenticated": authenticated,
                },
            )
        )

        return conn

    async def disconnect(self, client_id: str) -> None:
        """
        Remove disconnected client.

        Args:
            client_id: Client identifier
        """
        async with self._lock:
            if client_id in self._connections:
                del self._connections[client_id]
                logger.info(f"WebSocket disconnected: {client_id}")

    async def broadcast(
        self,
        message: WebSocketMessage,
        filter_func: Callable[[WebSocketConnection], bool] | None = None,
    ) -> int:
        """
        Broadcast message to all connected clients.

        Args:
            message: Message to broadcast
            filter_func: Optional function to filter recipients

        Returns:
            Number of clients message was sent to
        """
        await self._message_queue.put((message, filter_func))
        return self.connection_count

    async def send_to_client(
        self,
        client_id: str,
        message: WebSocketMessage,
    ) -> bool:
        """
        Send message to specific client.

        Args:
            client_id: Target client
            message: Message to send

        Returns:
            True if sent successfully
        """
        async with self._lock:
            conn = self._connections.get(client_id)
            if conn:
                return await conn.send(message)
        return False

    async def handle_client_message(
        self,
        conn: WebSocketConnection,
        raw_message: str,
    ) -> None:
        """
        Handle incoming message from client.

        Args:
            conn: Client connection
            raw_message: Raw message string
        """
        try:
            message = WebSocketMessage.from_json(raw_message)
        except json.JSONDecodeError:
            logger.warning(f"Invalid JSON from {conn.client_id}")
            return

        event_type = message.event_type

        # Handle subscription messages
        if event_type == WebSocketEventType.SUBSCRIBE.value:
            events = message.data.get("events", [])
            conn.subscriptions.update(events)
            logger.debug(f"Client {conn.client_id} subscribed to: {events}")

        elif event_type == WebSocketEventType.UNSUBSCRIBE.value:
            events = message.data.get("events", [])
            conn.subscriptions.difference_update(events)
            logger.debug(f"Client {conn.client_id} unsubscribed from: {events}")

        # Invoke registered handlers
        handlers = self._event_handlers.get(event_type, [])
        for handler in handlers:
            try:
                await handler(conn, message)
            except Exception as e:
                logger.error(f"Handler error for {event_type}: {e}")

    def on_event(self, event_type: str) -> Callable:
        """
        Decorator to register event handler.

        Args:
            event_type: Event type to handle

        Returns:
            Decorator function
        """

        def decorator(func: Callable) -> Callable:
            if event_type not in self._event_handlers:
                self._event_handlers[event_type] = []
            self._event_handlers[event_type].append(func)
            return func

        return decorator

    async def _broadcast_loop(self) -> None:
        """Background task to process broadcast queue."""
        while self._running:
            try:
                message, filter_func = await asyncio.wait_for(
                    self._message_queue.get(),
                    timeout=1.0,
                )

                async with self._lock:
                    dead_connections = []

                    for client_id, conn in self._connections.items():
                        # Apply filter
                        if filter_func and not filter_func(conn):
                            continue

                        # Check subscription
                        event_str = (
                            message.event_type.value
                            if isinstance(message.event_type, WebSocketEventType)
                            else message.event_type
                        )
                        if not conn.is_subscribed(event_str):
                            continue

                        # Send message
                        success = await conn.send(message)
                        if not success:
                            dead_connections.append(client_id)

                    # Clean up dead connections
                    for client_id in dead_connections:
                        del self._connections[client_id]
                        logger.debug(f"Removed dead connection: {client_id}")

            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Broadcast loop error: {e}")

    async def _heartbeat_loop(self) -> None:
        """Background task to send periodic heartbeats."""
        while self._running:
            try:
                await asyncio.sleep(30)  # Send heartbeat every 30 seconds

                message = WebSocketMessage(
                    event_type=WebSocketEventType.HEARTBEAT,
                    data={
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "connections": self.connection_count,
                    },
                )

                await self.broadcast(message)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Heartbeat loop error: {e}")

    def get_statistics(self) -> dict[str, Any]:
        """Get connection statistics."""
        return {
            "total_connections": self.connection_count,
            "authenticated_connections": sum(
                1 for c in self._connections.values() if c.authenticated
            ),
            "queue_size": self._message_queue.qsize(),
            "running": self._running,
        }


# Global connection manager instance
manager = ConnectionManager()


# ============================================================================
# Event Broadcasting Helpers
# ============================================================================


async def broadcast_device_event(
    event_type: WebSocketEventType,
    fingerprint: str,
    vid: str,
    pid: str,
    manufacturer: str | None = None,
    product: str | None = None,
    risk_score: int | None = None,
    verdict: str | None = None,
    **extra_data: Any,
) -> None:
    """
    Broadcast a device event.

    Args:
        event_type: Type of device event
        fingerprint: Device fingerprint
        vid: Vendor ID
        pid: Product ID
        manufacturer: Optional manufacturer name
        product: Optional product name
        risk_score: Optional risk score
        verdict: Optional verdict
        **extra_data: Additional event data
    """
    message = WebSocketMessage(
        event_type=event_type,
        data={
            "fingerprint": fingerprint,
            "vid": vid,
            "pid": pid,
            "manufacturer": manufacturer,
            "product": product,
            "risk_score": risk_score,
            "verdict": verdict,
            **extra_data,
        },
    )
    await manager.broadcast(message)


async def broadcast_analysis_event(
    fingerprint: str,
    status: str,
    risk_score: int | None = None,
    analysis: str | None = None,
    **extra_data: Any,
) -> None:
    """
    Broadcast an analysis event.

    Args:
        fingerprint: Device fingerprint
        status: Analysis status (started/completed)
        risk_score: Optional risk score
        analysis: Optional analysis text
        **extra_data: Additional data
    """
    event_type = (
        WebSocketEventType.ANALYSIS_COMPLETED
        if status == "completed"
        else WebSocketEventType.ANALYSIS_STARTED
    )

    message = WebSocketMessage(
        event_type=event_type,
        data={
            "fingerprint": fingerprint,
            "status": status,
            "risk_score": risk_score,
            "analysis": analysis,
            **extra_data,
        },
    )
    await manager.broadcast(message)


async def broadcast_policy_update() -> None:
    """Broadcast policy update notification."""
    message = WebSocketMessage(
        event_type=WebSocketEventType.POLICY_UPDATED,
        data={"updated_at": datetime.now(timezone.utc).isoformat()},
    )
    await manager.broadcast(message)


# ============================================================================
# WebSocket Endpoint Handler
# ============================================================================


async def websocket_endpoint(
    websocket: WebSocket,
    client_id: str | None = None,
    api_key: str | None = None,
) -> None:
    """
    WebSocket endpoint handler.

    Args:
        websocket: WebSocket connection
        client_id: Optional client identifier
        api_key: Optional API key for authentication
    """
    # Generate client ID if not provided
    if not client_id:
        client_id = f"client_{datetime.now(timezone.utc).timestamp()}"

    conn = await manager.connect(websocket, client_id, api_key)

    try:
        while True:
            # Wait for messages from client
            raw_message = await websocket.receive_text()
            await manager.handle_client_message(conn, raw_message)

    except WebSocketDisconnect:
        logger.debug(f"Client {client_id} disconnected normally")
    except Exception as e:
        logger.error(f"WebSocket error for {client_id}: {e}")
    finally:
        await manager.disconnect(client_id)


# ============================================================================
# Initialization
# ============================================================================


async def init_websocket() -> None:
    """Initialize WebSocket support."""
    await manager.start()


async def shutdown_websocket() -> None:
    """Shutdown WebSocket support."""
    await manager.stop()
