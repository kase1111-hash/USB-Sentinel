"""
USB Event handling and processing.

Provides event queue and async event processing infrastructure.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Coroutine

from sentinel.interceptor.descriptors import DeviceDescriptor


logger = logging.getLogger(__name__)


class EventPriority(Enum):
    """Event processing priority."""

    HIGH = 0
    NORMAL = 1
    LOW = 2


@dataclass(order=True)
class PrioritizedEvent:
    """Event wrapper with priority for queue ordering."""

    priority: int
    timestamp: float = field(compare=True)
    event: Any = field(compare=False)


class EventQueue:
    """
    Async event queue for USB events.

    Supports priority-based processing and backpressure.
    """

    def __init__(self, maxsize: int = 1000) -> None:
        """
        Initialize event queue.

        Args:
            maxsize: Maximum queue size (0 for unlimited)
        """
        self._queue: asyncio.PriorityQueue[PrioritizedEvent] = asyncio.PriorityQueue(
            maxsize=maxsize
        )
        self._closed = False

    async def put(
        self,
        event: Any,
        priority: EventPriority = EventPriority.NORMAL,
    ) -> None:
        """
        Add event to queue.

        Args:
            event: Event to add
            priority: Event priority
        """
        if self._closed:
            raise RuntimeError("Queue is closed")

        prioritized = PrioritizedEvent(
            priority=priority.value,
            timestamp=datetime.utcnow().timestamp(),
            event=event,
        )
        await self._queue.put(prioritized)

    async def get(self) -> Any:
        """
        Get next event from queue.

        Returns:
            Next event (highest priority, oldest first)
        """
        prioritized = await self._queue.get()
        return prioritized.event

    def get_nowait(self) -> Any | None:
        """
        Get next event without blocking.

        Returns:
            Next event or None if queue is empty
        """
        try:
            prioritized = self._queue.get_nowait()
            return prioritized.event
        except asyncio.QueueEmpty:
            return None

    def task_done(self) -> None:
        """Mark current task as done."""
        self._queue.task_done()

    async def join(self) -> None:
        """Wait for all events to be processed."""
        await self._queue.join()

    def close(self) -> None:
        """Close the queue."""
        self._closed = True

    @property
    def qsize(self) -> int:
        """Get current queue size."""
        return self._queue.qsize()

    @property
    def empty(self) -> bool:
        """Check if queue is empty."""
        return self._queue.empty()


# Type alias for event handlers
EventHandler = Callable[[Any], Coroutine[Any, Any, None]]


class EventDispatcher:
    """
    Event dispatcher with support for multiple handlers.

    Handlers are called in registration order.
    """

    def __init__(self) -> None:
        self._handlers: dict[str, list[EventHandler]] = {}

    def register(self, event_type: str, handler: EventHandler) -> None:
        """
        Register a handler for an event type.

        Args:
            event_type: Type of event to handle
            handler: Async handler function
        """
        if event_type not in self._handlers:
            self._handlers[event_type] = []
        self._handlers[event_type].append(handler)
        logger.debug("Registered handler for %s", event_type)

    def unregister(self, event_type: str, handler: EventHandler) -> None:
        """
        Unregister a handler.

        Args:
            event_type: Type of event
            handler: Handler to remove
        """
        if event_type in self._handlers:
            self._handlers[event_type].remove(handler)

    async def dispatch(self, event_type: str, event: Any) -> list[Any]:
        """
        Dispatch event to all registered handlers.

        Args:
            event_type: Type of event
            event: Event data

        Returns:
            List of handler results
        """
        handlers = self._handlers.get(event_type, [])
        results = []

        for handler in handlers:
            try:
                result = await handler(event)
                results.append(result)
            except Exception as e:
                logger.error("Handler error for %s: %s", event_type, e)
                results.append(None)

        return results


@dataclass
class ProcessedEvent:
    """
    Result of processing a USB event.

    Contains the original event plus processing results.
    """

    event: Any
    timestamp: datetime = field(default_factory=datetime.utcnow)
    descriptor: DeviceDescriptor | None = None
    policy_action: str | None = None
    policy_rule: str | None = None
    risk_score: int | None = None
    llm_analysis: str | None = None
    final_verdict: str | None = None
    processing_time_ms: float = 0.0
    error: str | None = None

    @property
    def was_allowed(self) -> bool:
        """Check if device was allowed."""
        return self.final_verdict == "allow"

    @property
    def was_blocked(self) -> bool:
        """Check if device was blocked."""
        return self.final_verdict == "block"


class EventProcessor:
    """
    USB event processor.

    Coordinates event processing through policy engine and LLM analyzer.
    """

    def __init__(
        self,
        queue: EventQueue,
        dispatcher: EventDispatcher,
        max_concurrent: int = 5,
    ) -> None:
        """
        Initialize processor.

        Args:
            queue: Event queue to process
            dispatcher: Event dispatcher for notifications
            max_concurrent: Maximum concurrent processing tasks
        """
        self.queue = queue
        self.dispatcher = dispatcher
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._running = False
        self._tasks: set[asyncio.Task] = set()

    async def start(self) -> None:
        """Start processing events."""
        self._running = True
        logger.info("Event processor started")

        while self._running:
            try:
                event = await asyncio.wait_for(self.queue.get(), timeout=1.0)
                task = asyncio.create_task(self._process_event(event))
                self._tasks.add(task)
                task.add_done_callback(self._tasks.discard)
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error("Error getting event: %s", e)

    async def stop(self) -> None:
        """Stop processing events."""
        self._running = False

        # Wait for pending tasks
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)

        logger.info("Event processor stopped")

    async def _process_event(self, event: Any) -> ProcessedEvent:
        """
        Process a single event.

        Args:
            event: Event to process

        Returns:
            ProcessedEvent with results
        """
        async with self._semaphore:
            start_time = datetime.utcnow()
            result = ProcessedEvent(event=event)

            try:
                # Dispatch to handlers
                await self.dispatcher.dispatch("usb_event", event)

                # Calculate processing time
                elapsed = datetime.utcnow() - start_time
                result.processing_time_ms = elapsed.total_seconds() * 1000

            except Exception as e:
                result.error = str(e)
                logger.error("Error processing event: %s", e)

            finally:
                self.queue.task_done()

            return result
