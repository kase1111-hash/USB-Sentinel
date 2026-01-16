"""
Tests for USB Interceptor module.
"""

from __future__ import annotations

import asyncio
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from sentinel.interceptor.descriptors import (
    DeviceDescriptor,
    EndpointDescriptor,
    InterfaceDescriptor,
)
from sentinel.interceptor.events import (
    EventDispatcher,
    EventPriority,
    EventQueue,
    ProcessedEvent,
)
from sentinel.interceptor.linux import (
    DeviceAuthorizer,
    EventType,
    USBEnumerator,
    USBEvent,
    USBInterceptor,
)


class TestDeviceDescriptor:
    """Tests for DeviceDescriptor."""

    def test_create_descriptor(self, sample_device_descriptor: dict) -> None:
        """Test creating a device descriptor from dict."""
        interfaces = [
            InterfaceDescriptor(
                interface_class=intf["interface_class"],
                interface_subclass=intf["interface_subclass"],
                interface_protocol=intf["interface_protocol"],
                num_endpoints=intf["num_endpoints"],
                endpoints=[
                    EndpointDescriptor(**ep)
                    for ep in intf.get("endpoints", [])
                ],
            )
            for intf in sample_device_descriptor["interfaces"]
        ]

        desc = DeviceDescriptor(
            vid=sample_device_descriptor["vid"],
            pid=sample_device_descriptor["pid"],
            device_class=sample_device_descriptor["device_class"],
            device_subclass=sample_device_descriptor["device_subclass"],
            device_protocol=sample_device_descriptor["device_protocol"],
            manufacturer=sample_device_descriptor["manufacturer"],
            product=sample_device_descriptor["product"],
            serial=sample_device_descriptor["serial"],
            interfaces=interfaces,
        )

        assert desc.vid == "046d"
        assert desc.pid == "c534"
        assert desc.manufacturer == "Logitech"
        assert len(desc.interfaces) == 1

    def test_has_class(self) -> None:
        """Test has_class method."""
        desc = DeviceDescriptor(
            vid="1234",
            pid="5678",
            device_class=0,
            device_subclass=0,
            device_protocol=0,
            manufacturer=None,
            product=None,
            serial=None,
            interfaces=[
                InterfaceDescriptor(
                    interface_class=3,  # HID
                    interface_subclass=0,
                    interface_protocol=0,
                    num_endpoints=1,
                ),
                InterfaceDescriptor(
                    interface_class=8,  # Mass Storage
                    interface_subclass=6,
                    interface_protocol=80,
                    num_endpoints=2,
                ),
            ],
        )

        assert desc.has_class(3) is True  # HID
        assert desc.has_class(8) is True  # Mass Storage
        assert desc.has_class(1) is False  # Audio

    def test_to_dict(self) -> None:
        """Test serialization to dict."""
        desc = DeviceDescriptor(
            vid="046d",
            pid="c534",
            device_class=0,
            device_subclass=0,
            device_protocol=0,
            manufacturer="Test",
            product="Device",
            serial="12345",
            interfaces=[],
        )

        d = desc.to_dict()
        assert d["vid"] == "046d"
        assert d["pid"] == "c534"
        assert d["manufacturer"] == "Test"
        assert "timestamp" in d


class TestInterfaceDescriptor:
    """Tests for InterfaceDescriptor."""

    def test_class_name(self) -> None:
        """Test class name property."""
        hid = InterfaceDescriptor(
            interface_class=3,
            interface_subclass=0,
            interface_protocol=0,
            num_endpoints=1,
        )
        assert hid.class_name == "HID"

        storage = InterfaceDescriptor(
            interface_class=8,
            interface_subclass=6,
            interface_protocol=80,
            num_endpoints=2,
        )
        assert storage.class_name == "Mass Storage"

        unknown = InterfaceDescriptor(
            interface_class=0x99,
            interface_subclass=0,
            interface_protocol=0,
            num_endpoints=0,
        )
        assert "Unknown" in unknown.class_name


class TestEndpointDescriptor:
    """Tests for EndpointDescriptor."""

    def test_direction(self) -> None:
        """Test endpoint direction property."""
        ep_in = EndpointDescriptor(
            address=0x81,
            attributes=0x03,
            max_packet_size=8,
            interval=10,
        )
        assert ep_in.direction == "IN"

        ep_out = EndpointDescriptor(
            address=0x01,
            attributes=0x03,
            max_packet_size=8,
            interval=10,
        )
        assert ep_out.direction == "OUT"

    def test_transfer_type(self) -> None:
        """Test transfer type property."""
        interrupt = EndpointDescriptor(
            address=0x81,
            attributes=0x03,
            max_packet_size=8,
            interval=10,
        )
        assert interrupt.transfer_type == "Interrupt"

        bulk = EndpointDescriptor(
            address=0x82,
            attributes=0x02,
            max_packet_size=512,
            interval=0,
        )
        assert bulk.transfer_type == "Bulk"


class TestUSBEvent:
    """Tests for USBEvent."""

    def test_device_id(self) -> None:
        """Test device_id property."""
        event = USBEvent(
            event_type=EventType.ADD,
            bus=1,
            address=5,
            device_path="/dev/bus/usb/001/005",
            sys_path="/sys/devices/pci0000:00/0000:00:14.0/usb1/1-1",
        )
        assert event.device_id == "1:5"


class TestEventQueue:
    """Tests for EventQueue."""

    @pytest.mark.asyncio
    async def test_put_get(self) -> None:
        """Test basic put and get operations."""
        queue = EventQueue()

        await queue.put("event1")
        await queue.put("event2")

        assert queue.qsize == 2

        event = await queue.get()
        assert event == "event1"
        queue.task_done()

        event = await queue.get()
        assert event == "event2"
        queue.task_done()

        assert queue.empty

    @pytest.mark.asyncio
    async def test_priority_ordering(self) -> None:
        """Test that high priority events are processed first."""
        queue = EventQueue()

        await queue.put("low", EventPriority.LOW)
        await queue.put("high", EventPriority.HIGH)
        await queue.put("normal", EventPriority.NORMAL)

        # Should come out in priority order
        assert await queue.get() == "high"
        queue.task_done()
        assert await queue.get() == "normal"
        queue.task_done()
        assert await queue.get() == "low"
        queue.task_done()

    def test_get_nowait_empty(self) -> None:
        """Test get_nowait on empty queue."""
        queue = EventQueue()
        assert queue.get_nowait() is None

    @pytest.mark.asyncio
    async def test_close(self) -> None:
        """Test queue close behavior."""
        queue = EventQueue()
        queue.close()

        with pytest.raises(RuntimeError):
            await queue.put("event")


class TestEventDispatcher:
    """Tests for EventDispatcher."""

    @pytest.mark.asyncio
    async def test_register_and_dispatch(self) -> None:
        """Test handler registration and dispatch."""
        dispatcher = EventDispatcher()
        results = []

        async def handler(event):
            results.append(event)

        dispatcher.register("test_event", handler)
        await dispatcher.dispatch("test_event", "data")

        assert results == ["data"]

    @pytest.mark.asyncio
    async def test_multiple_handlers(self) -> None:
        """Test multiple handlers for same event."""
        dispatcher = EventDispatcher()
        results = []

        async def handler1(event):
            results.append(f"h1:{event}")

        async def handler2(event):
            results.append(f"h2:{event}")

        dispatcher.register("test", handler1)
        dispatcher.register("test", handler2)
        await dispatcher.dispatch("test", "data")

        assert len(results) == 2
        assert "h1:data" in results
        assert "h2:data" in results

    @pytest.mark.asyncio
    async def test_unregister(self) -> None:
        """Test handler unregistration."""
        dispatcher = EventDispatcher()
        results = []

        async def handler(event):
            results.append(event)

        dispatcher.register("test", handler)
        dispatcher.unregister("test", handler)
        await dispatcher.dispatch("test", "data")

        assert results == []

    @pytest.mark.asyncio
    async def test_handler_error(self) -> None:
        """Test that handler errors don't break dispatch."""
        dispatcher = EventDispatcher()
        results = []

        async def bad_handler(event):
            raise ValueError("Handler error")

        async def good_handler(event):
            results.append(event)

        dispatcher.register("test", bad_handler)
        dispatcher.register("test", good_handler)

        # Should not raise, and good handler should still run
        await dispatcher.dispatch("test", "data")
        assert results == ["data"]


class TestProcessedEvent:
    """Tests for ProcessedEvent."""

    def test_was_allowed(self) -> None:
        """Test was_allowed property."""
        event = ProcessedEvent(
            event=MagicMock(),
            final_verdict="allow",
        )
        assert event.was_allowed is True
        assert event.was_blocked is False

    def test_was_blocked(self) -> None:
        """Test was_blocked property."""
        event = ProcessedEvent(
            event=MagicMock(),
            final_verdict="block",
        )
        assert event.was_blocked is True
        assert event.was_allowed is False


class TestUSBEnumerator:
    """Tests for USBEnumerator."""

    def test_enumerate_all_no_backend(self) -> None:
        """Test enumeration with no USB backend."""
        enumerator = USBEnumerator()

        with patch("usb.core.find") as mock_find:
            mock_find.side_effect = Exception("No backend available")

            with pytest.raises(Exception):
                enumerator.enumerate_all()

    def test_enumerate_all_empty(self) -> None:
        """Test enumeration with no devices."""
        enumerator = USBEnumerator()

        with patch("usb.core.find") as mock_find:
            mock_find.return_value = []
            devices = enumerator.enumerate_all()
            assert devices == []


class TestDeviceAuthorizer:
    """Tests for DeviceAuthorizer."""

    def test_get_device_path_not_found(self, temp_dir: Path) -> None:
        """Test getting path for non-existent device."""
        authorizer = DeviceAuthorizer()

        with patch.object(
            DeviceAuthorizer, "SYSFS_USB_PATH", temp_dir
        ):
            path = authorizer._get_device_path(99, 99)
            assert path is None

    def test_is_authorized_no_device(self) -> None:
        """Test checking authorization for non-existent device."""
        authorizer = DeviceAuthorizer()

        with patch.object(authorizer, "_get_device_path", return_value=None):
            result = authorizer.is_authorized(1, 1)
            assert result is None


class TestUSBInterceptor:
    """Tests for USBInterceptor."""

    def test_init(self) -> None:
        """Test interceptor initialization."""
        interceptor = USBInterceptor(
            block_during_analysis=True,
            analysis_timeout=5.0,
        )
        assert interceptor.block_during_analysis is True
        assert interceptor.analysis_timeout == 5.0

    def test_add_event_handler(self) -> None:
        """Test adding event handlers."""
        interceptor = USBInterceptor()

        def handler(event):
            pass

        interceptor.add_event_handler(handler)
        assert handler in interceptor._event_handlers

        interceptor.remove_event_handler(handler)
        assert handler not in interceptor._event_handlers

    def test_stop(self) -> None:
        """Test stopping interceptor."""
        interceptor = USBInterceptor()
        interceptor.stop()
        assert interceptor.monitor._running is False
