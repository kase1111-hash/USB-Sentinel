"""
Tests for the Virtual USB Proxy module (Phase 8).

Tests USB/IP wrapper, traffic capture, HID analysis, and sandbox behaviors.
"""

import time
import pytest
from datetime import datetime

from sentinel.proxy import (
    # USB/IP
    MockUSBIPProxy,
    ProxyDevice,
    ProxyStatus,
    USBIPConfig,
    USBIPError,
    create_proxy,
    # Capture
    CaptureFile,
    CaptureSession,
    Direction,
    MockUSBTrafficCapture,
    TransferType,
    URBType,
    USBPacket,
    create_capture,
    # HID
    HIDAnalyzer,
    Keystroke,
    KeystrokeAnalysis,
    KeystrokeSequence,
    ModifierKey,
    analyze_hid_traffic,
    create_mock_keystrokes,
    decode_keystrokes,
    detect_modifier_patterns,
    extract_keystrokes,
    # Sandbox
    DeviceSandbox,
    ModifierBlocker,
    ReEnumerationDetector,
    SandboxAction,
    SandboxConfig,
    SandboxManager,
)


# ============================================================================
# USB/IP Proxy Tests
# ============================================================================


class TestUSBIPProxy:
    """Tests for USB/IP proxy functionality."""

    def test_create_mock_proxy(self):
        """Test creating a mock proxy."""
        proxy = create_proxy(use_mock=True)
        assert isinstance(proxy, MockUSBIPProxy)
        assert proxy.check_available()

    def test_mock_list_devices(self):
        """Test listing mock devices."""
        proxy = MockUSBIPProxy()
        devices = proxy.list_local_devices()
        assert len(devices) >= 1
        assert "bus_id" in devices[0]
        assert "vid" in devices[0]
        assert "pid" in devices[0]

    def test_mock_bind_device(self):
        """Test binding a mock device."""
        proxy = MockUSBIPProxy()
        devices = proxy.list_local_devices()
        bus_id = devices[0]["bus_id"]

        device = proxy.bind_device(bus_id)
        assert device.status == ProxyStatus.BOUND
        assert device.vid == devices[0]["vid"]
        assert device.pid == devices[0]["pid"]

    def test_mock_bind_nonexistent_device(self):
        """Test binding a non-existent device."""
        proxy = MockUSBIPProxy()
        with pytest.raises(USBIPError):
            proxy.bind_device("99-99")

    def test_mock_attach_device(self):
        """Test attaching a mock device."""
        proxy = MockUSBIPProxy()
        device = proxy.attach_device("localhost", "1-1")

        assert device.status == ProxyStatus.ATTACHED
        assert device.remote_host == "localhost"
        assert device.local_port is not None
        assert device.attached_at is not None

    def test_mock_detach_device(self):
        """Test detaching a mock device."""
        proxy = MockUSBIPProxy()
        device = proxy.attach_device("localhost", "1-1")
        port = device.local_port

        result = proxy.detach_device(port)
        assert result is True

        device = proxy.get_device("1-1")
        assert device.status == ProxyStatus.UNBOUND

    def test_mock_list_attached(self):
        """Test listing attached devices."""
        proxy = MockUSBIPProxy()
        proxy.attach_device("localhost", "1-1")
        proxy.attach_device("localhost", "1-2")

        attached = proxy.list_attached()
        assert len(attached) == 2

    def test_mock_statistics(self):
        """Test proxy statistics."""
        proxy = MockUSBIPProxy()
        proxy.bind_device("1-1")
        proxy.attach_device("localhost", "1-2")

        stats = proxy.get_statistics()
        assert stats["bind_count"] == 1
        assert stats["attach_count"] == 1
        assert stats["mock"] is True

    def test_mock_cleanup(self):
        """Test proxy cleanup."""
        proxy = MockUSBIPProxy()
        proxy.bind_device("1-1")
        proxy.attach_device("localhost", "1-2")

        proxy.cleanup()
        assert len(proxy.get_all_devices()) == 0


class TestProxyDevice:
    """Tests for ProxyDevice dataclass."""

    def test_device_id(self):
        """Test device_id property."""
        device = ProxyDevice(
            bus_id="1-1",
            vid="046d",
            pid="c52b",
        )
        assert device.device_id == "046d:c52b"

    def test_to_dict(self):
        """Test to_dict conversion."""
        device = ProxyDevice(
            bus_id="1-1",
            vid="046d",
            pid="c52b",
            status=ProxyStatus.ATTACHED,
            local_port=3240,
            attached_at=datetime.utcnow(),
        )
        d = device.to_dict()
        assert d["bus_id"] == "1-1"
        assert d["vid"] == "046d"
        assert d["status"] == "attached"


# ============================================================================
# Traffic Capture Tests
# ============================================================================


class TestUSBPacket:
    """Tests for USBPacket dataclass."""

    def test_endpoint_address_in(self):
        """Test endpoint address with IN direction."""
        packet = USBPacket(
            timestamp=0,
            urb_type=URBType.COMPLETE,
            bus_num=1,
            device_num=1,
            endpoint=1,
            transfer_type=TransferType.INTERRUPT,
            direction=Direction.IN,
            status=0,
            length=8,
        )
        assert packet.endpoint_address == 0x81  # 0x80 | 0x01

    def test_endpoint_address_out(self):
        """Test endpoint address with OUT direction."""
        packet = USBPacket(
            timestamp=0,
            urb_type=URBType.COMPLETE,
            bus_num=1,
            device_num=1,
            endpoint=2,
            transfer_type=TransferType.BULK,
            direction=Direction.OUT,
            status=0,
            length=64,
        )
        assert packet.endpoint_address == 0x02

    def test_is_hid(self):
        """Test HID detection."""
        packet = USBPacket(
            timestamp=0,
            urb_type=URBType.COMPLETE,
            bus_num=1,
            device_num=1,
            endpoint=1,
            transfer_type=TransferType.INTERRUPT,
            direction=Direction.IN,
            status=0,
            length=8,
        )
        assert packet.is_hid is True

    def test_to_dict(self):
        """Test packet to_dict."""
        packet = USBPacket(
            timestamp=1234.5,
            urb_type=URBType.COMPLETE,
            bus_num=1,
            device_num=2,
            endpoint=1,
            transfer_type=TransferType.INTERRUPT,
            direction=Direction.IN,
            status=0,
            length=8,
            data=b"\x00\x00\x04\x00\x00\x00\x00\x00",
        )
        d = packet.to_dict()
        assert d["timestamp"] == 1234.5
        assert d["transfer_type"] == "INTERRUPT"
        assert d["data_hex"] == "0000040000000000"


class TestMockCapture:
    """Tests for mock traffic capture."""

    def test_create_mock_capture(self):
        """Test creating mock capture."""
        capture = create_capture(use_mock=True)
        assert isinstance(capture, MockUSBTrafficCapture)
        assert capture.check_available()

    def test_mock_start_stop(self):
        """Test starting and stopping mock capture."""
        capture = MockUSBTrafficCapture()
        session = capture.start_capture()

        assert session is not None
        assert capture.is_capturing

        packets = capture.stop_capture()
        assert not capture.is_capturing
        assert isinstance(packets, list)

    def test_add_mock_packet(self):
        """Test adding mock packets."""
        capture = MockUSBTrafficCapture()
        capture.start_capture()

        capture.add_mock_packet(b"\x00\x00\x04\x00\x00\x00\x00\x00")
        capture.add_mock_packet(b"\x00\x00\x05\x00\x00\x00\x00\x00")

        packets = capture.stop_capture()
        assert len(packets) == 2

    def test_add_hid_keystroke(self):
        """Test adding mock HID keystrokes."""
        capture = MockUSBTrafficCapture()
        capture.start_capture()

        capture.add_hid_keystroke(modifier=0, keycode=0x04)  # 'a'
        capture.add_hid_keystroke(modifier=0, keycode=0x05)  # 'b'

        packets = capture.stop_capture()
        assert len(packets) == 2
        assert packets[0].data[2] == 0x04
        assert packets[1].data[2] == 0x05


class TestCaptureSession:
    """Tests for capture session."""

    def test_session_creation(self):
        """Test session creation."""
        session = CaptureSession(
            session_id="test123",
            bus_num=1,
            device_num=2,
            started_at=datetime.utcnow(),
        )
        assert session.session_id == "test123"
        assert session.packet_count == 0


# ============================================================================
# HID Analysis Tests
# ============================================================================


class TestModifierKey:
    """Tests for ModifierKey flags."""

    def test_modifier_combinations(self):
        """Test modifier combinations."""
        ctrl_shift = ModifierKey.LEFT_CTRL | ModifierKey.LEFT_SHIFT
        assert ctrl_shift & ModifierKey.CTRL
        assert ctrl_shift & ModifierKey.SHIFT
        assert not (ctrl_shift & ModifierKey.ALT)

    def test_gui_key(self):
        """Test GUI key detection."""
        left_gui = ModifierKey.LEFT_GUI
        assert left_gui & ModifierKey.GUI


class TestKeystroke:
    """Tests for Keystroke class."""

    def test_keystroke_char(self):
        """Test keystroke character conversion."""
        ks = Keystroke(
            timestamp=0,
            modifier=ModifierKey.NONE,
            keycode=0x04,  # 'a'
            is_press=True,
        )
        assert ks.char == 'a'

    def test_keystroke_shifted_char(self):
        """Test shifted keystroke."""
        ks = Keystroke(
            timestamp=0,
            modifier=ModifierKey.LEFT_SHIFT,
            keycode=0x04,  # 'A'
            is_press=True,
        )
        assert ks.char == 'A'

    def test_modifier_names(self):
        """Test modifier name extraction."""
        ks = Keystroke(
            timestamp=0,
            modifier=ModifierKey.LEFT_CTRL | ModifierKey.LEFT_ALT,
            keycode=0x04,
            is_press=True,
        )
        names = ks.modifier_names
        assert "CTRL" in names
        assert "ALT" in names


class TestKeystrokeSequence:
    """Tests for KeystrokeSequence."""

    def test_intervals(self):
        """Test interval calculation."""
        keystrokes = [
            Keystroke(timestamp=0.0, modifier=ModifierKey.NONE, keycode=0x04, is_press=True),
            Keystroke(timestamp=0.05, modifier=ModifierKey.NONE, keycode=0x05, is_press=True),
            Keystroke(timestamp=0.10, modifier=ModifierKey.NONE, keycode=0x06, is_press=True),
        ]
        seq = KeystrokeSequence(keystrokes=keystrokes)

        intervals = seq.intervals
        assert len(intervals) == 2
        assert abs(intervals[0] - 50.0) < 1  # ~50ms

    def test_avg_interval(self):
        """Test average interval calculation."""
        keystrokes = [
            Keystroke(timestamp=0.0, modifier=ModifierKey.NONE, keycode=0x04, is_press=True),
            Keystroke(timestamp=0.050, modifier=ModifierKey.NONE, keycode=0x05, is_press=True),
            Keystroke(timestamp=0.100, modifier=ModifierKey.NONE, keycode=0x06, is_press=True),
        ]
        seq = KeystrokeSequence(keystrokes=keystrokes)
        assert abs(seq.avg_interval_ms - 50.0) < 1

    def test_duration(self):
        """Test duration calculation."""
        keystrokes = [
            Keystroke(timestamp=0.0, modifier=ModifierKey.NONE, keycode=0x04, is_press=True),
            Keystroke(timestamp=1.0, modifier=ModifierKey.NONE, keycode=0x05, is_press=True),
        ]
        seq = KeystrokeSequence(keystrokes=keystrokes)
        assert abs(seq.duration_ms - 1000.0) < 1


class TestDecodeKeystrokes:
    """Tests for keystroke decoding."""

    def test_decode_simple_text(self):
        """Test decoding simple text."""
        keystrokes = create_mock_keystrokes("hello", interval_ms=50)
        text = decode_keystrokes(keystrokes)
        assert text == "hello"

    def test_decode_with_shift(self):
        """Test decoding with explicit shift modifier."""
        # Create manual keystrokes with shift for uppercase
        keystrokes = [
            Keystroke(timestamp=0.0, modifier=ModifierKey.LEFT_SHIFT, keycode=0x0B, is_press=True),  # 'H'
            Keystroke(timestamp=0.05, modifier=ModifierKey.NONE, keycode=0x08, is_press=True),  # 'e'
            Keystroke(timestamp=0.10, modifier=ModifierKey.NONE, keycode=0x0F, is_press=True),  # 'l'
            Keystroke(timestamp=0.15, modifier=ModifierKey.NONE, keycode=0x0F, is_press=True),  # 'l'
            Keystroke(timestamp=0.20, modifier=ModifierKey.NONE, keycode=0x12, is_press=True),  # 'o'
        ]
        text = decode_keystrokes(keystrokes)
        assert text == "Hello"


class TestDetectModifierPatterns:
    """Tests for modifier pattern detection."""

    def test_detect_gui_r(self):
        """Test detection of GUI+R pattern."""
        keystrokes = [
            Keystroke(
                timestamp=0,
                modifier=ModifierKey.LEFT_GUI,
                keycode=0x15,  # 'r'
                is_press=True,
            )
        ]
        patterns = detect_modifier_patterns(keystrokes)
        assert len(patterns) > 0
        assert any("GUI" in p for p in patterns)


class TestAnalyzeHIDTraffic:
    """Tests for full HID traffic analysis."""

    def test_analyze_normal_typing(self):
        """Test analysis of normal typing speed."""
        capture = MockUSBTrafficCapture()
        capture.start_capture()

        # Add keystrokes at normal speed (100ms apart = 10 keys/sec, well under 20/sec threshold)
        for keycode in [0x04, 0x05, 0x06, 0x07]:  # a, b, c, d
            capture.add_hid_keystroke(modifier=0, keycode=keycode, delay_ms=100)

        packets = capture.stop_capture()
        analysis = analyze_hid_traffic(packets)

        assert analysis.keystroke_count >= 4
        assert not analysis.is_suspicious
        assert analysis.risk_score < 50

    def test_analyze_superhuman_typing(self):
        """Test detection of superhuman typing speed."""
        capture = MockUSBTrafficCapture()
        capture.start_capture()

        # Add keystrokes at superhuman speed (5ms apart)
        for keycode in [0x04, 0x05, 0x06, 0x07, 0x08]:
            capture.add_hid_keystroke(modifier=0, keycode=keycode, delay_ms=5)

        packets = capture.stop_capture()
        analysis = analyze_hid_traffic(packets)

        assert analysis.is_suspicious
        assert analysis.min_interval_ms < 10
        assert analysis.risk_score >= 40
        assert any("superhuman" in r.lower() for r in analysis.suspicion_reasons)

    def test_analyze_gui_combo(self):
        """Test detection of GUI key combinations."""
        capture = MockUSBTrafficCapture()
        capture.start_capture()

        # Add GUI+R keystroke
        packet = USBPacket(
            timestamp=time.time(),
            urb_type=URBType.COMPLETE,
            bus_num=1,
            device_num=1,
            endpoint=1,
            transfer_type=TransferType.INTERRUPT,
            direction=Direction.IN,
            status=0,
            length=8,
            data=bytes([ModifierKey.LEFT_GUI, 0, 0x15, 0, 0, 0, 0, 0]),  # GUI+R
        )
        capture._packets.append(packet)

        packets = capture.stop_capture()
        analysis = analyze_hid_traffic(packets)

        assert len(analysis.modifier_sequences) > 0

    def test_analysis_to_dict(self):
        """Test analysis to_dict conversion."""
        capture = MockUSBTrafficCapture()
        capture.start_capture()
        capture.add_hid_keystroke(modifier=0, keycode=0x04, delay_ms=50)
        packets = capture.stop_capture()

        analysis = analyze_hid_traffic(packets)
        d = analysis.to_dict()

        assert "avg_interval_ms" in d
        assert "is_suspicious" in d
        assert "risk_score" in d


class TestHIDAnalyzer:
    """Tests for HIDAnalyzer class."""

    def test_analyzer_statistics(self):
        """Test analyzer statistics tracking."""
        analyzer = HIDAnalyzer()

        capture = MockUSBTrafficCapture()
        capture.start_capture()
        capture.add_hid_keystroke(modifier=0, keycode=0x04, delay_ms=50)
        packets = capture.stop_capture()

        analyzer.analyze(packets)
        analyzer.analyze(packets)

        stats = analyzer.get_statistics()
        assert stats["analysis_count"] == 2


# ============================================================================
# Sandbox Tests
# ============================================================================


class TestModifierBlocker:
    """Tests for modifier blocker."""

    def test_block_gui_r(self):
        """Test blocking GUI+R."""
        blocker = ModifierBlocker(enabled=True)

        # GUI+R report
        data = bytes([ModifierKey.LEFT_GUI, 0, 0x15, 0, 0, 0, 0, 0])
        should_block, reason = blocker.check(data)

        assert should_block
        assert reason is not None

    def test_allow_normal_keystroke(self):
        """Test allowing normal keystrokes."""
        blocker = ModifierBlocker(enabled=True)

        # Normal 'a' keystroke
        data = bytes([0, 0, 0x04, 0, 0, 0, 0, 0])
        should_block, reason = blocker.check(data)

        assert not should_block
        assert reason is None

    def test_disabled_blocker(self):
        """Test disabled blocker passes everything."""
        blocker = ModifierBlocker(enabled=False)

        # GUI+R report
        data = bytes([ModifierKey.LEFT_GUI, 0, 0x15, 0, 0, 0, 0, 0])
        should_block, _ = blocker.check(data)

        assert not should_block


class TestReEnumerationDetector:
    """Tests for re-enumeration detector."""

    def test_single_reset_ok(self):
        """Test single reset is OK."""
        detector = ReEnumerationDetector(
            max_resets_per_minute=3,
            detection_window_sec=60,
        )

        result = detector.record_reset()
        assert not result  # Not an attack

    def test_multiple_resets_detected(self):
        """Test multiple resets are detected."""
        detector = ReEnumerationDetector(
            max_resets_per_minute=2,
            detection_window_sec=60,
        )

        detector.record_reset()
        detector.record_reset()
        result = detector.record_reset()  # Third reset

        assert result  # Attack detected
        assert detector.get_detection_count() == 1


class TestDeviceSandbox:
    """Tests for device sandbox."""

    def test_sandbox_creation(self):
        """Test sandbox creation."""
        sandbox = DeviceSandbox(device_id="test-device")
        assert sandbox.device_id == "test-device"

    def test_process_normal_keystroke(self):
        """Test processing normal keystroke."""
        sandbox = DeviceSandbox(device_id="test")

        # Normal 'a' keystroke
        data = bytes([0, 0, 0x04, 0, 0, 0, 0, 0])
        action, modified_data, delay = sandbox.process_hid_report(data)

        assert action == SandboxAction.ALLOW
        assert modified_data == data
        assert delay == 0.0

    def test_block_modifier_combo(self):
        """Test blocking modifier combination."""
        config = SandboxConfig(enable_modifier_blocking=True)
        sandbox = DeviceSandbox(device_id="test", config=config)

        # GUI+R keystroke
        data = bytes([ModifierKey.LEFT_GUI, 0, 0x15, 0, 0, 0, 0, 0])
        action, modified_data, delay = sandbox.process_hid_report(data)

        assert action == SandboxAction.BLOCK
        assert modified_data == b""

    def test_sandbox_statistics(self):
        """Test sandbox statistics tracking."""
        sandbox = DeviceSandbox(device_id="test")

        # Process some keystrokes
        for _ in range(5):
            data = bytes([0, 0, 0x04, 0, 0, 0, 0, 0])
            sandbox.process_hid_report(data)

        stats = sandbox.get_statistics()
        assert stats["total_packets"] == 5
        assert stats["device_id"] == "test"

    def test_sandbox_deactivation(self):
        """Test sandbox deactivation (pass-through mode)."""
        config = SandboxConfig(enable_modifier_blocking=True)
        sandbox = DeviceSandbox(device_id="test", config=config)

        sandbox.deactivate()

        # GUI+R should now pass through
        data = bytes([ModifierKey.LEFT_GUI, 0, 0x15, 0, 0, 0, 0, 0])
        action, modified_data, _ = sandbox.process_hid_report(data)

        assert action == SandboxAction.ALLOW
        assert modified_data == data


class TestSandboxManager:
    """Tests for sandbox manager."""

    def test_create_sandbox(self):
        """Test creating sandbox through manager."""
        manager = SandboxManager()
        sandbox = manager.create_sandbox("device-1")

        assert sandbox is not None
        assert sandbox.device_id == "device-1"

    def test_get_existing_sandbox(self):
        """Test getting existing sandbox."""
        manager = SandboxManager()
        sandbox1 = manager.create_sandbox("device-1")
        sandbox2 = manager.create_sandbox("device-1")

        assert sandbox1 is sandbox2

    def test_remove_sandbox(self):
        """Test removing sandbox."""
        manager = SandboxManager()
        manager.create_sandbox("device-1")

        result = manager.remove_sandbox("device-1")
        assert result is True

        assert manager.get_sandbox("device-1") is None

    def test_manager_statistics(self):
        """Test manager statistics."""
        manager = SandboxManager()
        manager.create_sandbox("device-1")
        manager.create_sandbox("device-2")

        stats = manager.get_statistics()
        assert stats["sandbox_count"] == 2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
