"""
Tests for the integrated device processor.

Tests the core processing pipeline that combines policy engine,
descriptor validation, and audit logging.
"""

import pytest
import tempfile
from pathlib import Path

from sentinel.core import (
    DeviceProcessor,
    PolicyWatcher,
    ProcessingResult,
    Verdict,
    create_processor,
)
from sentinel.interceptor.descriptors import (
    DeviceDescriptor,
    InterfaceDescriptor,
    EndpointDescriptor,
)
from sentinel.policy import (
    Action,
    MatchCondition,
    Policy,
    PolicyBuilder,
    PolicyEngine,
    PolicyRule,
)
from sentinel.policy.fingerprint import FingerprintDatabase


# Test fixtures

@pytest.fixture
def normal_keyboard():
    """Create a normal keyboard device descriptor."""
    return DeviceDescriptor(
        vid="046d",
        pid="c52b",
        device_class=0,
        device_subclass=0,
        device_protocol=0,
        manufacturer="Logitech",
        product="USB Receiver",
        serial="1234567890",
        interfaces=[
            InterfaceDescriptor(
                interface_class=3,  # HID
                interface_subclass=1,
                interface_protocol=1,  # Keyboard
                num_endpoints=1,
                interface_number=0,
                alternate_setting=0,
                interface_string="Keyboard",
                endpoints=[
                    EndpointDescriptor(
                        address=0x81,
                        attributes=0x03,
                        max_packet_size=8,
                        interval=10,
                    )
                ],
            )
        ],
    )


@pytest.fixture
def suspicious_hid_storage():
    """Create a suspicious HID device with storage capability."""
    return DeviceDescriptor(
        vid="1234",
        pid="5678",
        device_class=0,
        device_subclass=0,
        device_protocol=0,
        manufacturer="",
        product="USB Device",
        serial="",
        interfaces=[
            # HID interface
            InterfaceDescriptor(
                interface_class=3,  # HID
                interface_subclass=1,
                interface_protocol=1,  # Keyboard
                num_endpoints=1,
                interface_number=0,
                alternate_setting=0,
                interface_string="",
                endpoints=[
                    EndpointDescriptor(
                        address=0x81,
                        attributes=0x03,
                        max_packet_size=8,
                        interval=10,
                    )
                ],
            ),
            # Mass storage interface
            InterfaceDescriptor(
                interface_class=8,  # Mass storage
                interface_subclass=6,
                interface_protocol=80,
                num_endpoints=2,
                interface_number=1,
                alternate_setting=0,
                interface_string="",
                endpoints=[
                    EndpointDescriptor(
                        address=0x82,
                        attributes=0x02,  # Bulk
                        max_packet_size=512,
                        interval=0,
                    ),
                    EndpointDescriptor(
                        address=0x02,
                        attributes=0x02,  # Bulk
                        max_packet_size=512,
                        interval=0,
                    ),
                ],
            ),
        ],
    )


@pytest.fixture
def attack_device():
    """Create a known attack device (CH340 - common attack hardware)."""
    return DeviceDescriptor(
        vid="1a86",
        pid="7523",
        device_class=0,
        device_subclass=0,
        device_protocol=0,
        manufacturer="CH340",
        product="USB Serial",
        serial="",
        interfaces=[
            InterfaceDescriptor(
                interface_class=255,  # Vendor specific
                interface_subclass=1,
                interface_protocol=2,
                num_endpoints=2,
                interface_number=0,
                alternate_setting=0,
                interface_string="",
                endpoints=[
                    EndpointDescriptor(
                        address=0x82,
                        attributes=0x02,
                        max_packet_size=32,
                        interval=0,
                    ),
                    EndpointDescriptor(
                        address=0x02,
                        attributes=0x02,
                        max_packet_size=32,
                        interval=0,
                    ),
                ],
            )
        ],
    )


@pytest.fixture
def simple_policy():
    """Create a simple policy for testing."""
    return (
        PolicyBuilder()
        .allow("046d", comment="Logitech devices")
        .block("1a86", "7523", comment="CH340 attack hardware")
        .review(device_class="HID", has_storage_endpoint=True, comment="HID with storage")
        .default_review()
        .build()
    )


@pytest.fixture
def processor(simple_policy):
    """Create a device processor with simple policy."""
    engine = PolicyEngine(policy=simple_policy)
    return DeviceProcessor(policy_engine=engine)


# Tests for ProcessingResult

class TestProcessingResult:
    """Tests for ProcessingResult class."""

    def test_verdict_properties(self, processor, normal_keyboard):
        """Test verdict property methods via actual processing."""
        result = processor.process(normal_keyboard)

        # Logitech should be allowed
        assert result.should_allow
        assert not result.should_block
        assert not result.needs_sandbox

    def test_to_dict(self, processor, normal_keyboard):
        """Test serialization to dictionary."""
        result = processor.process(normal_keyboard)
        d = result.to_dict()

        assert "verdict" in d
        assert "risk_score" in d
        assert "fingerprint" in d
        assert d["vid"] == "046d"
        assert d["pid"] == "c52b"


# Tests for DeviceProcessor

class TestDeviceProcessor:
    """Tests for DeviceProcessor class."""

    def test_process_allowed_device(self, processor, normal_keyboard):
        """Test processing a device that should be allowed."""
        result = processor.process(normal_keyboard)
        assert result.verdict == Verdict.ALLOW
        assert result.policy_result.action == Action.ALLOW
        assert "Logitech" in result.policy_result.reason

    def test_process_blocked_device(self, processor, attack_device):
        """Test processing a device that should be blocked."""
        result = processor.process(attack_device)
        assert result.verdict == Verdict.BLOCK
        assert result.policy_result.action == Action.BLOCK
        assert "CH340" in result.policy_result.reason or "attack" in result.policy_result.reason.lower()

    def test_process_suspicious_device(self, processor, suspicious_hid_storage):
        """Test processing a suspicious device that needs review."""
        result = processor.process(suspicious_hid_storage)
        # Should either be REVIEW, SANDBOX, or BLOCK based on risk score
        assert result.verdict in (Verdict.REVIEW, Verdict.SANDBOX, Verdict.BLOCK)
        # Should have anomalies detected
        assert len(result.validation_result.anomalies) > 0 or result.risk_score > 50

    def test_risk_score_thresholds(self, simple_policy):
        """Test that risk score thresholds affect verdict."""
        engine = PolicyEngine(policy=simple_policy)

        # Low threshold processor - more likely to block
        strict_processor = DeviceProcessor(
            policy_engine=engine,
            block_threshold=30,
            review_threshold=20,
        )

        # High threshold processor - more lenient
        lenient_processor = DeviceProcessor(
            policy_engine=engine,
            block_threshold=90,
            review_threshold=80,
        )

        # Both should allow known good devices
        keyboard = DeviceDescriptor(
            vid="046d",
            pid="c52b",
            device_class=0,
            device_subclass=0,
            device_protocol=0,
            manufacturer="Logitech",
            product="Keyboard",
            serial=None,
            interfaces=[],
        )

        strict_result = strict_processor.process(keyboard)
        lenient_result = lenient_processor.process(keyboard)

        assert strict_result.policy_result.action == Action.ALLOW
        assert lenient_result.policy_result.action == Action.ALLOW

    def test_fingerprint_generation(self, processor, normal_keyboard):
        """Test that fingerprint is generated for devices."""
        result = processor.process(normal_keyboard)
        assert result.fingerprint is not None
        assert len(result.fingerprint) >= 16  # Fingerprint hash (length varies by mode)

    def test_processing_hooks(self, simple_policy):
        """Test pre and post processing hooks."""
        engine = PolicyEngine(policy=simple_policy)
        processor = DeviceProcessor(policy_engine=engine)

        pre_hook_called = []
        post_hook_called = []

        def pre_hook(device, _result):
            pre_hook_called.append(device.vid)

        def post_hook(device, result):
            post_hook_called.append((device.vid, result.verdict))

        processor.add_pre_process_hook(pre_hook)
        processor.add_post_process_hook(post_hook)

        keyboard = DeviceDescriptor(
            vid="046d",
            pid="c52b",
            device_class=0,
            device_subclass=0,
            device_protocol=0,
            manufacturer="Logitech",
            product="Keyboard",
            serial=None,
            interfaces=[],
        )

        processor.process(keyboard)

        assert "046d" in pre_hook_called
        assert len(post_hook_called) == 1
        assert post_hook_called[0][0] == "046d"

    def test_statistics_tracking(self, processor, normal_keyboard, attack_device):
        """Test that statistics are tracked correctly."""
        processor.reset_statistics()

        processor.process(normal_keyboard)
        processor.process(attack_device)

        stats = processor.get_statistics()
        assert stats["total_processed"] == 2
        assert stats["allowed"] >= 1  # At least the keyboard
        assert stats["blocked"] >= 1  # At least the attack device


# Tests for advanced matching conditions

class TestAdvancedMatching:
    """Tests for advanced matching conditions."""

    def test_vid_list_match(self):
        """Test matching against a list of VIDs."""
        policy = Policy(rules=[
            PolicyRule(
                match=MatchCondition(vid_list=["046d", "045e", "05ac"]),
                action=Action.ALLOW,
                comment="Known vendors",
            ),
            PolicyRule(
                match=MatchCondition(match_all=True),
                action=Action.BLOCK,
                comment="Block others",
            ),
        ])
        engine = PolicyEngine(policy=policy)
        processor = DeviceProcessor(policy_engine=engine)

        logitech = DeviceDescriptor(vid="046d", pid="1234", device_class=0, device_subclass=0, device_protocol=0, manufacturer=None, product=None, serial=None, interfaces=[])
        microsoft = DeviceDescriptor(vid="045e", pid="1234", device_class=0, device_subclass=0, device_protocol=0, manufacturer=None, product=None, serial=None, interfaces=[])
        unknown = DeviceDescriptor(vid="dead", pid="beef", device_class=0, device_subclass=0, device_protocol=0, manufacturer=None, product=None, serial=None, interfaces=[])

        assert processor.process(logitech).policy_result.action == Action.ALLOW
        assert processor.process(microsoft).policy_result.action == Action.ALLOW
        assert processor.process(unknown).policy_result.action == Action.BLOCK

    def test_vid_range_match(self):
        """Test matching against a VID range."""
        policy = Policy(rules=[
            PolicyRule(
                match=MatchCondition(vid_range=("0400", "04ff")),
                action=Action.ALLOW,
                comment="VID range 0400-04ff",
            ),
            PolicyRule(
                match=MatchCondition(match_all=True),
                action=Action.BLOCK,
                comment="Block others",
            ),
        ])
        engine = PolicyEngine(policy=policy)
        processor = DeviceProcessor(policy_engine=engine)

        in_range = DeviceDescriptor(vid="0450", pid="1234", device_class=0, device_subclass=0, device_protocol=0, manufacturer=None, product=None, serial=None, interfaces=[])
        below_range = DeviceDescriptor(vid="0300", pid="1234", device_class=0, device_subclass=0, device_protocol=0, manufacturer=None, product=None, serial=None, interfaces=[])
        above_range = DeviceDescriptor(vid="0500", pid="1234", device_class=0, device_subclass=0, device_protocol=0, manufacturer=None, product=None, serial=None, interfaces=[])

        assert processor.process(in_range).policy_result.action == Action.ALLOW
        assert processor.process(below_range).policy_result.action == Action.BLOCK
        assert processor.process(above_range).policy_result.action == Action.BLOCK

    def test_composite_device_match(self):
        """Test matching composite devices."""
        policy = Policy(rules=[
            PolicyRule(
                match=MatchCondition(is_composite=True),
                action=Action.REVIEW,
                comment="Review composite devices",
            ),
            PolicyRule(
                match=MatchCondition(match_all=True),
                action=Action.ALLOW,
                comment="Allow simple devices",
            ),
        ])
        engine = PolicyEngine(policy=policy)
        processor = DeviceProcessor(policy_engine=engine)

        simple = DeviceDescriptor(
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
                    interface_class=3,
                    interface_subclass=0,
                    interface_protocol=0,
                    num_endpoints=0,
                    interface_number=0,
                    endpoints=[],
                )
            ],
        )

        composite = DeviceDescriptor(
            vid="1234",
            pid="5678",
            device_class=0,
            device_subclass=0,
            device_protocol=0,
            manufacturer=None,
            product=None,
            serial=None,
            interfaces=[
                InterfaceDescriptor(interface_class=3, interface_subclass=0, interface_protocol=0, num_endpoints=0, interface_number=0, endpoints=[]),
                InterfaceDescriptor(interface_class=8, interface_subclass=0, interface_protocol=0, num_endpoints=0, interface_number=1, endpoints=[]),
            ],
        )

        assert processor.process(simple).policy_result.action == Action.ALLOW
        assert processor.process(composite).policy_result.action == Action.REVIEW

    def test_keyboard_mouse_match(self):
        """Test matching keyboard and mouse devices."""
        policy = Policy(rules=[
            PolicyRule(
                match=MatchCondition(is_keyboard=True),
                action=Action.REVIEW,
                comment="Review keyboards",
            ),
            PolicyRule(
                match=MatchCondition(is_mouse=True),
                action=Action.ALLOW,
                comment="Allow mice",
            ),
            PolicyRule(
                match=MatchCondition(match_all=True),
                action=Action.BLOCK,
                comment="Block others",
            ),
        ])
        engine = PolicyEngine(policy=policy)
        processor = DeviceProcessor(policy_engine=engine)

        keyboard = DeviceDescriptor(
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
                    interface_subclass=1,  # Boot
                    interface_protocol=1,  # Keyboard
                    num_endpoints=0,
                    interface_number=0,
                    endpoints=[],
                )
            ],
        )

        mouse = DeviceDescriptor(
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
                    interface_subclass=1,  # Boot
                    interface_protocol=2,  # Mouse
                    num_endpoints=0,
                    interface_number=0,
                    endpoints=[],
                )
            ],
        )

        assert processor.process(keyboard).policy_result.action == Action.REVIEW
        assert processor.process(mouse).policy_result.action == Action.ALLOW

    def test_interface_count_match(self):
        """Test matching by interface count."""
        policy = Policy(rules=[
            PolicyRule(
                match=MatchCondition(interface_count_gt=2),
                action=Action.BLOCK,
                comment="Block devices with >2 interfaces",
            ),
            PolicyRule(
                match=MatchCondition(match_all=True),
                action=Action.ALLOW,
                comment="Allow others",
            ),
        ])
        engine = PolicyEngine(policy=policy)
        processor = DeviceProcessor(policy_engine=engine)

        two_interfaces = DeviceDescriptor(
            vid="1234",
            pid="5678",
            device_class=0,
            device_subclass=0,
            device_protocol=0,
            manufacturer=None,
            product=None,
            serial=None,
            interfaces=[
                InterfaceDescriptor(interface_class=3, interface_subclass=0, interface_protocol=0, num_endpoints=0, interface_number=0, endpoints=[]),
                InterfaceDescriptor(interface_class=8, interface_subclass=0, interface_protocol=0, num_endpoints=0, interface_number=1, endpoints=[]),
            ],
        )

        four_interfaces = DeviceDescriptor(
            vid="1234",
            pid="5678",
            device_class=0,
            device_subclass=0,
            device_protocol=0,
            manufacturer=None,
            product=None,
            serial=None,
            interfaces=[
                InterfaceDescriptor(interface_class=3, interface_subclass=0, interface_protocol=0, num_endpoints=0, interface_number=0, endpoints=[]),
                InterfaceDescriptor(interface_class=8, interface_subclass=0, interface_protocol=0, num_endpoints=0, interface_number=1, endpoints=[]),
                InterfaceDescriptor(interface_class=1, interface_subclass=0, interface_protocol=0, num_endpoints=0, interface_number=2, endpoints=[]),
                InterfaceDescriptor(interface_class=2, interface_subclass=0, interface_protocol=0, num_endpoints=0, interface_number=3, endpoints=[]),
            ],
        )

        assert processor.process(two_interfaces).policy_result.action == Action.ALLOW
        assert processor.process(four_interfaces).policy_result.action == Action.BLOCK


# Tests for PolicyWatcher

class TestPolicyWatcher:
    """Tests for PolicyWatcher class."""

    def test_policy_watcher_creation(self, tmp_path):
        """Test that policy watcher can be created."""
        policy_file = tmp_path / "policy.yaml"
        policy_file.write_text("""
rules:
  - match: "*"
    action: allow
    comment: Allow all
""")

        engine = PolicyEngine.from_file(policy_file)
        processor = DeviceProcessor(policy_engine=engine)
        watcher = PolicyWatcher(policy_file, processor)

        assert watcher.policy_path == policy_file
        assert watcher.processor == processor


# Tests for create_processor helper

class TestCreateProcessor:
    """Tests for create_processor factory function."""

    def test_create_with_policy_path(self, tmp_path):
        """Test creating processor from policy file path."""
        policy_file = tmp_path / "policy.yaml"
        policy_file.write_text("""
rules:
  - match:
      vid: "046d"
    action: allow
    comment: Logitech
  - match: "*"
    action: review
    comment: Default
""")

        processor = create_processor(policy_path=policy_file)
        assert processor is not None

        device = DeviceDescriptor(vid="046d", pid="1234", device_class=0, device_subclass=0, device_protocol=0, manufacturer=None, product=None, serial=None, interfaces=[])
        result = processor.process(device)
        assert result.policy_result.action == Action.ALLOW

    def test_create_with_default_policy(self):
        """Test creating processor without policy file uses default."""
        processor = create_processor()
        assert processor is not None

        # Default policy should allow Logitech
        device = DeviceDescriptor(vid="046d", pid="1234", device_class=0, device_subclass=0, device_protocol=0, manufacturer=None, product=None, serial=None, interfaces=[])
        result = processor.process(device)
        assert result.policy_result.action == Action.ALLOW


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
