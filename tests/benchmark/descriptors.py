"""
Benchmark descriptor dataset for evaluating detection accuracy.

Contains 25 malicious and 25 benign USB device descriptors modeled
after real-world hardware.  Each entry carries a ground-truth label
so the benchmark harness can compute TP / FP / TN / FN.
"""

from __future__ import annotations

from dataclasses import dataclass

from sentinel.interceptor.descriptors import (
    DeviceDescriptor,
    EndpointDescriptor,
    InterfaceDescriptor,
)


@dataclass
class LabeledDescriptor:
    """A device descriptor annotated with ground truth."""

    descriptor: DeviceDescriptor
    is_malicious: bool
    name: str
    attack_type: str | None = None  # e.g. "keystroke_injection", "class_spoofing"


# ---------------------------------------------------------------------------
# Helper builders
# ---------------------------------------------------------------------------

def _intf(cls: int, sub: int = 0, proto: int = 0, num_ep: int = 1,
          eps: list[EndpointDescriptor] | None = None) -> InterfaceDescriptor:
    """Shorthand for building an InterfaceDescriptor."""
    if eps is None:
        eps = [EndpointDescriptor(address=0x81, attributes=0x03,
                                  max_packet_size=8, interval=10)]
        # pad to match num_ep
        while len(eps) < num_ep:
            eps.append(EndpointDescriptor(
                address=0x81 + len(eps), attributes=0x03,
                max_packet_size=8, interval=10,
            ))
    return InterfaceDescriptor(
        interface_class=cls,
        interface_subclass=sub,
        interface_protocol=proto,
        num_endpoints=num_ep,
        endpoints=eps,
    )


def _bulk_ep(addr: int = 0x81) -> EndpointDescriptor:
    """Create a bulk transfer endpoint."""
    return EndpointDescriptor(address=addr, attributes=0x02,
                              max_packet_size=512, interval=0)


def _intr_ep(addr: int = 0x81) -> EndpointDescriptor:
    """Create an interrupt transfer endpoint."""
    return EndpointDescriptor(address=addr, attributes=0x03,
                              max_packet_size=8, interval=10)


def _desc(vid: str, pid: str, mfr: str | None, prod: str | None,
          intfs: list[InterfaceDescriptor],
          dev_class: int = 0, serial: str | None = None) -> DeviceDescriptor:
    return DeviceDescriptor(
        vid=vid, pid=pid,
        device_class=dev_class, device_subclass=0, device_protocol=0,
        manufacturer=mfr, product=prod, serial=serial,
        interfaces=intfs,
    )


# =========================================================================
# MALICIOUS DESCRIPTORS  (25)
# =========================================================================

MALICIOUS: list[LabeledDescriptor] = [
    # --- 1. Rubber Ducky (Atmel DFU VID:PID, HID keyboard) ---
    LabeledDescriptor(
        name="Rubber Ducky classic",
        is_malicious=True,
        attack_type="keystroke_injection",
        descriptor=_desc(
            vid="03eb", pid="2ff4", mfr="Atmel Corp.", prod="ATmega32U4",
            intfs=[_intf(0x03, 0x01, 0x01)],  # HID keyboard
        ),
    ),
    # --- 2. BadUSB: mass-storage claiming HID ---
    LabeledDescriptor(
        name="BadUSB HID+Storage",
        is_malicious=True,
        attack_type="class_spoofing",
        descriptor=_desc(
            vid="abcd", pid="1234", mfr=None, prod="USB Composite Device",
            intfs=[
                _intf(0x03, 0x01, 0x01),  # HID keyboard
                _intf(0x08, 0x06, 0x50, num_ep=2,
                      eps=[_bulk_ep(0x81), _bulk_ep(0x02)]),  # mass storage
            ],
        ),
    ),
    # --- 3. Vendor-string mismatch (claims Logitech, VID is generic) ---
    LabeledDescriptor(
        name="Vendor mismatch (fake Logitech VID)",
        is_malicious=True,
        attack_type="vendor_spoofing",
        descriptor=_desc(
            vid="046d", pid="ffff", mfr="Shenzhen Electronic Co.",
            prod="Wireless Receiver",
            intfs=[_intf(0x03, 0x01, 0x02)],  # HID mouse
        ),
    ),
    # --- 4. CH340 serial adapter (known attack HW) ---
    LabeledDescriptor(
        name="CH340 serial adapter",
        is_malicious=True,
        attack_type="known_signature",
        descriptor=_desc(
            vid="1a86", pid="7523", mfr="QinHeng Electronics",
            prod="CH340 serial converter",
            intfs=[_intf(0xFF, 0x01, 0x02)],  # vendor-specific
        ),
    ),
    # --- 5. Teensy (programmable HID attack board) ---
    LabeledDescriptor(
        name="Teensy HID injector",
        is_malicious=True,
        attack_type="keystroke_injection",
        descriptor=_desc(
            vid="16c0", pid="0483", mfr="Teensy", prod="Teensy Keyboard/Mouse",
            intfs=[
                _intf(0x03, 0x01, 0x01),  # HID keyboard
                _intf(0x03, 0x01, 0x02),  # HID mouse
            ],
        ),
    ),
    # --- 6. Digispark (ATtiny85) ---
    LabeledDescriptor(
        name="Digispark ATtiny85",
        is_malicious=True,
        attack_type="keystroke_injection",
        descriptor=_desc(
            vid="1781", pid="0c9f", mfr="Digispark", prod="DigiUSB",
            intfs=[_intf(0x03, 0x00, 0x00)],
        ),
    ),
    # --- 7. STM32 DFU mode ---
    LabeledDescriptor(
        name="STM32 DFU bootloader",
        is_malicious=True,
        attack_type="firmware_attack",
        descriptor=_desc(
            vid="0483", pid="df11", mfr="STMicroelectronics",
            prod="STM32 BOOTLOADER",
            intfs=[_intf(0xFE, 0x01, 0x02)],  # DFU
        ),
    ),
    # --- 8. Bash Bunny (composite HID+Storage+Network) ---
    LabeledDescriptor(
        name="Bash Bunny",
        is_malicious=True,
        attack_type="multi_vector",
        descriptor=_desc(
            vid="f000", pid="ff01", mfr="Hak5", prod="Bash Bunny",
            intfs=[
                _intf(0x03, 0x01, 0x01),       # HID keyboard
                _intf(0x08, 0x06, 0x50, num_ep=2,
                      eps=[_bulk_ep(0x81), _bulk_ep(0x02)]),
                _intf(0x02, 0x06, 0x00),        # CDC (network)
            ],
        ),
    ),
    # --- 9. LAN Turtle ---
    LabeledDescriptor(
        name="LAN Turtle",
        is_malicious=True,
        attack_type="network_attack",
        descriptor=_desc(
            vid="f000", pid="ff02", mfr="Hak5", prod="LAN Turtle",
            intfs=[
                _intf(0x02, 0x06, 0x00),        # CDC ethernet
                _intf(0x0A, 0x00, 0x00),         # CDC-Data
            ],
        ),
    ),
    # --- 10. P4wnP1 (Raspberry Pi HID) ---
    LabeledDescriptor(
        name="P4wnP1 HID attack",
        is_malicious=True,
        attack_type="keystroke_injection",
        descriptor=_desc(
            vid="1d6b", pid="0104", mfr="P4wnP1 by MaMe82",
            prod="P4wnP1 HID Keyboard",
            intfs=[_intf(0x03, 0x01, 0x01)],  # HID keyboard
        ),
    ),
    # --- 11. Arduino Leonardo (HID attack platform) ---
    LabeledDescriptor(
        name="Arduino Leonardo HID",
        is_malicious=True,
        attack_type="keystroke_injection",
        descriptor=_desc(
            vid="2341", pid="8036", mfr="Arduino LLC",
            prod="Arduino Leonardo",
            intfs=[
                _intf(0x02, 0x02, 0x01),       # CDC
                _intf(0x0A, 0x00, 0x00),        # CDC-Data
                _intf(0x03, 0x01, 0x01),        # HID keyboard
            ],
        ),
    ),
    # --- 12. HID with bulk endpoint (data exfiltration) ---
    LabeledDescriptor(
        name="HID with bulk endpoint",
        is_malicious=True,
        attack_type="data_exfiltration",
        descriptor=_desc(
            vid="1234", pid="5678", mfr=None, prod="USB Input Device",
            intfs=[_intf(0x03, 0x00, 0x00, num_ep=1,
                         eps=[_bulk_ep(0x81)])],  # HID with bulk = suspicious
        ),
    ),
    # --- 13. Class mismatch (device_class != interface) ---
    LabeledDescriptor(
        name="Device class mismatch",
        is_malicious=True,
        attack_type="class_spoofing",
        descriptor=_desc(
            vid="dead", pid="cafe", mfr="Unknown", prod="USB Device",
            intfs=[_intf(0x03, 0x01, 0x01)],
            dev_class=0x08,  # claims mass-storage at device level
        ),
    ),
    # --- 14. Excessive endpoints on HID ---
    LabeledDescriptor(
        name="HID with excessive endpoints",
        is_malicious=True,
        attack_type="anomalous_descriptor",
        descriptor=_desc(
            vid="cafe", pid="babe", mfr="Suspicious Co", prod="Keyboard Pro",
            intfs=[_intf(0x03, 0x01, 0x01, num_ep=5)],  # HID expects 1-2
        ),
    ),
    # --- 15. USB Armory ---
    LabeledDescriptor(
        name="USB Armory",
        is_malicious=True,
        attack_type="multi_vector",
        descriptor=_desc(
            vid="1d6b", pid="0104", mfr="USB Armory Team",
            prod="USB Armory Mk II",
            intfs=[
                _intf(0x02, 0x06, 0x00),        # CDC
                _intf(0x0A, 0x00, 0x00),         # CDC-Data
                _intf(0x08, 0x06, 0x50, num_ep=2,
                      eps=[_bulk_ep(0x81), _bulk_ep(0x02)]),
            ],
        ),
    ),
    # --- 16. Keyboard with CDC (serial+keyboard attack) ---
    LabeledDescriptor(
        name="CDC+Keyboard combo",
        is_malicious=True,
        attack_type="multi_vector",
        descriptor=_desc(
            vid="2e8a", pid="000a", mfr="Raspberry Pi",
            prod="Pico HID Payload",
            intfs=[
                _intf(0x02, 0x02, 0x01),        # CDC
                _intf(0x03, 0x01, 0x01),         # HID keyboard
            ],
        ),
    ),
    # --- 17. No-manufacturer HID keyboard ---
    LabeledDescriptor(
        name="Anonymous HID keyboard",
        is_malicious=True,
        attack_type="anonymous_device",
        descriptor=_desc(
            vid="0000", pid="0001", mfr=None, prod=None,
            intfs=[_intf(0x03, 0x01, 0x01)],
        ),
    ),
    # --- 18. Vendor-specific class pretending to be normal ---
    LabeledDescriptor(
        name="Vendor-specific masquerade",
        is_malicious=True,
        attack_type="class_spoofing",
        descriptor=_desc(
            vid="beef", pid="dead", mfr=None, prod="USB Device",
            intfs=[
                _intf(0xFF, 0x00, 0x00),         # vendor-specific
                _intf(0x03, 0x01, 0x01),         # HID keyboard
            ],
        ),
    ),
    # --- 19. Fake Microsoft VID ---
    LabeledDescriptor(
        name="Fake Microsoft keyboard",
        is_malicious=True,
        attack_type="vendor_spoofing",
        descriptor=_desc(
            vid="045e", pid="ffff", mfr="Generic Manufacturer",
            prod="USB Keyboard",
            intfs=[_intf(0x03, 0x01, 0x01)],
        ),
    ),
    # --- 20. HID+Storage+Vendor-specific (triple threat) ---
    LabeledDescriptor(
        name="Triple-class attack",
        is_malicious=True,
        attack_type="multi_vector",
        descriptor=_desc(
            vid="1337", pid="1337", mfr=None, prod="Multi Device",
            intfs=[
                _intf(0x03, 0x00, 0x00),
                _intf(0x08, 0x06, 0x50, num_ep=2,
                      eps=[_bulk_ep(0x81), _bulk_ep(0x02)]),
                _intf(0xFF, 0x00, 0x00),
            ],
        ),
    ),
    # --- 21. Fake Apple VID ---
    LabeledDescriptor(
        name="Fake Apple keyboard",
        is_malicious=True,
        attack_type="vendor_spoofing",
        descriptor=_desc(
            vid="05ac", pid="0000", mfr="Shenzhen Keyboard Co.",
            prod="Apple Keyboard",
            intfs=[_intf(0x03, 0x01, 0x01)],
        ),
    ),
    # --- 22. Generic-string HID ---
    LabeledDescriptor(
        name="Generic-string HID",
        is_malicious=True,
        attack_type="anonymous_device",
        descriptor=_desc(
            vid="1111", pid="2222", mfr="USB Device",
            prod="USB Keyboard",
            intfs=[_intf(0x03, 0x01, 0x01)],
        ),
    ),
    # --- 23. 4-interface composite (suspicious complexity) ---
    LabeledDescriptor(
        name="Over-complex composite",
        is_malicious=True,
        attack_type="anomalous_descriptor",
        descriptor=_desc(
            vid="3333", pid="4444", mfr="NoName", prod="Multi Gadget",
            intfs=[
                _intf(0x03, 0x01, 0x01),         # HID keyboard
                _intf(0x03, 0x01, 0x02),         # HID mouse
                _intf(0x08, 0x06, 0x50, num_ep=2,
                      eps=[_bulk_ep(0x81), _bulk_ep(0x02)]),
                _intf(0x02, 0x06, 0x00),         # CDC
            ],
        ),
    ),
    # --- 24. DFU-capable HID ---
    LabeledDescriptor(
        name="DFU-capable HID",
        is_malicious=True,
        attack_type="firmware_attack",
        descriptor=_desc(
            vid="5555", pid="6666", mfr="Unknown", prod="Programmable Keyboard",
            intfs=[
                _intf(0x03, 0x01, 0x01),         # HID keyboard
                _intf(0xFE, 0x01, 0x02),         # DFU
            ],
        ),
    ),
    # --- 25. Rubber Ducky variant (ATmega manufacturer, different VID) ---
    LabeledDescriptor(
        name="Rubber Ducky variant (Atmel name, new VID)",
        is_malicious=True,
        attack_type="keystroke_injection",
        descriptor=_desc(
            vid="aaaa", pid="bbbb", mfr="Atmel Corporation",
            prod="ATxmega128A4U",
            intfs=[_intf(0x03, 0x01, 0x01)],
        ),
    ),
]


# =========================================================================
# BENIGN DESCRIPTORS  (25)
# =========================================================================

BENIGN: list[LabeledDescriptor] = [
    # --- 1. Logitech Unifying Receiver ---
    LabeledDescriptor(
        name="Logitech Unifying Receiver",
        is_malicious=False,
        descriptor=_desc(
            vid="046d", pid="c534", mfr="Logitech", prod="USB Receiver",
            intfs=[
                _intf(0x03, 0x01, 0x01),         # HID keyboard
                _intf(0x03, 0x01, 0x02),         # HID mouse
            ],
        ),
    ),
    # --- 2. Microsoft Sculpt Keyboard ---
    LabeledDescriptor(
        name="Microsoft Sculpt Keyboard",
        is_malicious=False,
        descriptor=_desc(
            vid="045e", pid="07a5", mfr="Microsoft", prod="Microsoft Sculpt",
            intfs=[_intf(0x03, 0x01, 0x01)],
        ),
    ),
    # --- 3. Apple Magic Keyboard ---
    LabeledDescriptor(
        name="Apple Magic Keyboard",
        is_malicious=False,
        descriptor=_desc(
            vid="05ac", pid="024f", mfr="Apple Inc.", prod="Magic Keyboard",
            intfs=[_intf(0x03, 0x01, 0x01)],
        ),
    ),
    # --- 4. Logitech MX Master mouse ---
    LabeledDescriptor(
        name="Logitech MX Master",
        is_malicious=False,
        descriptor=_desc(
            vid="046d", pid="c52b", mfr="Logitech", prod="MX Master 3",
            intfs=[_intf(0x03, 0x01, 0x02)],
        ),
    ),
    # --- 5. Kingston DataTraveler USB 3.0 ---
    LabeledDescriptor(
        name="Kingston DataTraveler 32GB",
        is_malicious=False,
        descriptor=_desc(
            vid="0951", pid="1666", mfr="Kingston", prod="DataTraveler 3.0",
            intfs=[_intf(0x08, 0x06, 0x50, num_ep=2,
                         eps=[_bulk_ep(0x81), _bulk_ep(0x02)])],
        ),
    ),
    # --- 6. SanDisk Cruzer Blade ---
    LabeledDescriptor(
        name="SanDisk Cruzer Blade",
        is_malicious=False,
        descriptor=_desc(
            vid="0781", pid="5567", mfr="SanDisk", prod="Cruzer Blade",
            intfs=[_intf(0x08, 0x06, 0x50, num_ep=2,
                         eps=[_bulk_ep(0x81), _bulk_ep(0x02)])],
        ),
    ),
    # --- 7. Logitech C920 Webcam ---
    LabeledDescriptor(
        name="Logitech C920 Webcam",
        is_malicious=False,
        descriptor=_desc(
            vid="046d", pid="082d", mfr="Logitech", prod="HD Pro Webcam C920",
            intfs=[
                _intf(0x0E, 0x01, 0x00, num_ep=1),  # video control
                _intf(0x0E, 0x02, 0x00, num_ep=1),  # video streaming
                _intf(0x01, 0x01, 0x00, num_ep=1),  # audio control
                _intf(0x01, 0x02, 0x00, num_ep=1),  # audio streaming
            ],
        ),
    ),
    # --- 8. HP LaserJet Printer ---
    LabeledDescriptor(
        name="HP LaserJet Printer",
        is_malicious=False,
        descriptor=_desc(
            vid="03f0", pid="4117", mfr="Hewlett-Packard", prod="LaserJet Pro",
            intfs=[_intf(0x07, 0x01, 0x02, num_ep=2,
                         eps=[_bulk_ep(0x81), _bulk_ep(0x02)])],
        ),
    ),
    # --- 9. Intel Bluetooth adapter ---
    LabeledDescriptor(
        name="Intel Bluetooth Adapter",
        is_malicious=False,
        descriptor=_desc(
            vid="8087", pid="0029", mfr="Intel Corp.", prod="AX201 Bluetooth",
            intfs=[
                _intf(0xE0, 0x01, 0x01, num_ep=3),  # BT event+ACL+SCO
            ],
            dev_class=0xE0,
        ),
    ),
    # --- 10. Realtek USB NIC ---
    LabeledDescriptor(
        name="Realtek USB Ethernet",
        is_malicious=False,
        descriptor=_desc(
            vid="0bda", pid="8153", mfr="Realtek", prod="RTL8153 Gigabit",
            intfs=[
                _intf(0x02, 0x06, 0x00),        # CDC ethernet
                _intf(0x0A, 0x00, 0x00, num_ep=2,
                      eps=[_bulk_ep(0x81), _bulk_ep(0x02)]),
            ],
            dev_class=0x02,
        ),
    ),
    # --- 11. Generic USB Hub ---
    LabeledDescriptor(
        name="Generic USB 3.0 Hub",
        is_malicious=False,
        descriptor=_desc(
            vid="0424", pid="5744", mfr="Microchip Technology",
            prod="USB 5744 Hub",
            intfs=[_intf(0x09, 0x00, 0x00, num_ep=1)],
            dev_class=0x09,
        ),
    ),
    # --- 12. USB Audio DAC ---
    LabeledDescriptor(
        name="USB Audio DAC",
        is_malicious=False,
        descriptor=_desc(
            vid="20b1", pid="3066", mfr="XMOS Ltd", prod="XMOS USB Audio 2.0",
            intfs=[
                _intf(0x01, 0x01, 0x20, num_ep=1),  # audio control
                _intf(0x01, 0x02, 0x20, num_ep=2),  # audio streaming
            ],
        ),
    ),
    # --- 13. Corsair K70 gaming keyboard ---
    LabeledDescriptor(
        name="Corsair K70 Keyboard",
        is_malicious=False,
        descriptor=_desc(
            vid="1b1c", pid="1b13", mfr="Corsair", prod="Corsair K70 RGB",
            intfs=[
                _intf(0x03, 0x01, 0x01),         # HID keyboard
                _intf(0x03, 0x00, 0x00),          # HID extra keys
            ],
        ),
    ),
    # --- 14. Razer DeathAdder mouse ---
    LabeledDescriptor(
        name="Razer DeathAdder Mouse",
        is_malicious=False,
        descriptor=_desc(
            vid="1532", pid="0084", mfr="Razer Inc.",
            prod="Razer DeathAdder V2",
            intfs=[
                _intf(0x03, 0x01, 0x02),         # HID mouse
                _intf(0x03, 0x00, 0x00),          # HID extra
            ],
        ),
    ),
    # --- 15. Chicony HD Webcam (laptop internal) ---
    LabeledDescriptor(
        name="Chicony HD Webcam",
        is_malicious=False,
        descriptor=_desc(
            vid="04f2", pid="b604", mfr="Chicony Electronics",
            prod="HD Webcam",
            intfs=[
                _intf(0x0E, 0x01, 0x00, num_ep=1),
                _intf(0x0E, 0x02, 0x00, num_ep=1),
            ],
        ),
    ),
    # --- 16. Samsung phone (MTP) ---
    LabeledDescriptor(
        name="Samsung Galaxy MTP",
        is_malicious=False,
        descriptor=_desc(
            vid="04e8", pid="6860", mfr="Samsung", prod="Galaxy S23",
            intfs=[_intf(0x06, 0x01, 0x01, num_ep=3)],  # MTP
        ),
    ),
    # --- 17. Yubikey security key ---
    LabeledDescriptor(
        name="Yubikey 5",
        is_malicious=False,
        descriptor=_desc(
            vid="1050", pid="0407", mfr="Yubico", prod="YubiKey OTP+FIDO+CCID",
            intfs=[
                _intf(0x03, 0x00, 0x00),          # HID FIDO
                _intf(0x0B, 0x00, 0x00),           # Smart Card
            ],
        ),
    ),
    # --- 18. Silicon Labs CP2102 serial (legitimate dev tool) ---
    LabeledDescriptor(
        name="Silicon Labs CP2102",
        is_malicious=False,
        descriptor=_desc(
            vid="10c4", pid="ea60", mfr="Silicon Labs",
            prod="CP2102 USB to UART Bridge",
            intfs=[_intf(0xFF, 0x00, 0x00)],  # vendor-specific serial
        ),
    ),
    # --- 19. Wacom tablet ---
    LabeledDescriptor(
        name="Wacom Intuos Tablet",
        is_malicious=False,
        descriptor=_desc(
            vid="056a", pid="0374", mfr="Wacom Co., Ltd.",
            prod="Wacom Intuos S",
            intfs=[_intf(0x03, 0x00, 0x00)],  # HID
        ),
    ),
    # --- 20. Canon EOS DSLR camera ---
    LabeledDescriptor(
        name="Canon EOS R5",
        is_malicious=False,
        descriptor=_desc(
            vid="04a9", pid="3218", mfr="Canon, Inc.",
            prod="EOS R5",
            intfs=[_intf(0x06, 0x01, 0x01, num_ep=3)],  # PTP/MTP
        ),
    ),
    # --- 21. Microsoft Xbox controller ---
    LabeledDescriptor(
        name="Xbox Wireless Controller",
        is_malicious=False,
        descriptor=_desc(
            vid="045e", pid="0b12", mfr="Microsoft",
            prod="Xbox Wireless Controller",
            intfs=[
                _intf(0xFF, 0x47, 0xD0, num_ep=2,
                      eps=[_intr_ep(0x81), _intr_ep(0x01)]),
            ],
        ),
    ),
    # --- 22. Alcor Micro card reader (laptop internal) ---
    LabeledDescriptor(
        name="Alcor Micro Card Reader",
        is_malicious=False,
        descriptor=_desc(
            vid="058f", pid="6366", mfr="Alcor Micro",
            prod="AU6435 Card Reader",
            intfs=[_intf(0x08, 0x06, 0x50, num_ep=2,
                         eps=[_bulk_ep(0x81), _bulk_ep(0x02)])],
        ),
    ),
    # --- 23. Linux Foundation internal root hub ---
    LabeledDescriptor(
        name="Linux USB Root Hub",
        is_malicious=False,
        descriptor=_desc(
            vid="1d6b", pid="0002", mfr="Linux Foundation",
            prod="USB 2.0 Root Hub",
            intfs=[_intf(0x09, 0x00, 0x00, num_ep=1)],
            dev_class=0x09,
        ),
    ),
    # --- 24. Brother printer ---
    LabeledDescriptor(
        name="Brother HL-L2370DW Printer",
        is_malicious=False,
        descriptor=_desc(
            vid="04f9", pid="0054", mfr="Brother Industries",
            prod="HL-L2370DW",
            intfs=[_intf(0x07, 0x01, 0x02, num_ep=2,
                         eps=[_bulk_ep(0x81), _bulk_ep(0x02)])],
        ),
    ),
    # --- 25. Audio-Technica USB microphone ---
    LabeledDescriptor(
        name="Audio-Technica AT2020USB+",
        is_malicious=False,
        descriptor=_desc(
            vid="0909", pid="001b", mfr="Audio-Technica",
            prod="AT2020USB+",
            intfs=[
                _intf(0x01, 0x01, 0x00, num_ep=1),  # audio control
                _intf(0x01, 0x02, 0x00, num_ep=1),  # audio streaming
            ],
        ),
    ),
]


ALL_DESCRIPTORS: list[LabeledDescriptor] = MALICIOUS + BENIGN
