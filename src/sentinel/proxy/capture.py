"""
USB traffic capture via usbmon.

Captures USB packets for behavioral analysis, supporting both
real-time monitoring and offline replay.
"""

from __future__ import annotations

import logging
import os
import struct
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, BinaryIO, Callable, Iterator


logger = logging.getLogger(__name__)


class URBType(Enum):
    """USB Request Block types."""

    SUBMIT = "S"
    COMPLETE = "C"
    ERROR = "E"


class TransferType(Enum):
    """USB transfer types."""

    ISOCHRONOUS = 0
    INTERRUPT = 1
    CONTROL = 2
    BULK = 3


class Direction(Enum):
    """USB transfer direction."""

    OUT = 0  # Host to device
    IN = 1   # Device to host


@dataclass
class USBPacket:
    """Represents a captured USB packet."""

    timestamp: float
    urb_type: URBType
    bus_num: int
    device_num: int
    endpoint: int
    transfer_type: TransferType
    direction: Direction
    status: int
    length: int
    data: bytes = field(default_factory=bytes)
    setup_packet: bytes | None = None

    @property
    def endpoint_address(self) -> int:
        """Get full endpoint address with direction bit."""
        addr = self.endpoint
        if self.direction == Direction.IN:
            addr |= 0x80
        return addr

    @property
    def is_hid(self) -> bool:
        """Check if this appears to be HID traffic."""
        # HID typically uses interrupt transfers
        return self.transfer_type == TransferType.INTERRUPT

    @property
    def is_control(self) -> bool:
        """Check if this is a control transfer."""
        return self.transfer_type == TransferType.CONTROL

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "timestamp": self.timestamp,
            "urb_type": self.urb_type.value,
            "bus_num": self.bus_num,
            "device_num": self.device_num,
            "endpoint": self.endpoint,
            "endpoint_address": f"0x{self.endpoint_address:02X}",
            "transfer_type": self.transfer_type.name,
            "direction": self.direction.name,
            "status": self.status,
            "length": self.length,
            "data_hex": self.data.hex() if self.data else "",
        }


@dataclass
class CaptureSession:
    """Represents a capture session."""

    session_id: str
    bus_num: int
    device_num: int | None
    started_at: datetime
    ended_at: datetime | None = None
    packet_count: int = 0
    total_bytes: int = 0
    capture_file: Path | None = None


# usbmon packet format (from kernel documentation)
# struct usbmon_packet {
#     u64 id;           /* URB ID */
#     unsigned char type;    /* Submit ('S') or Complete ('C') */
#     unsigned char xfer_type;  /* Transfer type */
#     unsigned char epnum;   /* Endpoint number */
#     unsigned char devnum;  /* Device address */
#     u16 busnum;       /* Bus number */
#     char flag_setup;
#     char flag_data;
#     s64 ts_sec;       /* Timestamp seconds */
#     s32 ts_usec;      /* Timestamp microseconds */
#     int status;
#     unsigned int length;   /* Data length */
#     unsigned int len_cap;  /* Captured data length */
#     union {
#         unsigned char setup[8];
#         struct iso_rec iso;
#     } s;
#     int interval;
#     int start_frame;
#     unsigned int xfer_flags;
#     unsigned int ndesc;
# };

USBMON_PACKET_FORMAT = "<QBBBBH2sQiIII8siiII"
USBMON_PACKET_SIZE = struct.calcsize(USBMON_PACKET_FORMAT)


def parse_usbmon_packet(data: bytes, timestamp_base: float = 0) -> USBPacket | None:
    """
    Parse a usbmon binary packet.

    Args:
        data: Raw packet data
        timestamp_base: Base timestamp offset

    Returns:
        Parsed USBPacket or None if invalid
    """
    if len(data) < USBMON_PACKET_SIZE:
        return None

    try:
        (
            urb_id,
            urb_type_byte,
            xfer_type,
            epnum,
            devnum,
            busnum,
            flags,
            ts_sec,
            ts_usec,
            status,
            length,
            len_cap,
            setup,
            interval,
            start_frame,
            xfer_flags,
            ndesc,
        ) = struct.unpack(USBMON_PACKET_FORMAT, data[:USBMON_PACKET_SIZE])

        # Parse URB type
        try:
            urb_type = URBType(chr(urb_type_byte))
        except ValueError:
            return None

        # Parse transfer type
        try:
            transfer_type = TransferType(xfer_type & 0x03)
        except ValueError:
            transfer_type = TransferType.CONTROL

        # Determine direction from endpoint
        direction = Direction.IN if epnum & 0x80 else Direction.OUT
        endpoint = epnum & 0x0F

        # Calculate timestamp
        timestamp = timestamp_base + ts_sec + (ts_usec / 1_000_000)

        # Extract payload data
        payload = data[USBMON_PACKET_SIZE:USBMON_PACKET_SIZE + len_cap]

        # Setup packet for control transfers
        setup_packet = setup if transfer_type == TransferType.CONTROL else None

        return USBPacket(
            timestamp=timestamp,
            urb_type=urb_type,
            bus_num=busnum,
            device_num=devnum,
            endpoint=endpoint,
            transfer_type=transfer_type,
            direction=direction,
            status=status,
            length=length,
            data=payload,
            setup_packet=setup_packet,
        )

    except struct.error:
        return None


class USBTrafficCapture:
    """
    USB traffic capture using usbmon.

    Captures USB packets from the kernel's usbmon interface for
    behavioral analysis.
    """

    def __init__(
        self,
        bus_num: int = 0,
        device_num: int | None = None,
        buffer_size: int = 65536,
    ) -> None:
        """
        Initialize capture.

        Args:
            bus_num: USB bus number to monitor (0 for all)
            device_num: Specific device number to filter (None for all)
            buffer_size: Read buffer size
        """
        self.bus_num = bus_num
        self.device_num = device_num
        self.buffer_size = buffer_size

        self._usbmon_file: BinaryIO | None = None
        self._capturing = False
        self._capture_thread: threading.Thread | None = None
        self._packets: list[USBPacket] = []
        self._packet_callback: Callable[[USBPacket], None] | None = None
        self._lock = threading.Lock()

        # Session tracking
        self._session: CaptureSession | None = None
        self._start_time: float = 0

    @property
    def usbmon_path(self) -> str:
        """Get usbmon device path."""
        if self.bus_num == 0:
            return "/dev/usbmon0"  # All buses
        return f"/dev/usbmon{self.bus_num}"

    def check_available(self) -> bool:
        """Check if usbmon is available."""
        path = Path(self.usbmon_path)
        return path.exists()

    def start_capture(
        self,
        callback: Callable[[USBPacket], None] | None = None,
    ) -> CaptureSession:
        """
        Start capturing USB traffic.

        Args:
            callback: Optional callback for each packet

        Returns:
            CaptureSession info

        Raises:
            RuntimeError: If capture cannot start
        """
        if self._capturing:
            raise RuntimeError("Capture already in progress")

        # Check usbmon availability
        if not self.check_available():
            raise RuntimeError(f"usbmon not available: {self.usbmon_path}")

        try:
            self._usbmon_file = open(self.usbmon_path, "rb")
        except PermissionError:
            raise RuntimeError(
                f"Permission denied: {self.usbmon_path}. "
                "Run with elevated privileges or add user to 'usbmon' group."
            )

        self._capturing = True
        self._packets = []
        self._packet_callback = callback
        self._start_time = time.time()

        # Create session
        self._session = CaptureSession(
            session_id=f"cap_{int(time.time())}",
            bus_num=self.bus_num,
            device_num=self.device_num,
            started_at=datetime.utcnow(),
        )

        # Start capture thread
        self._capture_thread = threading.Thread(
            target=self._capture_loop,
            daemon=True,
        )
        self._capture_thread.start()

        logger.info(
            "Started capture on bus %d (device: %s)",
            self.bus_num,
            self.device_num or "all",
        )

        return self._session

    def _capture_loop(self) -> None:
        """Main capture loop running in thread."""
        while self._capturing and self._usbmon_file:
            try:
                # Read packet header + data
                data = self._usbmon_file.read(self.buffer_size)
                if not data:
                    continue

                # Parse packets from buffer
                offset = 0
                while offset < len(data):
                    packet = parse_usbmon_packet(
                        data[offset:],
                        timestamp_base=self._start_time,
                    )
                    if packet is None:
                        break

                    # Apply device filter
                    if self.device_num is not None:
                        if packet.device_num != self.device_num:
                            offset += USBMON_PACKET_SIZE + packet.length
                            continue

                    # Store packet
                    with self._lock:
                        self._packets.append(packet)
                        if self._session:
                            self._session.packet_count += 1
                            self._session.total_bytes += len(packet.data)

                    # Call callback
                    if self._packet_callback:
                        try:
                            self._packet_callback(packet)
                        except Exception as e:
                            logger.error("Packet callback error: %s", e)

                    offset += USBMON_PACKET_SIZE + packet.length

            except Exception as e:
                if self._capturing:
                    logger.error("Capture error: %s", e)
                break

    def stop_capture(self) -> list[USBPacket]:
        """
        Stop capturing and return collected packets.

        Returns:
            List of captured packets
        """
        self._capturing = False

        # Wait for thread
        if self._capture_thread:
            self._capture_thread.join(timeout=2.0)
            self._capture_thread = None

        # Close file
        if self._usbmon_file:
            self._usbmon_file.close()
            self._usbmon_file = None

        # Update session
        if self._session:
            self._session.ended_at = datetime.utcnow()

        # Return packets
        with self._lock:
            packets = self._packets.copy()
            self._packets = []

        logger.info("Stopped capture: %d packets", len(packets))
        return packets

    def get_packets(self) -> list[USBPacket]:
        """Get currently captured packets without stopping."""
        with self._lock:
            return self._packets.copy()

    def get_session(self) -> CaptureSession | None:
        """Get current capture session info."""
        return self._session

    @property
    def is_capturing(self) -> bool:
        """Check if currently capturing."""
        return self._capturing


class CaptureFile:
    """
    Save and load captured packets to/from files.

    Supports pcap-like format for offline analysis.
    """

    MAGIC = b"USBCAP01"
    HEADER_FORMAT = "<8sQII"  # magic, timestamp, packet_count, version
    PACKET_HEADER_FORMAT = "<dBBBBBBiII"  # timestamp + packet header fields

    def __init__(self, path: str | Path) -> None:
        """Initialize capture file."""
        self.path = Path(path)

    def save(self, packets: list[USBPacket]) -> None:
        """
        Save packets to file.

        Args:
            packets: Packets to save
        """
        with open(self.path, "wb") as f:
            # Write file header
            header = struct.pack(
                self.HEADER_FORMAT,
                self.MAGIC,
                int(time.time()),
                len(packets),
                1,  # version
            )
            f.write(header)

            # Write packets
            for packet in packets:
                self._write_packet(f, packet)

        logger.info("Saved %d packets to %s", len(packets), self.path)

    def _write_packet(self, f: BinaryIO, packet: USBPacket) -> None:
        """Write a single packet to file."""
        # Packet header
        header = struct.pack(
            self.PACKET_HEADER_FORMAT,
            packet.timestamp,
            ord(packet.urb_type.value),
            packet.bus_num,
            packet.device_num,
            packet.endpoint,
            packet.transfer_type.value,
            packet.direction.value,
            packet.status,
            packet.length,
            len(packet.data),
        )
        f.write(header)
        f.write(packet.data)

    def load(self) -> list[USBPacket]:
        """
        Load packets from file.

        Returns:
            List of loaded packets
        """
        packets = []

        with open(self.path, "rb") as f:
            # Read file header
            header_data = f.read(struct.calcsize(self.HEADER_FORMAT))
            magic, timestamp, packet_count, version = struct.unpack(
                self.HEADER_FORMAT, header_data
            )

            if magic != self.MAGIC:
                raise ValueError(f"Invalid capture file: {self.path}")

            # Read packets
            for _ in range(packet_count):
                packet = self._read_packet(f)
                if packet:
                    packets.append(packet)

        logger.info("Loaded %d packets from %s", len(packets), self.path)
        return packets

    def _read_packet(self, f: BinaryIO) -> USBPacket | None:
        """Read a single packet from file."""
        header_size = struct.calcsize(self.PACKET_HEADER_FORMAT)
        header_data = f.read(header_size)

        if len(header_data) < header_size:
            return None

        (
            timestamp,
            urb_type_byte,
            bus_num,
            device_num,
            endpoint,
            transfer_type,
            direction,
            status,
            length,
            data_len,
        ) = struct.unpack(self.PACKET_HEADER_FORMAT, header_data)

        data = f.read(data_len)

        return USBPacket(
            timestamp=timestamp,
            urb_type=URBType(chr(urb_type_byte)),
            bus_num=bus_num,
            device_num=device_num,
            endpoint=endpoint,
            transfer_type=TransferType(transfer_type),
            direction=Direction(direction),
            status=status,
            length=length,
            data=data,
        )

    def iterate(self) -> Iterator[USBPacket]:
        """
        Iterate over packets without loading all into memory.

        Yields:
            USBPacket objects
        """
        with open(self.path, "rb") as f:
            # Skip file header
            f.read(struct.calcsize(self.HEADER_FORMAT))

            while True:
                packet = self._read_packet(f)
                if packet is None:
                    break
                yield packet


class MockUSBTrafficCapture:
    """
    Mock traffic capture for testing.

    Generates synthetic packets for testing without actual USB traffic.
    """

    def __init__(
        self,
        bus_num: int = 0,
        device_num: int | None = None,
    ) -> None:
        """Initialize mock capture."""
        self.bus_num = bus_num
        self.device_num = device_num
        self._capturing = False
        self._packets: list[USBPacket] = []
        self._session: CaptureSession | None = None

    def check_available(self) -> bool:
        """Always available for mocking."""
        return True

    def add_mock_packet(
        self,
        data: bytes,
        endpoint: int = 1,
        transfer_type: TransferType = TransferType.INTERRUPT,
        direction: Direction = Direction.IN,
    ) -> None:
        """Add a mock packet for testing."""
        packet = USBPacket(
            timestamp=time.time(),
            urb_type=URBType.COMPLETE,
            bus_num=self.bus_num or 1,
            device_num=self.device_num or 1,
            endpoint=endpoint,
            transfer_type=transfer_type,
            direction=direction,
            status=0,
            length=len(data),
            data=data,
        )
        self._packets.append(packet)

    def add_hid_keystroke(
        self,
        modifier: int,
        keycode: int,
        delay_ms: float = 50.0,
    ) -> None:
        """
        Add a mock HID keystroke packet.

        Args:
            modifier: Modifier byte (Ctrl, Shift, etc.)
            keycode: USB HID keycode
            delay_ms: Delay from previous keystroke
        """
        # Standard 8-byte HID keyboard report
        data = bytes([modifier, 0, keycode, 0, 0, 0, 0, 0])

        base_time = self._packets[-1].timestamp if self._packets else time.time()

        packet = USBPacket(
            timestamp=base_time + (delay_ms / 1000.0),
            urb_type=URBType.COMPLETE,
            bus_num=self.bus_num or 1,
            device_num=self.device_num or 1,
            endpoint=1,
            transfer_type=TransferType.INTERRUPT,
            direction=Direction.IN,
            status=0,
            length=8,
            data=data,
        )
        self._packets.append(packet)

    def start_capture(
        self,
        callback: Callable[[USBPacket], None] | None = None,
    ) -> CaptureSession:
        """Start mock capture."""
        self._capturing = True
        self._session = CaptureSession(
            session_id="mock_session",
            bus_num=self.bus_num,
            device_num=self.device_num,
            started_at=datetime.utcnow(),
        )
        return self._session

    def stop_capture(self) -> list[USBPacket]:
        """Stop mock capture and return packets."""
        self._capturing = False
        if self._session:
            self._session.ended_at = datetime.utcnow()
            self._session.packet_count = len(self._packets)
        packets = self._packets.copy()
        self._packets = []
        return packets

    def get_packets(self) -> list[USBPacket]:
        """Get current mock packets."""
        return self._packets.copy()

    def get_session(self) -> CaptureSession | None:
        """Get mock session."""
        return self._session

    @property
    def is_capturing(self) -> bool:
        """Check if mock capture is running."""
        return self._capturing


def create_capture(
    bus_num: int = 0,
    device_num: int | None = None,
    use_mock: bool = False,
) -> USBTrafficCapture | MockUSBTrafficCapture:
    """
    Create a traffic capture instance.

    Args:
        bus_num: USB bus number
        device_num: Device number filter
        use_mock: Use mock capture for testing

    Returns:
        Capture instance
    """
    if use_mock:
        return MockUSBTrafficCapture(bus_num, device_num)
    return USBTrafficCapture(bus_num, device_num)
