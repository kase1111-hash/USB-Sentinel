"""
USB Sentinel Core - Integrated Processing Pipeline.

Provides the main device processing functionality that ties together
the interceptor, policy engine, validator, and audit database.
"""

from sentinel.core.processor import (
    DeviceProcessor,
    PolicyWatcher,
    ProcessingResult,
    Verdict,
    create_processor,
)

__all__ = [
    "DeviceProcessor",
    "PolicyWatcher",
    "ProcessingResult",
    "Verdict",
    "create_processor",
]
