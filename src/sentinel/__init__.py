"""
USB Sentinel - LLM-integrated USB firewall system.

A constitutional security layer that interposes between the operating system
and physical USB subsystem, combining deterministic rule-based policy enforcement
with LLM-assisted heuristic analysis.
"""

__version__ = "0.1.0"
__author__ = "USB Sentinel Contributors"

from sentinel.config import SentinelConfig, load_config

__all__ = ["SentinelConfig", "load_config", "__version__"]
