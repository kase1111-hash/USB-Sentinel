"""
USB Sentinel Daemon.

Main entry point that integrates all system layers:
- USB Interceptor (Layer 1)
- Policy Engine (Layer 2)
- LLM Analyzer (Layer 3)
- Audit Database (Layer 4)
- REST API (Layer 5, optional)

Decision order for each attached device:

1. Operator decisions (``usb-sentinel devices trust``): trusted -> allow,
   blocked -> block.
2. Policy rules: block is final; allow is final unless the descriptor looks
   spoofed (vendor string does not match the VID, or serious anomalies),
   in which case the device is analyzed like a review.
3. Review: the descriptor validator and local heuristics score the device,
   plus the LLM when configured. The highest score wins (the LLM can raise
   risk but never lower it below the local checks), with a penalty for
   devices that were never allowed before. 0-50 allow, 51-75 hold for
   manual review (kept unauthorized), 76-100 block.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import logging
import os
import signal
import sys
import urllib.request
from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from sentinel import __version__
from sentinel.analyzer.llm import LLMAnalyzer, MockLLMAnalyzer, RetryConfig
from sentinel.analyzer.prompts import check_vendor_mismatch
from sentinel.analyzer.scoring import AnalysisResult, calculate_composite_score, score_to_action
from sentinel.audit.database import AuditDatabase
from sentinel.audit.models import EventType as AuditEventType
from sentinel.audit.models import TrustLevel
from sentinel.config import SentinelConfig, load_config, validate_config
from sentinel.interceptor.descriptors import DeviceDescriptor
from sentinel.interceptor.linux import (
    EventType,
    USBEvent,
    USBInterceptor,
    get_platform_interceptor,
)
from sentinel.interceptor.validator import DescriptorValidator
from sentinel.policy.engine import PolicyEngine, create_default_policy
from sentinel.policy.fingerprint import generate_fingerprint
from sentinel.policy.models import Action, Policy
from sentinel.policy.parser import load_policy

logger = logging.getLogger("sentinel")

# Validator score at which an allow rule is re-examined (one HIGH + one
# MEDIUM anomaly, or any CRITICAL one).
SPOOF_ESCALATION_SCORE = 50

_EVENT_TYPES = {
    Action.ALLOW: AuditEventType.ALLOWED,
    Action.BLOCK: AuditEventType.BLOCKED,
    Action.REVIEW: AuditEventType.REVIEWED,
}


@dataclass
class Decision:
    """Verdict for one device connection and why it was reached."""

    action: Action  # ALLOW, BLOCK, or REVIEW (= held for manual review)
    fingerprint: str
    reason: str
    rule: str | None = None
    risk_score: int | None = None
    analysis: str | None = None
    operator_decision: bool = False

    @property
    def held(self) -> bool:
        return self.action == Action.REVIEW

    def to_result(self) -> dict[str, Any]:
        return {
            "fingerprint": self.fingerprint,
            "action": self.action.value,
            "rule": self.rule,
            "reason": self.reason,
            "analysis": self.analysis,
            "risk_score": self.risk_score,
        }


class _AuditSeenView:
    """Lets policy ``first_seen`` rules consult the audit database."""

    def __init__(self, daemon: SentinelDaemon) -> None:
        self._daemon = daemon

    def is_first_seen(self, fingerprint: str) -> bool:
        return not self._daemon.db.device_exists(fingerprint)


def _process_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


class SentinelDaemon:
    """
    Main USB Sentinel daemon.

    Orchestrates all system components and processes USB device events.
    """

    def __init__(self, config: SentinelConfig) -> None:
        """
        Initialize daemon with configuration.

        Args:
            config: Validated configuration object
        """
        self.config = config
        self._setup_logging()

        # Initialize components (lazy loading)
        self._db: AuditDatabase | None = None
        self._policy_engine: PolicyEngine | None = None
        self._analyzer: Any = None
        self._analyzer_checked = False
        self._interceptor: USBInterceptor | None = None
        self._api_server: Any = None
        self._api_enabled: bool = config.api.enabled

        # Local scoring, always available
        self._heuristics = MockLLMAnalyzer()
        self._validator = DescriptorValidator()

        # State
        self.running = False
        self._stopped = False
        self._shutdown_event = asyncio.Event()
        self._pending: list[USBEvent] = []
        self._attached: dict[str, str] = {}  # sys_path -> fingerprint
        self._policy_mtime: float | None = None
        self._pid_written = False
        self._stats: dict[str, Any] = {
            "devices_processed": 0,
            "devices_allowed": 0,
            "devices_blocked": 0,
            "devices_held": 0,
            "start_time": None,
        }

    def _setup_logging(self) -> None:
        """Configure logging based on config."""
        level = getattr(logging, self.config.daemon.log_level.upper(), logging.INFO)
        logging.basicConfig(
            level=level,
            format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

    def _setup_log_file(self) -> None:
        """Also log to daemon.log_file, if configured and writable."""
        log_file = self.config.daemon.log_file
        if not log_file:
            return
        root = logging.getLogger()
        target = str(Path(log_file).resolve())
        if any(getattr(h, "baseFilename", None) == target for h in root.handlers):
            return
        try:
            handler = logging.FileHandler(log_file)
        except OSError as e:
            logger.warning("Cannot open log file %s: %s", log_file, e)
            return
        handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s"))
        root.addHandler(handler)

    # ------------------------------------------------------------------
    # Components
    # ------------------------------------------------------------------

    @property
    def db(self) -> AuditDatabase:
        """Get or initialize audit database.

        Creates parent directories automatically and retries once on
        failure (e.g. locked database) before raising.
        """
        if self._db is None:
            db_path = Path(self.config.database.path)
            db_path.parent.mkdir(parents=True, exist_ok=True)
            try:
                self._db = AuditDatabase(str(db_path), wal_mode=self.config.database.wal_mode)
            except Exception as e:
                logger.warning("Database init failed (%s), retrying...", e)
                import time

                time.sleep(0.5)
                self._db = AuditDatabase(str(db_path), wal_mode=self.config.database.wal_mode)
        return self._db

    def _load_policy_or_default(self) -> Policy:
        """Load the policy file; fall back to the built-in policy if unusable."""
        policy_path = Path(self.config.policy.rules_file)
        try:
            policy = load_policy(policy_path)
            self._policy_mtime = policy_path.stat().st_mtime
            return policy
        except FileNotFoundError:
            logger.warning("Policy file not found: %s — using built-in default policy", policy_path)
        except Exception as e:
            logger.error(
                "Failed to load policy %s: %s — using built-in default policy",
                policy_path,
                e,
            )
        return create_default_policy()

    @property
    def policy_engine(self) -> PolicyEngine:
        """Get or initialize policy engine.

        If the policy file is malformed, falls back to the default
        built-in policy so the daemon can still protect the host.
        """
        if self._policy_engine is None:
            self._policy_engine = PolicyEngine(
                policy=self._load_policy_or_default(),
                fingerprint_db=_AuditSeenView(self),  # type: ignore[arg-type]
                default_action=Action(self.config.policy.default_action),
                trust_lookup=self._trust_level,
            )
        return self._policy_engine

    def _trust_level(self, fingerprint: str) -> str | None:
        device = self.db.get_device(fingerprint)
        return str(device.trust_level) if device is not None else None

    def reload_policy(self) -> bool:
        """
        Reload the policy file, keeping the current policy if the new one is invalid.

        Returns:
            True if the new policy is active
        """
        path = Path(self.config.policy.rules_file)
        try:
            warnings = self.policy_engine.reload_policy(path)
        except Exception as e:
            logger.error("Policy reload failed, keeping current policy: %s", e)
            return False
        finally:
            with contextlib.suppress(OSError):
                self._policy_mtime = path.stat().st_mtime
        for warning in warnings:
            logger.warning("Policy: %s", warning)
        logger.info("Policy reloaded from %s", path)
        return True

    @property
    def analyzer(self) -> Any:
        """The configured LLM analyzer, or None to score with local checks only."""
        if not self._analyzer_checked:
            self._analyzer_checked = True
            self._analyzer = self._create_analyzer()
        return self._analyzer

    def _create_analyzer(self) -> Any:
        cfg = self.config.analyzer
        if not cfg.enabled:
            logger.info("LLM analysis disabled; scoring devices with local checks only")
            return None

        if cfg.provider == "local":
            try:
                from sentinel.analyzer.local import LocalLLMAnalyzer
                from sentinel.analyzer.local import LocalLLMConfig as LocalModelConfig

                return LocalLLMAnalyzer(
                    LocalModelConfig(
                        model_path=cfg.local.model_path,
                        n_ctx=cfg.local.n_ctx,
                        n_gpu_layers=cfg.local.n_gpu_layers,
                    )
                )
            except Exception as e:
                logger.warning("Local LLM unavailable (%s); using local checks only", e)
                return None

        if not cfg.api_key:
            logger.warning(
                "No ANTHROPIC_API_KEY configured; scoring devices with local checks only"
            )
            return None

        try:
            analyzer = LLMAnalyzer(
                api_key=cfg.api_key,
                model=cfg.model,
                max_tokens=cfg.max_tokens,
                timeout=float(min(cfg.timeout, self.config.interceptor.analysis_timeout)),
                rate_limit=cfg.rate_limit,
                retry_config=RetryConfig(max_retries=1, base_delay=0.5),
                effort=cfg.effort,
            )
        except Exception as e:
            logger.warning("LLM analyzer failed to initialize (%s); using local checks only", e)
            return None
        logger.info("LLM analyzer ready: %s", cfg.model)
        return analyzer

    @property
    def interceptor(self) -> USBInterceptor:
        """Get or initialize USB interceptor."""
        if self._interceptor is None:
            self._interceptor = get_platform_interceptor(
                block_during_analysis=self.config.interceptor.block_during_analysis,
                analysis_timeout=float(self.config.interceptor.analysis_timeout),
            )
        return self._interceptor

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def _write_pid_file(self) -> None:
        path = Path(self.config.daemon.pid_file)
        if path.exists():
            try:
                other = int(path.read_text().strip())
            except (OSError, ValueError):
                other = None
            if other and other != os.getpid() and _process_alive(other):
                raise RuntimeError(f"Another usb-sentinel daemon is running (PID {other})")
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(f"{os.getpid()}\n")
            self._pid_written = True
        except OSError as e:
            logger.warning("Cannot write PID file %s: %s", path, e)

    def _remove_pid_file(self) -> None:
        if self._pid_written:
            Path(self.config.daemon.pid_file).unlink(missing_ok=True)
            self._pid_written = False

    async def start(self) -> None:
        """Start the daemon and all services."""
        self._setup_log_file()
        logger.info("Starting USB Sentinel daemon v%s", __version__)
        self._write_pid_file()
        self.running = True
        self._stopped = False
        self._stats["start_time"] = datetime.now(timezone.utc)
        self._shutdown_event.clear()

        try:
            logger.info("Initializing database: %s", self.config.database.path)
            _ = self.db

            logger.info("Loading policy from: %s", self.config.policy.rules_file)
            logger.info("Loaded %d policy rules", len(self.policy_engine.policy.rules))

            _ = self.analyzer

            logger.info("Initializing USB interceptor")
            self._pending = list(self.interceptor.start())
            if self._pending:
                logger.info("%d attached device(s) are waiting for a verdict", len(self._pending))

            if self.config.api.enabled:
                await self._start_api_server()
        except BaseException:
            # Never leave the buses in default-deny with nobody to authorize
            await self.stop()
            raise

        logger.info("Waiting for USB events...")

    async def stop(self) -> None:
        """Stop the daemon gracefully."""
        if self._stopped:
            return
        self._stopped = True
        logger.info("Stopping USB Sentinel daemon...")
        self.running = False
        self._shutdown_event.set()

        # Stop API server
        if self._api_server is not None:
            self._api_server.should_exit = True
            from sentinel.api.websocket import shutdown_websocket

            await shutdown_websocket()

        # Stop monitoring and restore the kernel's default authorization
        if self._interceptor is not None:
            self._interceptor.stop()

        # Close database
        if self._db is not None:
            self._db.close()

        self._remove_pid_file()
        logger.info("Daemon stopped")

    async def run(self) -> None:
        """Main daemon loop - process device events."""
        await self.start()

        watcher = None
        if self.config.policy.hot_reload:
            watcher = asyncio.create_task(self._watch_policy())

        try:
            pending, self._pending = self._pending, []
            for event in pending:
                await self.process_event(event)

            async for event in self._event_loop():
                await self.process_event(event)

        except asyncio.CancelledError:
            logger.info("Daemon loop cancelled")
        except Exception as e:
            # Re-raised so the process exits non-zero and systemd restarts it
            logger.error("Daemon error: %s", e, exc_info=True)
            raise
        finally:
            if watcher is not None:
                watcher.cancel()
            await self.stop()

    async def _event_loop(self) -> AsyncIterator[USBEvent]:
        """Async generator for device events."""
        async for event in self.interceptor.events():
            if not self.running or self._shutdown_event.is_set():
                break
            yield event

    async def _watch_policy(self) -> None:
        """Reload the policy when its file changes."""
        path = Path(self.config.policy.rules_file)
        while self.running:
            await asyncio.sleep(2.0)
            try:
                mtime = path.stat().st_mtime
            except OSError:
                continue
            if self._policy_mtime is None:
                self._policy_mtime = mtime
            elif mtime != self._policy_mtime:
                self.reload_policy()

    def request_shutdown(self) -> None:
        """Ask the main loop to exit (safe to call from a signal handler)."""
        self.running = False
        self._shutdown_event.set()
        if self._interceptor is not None:
            self._interceptor.stop()

    def handle_signal(self, signum: int) -> None:
        """Handle termination signals."""
        sig_name = signal.Signals(signum).name
        if signum == signal.SIGHUP:
            logger.info("Received %s, reloading policy", sig_name)
            self.reload_policy()
            return
        logger.info("Received signal %s, initiating shutdown", sig_name)
        self.request_shutdown()

    # ------------------------------------------------------------------
    # Event handling
    # ------------------------------------------------------------------

    async def process_event(self, event: USBEvent) -> dict[str, Any] | None:
        """Handle one event; a failure is logged and never stops the daemon."""
        try:
            return await self.handle_device_event(event)
        except Exception:
            logger.exception(
                "Error processing %s event for %s (%s:%s)",
                event.event_type.value,
                event.sys_path or event.device_id,
                event.vid,
                event.pid,
            )
            return None

    async def handle_device_event(self, event: USBEvent) -> dict[str, Any] | None:
        """
        Process a device event through all layers.

        Args:
            event: Device event to process

        Returns:
            Processing result with verdict and analysis for ADD events,
            None for other events.
        """
        if event.event_type == EventType.REMOVE:
            self._record_disconnect(event)
            return None
        if event.event_type != EventType.ADD:
            return None  # bind/unbind follow from our own authorization changes

        descriptor = event.descriptor
        if descriptor is None:
            logger.error(
                "Cannot read descriptors for %s (%s:%s); keeping it blocked",
                event.sys_path or event.device_id,
                event.vid,
                event.pid,
            )
            self.interceptor.block_device(event)
            return None

        logger.info(
            "Processing device: %s (%s)",
            descriptor.vid_pid,
            descriptor.product or "Unknown",
        )

        decision = await self.evaluate(descriptor)
        await self._execute_verdict(event, descriptor, decision)
        self._record(descriptor, decision)
        if event.sys_path:
            self._attached[event.sys_path] = decision.fingerprint

        self._stats["devices_processed"] += 1
        if decision.action == Action.ALLOW:
            self._stats["devices_allowed"] += 1
        elif decision.action == Action.BLOCK:
            self._stats["devices_blocked"] += 1
        else:
            self._stats["devices_held"] += 1

        result = decision.to_result()
        await self._broadcast_event(event, decision.action, result)
        return result

    async def evaluate(self, descriptor: DeviceDescriptor) -> Decision:
        """Decide what to do with a device. Does not touch the device or the database."""
        fingerprint = generate_fingerprint(descriptor)
        known = self.db.get_device(fingerprint)
        trust = str(known.trust_level) if known is not None else TrustLevel.UNKNOWN.value

        if trust == TrustLevel.TRUSTED.value:
            return Decision(
                Action.ALLOW, fingerprint, "Trusted by operator", operator_decision=True
            )
        if trust == TrustLevel.BLOCKED.value:
            return Decision(
                Action.BLOCK, fingerprint, "Blocked by operator", operator_decision=True
            )

        policy_result = self.policy_engine.evaluate(descriptor)
        rule = policy_result.matched_rule.comment if policy_result.matched_rule else None
        rule_label = rule or "default action"

        if policy_result.action == Action.BLOCK:
            return Decision(Action.BLOCK, fingerprint, f"Policy: {rule_label}", rule=rule)

        validation = self._validator.validate(descriptor)

        if policy_result.action == Action.ALLOW:
            spoof = check_vendor_mismatch(descriptor)
            if not spoof and validation.risk_score < SPOOF_ESCALATION_SCORE:
                return Decision(Action.ALLOW, fingerprint, f"Policy: {rule_label}", rule=rule)
            concern = spoof or "descriptor anomalies: " + "; ".join(
                a.description for a in validation.anomalies
            )
            logger.warning(
                "Rule %r allows %s but %s; analyzing instead",
                rule_label,
                descriptor.vid_pid,
                concern,
            )
        elif self._bypasses_review(descriptor):
            return Decision(Action.ALLOW, fingerprint, "Class listed in bypass_classes", rule=rule)

        # Never-allowed devices (new, or held last time) carry extra risk
        never_allowed = known is None or trust == TrustLevel.REVIEW.value

        heuristic = self._heuristics.analyze(descriptor)
        scores = {"validator": validation.risk_score, "heuristics": heuristic.risk_score}
        notes = [a.description for a in validation.anomalies]
        if heuristic.analysis:
            notes.append(heuristic.analysis.removeprefix("Mock analysis: "))

        llm = await self._llm_analyze(descriptor)
        if llm is not None:
            scores["llm"] = llm.risk_score
            notes.insert(0, f"LLM: {llm.analysis}")

        # Max, not average: the LLM sees device-controlled strings and must
        # not be able to talk a device below what the local checks found.
        score = calculate_composite_score(
            max(scores.values()),
            confidence=1.0,
            first_seen=never_allowed,
            has_anomalies=validation.has_anomalies,
        )
        action = score_to_action(score)
        breakdown = ", ".join(f"{k}={v}" for k, v in scores.items())
        verb = {Action.ALLOW: "allowed", Action.BLOCK: "blocked", Action.REVIEW: "held"}[action]
        return Decision(
            action,
            fingerprint,
            f"Risk {score}/100 ({breakdown}{', never allowed' if never_allowed else ''}): {verb}",
            rule=rule,
            risk_score=score,
            analysis="; ".join(n for n in notes if n) or None,
        )

    def _bypasses_review(self, descriptor: DeviceDescriptor) -> bool:
        bypass = set(self.config.interceptor.bypass_classes)
        if not bypass or not descriptor.interfaces:
            return False
        classes = {intf.interface_class for intf in descriptor.interfaces}
        if descriptor.device_class not in (0x00, 0xEF):
            classes.add(descriptor.device_class)
        return classes <= bypass

    async def _llm_analyze(self, descriptor: DeviceDescriptor) -> AnalysisResult | None:
        analyzer = self.analyzer
        if analyzer is None:
            return None
        timeout = float(self.config.interceptor.analysis_timeout)
        try:
            if hasattr(analyzer, "analyze_async"):
                coro = analyzer.analyze_async(descriptor)
            else:
                coro = asyncio.get_running_loop().run_in_executor(
                    None, analyzer.analyze, descriptor
                )
            return await asyncio.wait_for(coro, timeout=timeout)
        except asyncio.TimeoutError:
            logger.warning("LLM analysis timed out after %.0fs; using local scoring", timeout)
        except Exception as e:
            logger.warning("LLM analysis failed (%s); using local scoring", e)
        return None

    async def _execute_verdict(
        self,
        event: USBEvent,
        descriptor: DeviceDescriptor,
        decision: Decision,
    ) -> None:
        """Apply the decision to the device and alert if it was stopped."""
        name = f"{descriptor.vid_pid} {descriptor.display_name!r}"
        if decision.action == Action.ALLOW:
            self.interceptor.allow_device(event)
            logger.info("ALLOWED %s: %s", name, decision.reason)
            return

        self.interceptor.block_device(event)
        if decision.held:
            logger.warning(
                "HELD %s: %s. To allow it: usb-sentinel devices trust %s trusted",
                name,
                decision.reason,
                decision.fingerprint,
            )
        else:
            logger.warning("BLOCKED %s: %s", name, decision.reason)
        await self._send_alert(descriptor, decision)

    def _record(self, descriptor: DeviceDescriptor, decision: Decision) -> None:
        """Persist the device and the event (non-fatal if the DB is unavailable)."""
        try:
            device = self.db.add_device(
                fingerprint=decision.fingerprint,
                vid=descriptor.vid,
                pid=descriptor.pid,
                manufacturer=descriptor.manufacturer,
                product=descriptor.product,
                serial=descriptor.serial,
            )
            if not decision.operator_decision:
                # "review" marks devices waiting for an operator decision
                current = str(device.trust_level)
                wanted = TrustLevel.REVIEW.value if decision.held else TrustLevel.UNKNOWN.value
                if current in (TrustLevel.UNKNOWN.value, TrustLevel.REVIEW.value) and (
                    current != wanted
                ):
                    self.db.update_trust_level(decision.fingerprint, wanted)

            self.db.log_event(
                device_fingerprint=decision.fingerprint,
                event_type=_EVENT_TYPES[decision.action],
                policy_rule=(decision.rule or decision.reason)[:256],
                llm_analysis=decision.analysis,
                risk_score=decision.risk_score,
                verdict=decision.action.value,
                raw_descriptor=descriptor.to_dict(),
            )
        except Exception as db_err:
            logger.warning("Failed to log event to database: %s", db_err)

    def _record_disconnect(self, event: USBEvent) -> None:
        fingerprint = self._attached.pop(event.sys_path, None)
        if fingerprint is None:
            return
        logger.info("Disconnected %s:%s (%s)", event.vid, event.pid, fingerprint)
        try:
            self.db.log_event(device_fingerprint=fingerprint, event_type=AuditEventType.DISCONNECT)
        except Exception as db_err:
            logger.warning("Failed to log disconnect: %s", db_err)

    async def _broadcast_event(
        self,
        event: USBEvent,
        action: Action,
        result: dict[str, Any],
    ) -> None:
        """Broadcast device event via WebSocket (only when API is enabled)."""
        if not self._api_enabled or event.descriptor is None:
            return

        try:
            from sentinel.api.websocket import (
                WebSocketEventType,
                broadcast_device_event,
            )

            event_type_map = {
                Action.ALLOW: WebSocketEventType.DEVICE_ALLOWED,
                Action.BLOCK: WebSocketEventType.DEVICE_BLOCKED,
                Action.REVIEW: WebSocketEventType.DEVICE_SANDBOXED,
            }

            await broadcast_device_event(
                event_type=event_type_map.get(action, WebSocketEventType.DEVICE_CONNECT),
                fingerprint=result["fingerprint"],
                vid=event.descriptor.vid,
                pid=event.descriptor.pid,
                manufacturer=event.descriptor.manufacturer,
                product=event.descriptor.product,
                risk_score=result.get("risk_score"),
                verdict=action.value,
            )
        except Exception as e:
            logger.debug("WebSocket broadcast failed: %s", e)

    async def _send_alert(self, descriptor: DeviceDescriptor, decision: Decision) -> None:
        """Alert on a blocked or held device."""
        alerts = self.config.alerts
        if not alerts.enabled:
            return
        if decision.risk_score is not None and decision.risk_score < alerts.threshold:
            return

        status = "held for review" if decision.held else "blocked"
        message = f"USB device {status}: {descriptor.vid_pid} {descriptor.display_name} ({decision.reason})"

        if alerts.methods.syslog:
            logger.warning("ALERT: %s", message)

        if alerts.methods.webhook:
            payload = {
                "event": "device_held" if decision.held else "device_blocked",
                "message": message,
                "fingerprint": decision.fingerprint,
                "vid": descriptor.vid,
                "pid": descriptor.pid,
                "manufacturer": descriptor.manufacturer,
                "product": descriptor.product,
                "verdict": decision.action.value,
                "risk_score": decision.risk_score,
                "reason": decision.reason,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(None, _post_webhook, alerts.methods.webhook, payload)

    async def _start_api_server(self) -> None:
        """Start the FastAPI server (requires api dependencies)."""
        import uvicorn

        from sentinel.api import configure_services, create_app
        from sentinel.api.websocket import init_websocket

        logger.info("Starting API server on %s:%s", self.config.api.host, self.config.api.port)

        # Create and configure app
        app = create_app(
            debug=self.config.daemon.log_level == "debug",
            cors_origins=self.config.api.cors_origins,
        )

        configure_services(
            app=app,
            db=self.db,
            policy_engine=self.policy_engine,
            analyzer=self.analyzer or self._heuristics,
            default_api_key=self.config.api.api_key,
        )

        # Initialize WebSocket
        await init_websocket()

        # Create server config
        config = uvicorn.Config(
            app=app,
            host=self.config.api.host,
            port=self.config.api.port,
            log_level=self.config.daemon.log_level,
            access_log=False,
        )

        self._api_server = uvicorn.Server(config)

        # Start server in background
        asyncio.create_task(self._api_server.serve())

        logger.info("API server started")

    def get_statistics(self) -> dict[str, Any]:
        """Get daemon statistics."""
        uptime = None
        if self._stats["start_time"]:
            uptime = (datetime.now(timezone.utc) - self._stats["start_time"]).total_seconds()

        return {
            **self._stats,
            "uptime_seconds": uptime,
            "running": self.running,
            "policy_rules": len(self.policy_engine.policy.rules) if self._policy_engine else 0,
            "llm_available": self._analyzer is not None,
        }


def _post_webhook(url: str, payload: dict[str, Any]) -> None:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            response.read()
    except Exception as e:
        logger.warning("Webhook alert to %s failed: %s", url, e)


async def run_daemon(config: SentinelConfig) -> int:
    """Run the daemon with the given configuration."""
    daemon = SentinelDaemon(config)

    # Set up signal handlers
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        loop.add_signal_handler(sig, daemon.handle_signal, sig)

    try:
        await daemon.run()
    except Exception as e:
        logger.error("Daemon failed: %s", e)
        logger.debug("Daemon failure details", exc_info=True)
        return 1

    return 0


def main(argv: list[str] | None = None) -> int:
    """Main entry point for the daemon."""
    parser = argparse.ArgumentParser(
        prog="sentinel-daemon",
        description="USB Sentinel daemon process",
    )
    parser.add_argument(
        "-V",
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    parser.add_argument(
        "-c",
        "--config",
        metavar="FILE",
        help="Path to configuration file",
    )
    parser.add_argument(
        "-f",
        "--foreground",
        action="store_true",
        help="Run in foreground (the daemon always does; kept for compatibility)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose logging",
    )

    args = parser.parse_args(argv)

    # Load configuration
    try:
        config = load_config(args.config)
    except (OSError, ValueError, yaml.YAMLError) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    # Override settings from command line
    if args.foreground:
        config.daemon.daemonize = False
    if args.verbose:
        config.daemon.log_level = "debug"

    # Validate configuration
    errors = validate_config(config)
    if errors:
        print("Configuration errors:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1

    # Run daemon
    return asyncio.run(run_daemon(config))


if __name__ == "__main__":
    sys.exit(main())
