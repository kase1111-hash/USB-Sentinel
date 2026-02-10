"""
USB Sentinel Daemon.

Main entry point that integrates all system layers:
- USB Interceptor (Layer 1)
- Policy Engine (Layer 2)
- LLM Analyzer (Layer 3)
- Audit Database (Layer 4)
- REST API (Layer 5, optional)
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import signal
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

from sentinel import __version__
from sentinel.analyzer.llm import LLMAnalyzer
from sentinel.analyzer.scoring import AnalysisResult, score_to_action
from sentinel.audit.database import AuditDatabase
from sentinel.config import SentinelConfig, load_config, validate_config
from sentinel.interceptor.descriptors import DeviceDescriptor
from sentinel.interceptor.events import DeviceEvent, EventType, MockUSBInterceptor
from sentinel.interceptor.linux import create_interceptor
from sentinel.policy.engine import PolicyEngine
from sentinel.policy.fingerprint import generate_fingerprint
from sentinel.policy.models import Action
from sentinel.policy.parser import load_policy

logger = logging.getLogger("sentinel")


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
        self._analyzer: LLMAnalyzer | None = None
        self._interceptor: MockUSBInterceptor | None = None
        self._api_server: Any = None
        self._api_enabled: bool = config.api.enabled

        # State
        self.running = False
        self._shutdown_event = asyncio.Event()
        self._stats = {
            "devices_processed": 0,
            "devices_allowed": 0,
            "devices_blocked": 0,
            "devices_sandboxed": 0,
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

    @property
    def db(self) -> AuditDatabase:
        """Get or initialize audit database."""
        if self._db is None:
            db_path = Path(self.config.database.path)
            db_path.parent.mkdir(parents=True, exist_ok=True)
            self._db = AuditDatabase(str(db_path))
        return self._db

    @property
    def policy_engine(self) -> PolicyEngine:
        """Get or initialize policy engine."""
        if self._policy_engine is None:
            policy_path = Path(self.config.policy.rules_file)
            if policy_path.exists():
                policy = load_policy(policy_path)
                self._policy_engine = PolicyEngine(policy=policy)
            else:
                logger.warning(f"Policy file not found: {policy_path}, using empty policy")
                self._policy_engine = PolicyEngine([])
        return self._policy_engine

    @property
    def analyzer(self) -> LLMAnalyzer | None:
        """Get or initialize LLM analyzer."""
        if self._analyzer is None and self.config.analyzer.enabled:
            if self.config.analyzer.api_key:
                self._analyzer = LLMAnalyzer(
                    api_key=self.config.analyzer.api_key,
                    model=self.config.analyzer.model,
                )
            else:
                logger.warning("LLM analyzer disabled: no API key configured")
        return self._analyzer

    @property
    def interceptor(self) -> MockUSBInterceptor:
        """Get or initialize USB interceptor."""
        if self._interceptor is None:
            self._interceptor = create_interceptor(use_mock=True)
        return self._interceptor

    async def start(self) -> None:
        """Start the daemon and all services."""
        logger.info("Starting USB Sentinel daemon v%s", __version__)
        self.running = True
        self._stats["start_time"] = datetime.utcnow()
        self._shutdown_event.clear()

        # Initialize database
        logger.info(f"Initializing database: {self.config.database.path}")
        _ = self.db

        # Initialize policy engine
        logger.info(f"Loading policy from: {self.config.policy.rules_file}")
        _ = self.policy_engine
        logger.info(f"Loaded {len(self.policy_engine.policy.rules)} policy rules")

        # Initialize analyzer if enabled
        if self.config.analyzer.enabled:
            _ = self.analyzer
            if self.analyzer:
                logger.info(f"LLM analyzer ready: {self.config.analyzer.model}")
            else:
                logger.warning("LLM analyzer not available")

        # Initialize interceptor
        logger.info("Initializing USB interceptor")
        _ = self.interceptor

        # Start API server if enabled
        if self.config.api.enabled:
            await self._start_api_server()

        logger.info("Daemon components initialized")
        logger.info("Waiting for USB events...")

    async def stop(self) -> None:
        """Stop the daemon gracefully."""
        logger.info("Stopping USB Sentinel daemon...")
        self.running = False
        self._shutdown_event.set()

        # Stop API server
        if self._api_server is not None:
            self._api_server.should_exit = True
            from sentinel.api.websocket import shutdown_websocket
            await shutdown_websocket()

        # Clean up interceptor
        if self._interceptor is not None:
            self._interceptor.cleanup()

        # Close database
        if self._db is not None:
            self._db.close()

        logger.info("Daemon stopped")

    async def run(self) -> None:
        """Main daemon loop - process device events."""
        await self.start()

        try:
            # Process events until shutdown
            async for event in self._event_loop():
                if not self.running:
                    break
                await self.handle_device_event(event)

        except asyncio.CancelledError:
            logger.info("Daemon loop cancelled")
        except Exception as e:
            logger.error(f"Daemon error: {e}", exc_info=True)
        finally:
            await self.stop()

    async def handle_device_event(self, event: DeviceEvent) -> dict[str, Any]:
        """
        Process a device event through all layers.

        Args:
            event: Device event to process

        Returns:
            Processing result with verdict and analysis
        """
        result = {
            "fingerprint": None,
            "action": None,
            "rule": None,
            "analysis": None,
            "risk_score": None,
        }

        try:
            descriptor = event.descriptor
            fingerprint = generate_fingerprint(descriptor)
            result["fingerprint"] = fingerprint

            logger.info(
                f"Processing device: {descriptor.vid}:{descriptor.pid} "
                f"({descriptor.product or 'Unknown'})"
            )

            # Check if device is known
            is_new = self.db.get_device(fingerprint) is None

            # Register device if new
            if is_new:
                self.db.register_device(
                    fingerprint=fingerprint,
                    vid=descriptor.vid,
                    pid=descriptor.pid,
                    manufacturer=descriptor.manufacturer,
                    product=descriptor.product,
                    serial=descriptor.serial,
                )
                logger.info(f"New device registered: {fingerprint}")

            # Layer 2: Policy evaluation
            eval_result = self.policy_engine.evaluate(descriptor)
            action = eval_result.action
            rule = eval_result.matched_rule
            result["action"] = action.value
            result["rule"] = rule.comment if rule else None

            logger.debug(f"Policy verdict: {action.value} (rule: {result['rule']})")

            # Layer 3: LLM analysis if needed
            analysis_result: AnalysisResult | None = None
            if action == Action.REVIEW and self.analyzer:
                logger.info("Triggering LLM analysis")
                try:
                    analysis_result = self.analyzer.analyze(descriptor)
                    result["analysis"] = analysis_result.analysis
                    result["risk_score"] = analysis_result.risk_score
                    action = score_to_action(analysis_result.risk_score)
                    result["action"] = action.value
                    logger.info(
                        f"LLM verdict: {action.value} "
                        f"(risk_score: {analysis_result.risk_score})"
                    )
                except Exception as e:
                    logger.error(f"LLM analysis failed: {e}")
                    # Fall back to default action on error
                    action = Action.REVIEW

            # Execute verdict
            await self._execute_verdict(event, action)

            # Log event to database
            self.db.log_event(
                device_fingerprint=fingerprint,
                event_type=event.event_type.value,
                policy_rule=result["rule"],
                llm_analysis=result["analysis"],
                risk_score=result["risk_score"],
                verdict=action.value,
            )

            # Update statistics
            self._stats["devices_processed"] += 1
            if action == Action.ALLOW:
                self._stats["devices_allowed"] += 1
            elif action == Action.BLOCK:
                self._stats["devices_blocked"] += 1
            else:
                self._stats["devices_sandboxed"] += 1

            # Broadcast event via WebSocket
            await self._broadcast_event(event, action, result)

            return result

        except Exception as e:
            logger.error(f"Error processing device event: {e}", exc_info=True)
            raise

    async def _execute_verdict(self, event: DeviceEvent, action: Action) -> None:
        """
        Execute the verdict on the device.

        Args:
            event: Device event
            action: Action to take
        """
        if action == Action.ALLOW:
            # Authorize device in kernel
            self.interceptor.authorize_device(event.bus_id, True)
            logger.info(f"Device authorized: {event.bus_id}")

        elif action == Action.BLOCK:
            # Reject device
            self.interceptor.authorize_device(event.bus_id, False)
            logger.warning(f"Device blocked: {event.bus_id}")

            # Send alert if configured
            if self.config.alerts.enabled:
                await self._send_alert(event, action)

        else:  # REVIEW/SANDBOX
            # Allow device but monitor (in real implementation, would sandbox)
            self.interceptor.authorize_device(event.bus_id, True)
            logger.info(f"Device sandboxed: {event.bus_id}")

    async def _broadcast_event(
        self,
        event: DeviceEvent,
        action: Action,
        result: dict[str, Any],
    ) -> None:
        """Broadcast device event via WebSocket (only when API is enabled)."""
        if not self._api_enabled:
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
            logger.debug(f"WebSocket broadcast failed: {e}")

    async def _send_alert(self, event: DeviceEvent, action: Action) -> None:
        """Send alert notification for blocked device."""
        descriptor = event.descriptor
        message = (
            f"USB Device Blocked: {descriptor.vid}:{descriptor.pid} "
            f"({descriptor.product or 'Unknown'})"
        )

        # Log to syslog if enabled
        if self.config.alerts.methods.syslog:
            logger.warning(f"ALERT: {message}")

        # Send webhook if configured
        if self.config.alerts.methods.webhook:
            # In a real implementation, would POST to webhook URL
            logger.debug(f"Would send webhook alert: {message}")

    async def _event_loop(self):
        """Async generator for device events."""
        while self.running:
            # Check for events from interceptor
            events = self.interceptor.poll_events(timeout=0.1)

            for event in events:
                yield event

            # Check for shutdown
            if self._shutdown_event.is_set():
                break

            # Small sleep to prevent busy-waiting
            await asyncio.sleep(0.01)

    async def _start_api_server(self) -> None:
        """Start the FastAPI server (requires api dependencies)."""
        import uvicorn

        from sentinel.api import configure_services, create_app
        from sentinel.api.websocket import init_websocket

        logger.info(f"Starting API server on {self.config.api.host}:{self.config.api.port}")

        # Create and configure app
        app = create_app(
            debug=self.config.daemon.log_level == "debug",
            cors_origins=self.config.api.cors_origins,
        )

        configure_services(
            app=app,
            db=self.db,
            policy_engine=self.policy_engine,
            analyzer=self.analyzer,
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

    def handle_signal(self, signum: int) -> None:
        """Handle termination signals."""
        sig_name = signal.Signals(signum).name
        logger.info("Received signal %s, initiating shutdown", sig_name)
        self.running = False
        self._shutdown_event.set()

    def get_statistics(self) -> dict[str, Any]:
        """Get daemon statistics."""
        uptime = None
        if self._stats["start_time"]:
            uptime = (datetime.utcnow() - self._stats["start_time"]).total_seconds()

        return {
            **self._stats,
            "uptime_seconds": uptime,
            "running": self.running,
            "policy_rules": len(self.policy_engine.policy.rules) if self._policy_engine else 0,
            "analyzer_available": self._analyzer is not None,
        }


async def run_daemon(config: SentinelConfig) -> int:
    """Run the daemon with the given configuration."""
    daemon = SentinelDaemon(config)

    # Set up signal handlers
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, lambda s=sig: daemon.handle_signal(s))

    try:
        await daemon.run()
    except Exception as e:
        logger.exception("Daemon crashed: %s", e)
        return 1

    return 0


def main(argv: list[str] | None = None) -> int:
    """Main entry point for the daemon."""
    parser = argparse.ArgumentParser(
        prog="sentinel-daemon",
        description="USB Sentinel daemon process",
    )
    parser.add_argument(
        "-V", "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    parser.add_argument(
        "-c", "--config",
        metavar="FILE",
        help="Path to configuration file",
    )
    parser.add_argument(
        "-f", "--foreground",
        action="store_true",
        help="Run in foreground (don't daemonize)",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose logging",
    )

    args = parser.parse_args(argv)

    # Load configuration
    try:
        config = load_config(args.config)
    except FileNotFoundError as e:
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
