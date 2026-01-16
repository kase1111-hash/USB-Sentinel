"""
USB Sentinel Daemon.

Main daemon process that orchestrates all layers:
- USB event interception
- Policy evaluation
- LLM analysis
- Audit logging
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import signal
import sys
from pathlib import Path

from sentinel import __version__
from sentinel.config import SentinelConfig, load_config, validate_config


logger = logging.getLogger("sentinel")


class SentinelDaemon:
    """Main daemon class orchestrating all USB Sentinel components."""

    def __init__(self, config: SentinelConfig) -> None:
        self.config = config
        self.running = False
        self._setup_logging()

    def _setup_logging(self) -> None:
        """Configure logging based on config."""
        level = getattr(logging, self.config.daemon.log_level.upper(), logging.INFO)
        logging.basicConfig(
            level=level,
            format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

    async def start(self) -> None:
        """Start the daemon."""
        logger.info("Starting USB Sentinel daemon v%s", __version__)
        self.running = True

        # TODO: Initialize components
        # - Event interceptor
        # - Policy engine
        # - LLM analyzer
        # - Audit database
        # - API server

        logger.info("Daemon components initialized")
        logger.info("Waiting for USB events...")

        # Main event loop
        while self.running:
            await asyncio.sleep(1)

    async def stop(self) -> None:
        """Stop the daemon gracefully."""
        logger.info("Stopping USB Sentinel daemon...")
        self.running = False

        # TODO: Cleanup components
        # - Close database connections
        # - Stop API server
        # - Release USB listeners

        logger.info("Daemon stopped")

    def handle_signal(self, signum: int) -> None:
        """Handle termination signals."""
        sig_name = signal.Signals(signum).name
        logger.info("Received signal %s, initiating shutdown", sig_name)
        self.running = False


async def run_daemon(config: SentinelConfig) -> int:
    """Run the daemon with the given configuration."""
    daemon = SentinelDaemon(config)

    # Set up signal handlers
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, lambda s=sig: daemon.handle_signal(s))

    try:
        await daemon.start()
    except Exception as e:
        logger.exception("Daemon crashed: %s", e)
        return 1
    finally:
        await daemon.stop()

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
