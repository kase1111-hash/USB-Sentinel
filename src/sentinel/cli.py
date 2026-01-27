"""
USB Sentinel Command Line Interface.

Provides commands for managing USB Sentinel:
- start: Start the daemon
- stop: Stop the daemon
- status: Show daemon status
- devices: List and manage devices
- events: Query event log
- policy: Manage policy rules
- analyze: Manually analyze a device
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

from sentinel import __version__
from sentinel.audit.database import AuditDatabase
from sentinel.config import load_config, validate_config
from sentinel.interceptor.descriptors import DeviceDescriptor, InterfaceDescriptor
from sentinel.policy.engine import PolicyEngine
from sentinel.policy.fingerprint import generate_fingerprint
from sentinel.policy.models import Action
from sentinel.policy.parser import load_policy


def main(argv: list[str] | None = None) -> int:
    """Main entry point for the CLI."""
    parser = argparse.ArgumentParser(
        prog="usb-sentinel",
        description="LLM-integrated USB firewall system",
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
        "--json",
        action="store_true",
        help="Output in JSON format",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # start command
    start_parser = subparsers.add_parser("start", help="Start the daemon")
    start_parser.add_argument(
        "-f", "--foreground",
        action="store_true",
        help="Run in foreground",
    )
    start_parser.set_defaults(func=cmd_start)

    # stop command
    stop_parser = subparsers.add_parser("stop", help="Stop the daemon")
    stop_parser.set_defaults(func=cmd_stop)

    # status command
    status_parser = subparsers.add_parser("status", help="Show daemon status")
    status_parser.set_defaults(func=cmd_status)

    # devices command
    devices_parser = subparsers.add_parser("devices", help="List and manage devices")
    devices_sub = devices_parser.add_subparsers(dest="devices_cmd")

    list_parser = devices_sub.add_parser("list", help="List known devices")
    list_parser.add_argument(
        "-a", "--all",
        action="store_true",
        help="Show all devices including old",
    )
    list_parser.add_argument(
        "--trust",
        choices=["trusted", "blocked", "unknown", "review"],
        help="Filter by trust level",
    )

    show_parser = devices_sub.add_parser("show", help="Show device details")
    show_parser.add_argument("fingerprint", help="Device fingerprint")

    trust_parser = devices_sub.add_parser("trust", help="Set device trust level")
    trust_parser.add_argument("fingerprint", help="Device fingerprint")
    trust_parser.add_argument(
        "level",
        choices=["trusted", "blocked", "unknown"],
        help="Trust level to set",
    )

    devices_parser.set_defaults(func=cmd_devices)

    # events command
    events_parser = subparsers.add_parser("events", help="Query event log")
    events_parser.add_argument(
        "-n", "--limit",
        type=int,
        default=20,
        help="Number of events to show",
    )
    events_parser.add_argument(
        "-d", "--device",
        help="Filter by device fingerprint",
    )
    events_parser.add_argument(
        "-t", "--type",
        choices=["connect", "disconnect", "allowed", "blocked"],
        help="Filter by event type",
    )
    events_parser.add_argument(
        "--since",
        help="Show events since (YYYY-MM-DD)",
    )
    events_parser.set_defaults(func=cmd_events)

    # policy command
    policy_parser = subparsers.add_parser("policy", help="Manage policy rules")
    policy_sub = policy_parser.add_subparsers(dest="policy_cmd")

    policy_sub.add_parser("show", help="Show current policy")
    policy_sub.add_parser("validate", help="Validate policy file")
    policy_sub.add_parser("reload", help="Reload policy from file")

    test_parser = policy_sub.add_parser("test", help="Test policy against device")
    test_parser.add_argument("vid", help="Vendor ID (4 hex chars)")
    test_parser.add_argument("pid", help="Product ID (4 hex chars)")
    test_parser.add_argument("--class", dest="device_class", type=int, default=0)

    policy_parser.set_defaults(func=cmd_policy)

    # analyze command
    analyze_parser = subparsers.add_parser("analyze", help="Analyze a device")
    analyze_parser.add_argument(
        "device",
        help="Device to analyze (vid:pid or fingerprint)",
    )
    analyze_parser.add_argument(
        "--manufacturer",
        help="Device manufacturer",
    )
    analyze_parser.add_argument(
        "--product",
        help="Device product name",
    )
    analyze_parser.set_defaults(func=cmd_analyze)

    # export command
    export_parser = subparsers.add_parser("export", help="Export data")
    export_parser.add_argument(
        "what",
        choices=["devices", "events", "policy"],
        help="What to export",
    )
    export_parser.add_argument(
        "-o", "--output",
        help="Output file (default: stdout)",
    )
    export_parser.add_argument(
        "--format",
        choices=["json", "csv"],
        default="json",
        help="Output format",
    )
    export_parser.set_defaults(func=cmd_export)

    # Parse arguments
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        return 0

    # Execute command
    return args.func(args)


def get_db(args: argparse.Namespace) -> AuditDatabase:
    """Get database instance from config."""
    config = load_config(args.config)
    db_path = Path(config.database.path)
    if not db_path.exists():
        db_path.parent.mkdir(parents=True, exist_ok=True)
    return AuditDatabase(str(db_path))


def output(data: Any, args: argparse.Namespace) -> None:
    """Output data in requested format."""
    if getattr(args, "json", False):
        print(json.dumps(data, indent=2, default=str))
    elif isinstance(data, dict):
        for key, value in data.items():
            print(f"{key}: {value}")
    elif isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                for key, value in item.items():
                    print(f"  {key}: {value}")
                print()
            else:
                print(f"  {item}")
    else:
        print(data)


def cmd_start(args: argparse.Namespace) -> int:
    """Start the daemon."""
    from sentinel.daemon import main as daemon_main

    daemon_args = []
    if args.config:
        daemon_args.extend(["-c", args.config])
    if args.foreground:
        daemon_args.append("-f")

    return daemon_main(daemon_args)


def cmd_stop(args: argparse.Namespace) -> int:
    """Stop the daemon."""
    import os
    import signal

    config = load_config(args.config)
    pid_file = Path(config.daemon.pid_file)

    if not pid_file.exists():
        print("Daemon is not running (no PID file)")
        return 1

    try:
        pid = int(pid_file.read_text().strip())
        os.kill(pid, signal.SIGTERM)
        print(f"Sent SIGTERM to daemon (PID {pid})")
        return 0
    except ProcessLookupError:
        print("Daemon process not found, removing stale PID file")
        pid_file.unlink()
        return 1
    except Exception as e:
        print(f"Error stopping daemon: {e}")
        return 1


def cmd_status(args: argparse.Namespace) -> int:
    """Show daemon status."""
    import os

    config = load_config(args.config)
    pid_file = Path(config.daemon.pid_file)

    daemon_running = False
    daemon_pid = None

    if pid_file.exists():
        try:
            daemon_pid = int(pid_file.read_text().strip())
            os.kill(daemon_pid, 0)  # Check if process exists
            daemon_running = True
        except (ProcessLookupError, ValueError):
            pass

    # Get database stats
    try:
        db = get_db(args)
        stats = db.get_system_statistics()
        db.close()
    except Exception:
        stats = {}

    status_data = {
        "version": __version__,
        "daemon_running": daemon_running,
        "daemon_pid": daemon_pid,
        "config_file": args.config or "default",
        "database": config.database.path,
        "policy_file": config.policy.rules_file,
        "total_devices": stats.get("total_devices", 0),
        "total_events": stats.get("total_events", 0),
        "blocked_today": stats.get("blocked_today", 0),
    }

    if getattr(args, "json", False):
        output(status_data, args)
    else:
        print("USB Sentinel Status")
        print("=" * 50)
        print(f"Version:        {status_data['version']}")
        print(f"Daemon:         {'Running' if daemon_running else 'Stopped'}")
        if daemon_pid:
            print(f"PID:            {daemon_pid}")
        print(f"Config:         {status_data['config_file']}")
        print(f"Database:       {status_data['database']}")
        print(f"Policy:         {status_data['policy_file']}")
        print()
        print("Statistics:")
        print(f"  Total Devices:  {status_data['total_devices']}")
        print(f"  Total Events:   {status_data['total_events']}")
        print(f"  Blocked Today:  {status_data['blocked_today']}")

    return 0


def cmd_devices(args: argparse.Namespace) -> int:
    """List and manage devices."""
    db = get_db(args)

    try:
        if args.devices_cmd == "list" or args.devices_cmd is None:
            filters = {}
            if hasattr(args, "trust") and args.trust:
                filters["trust_level"] = args.trust

            devices, total = db.list_devices(filters=filters, limit=100)

            if getattr(args, "json", False):
                output([d.to_dict() for d in devices], args)
            else:
                print(f"Known USB Devices ({total} total)")
                print("=" * 70)
                if not devices:
                    print("No devices found.")
                else:
                    print(f"{'Fingerprint':<20} {'VID:PID':<12} {'Product':<25} {'Trust':<10}")
                    print("-" * 70)
                    for device in devices:
                        product = (device.product or "Unknown")[:25]
                        print(
                            f"{device.fingerprint[:20]:<20} "
                            f"{device.vid}:{device.pid}  "
                            f"{product:<25} "
                            f"{device.trust_level:<10}"
                        )

        elif args.devices_cmd == "show":
            device = db.get_device(args.fingerprint)
            if device is None:
                print(f"Device not found: {args.fingerprint}")
                return 1

            if getattr(args, "json", False):
                output(device.to_dict(), args)
            else:
                print("Device Details")
                print("=" * 50)
                print(f"Fingerprint:   {device.fingerprint}")
                print(f"VID:PID:       {device.vid}:{device.pid}")
                print(f"Manufacturer:  {device.manufacturer or 'Unknown'}")
                print(f"Product:       {device.product or 'Unknown'}")
                print(f"Serial:        {device.serial or 'N/A'}")
                print(f"Trust Level:   {device.trust_level}")
                print(f"First Seen:    {device.first_seen}")
                print(f"Last Seen:     {device.last_seen or 'N/A'}")

        elif args.devices_cmd == "trust":
            device = db.get_device(args.fingerprint)
            if device is None:
                print(f"Device not found: {args.fingerprint}")
                return 1

            db.update_trust_level(args.fingerprint, args.level)
            print(f"Trust level updated: {args.fingerprint} -> {args.level}")

        return 0

    finally:
        db.close()


def cmd_events(args: argparse.Namespace) -> int:
    """Query event log."""
    db = get_db(args)

    try:
        filters = {}
        if args.device:
            filters["device_fingerprint"] = args.device
        if args.type:
            filters["event_type"] = args.type
        if args.since:
            filters["since"] = datetime.strptime(args.since, "%Y-%m-%d")

        events, total = db.list_events(filters=filters, limit=args.limit)

        if getattr(args, "json", False):
            output([e.to_dict() for e in events], args)
        else:
            print(f"Event Log ({len(events)} of {total} events)")
            print("=" * 80)
            if not events:
                print("No events found.")
            else:
                print(f"{'Time':<20} {'Device':<18} {'Type':<12} {'Verdict':<10} {'Risk':<6}")
                print("-" * 80)
                for event in events:
                    time_str = event.timestamp.strftime("%Y-%m-%d %H:%M:%S")
                    risk = str(event.risk_score) if event.risk_score else "-"
                    print(
                        f"{time_str:<20} "
                        f"{event.device_fingerprint[:18]:<18} "
                        f"{event.event_type:<12} "
                        f"{event.verdict or '-':<10} "
                        f"{risk:<6}"
                    )

        return 0

    finally:
        db.close()


def cmd_policy(args: argparse.Namespace) -> int:
    """Manage policy rules."""
    config = load_config(args.config)
    policy_path = Path(config.policy.rules_file)

    if args.policy_cmd == "show":
        if not policy_path.exists():
            print(f"Policy file not found: {policy_path}")
            return 1

        policy = load_policy(policy_path)

        if getattr(args, "json", False):
            output(policy.to_dict(), args)
        else:
            print(f"Current Policy ({len(policy.rules)} rules)")
            print("=" * 60)
            for i, rule in enumerate(policy.rules, 1):
                match_str = rule.match.to_dict()
                print(f"{i}. {rule.action.value.upper()}")
                print(f"   Match: {match_str}")
                if rule.comment:
                    print(f"   Comment: {rule.comment}")
                print()

    elif args.policy_cmd == "validate":
        if not policy_path.exists():
            print(f"Policy file not found: {policy_path}")
            return 1

        try:
            policy = load_policy(policy_path)
            print(f"Policy valid: {len(policy.rules)} rules loaded")

            # Check for warnings
            warnings = []
            for i, rule in enumerate(policy.rules[:-1]):
                if rule.match.is_wildcard():
                    warnings.append(f"Rule {i+1}: Wildcard not at end - later rules unreachable")

            if warnings:
                print("\nWarnings:")
                for w in warnings:
                    print(f"  - {w}")

            return 0
        except Exception as e:
            print(f"Policy validation failed: {e}")
            return 1

    elif args.policy_cmd == "reload":
        print("Policy reload requires daemon to be running.")
        print("The daemon will auto-reload if hot_reload is enabled.")
        return 0

    elif args.policy_cmd == "test":
        if not policy_path.exists():
            print(f"Policy file not found: {policy_path}")
            return 1

        policy = load_policy(policy_path)
        engine = PolicyEngine(policy=policy)

        # Create test descriptor
        descriptor = DeviceDescriptor(
            vid=args.vid,
            pid=args.pid,
            device_class=args.device_class,
            device_subclass=0,
            device_protocol=0,
            serial=None,
            interfaces=[],
        )

        # Evaluate
        eval_result = engine.evaluate(descriptor)
        action = eval_result.action
        rule = eval_result.matched_rule

        result = {
            "device": f"{args.vid}:{args.pid}",
            "action": action.value,
            "rule": rule.comment if rule else None,
        }

        if getattr(args, "json", False):
            output(result, args)
        else:
            print(f"Testing policy for {args.vid}:{args.pid}")
            print("=" * 40)
            print(f"Action:  {action.value.upper()}")
            print(f"Rule:    {rule.comment if rule else 'No match (default)'}")

    else:
        print("Usage: usb-sentinel policy {show|validate|reload|test}")

    return 0


def cmd_analyze(args: argparse.Namespace) -> int:
    """Analyze a specific device."""
    config = load_config(args.config)

    # Check if analyzer is configured
    if not config.analyzer.enabled:
        print("LLM analyzer is disabled in configuration")
        return 1

    if not config.analyzer.api_key:
        print("No API key configured for LLM analyzer")
        print("Set ANTHROPIC_API_KEY environment variable or configure in sentinel.yaml")
        return 1

    # Parse device identifier
    if ":" in args.device:
        vid, pid = args.device.split(":", 1)
    else:
        # Assume fingerprint, look up in database
        db = get_db(args)
        device = db.get_device(args.device)
        db.close()

        if device is None:
            print(f"Device not found: {args.device}")
            return 1

        vid, pid = device.vid, device.pid

    # Create descriptor
    descriptor = DeviceDescriptor(
        vid=vid,
        pid=pid,
        device_class=0,
        device_subclass=0,
        device_protocol=0,
        manufacturer=args.manufacturer,
        product=args.product,
        serial=None,
        interfaces=[],
    )

    print(f"Analyzing device: {vid}:{pid}")
    print("=" * 50)

    try:
        from sentinel.analyzer.llm import LLMAnalyzer

        analyzer = LLMAnalyzer(
            api_key=config.analyzer.api_key,
            model=config.analyzer.model,
        )

        result = analyzer.analyze(descriptor)

        if getattr(args, "json", False):
            output({
                "risk_score": result.risk_score,
                "verdict": result.verdict,
                "analysis": result.analysis,
                "confidence": result.confidence,
            }, args)
        else:
            print(f"Risk Score:  {result.risk_score}/100")
            print(f"Verdict:     {result.verdict}")
            print(f"Confidence:  {result.confidence:.0%}")
            print()
            print("Analysis:")
            print("-" * 50)
            print(result.analysis)

        return 0

    except Exception as e:
        print(f"Analysis failed: {e}")
        return 1


def cmd_export(args: argparse.Namespace) -> int:
    """Export data."""
    import csv
    import io

    db = get_db(args)

    try:
        if args.what == "devices":
            devices, _ = db.list_devices(limit=10000)
            data = [d.to_dict() for d in devices]
        elif args.what == "events":
            events, _ = db.list_events(limit=10000)
            data = [e.to_dict() for e in events]
        elif args.what == "policy":
            config = load_config(args.config)
            policy = load_policy(Path(config.policy.rules_file))
            data = policy.to_dict()
        else:
            print(f"Unknown export type: {args.what}")
            return 1

        # Format output
        if args.format == "json":
            output_str = json.dumps(data, indent=2, default=str)
        elif args.format == "csv" and args.what in ("devices", "events"):
            output_io = io.StringIO()
            if data:
                writer = csv.DictWriter(output_io, fieldnames=data[0].keys())
                writer.writeheader()
                writer.writerows(data)
            output_str = output_io.getvalue()
        else:
            output_str = json.dumps(data, indent=2, default=str)

        # Write output
        if args.output:
            Path(args.output).write_text(output_str)
            print(f"Exported to: {args.output}")
        else:
            print(output_str)

        return 0

    finally:
        db.close()


if __name__ == "__main__":
    sys.exit(main())
