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
import os
import signal
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

from sentinel import __version__
from sentinel.audit.database import AuditDatabase
from sentinel.config import SentinelConfig, load_config
from sentinel.interceptor.descriptors import DeviceDescriptor
from sentinel.policy.engine import PolicyEngine
from sentinel.policy.fingerprint import generate_fingerprint
from sentinel.policy.parser import (
    PolicyParseError,
    load_policy,
    parse_usb_class,
    validate_policy,
)


def main(argv: list[str] | None = None) -> int:
    """Main entry point for the CLI."""
    parser = argparse.ArgumentParser(
        prog="usb-sentinel",
        description="LLM-integrated USB firewall system",
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
        "--json",
        action="store_true",
        help="Output in JSON format",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # start command
    start_parser = subparsers.add_parser("start", help="Start the daemon")
    start_parser.add_argument(
        "-f",
        "--foreground",
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
        "-a",
        "--all",
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

    trust_parser = devices_sub.add_parser(
        "trust",
        help="Set device trust level (trusted/blocked also apply to it if attached)",
    )
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
        "-n",
        "--limit",
        type=int,
        default=20,
        help="Number of events to show",
    )
    events_parser.add_argument(
        "-d",
        "--device",
        help="Filter by device fingerprint",
    )
    events_parser.add_argument(
        "-t",
        "--type",
        choices=["connect", "disconnect", "allowed", "blocked", "reviewed"],
        help="Filter by event type (reviewed = held for review)",
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
    policy_sub.add_parser("reload", help="Tell the running daemon to reload the policy")

    test_parser = policy_sub.add_parser("test", help="Test policy against device")
    test_parser.add_argument("vid", help="Vendor ID (4 hex chars)")
    test_parser.add_argument("pid", help="Product ID (4 hex chars)")
    test_parser.add_argument(
        "--class", dest="device_class", default="0", help="Device class (name or number)"
    )
    test_parser.add_argument("--manufacturer", help="Manufacturer string")
    test_parser.add_argument("--product", help="Product string")

    # scan command
    scan_parser = subparsers.add_parser(
        "scan",
        help="Show what the daemon would decide for each attached device (changes nothing)",
    )
    scan_parser.add_argument(
        "--llm",
        action="store_true",
        help="Include LLM analysis (one API call per device)",
    )
    scan_parser.set_defaults(func=cmd_scan)

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
        "-o",
        "--output",
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


def daemon_pid(config: SentinelConfig) -> int | None:
    """PID of the running daemon, from its PID file, or None."""
    try:
        pid = int(Path(config.daemon.pid_file).read_text().strip())
    except (OSError, ValueError):
        return None
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return None
    except PermissionError:
        pass
    return pid


def apply_to_attached(fingerprint: str, authorized: bool) -> list[str]:
    """(De)authorize attached devices with this fingerprint. Returns their sysfs names."""
    from sentinel.interceptor import sysfs

    applied = []
    for path in sysfs.iter_devices():
        try:
            descriptor = sysfs.read_device(path)
        except sysfs.SysfsReadError:
            continue
        if generate_fingerprint(descriptor) == fingerprint and sysfs.set_authorized(
            path, authorized
        ):
            applied.append(path.name)
    return applied


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
    config = load_config(args.config)
    pid = daemon_pid(config)
    if pid is None:
        print("Daemon is not running")
        return 1

    try:
        os.kill(pid, signal.SIGTERM)
    except OSError as e:
        print(f"Error stopping daemon: {e}")
        return 1
    print(f"Sent SIGTERM to daemon (PID {pid})")
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    """Show daemon status."""
    config = load_config(args.config)
    pid = daemon_pid(config)
    daemon_running = pid is not None

    # Get database stats
    held = 0
    try:
        db = get_db(args)
        stats = db.get_system_statistics()
        held = db.count_devices(trust_level="review")
        db.close()
    except Exception:
        stats = {}

    status_data = {
        "version": __version__,
        "daemon_running": daemon_running,
        "daemon_pid": pid,
        "config_file": args.config or "default",
        "database": config.database.path,
        "policy_file": config.policy.rules_file,
        "total_devices": stats.get("total_devices", 0),
        "total_events": stats.get("total_events", 0),
        "blocked_today": stats.get("blocked_today", 0),
        "held_for_review": held,
    }

    if getattr(args, "json", False):
        output(status_data, args)
    else:
        print("USB Sentinel Status")
        print("=" * 50)
        print(f"Version:        {status_data['version']}")
        print(f"Daemon:         {'Running' if daemon_running else 'Stopped'}")
        if pid:
            print(f"PID:            {pid}")
        print(f"Config:         {status_data['config_file']}")
        print(f"Database:       {status_data['database']}")
        print(f"Policy:         {status_data['policy_file']}")
        print()
        print("Statistics:")
        print(f"  Total Devices:  {status_data['total_devices']}")
        print(f"  Total Events:   {status_data['total_events']}")
        print(f"  Blocked Today:  {status_data['blocked_today']}")
        print(f"  Held (review):  {held}")
        if held:
            print()
            print("Held devices: usb-sentinel devices list --trust review")
            print("Allow one:    usb-sentinel devices trust <fingerprint> trusted")

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

            if args.level in ("trusted", "blocked"):
                allow = args.level == "trusted"
                applied = apply_to_attached(args.fingerprint, allow)
                if applied:
                    verb = "Authorized" if allow else "Deauthorized"
                    print(f"{verb} attached device: {', '.join(applied)}")
                else:
                    print("Applies the next time the device is plugged in.")

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

            warnings = validate_policy(policy)
            if warnings:
                print("\nWarnings:")
                for w in warnings:
                    print(f"  - {w}")

            return 0
        except Exception as e:
            print(f"Policy validation failed: {e}")
            return 1

    elif args.policy_cmd == "reload":
        try:
            policy = load_policy(policy_path)
        except Exception as e:
            print(f"Not reloading, policy is invalid: {e}")
            return 1
        pid = daemon_pid(config)
        if pid is None:
            print("Daemon is not running")
            return 1
        os.kill(pid, signal.SIGHUP)
        print(f"Asked daemon (PID {pid}) to reload {len(policy.rules)} rules from {policy_path}")
        return 0

    elif args.policy_cmd == "test":
        if not policy_path.exists():
            print(f"Policy file not found: {policy_path}")
            return 1

        policy = load_policy(policy_path)
        engine = PolicyEngine(policy=policy)

        try:
            device_class = parse_usb_class(args.device_class)
        except PolicyParseError as e:
            print(e)
            return 1

        descriptor = DeviceDescriptor(
            vid=args.vid.lower(),
            pid=args.pid.lower(),
            device_class=device_class,
            device_subclass=0,
            device_protocol=0,
            manufacturer=args.manufacturer,
            product=args.product,
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


def cmd_scan(args: argparse.Namespace) -> int:
    """Show the daemon's decision for every attached device, without enforcing it."""
    import asyncio

    from sentinel.daemon import SentinelDaemon
    from sentinel.interceptor import sysfs

    config = load_config(args.config)
    paths = list(sysfs.iter_devices())
    if not paths:
        print(f"No USB devices found under {sysfs.SYSFS_USB_DEVICES}")
        return 1

    config.daemon.log_level = "warning"
    if not args.llm:
        config.analyzer.enabled = False
    daemon = SentinelDaemon(config)

    async def evaluate_all() -> list[dict[str, Any]]:
        rows = []
        for path in paths:
            try:
                descriptor = sysfs.read_device(path)
            except sysfs.SysfsReadError as e:
                rows.append({"port": path.name, "error": str(e)})
                continue
            decision = await daemon.evaluate(descriptor)
            rows.append(
                {
                    "port": path.name,
                    "vid_pid": descriptor.vid_pid,
                    "product": descriptor.display_name,
                    "authorized_now": sysfs.is_authorized(path),
                    **decision.to_result(),
                }
            )
        return rows

    try:
        rows = asyncio.run(evaluate_all())
    except Exception as e:
        print(f"Cannot evaluate devices: {e}")
        print("The audit database must be readable; run as root?")
        return 1

    if getattr(args, "json", False):
        output(rows, args)
        return 0

    print(f"{'Port':<10} {'VID:PID':<10} {'Product':<28} {'Now':<5} {'Verdict':<8} Reason")
    print("-" * 100)
    for row in rows:
        if "error" in row:
            print(f"{row['port']:<10} unreadable: {row['error']}")
            continue
        now = {True: "on", False: "off", None: "?"}[row["authorized_now"]]
        print(
            f"{row['port']:<10} {row['vid_pid']:<10} {row['product'][:28]:<28} {now:<5} "
            f"{row['action']:<8} {row['reason']}"
        )
    print()
    print("Nothing was changed. The daemon leaves devices attached at startup alone;")
    print("this is what it would decide if each were plugged in now.")
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
            output(
                {
                    "risk_score": result.risk_score,
                    "verdict": result.verdict,
                    "analysis": result.analysis,
                    "confidence": result.confidence,
                },
                args,
            )
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
