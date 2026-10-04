# USB Sentinel

A USB firewall daemon for Linux. New USB devices stay unbound (no driver, so a
keyboard cannot type and a disk cannot mount) until USB Sentinel has decided
what they are. Decisions combine YAML policy rules, a descriptor validator and
local heuristics, and optionally an LLM (Claude), and every decision is logged
to an append-only audit database.

It targets BadUSB-style attacks: keystroke injectors (Rubber Ducky, Teensy,
Digispark, P4wnP1), HID devices with hidden storage or network interfaces,
devices that claim a vendor ID their descriptor strings contradict, and known
attack hardware.

## How a device is decided

When a device is plugged in, the kernel enumerates it but binds no driver,
because USB Sentinel sets `authorized_default=0` on every USB bus while it runs.
The daemon reads the descriptors the kernel already cached in sysfs, rather
than querying the device, and decides:

1. **Your decision.** Devices you marked with `usb-sentinel devices trust`
   are allowed (`trusted`) or blocked (`blocked`), whatever the policy says.
2. **Policy rules** (`/etc/usb-sentinel/policy.yaml`, first match wins). A
   `block` is final. An `allow` is final unless the device's manufacturer
   string contradicts its vendor ID or its descriptor is seriously anomalous,
   in which case it is analyzed like a `review`.
3. **Review.** The descriptor validator and local heuristics score the device
   from 0 to 100. If an API key is configured, the LLM scores it too. The
   highest score wins, so the LLM can raise risk but cannot talk a device below
   what the local checks found. Devices that were never allowed before get a
   penalty.
   - 0-50: **allowed**
   - 51-75: **held**, kept unbound until you decide
   - 76-100: **blocked**

The device's sysfs `authorized` flag is then set accordingly. Devices that were
already attached when the daemon started are left alone. Stopping the daemon,
or an exit on error, restores the kernel's default; systemd restarts it after an
error. If the daemon is killed outright, new devices stay unbound (fail closed)
until it restarts and evaluates them.

## Install

Requirements: Linux, Python 3.10+, root.

```bash
git clone https://github.com/kase1111-hash/USB-Sentinel
cd USB-Sentinel
sudo scripts/install.sh
```

The installer puts a virtualenv in `/opt/usb-sentinel`, configuration in
`/etc/usb-sentinel`, the database in `/var/lib/usb-sentinel`, and a systemd
unit. `sudo scripts/install.sh --uninstall` removes everything except
configuration and data.

LLM analysis is optional. To enable it, put your key in
`/etc/usb-sentinel/environment`:

```bash
ANTHROPIC_API_KEY=sk-ant-...
```

## Use

Preview what the daemon would decide for the devices attached now (changes
nothing):

```bash
sudo usb-sentinel scan
```

Start it, and enable it at boot:

```bash
sudo systemctl enable --now usb-sentinel
journalctl -u usb-sentinel -f
```

Each decision is logged with its reason:

```
ALLOWED 046d:c31c 'USB Keyboard': Risk 40/100 (validator=0, heuristics=25, never allowed): allowed
BLOCKED 03eb:2ff4 'ATmega32U4': Risk 100/100 (validator=100, heuristics=25, never allowed): blocked
HELD 1c4f:0002 'USB Keyboard': Risk 60/100 (...): held. To allow it: usb-sentinel devices trust 4603dd7e6f9f3f2e trusted
```

When a device is held:

```bash
sudo usb-sentinel status                        # shows how many are held
sudo usb-sentinel devices list --trust review   # which ones
sudo usb-sentinel devices trust <fingerprint> trusted
```

`trusted` and `blocked` take effect immediately if the device is attached, and
apply every time it is plugged in again. Other commands:

| Command | What it does |
|---------|--------------|
| `usb-sentinel events [-t blocked\|reviewed\|allowed] [-n 50]` | Audit log |
| `usb-sentinel devices show <fingerprint>` | Device details |
| `usb-sentinel policy validate` | Check the policy file |
| `usb-sentinel policy test <vid> <pid> [--class HID] [--product ...]` | Which rule a device would hit |
| `usb-sentinel policy reload` | Reload the policy in the running daemon (SIGHUP) |
| `usb-sentinel export events --format csv` | Export the audit log |

## Policy

Rules are evaluated top to bottom; the first match decides. All keys in a
match must hold. Unknown keys are rejected when the policy loads. A typo
must never silently widen a rule to every device.

```yaml
rules:
  - match: {vid: '046d', pid: 'c534'}
    action: allow
    comment: 'Logitech Unifying Receiver'

  - match: {vid: '1a86', pid: '7523'}
    action: block
    comment: 'CH340 - common in attack hardware'

  - match: {class: HID, has_storage_endpoint: true}
    action: review
    comment: 'HID with storage'

  - match: {manufacturer: null}   # null = device reports no manufacturer
    action: review

  - match: '*'
    action: review
```

The shipped [`config/policy.yaml`](config/policy.yaml) lists every match key.
The daemon reloads the file when it changes. An invalid file is rejected and
the previous policy stays active.

## Configuration

[`config/sentinel.yaml`](config/sentinel.yaml) is commented. The settings
you are most likely to change:

| Setting | Default | Meaning |
|---------|---------|---------|
| `interceptor.block_during_analysis` | `true` | Keep new devices unbound until decided |
| `interceptor.analysis_timeout` | `10` | Seconds to wait for the LLM before using local scores only |
| `analyzer.model` | `claude-sonnet-5-5` | Model for LLM analysis |
| `alerts.methods.webhook` | `null` | URL that receives a JSON POST per blocked or held device |
| `api.enabled` | `false` | REST API and WebSocket for the dashboard |

## Detection benchmark

`tests/benchmark` runs 25 attack-device and 28 benign-device descriptors
through the daemon's own decision code with the shipped policy and no API key:

| | Attacks stopped | Benign devices stopped |
|---|---|---|
| Policy rules only, unresolved reviews allowed | 4/25 | 0/28 |
| Policy rules only, unresolved reviews held | 25/25 | 18/28 |
| **USB Sentinel (policy + local analysis)** | **25/25** | **1/28 (held, not blocked)** |

The held benign device is a no-name keyboard whose product string is literally
"USB Keyboard". The descriptors are synthetic and were written alongside the
heuristics, so treat these numbers as an upper bound. Run
`pytest tests/benchmark -s -k report` for the per-device table.

## Limitations

- **Descriptor-based.** A device that copies a trusted device's descriptors
  exactly (vendor, product, strings, interfaces) is indistinguishable from
  it. There is no keystroke-timing or traffic analysis.
- **Devices present at startup are not evaluated.** Run `usb-sentinel scan`
  to review them.
- **Linux only**, and it needs root to write sysfs.
- **No electrical protection.** USB-killer style devices are out of scope.

## Development

```bash
python -m venv venv && . venv/bin/activate
pip install -e ".[dev]"
pytest tests/
ruff check src/ tests/ && ruff format --check src/ tests/
```

The optional React dashboard in `dashboard/` talks to the REST API
(`api.enabled: true`).

## License

MIT
