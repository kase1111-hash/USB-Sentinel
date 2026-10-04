#!/bin/bash
#
# USB Sentinel Installation Script
#
# Installs USB Sentinel into a virtualenv under $INSTALL_PREFIX, with
# configuration in $CONFIG_DIR and a systemd service.
#

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Installation paths
INSTALL_PREFIX="${INSTALL_PREFIX:-/opt/usb-sentinel}"
CONFIG_DIR="${CONFIG_DIR:-/etc/usb-sentinel}"
DATA_DIR="${DATA_DIR:-/var/lib/usb-sentinel}"
BIN_DIR="${BIN_DIR:-/usr/local/bin}"
SYSTEMD_DIR="/etc/systemd/system"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
VENV="$INSTALL_PREFIX/venv"

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        echo "Usage: sudo $0"
        exit 1
    fi
}

check_dependencies() {
    log_info "Checking dependencies..."

    if ! command -v python3 &> /dev/null; then
        log_error "Python 3 is required but not installed"
        exit 1
    fi

    if ! python3 -c 'import sys; sys.exit(sys.version_info < (3, 10))'; then
        log_error "Python 3.10+ is required (found $(python3 --version 2>&1))"
        exit 1
    fi
    log_info "Using $(python3 --version 2>&1)"

    if ! python3 -c 'import venv, ensurepip' &> /dev/null; then
        log_error "Python venv support is missing (Debian/Ubuntu: apt install python3-venv)"
        exit 1
    fi

    if [[ ! -d /sys/bus/usb/devices ]]; then
        log_warn "/sys/bus/usb/devices not found - the daemon will have no USB buses to protect"
    fi
}

create_directories() {
    log_info "Creating directories..."

    mkdir -p "$INSTALL_PREFIX" "$CONFIG_DIR" "$DATA_DIR"
    chmod 755 "$INSTALL_PREFIX" "$CONFIG_DIR"
    chmod 700 "$DATA_DIR"
}

install_package() {
    log_info "Installing USB Sentinel into $VENV..."

    # A virtualenv avoids "externally-managed-environment" errors (PEP 668)
    # and keeps the daemon independent of the source checkout.
    python3 -m venv "$VENV"
    "$VENV/bin/pip" install --quiet --upgrade pip
    "$VENV/bin/pip" install --quiet "$PROJECT_DIR"

    ln -sf "$VENV/bin/usb-sentinel" "$BIN_DIR/usb-sentinel"
    ln -sf "$VENV/bin/sentinel-daemon" "$BIN_DIR/sentinel-daemon"

    log_info "Installed: $BIN_DIR/usb-sentinel, $BIN_DIR/sentinel-daemon"
}

install_config() {
    log_info "Installing configuration files..."

    for file in sentinel.yaml policy.yaml; do
        if [[ ! -f "$CONFIG_DIR/$file" ]]; then
            cp "$PROJECT_DIR/config/$file" "$CONFIG_DIR/$file"
            chmod 600 "$CONFIG_DIR/$file"
            log_info "Created $CONFIG_DIR/$file"
        else
            log_warn "$CONFIG_DIR/$file already exists, leaving it unchanged"
        fi
    done

    if [[ ! -f "$CONFIG_DIR/environment" ]]; then
        cat > "$CONFIG_DIR/environment" <<'ENV'
# Environment for the usb-sentinel service.
# Uncomment to enable LLM analysis (without it, local checks still run):
#ANTHROPIC_API_KEY=
ENV
        chmod 600 "$CONFIG_DIR/environment"
        log_info "Created $CONFIG_DIR/environment"
    fi

    chown root:root "$CONFIG_DIR"/*

    # Validate what is installed now
    if ! "$VENV/bin/usb-sentinel" -c "$CONFIG_DIR/sentinel.yaml" policy validate; then
        log_error "Policy validation failed - fix $CONFIG_DIR/policy.yaml before starting"
        exit 1
    fi
}

install_systemd() {
    log_info "Installing systemd service..."

    sed "s|/opt/usb-sentinel|$INSTALL_PREFIX|g" \
        "$SCRIPT_DIR/usb-sentinel.service" > "$SYSTEMD_DIR/usb-sentinel.service"
    chmod 644 "$SYSTEMD_DIR/usb-sentinel.service"

    if command -v systemctl &> /dev/null; then
        systemctl daemon-reload
    else
        log_warn "systemctl not found - start the daemon with: sentinel-daemon -c $CONFIG_DIR/sentinel.yaml"
    fi
}

remove_legacy_hook() {
    # Earlier versions installed a udev hook that authorized every device
    # when it could not reach the daemon, which defeats default-deny.
    if [[ -f /etc/udev/rules.d/99-usb-sentinel.rules ]]; then
        rm -f /etc/udev/rules.d/99-usb-sentinel.rules
        rm -f "$INSTALL_PREFIX/bin/usb-sentinel-intercept"
        command -v udevadm &> /dev/null && udevadm control --reload-rules
        log_info "Removed legacy udev hook"
    fi
}

print_instructions() {
    echo ""
    echo "========================================"
    echo "USB Sentinel Installation Complete!"
    echo "========================================"
    echo ""
    echo "Configuration:"
    echo "  $CONFIG_DIR/sentinel.yaml   daemon settings"
    echo "  $CONFIG_DIR/policy.yaml     device rules"
    echo "  $CONFIG_DIR/environment     ANTHROPIC_API_KEY (optional)"
    echo ""
    echo "Next steps:"
    echo ""
    echo "1. Preview what the daemon would do with the devices attached now:"
    echo "   sudo usb-sentinel scan"
    echo ""
    echo "2. Start the daemon and enable it at boot:"
    echo "   sudo systemctl enable --now usb-sentinel"
    echo ""
    echo "   Devices attached when it starts keep working. New devices stay"
    echo "   unbound until they are evaluated."
    echo ""
    echo "3. Watch decisions, and allow a held device:"
    echo "   journalctl -u usb-sentinel -f"
    echo "   sudo usb-sentinel devices list --trust review"
    echo "   sudo usb-sentinel devices trust <fingerprint> trusted"
    echo ""
}

uninstall() {
    log_info "Uninstalling USB Sentinel..."

    if command -v systemctl &> /dev/null; then
        systemctl disable --now usb-sentinel 2> /dev/null || true
        rm -f "$SYSTEMD_DIR/usb-sentinel.service"
        systemctl daemon-reload
    fi

    remove_legacy_hook
    rm -f "$BIN_DIR/usb-sentinel" "$BIN_DIR/sentinel-daemon"
    rm -rf "$INSTALL_PREFIX"

    log_info "USB Sentinel uninstalled"
    log_warn "Configuration and data files were not removed:"
    log_warn "  - $CONFIG_DIR"
    log_warn "  - $DATA_DIR"
    echo ""
    echo "To remove all data, run:"
    echo "  sudo rm -rf $CONFIG_DIR $DATA_DIR"
}

main() {
    echo "========================================"
    echo "USB Sentinel Installer"
    echo "========================================"
    echo ""

    case "${1:-}" in
        --uninstall)
            check_root
            uninstall
            exit 0
            ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --uninstall    Uninstall USB Sentinel"
            echo "  --help         Show this help message"
            echo ""
            echo "Environment variables:"
            echo "  INSTALL_PREFIX  Installation prefix (default: /opt/usb-sentinel)"
            echo "  CONFIG_DIR      Configuration directory (default: /etc/usb-sentinel)"
            echo "  DATA_DIR        Data directory (default: /var/lib/usb-sentinel)"
            echo "  BIN_DIR         Command symlinks (default: /usr/local/bin)"
            exit 0
            ;;
    esac

    check_root
    check_dependencies
    create_directories
    install_package
    install_config
    remove_legacy_hook
    install_systemd
    print_instructions
}

main "$@"
