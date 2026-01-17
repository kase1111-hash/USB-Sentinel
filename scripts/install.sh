#!/bin/bash
#
# USB Sentinel Installation Script
#
# Installs USB Sentinel system-wide with all dependencies.
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Installation paths
INSTALL_PREFIX="${INSTALL_PREFIX:-/opt/usb-sentinel}"
CONFIG_DIR="${CONFIG_DIR:-/etc/usb-sentinel}"
DATA_DIR="${DATA_DIR:-/var/lib/usb-sentinel}"
LOG_DIR="${LOG_DIR:-/var/log}"
SYSTEMD_DIR="/etc/systemd/system"
UDEV_DIR="/etc/udev/rules.d"

# Print colored message
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        echo "Usage: sudo $0"
        exit 1
    fi
}

# Check dependencies
check_dependencies() {
    log_info "Checking dependencies..."

    # Check Python version
    if ! command -v python3 &> /dev/null; then
        log_error "Python 3 is required but not installed"
        exit 1
    fi

    PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
    if [[ $(echo "$PYTHON_VERSION < 3.10" | bc -l) -eq 1 ]]; then
        log_error "Python 3.10+ is required (found $PYTHON_VERSION)"
        exit 1
    fi
    log_info "Python version: $PYTHON_VERSION"

    # Check pip
    if ! command -v pip3 &> /dev/null; then
        log_error "pip3 is required but not installed"
        exit 1
    fi

    # Check for optional dependencies
    if command -v udevadm &> /dev/null; then
        log_info "udev tools found"
    else
        log_warn "udevadm not found - udev rules may not work"
    fi
}

# Create directories
create_directories() {
    log_info "Creating directories..."

    mkdir -p "$INSTALL_PREFIX"
    mkdir -p "$INSTALL_PREFIX/bin"
    mkdir -p "$CONFIG_DIR"
    mkdir -p "$DATA_DIR"
    mkdir -p "$DATA_DIR/captures"
    mkdir -p "$DATA_DIR/models"

    # Set permissions
    chmod 755 "$INSTALL_PREFIX"
    chmod 755 "$CONFIG_DIR"
    chmod 700 "$DATA_DIR"

    log_info "Directories created"
}

# Install Python package
install_package() {
    log_info "Installing USB Sentinel Python package..."

    # Get the script's directory (should be in scripts/)
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

    # Install the package
    pip3 install -e "$PROJECT_DIR"

    # Create symlinks to CLI tools
    ln -sf "$(which usb-sentinel)" "$INSTALL_PREFIX/bin/usb-sentinel"
    ln -sf "$(which sentinel-daemon)" "$INSTALL_PREFIX/bin/sentinel-daemon"

    log_info "Python package installed"
}

# Install configuration files
install_config() {
    log_info "Installing configuration files..."

    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

    # Copy configuration files if they don't exist
    if [[ ! -f "$CONFIG_DIR/sentinel.yaml" ]]; then
        cp "$PROJECT_DIR/config/sentinel.yaml" "$CONFIG_DIR/sentinel.yaml"
        chmod 600 "$CONFIG_DIR/sentinel.yaml"
        log_info "Created sentinel.yaml"
    else
        log_warn "sentinel.yaml already exists, skipping"
    fi

    if [[ ! -f "$CONFIG_DIR/policy.yaml" ]]; then
        cp "$PROJECT_DIR/config/policy.yaml" "$CONFIG_DIR/policy.yaml"
        chmod 600 "$CONFIG_DIR/policy.yaml"
        log_info "Created policy.yaml"
    else
        log_warn "policy.yaml already exists, skipping"
    fi

    # Set ownership
    chown root:root "$CONFIG_DIR"/*

    log_info "Configuration files installed"
}

# Install udev rules
install_udev() {
    log_info "Installing udev rules..."

    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

    # Copy udev rules
    cp "$SCRIPT_DIR/99-usb-sentinel.rules" "$UDEV_DIR/"
    chmod 644 "$UDEV_DIR/99-usb-sentinel.rules"

    # Copy intercept script
    cp "$SCRIPT_DIR/usb-sentinel-intercept" "$INSTALL_PREFIX/bin/"
    chmod 755 "$INSTALL_PREFIX/bin/usb-sentinel-intercept"

    # Copy notify script
    cp "$SCRIPT_DIR/usb-sentinel-notify" "$INSTALL_PREFIX/bin/"
    chmod 755 "$INSTALL_PREFIX/bin/usb-sentinel-notify"

    # Reload udev rules
    if command -v udevadm &> /dev/null; then
        udevadm control --reload-rules
        udevadm trigger
        log_info "udev rules reloaded"
    else
        log_warn "Could not reload udev rules - reboot may be required"
    fi

    log_info "udev rules installed"
}

# Install systemd service
install_systemd() {
    log_info "Installing systemd service..."

    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

    # Copy service file
    cp "$SCRIPT_DIR/usb-sentinel.service" "$SYSTEMD_DIR/"
    chmod 644 "$SYSTEMD_DIR/usb-sentinel.service"

    # Reload systemd
    systemctl daemon-reload

    log_info "systemd service installed"
}

# Create database
initialize_database() {
    log_info "Initializing database..."

    # The database will be created on first run
    touch "$DATA_DIR/audit.db"
    chmod 600 "$DATA_DIR/audit.db"

    log_info "Database initialized"
}

# Print post-installation instructions
print_instructions() {
    echo ""
    echo "========================================"
    echo "USB Sentinel Installation Complete!"
    echo "========================================"
    echo ""
    echo "Configuration files:"
    echo "  - $CONFIG_DIR/sentinel.yaml"
    echo "  - $CONFIG_DIR/policy.yaml"
    echo ""
    echo "Next steps:"
    echo ""
    echo "1. Configure your Anthropic API key:"
    echo "   export ANTHROPIC_API_KEY='your-key-here'"
    echo "   Or add to $CONFIG_DIR/sentinel.yaml"
    echo ""
    echo "2. Review and customize the policy:"
    echo "   nano $CONFIG_DIR/policy.yaml"
    echo ""
    echo "3. Start the daemon:"
    echo "   sudo systemctl start usb-sentinel"
    echo ""
    echo "4. Enable on boot:"
    echo "   sudo systemctl enable usb-sentinel"
    echo ""
    echo "5. Check status:"
    echo "   usb-sentinel status"
    echo "   sudo systemctl status usb-sentinel"
    echo ""
    echo "Documentation: https://github.com/usb-sentinel/docs"
    echo ""
}

# Uninstall function
uninstall() {
    log_info "Uninstalling USB Sentinel..."

    # Stop and disable service
    if systemctl is-active usb-sentinel &> /dev/null; then
        systemctl stop usb-sentinel
    fi
    if systemctl is-enabled usb-sentinel &> /dev/null; then
        systemctl disable usb-sentinel
    fi

    # Remove systemd service
    rm -f "$SYSTEMD_DIR/usb-sentinel.service"
    systemctl daemon-reload

    # Remove udev rules
    rm -f "$UDEV_DIR/99-usb-sentinel.rules"
    udevadm control --reload-rules 2>/dev/null || true

    # Remove installation directory
    rm -rf "$INSTALL_PREFIX"

    # Uninstall Python package
    pip3 uninstall -y usb-sentinel 2>/dev/null || true

    log_info "USB Sentinel uninstalled"
    log_warn "Configuration and data files were not removed:"
    log_warn "  - $CONFIG_DIR"
    log_warn "  - $DATA_DIR"
    echo ""
    echo "To remove all data, run:"
    echo "  sudo rm -rf $CONFIG_DIR $DATA_DIR"
}

# Main installation
main() {
    echo "========================================"
    echo "USB Sentinel Installer"
    echo "========================================"
    echo ""

    # Parse arguments
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
            exit 0
            ;;
    esac

    # Run installation steps
    check_root
    check_dependencies
    create_directories
    install_package
    install_config
    install_udev
    install_systemd
    initialize_database
    print_instructions
}

# Run main
main "$@"
