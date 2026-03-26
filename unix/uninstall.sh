#!/bin/bash
# SPIRE Agent - Unix/VM Uninstall Script
# Run as root: sudo bash uninstall.sh
#
# Options:
#   --purge    Also remove config and data directories

set -euo pipefail

PURGE=false
if [ "${1:-}" = "--purge" ]; then
    PURGE=true
fi

echo "=== SPIRE Agent Uninstall ==="

# Check root
if [ "$(id -u)" -ne 0 ]; then
    echo "Error: Run this script as root (sudo bash uninstall.sh)"
    exit 1
fi

# 1. Stop and disable service
echo "[1/4] Stopping service..."
if systemctl is-active --quiet spire-agent 2>/dev/null; then
    systemctl stop spire-agent
    echo "  Stopped spire-agent"
fi
if systemctl is-enabled --quiet spire-agent 2>/dev/null; then
    systemctl disable spire-agent
    echo "  Disabled spire-agent"
fi

# 2. Remove systemd service file
echo "[2/4] Removing systemd service..."
rm -f /etc/systemd/system/spire-agent.service
systemctl daemon-reload
echo "  Removed service file"

# 3. Remove binary
echo "[3/4] Removing binary..."
rm -f /usr/local/bin/spire-agent
echo "  Removed /usr/local/bin/spire-agent"

# 4. Remove directories
if [ "$PURGE" = true ]; then
    echo "[4/4] Purging config, data, and logs..."
    rm -rf /etc/spire-agent
    rm -rf /var/lib/spire-agent
    rm -rf /run/spire/sockets
    rm -rf /var/log/spire-agent
    echo "  Removed /etc/spire-agent"
    echo "  Removed /var/lib/spire-agent"
    echo "  Removed /run/spire/sockets"
    echo "  Removed /var/log/spire-agent"

    # Remove system user
    if id -u spire-agent &>/dev/null; then
        userdel spire-agent
        echo "  Removed user: spire-agent"
    fi
else
    echo "[4/4] Keeping config and data (use --purge to remove)"
    echo "  /etc/spire-agent     (config)"
    echo "  /var/lib/spire-agent (data)"
    echo "  /var/log/spire-agent (logs)"
fi

echo ""
echo "=== Uninstall Complete ==="
