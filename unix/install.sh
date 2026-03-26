#!/bin/bash
# SPIRE Agent - Unix/VM Installation Script
# Run as root: sudo bash install.sh
#
# This script:
#   1. Creates the spire-agent system user
#   2. Sets up directories and permissions
#   3. Installs the spire-agent binary
#   4. Copies config and systemd service files
#   5. Enables and starts the service

set -euo pipefail

INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/spire-agent"
DATA_DIR="/var/lib/spire-agent"
SOCKET_DIR="/run/spire/sockets"
LOG_DIR="/var/log/spire-agent"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "=== SPIRE Agent Unix Installation ==="

# Check root
if [ "$(id -u)" -ne 0 ]; then
    echo "Error: Run this script as root (sudo bash install.sh)"
    exit 1
fi

# Check binary exists
if [ ! -f "$SCRIPT_DIR/spire-agent" ]; then
    echo "Error: spire-agent binary not found in $SCRIPT_DIR"
    exit 1
fi

# Get tenant ID
TENANT_ID="${TENANT_ID:-}"

# On reinstall, show the existing value
if [ -z "$TENANT_ID" ] && [ -f "$CONFIG_DIR/agent.env" ]; then
    EXISTING=$(grep -E "^TENANT_ID=" "$CONFIG_DIR/agent.env" 2>/dev/null | cut -d= -f2)
    if [ -n "$EXISTING" ] && [ "$EXISTING" != "YOUR-TENANT-UUID" ]; then
        echo ""
        read -rp "Tenant ID [${EXISTING}]: " TENANT_ID
        TENANT_ID="${TENANT_ID:-$EXISTING}"
    fi
fi

# Fresh install — require input
if [ -z "$TENANT_ID" ] || [ "$TENANT_ID" = "YOUR-TENANT-UUID" ]; then
    echo ""
    read -rp "Enter your Tenant ID (UUID from AuthSec): " TENANT_ID
    if [ -z "$TENANT_ID" ]; then
        echo "Error: Tenant ID is required"
        exit 1
    fi
fi
echo ""

# 1. Create system user
echo "[1/5] Creating spire-agent system user..."
if ! id -u spire-agent &>/dev/null; then
    useradd --system --no-create-home --shell /usr/sbin/nologin spire-agent
    echo "  Created user: spire-agent"
else
    echo "  User spire-agent already exists"
fi

# 2. Create directories
echo "[2/5] Creating directories..."
mkdir -p "$CONFIG_DIR" "$DATA_DIR/cache" "$SOCKET_DIR" "$LOG_DIR"
chown spire-agent:spire-agent "$DATA_DIR" "$DATA_DIR/cache" "$SOCKET_DIR" "$LOG_DIR"
chmod 700 "$DATA_DIR/cache"

# 3. Install binary
echo "[3/5] Installing spire-agent binary..."
cp "$SCRIPT_DIR/spire-agent" "$INSTALL_DIR/spire-agent"
chmod 755 "$INSTALL_DIR/spire-agent"
echo "  Installed: $INSTALL_DIR/spire-agent"

# 4. Copy configuration files
echo "[4/5] Copying configuration..."
cp "$SCRIPT_DIR/config.unix.yaml" "$CONFIG_DIR/config.yaml"

if [ ! -f "$CONFIG_DIR/agent.env" ]; then
    cp "$SCRIPT_DIR/agent.env.example" "$CONFIG_DIR/agent.env"
fi

# Set TENANT_ID
if grep -q "^TENANT_ID=" "$CONFIG_DIR/agent.env"; then
    sed -i "s/^TENANT_ID=.*/TENANT_ID=${TENANT_ID}/" "$CONFIG_DIR/agent.env"
else
    echo "TENANT_ID=${TENANT_ID}" >> "$CONFIG_DIR/agent.env"
fi

# Set NODE_ID to hostname
if grep -q "^NODE_ID=" "$CONFIG_DIR/agent.env"; then
    sed -i "s/^NODE_ID=.*/NODE_ID=$(hostname)/" "$CONFIG_DIR/agent.env"
else
    echo "NODE_ID=$(hostname)" >> "$CONFIG_DIR/agent.env"
fi

chmod 600 "$CONFIG_DIR/agent.env"
echo "  Tenant ID: $TENANT_ID"
echo "  Node ID:   $(hostname)"

# 5. Install and enable systemd service
echo "[5/5] Installing systemd service..."
cp "$SCRIPT_DIR/spire-agent.service" /etc/systemd/system/spire-agent.service
systemctl daemon-reload
systemctl enable spire-agent

echo ""
echo "=== Installation Complete ==="
echo ""
echo "Next steps:"
echo "  1. Start the agent:  sudo systemctl start spire-agent"
echo "  2. Check status:     sudo systemctl status spire-agent"
echo "  3. View logs:        sudo journalctl -u spire-agent -f"
