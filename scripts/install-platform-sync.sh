#!/usr/bin/env bash
# Install platform-sync on Ubuntu server
# Run as root or with sudo

set -euo pipefail

INSTALL_DIR="/opt/platform-sync"
CONFIG_DIR="/etc/platform-sync"
SERVICE_USER="platform-sync"
SERVICE_GROUP="platform-sync"

echo "=== Platform Sync Installer ==="

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "ERROR: Please run as root or with sudo" >&2
    exit 1
fi

# Create service user
if ! id "$SERVICE_USER" &>/dev/null; then
    echo "Creating user: $SERVICE_USER"
    useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER"
fi

# Create directories
echo "Creating directories"
mkdir -p "$INSTALL_DIR/bin"
mkdir -p "$INSTALL_DIR/contract"
mkdir -p "$CONFIG_DIR"
mkdir -p /run/platform-sync

# Install binaries
echo "Installing binaries"
if [ -f "./services/platform-sync/platform-sync" ]; then
    cp ./services/platform-sync/platform-sync "$INSTALL_DIR/bin/"
    cp ./services/platform-sync/cred-gen "$INSTALL_DIR/bin/"
else
    echo "Building binaries"
    cd services/platform-sync
    go build -o "$INSTALL_DIR/bin/platform-sync" .
    go build -o "$INSTALL_DIR/bin/cred-gen" ./cmd/cred-gen
    cd ../..
fi

chmod 755 "$INSTALL_DIR/bin/platform-sync"
chmod 755 "$INSTALL_DIR/bin/cred-gen"

# Install contract
echo "Installing contract"
cp cyber-stack/platform-input-contract.yaml "$INSTALL_DIR/contract/"

# Install configuration
echo "Installing configuration"
if [ ! -f "$CONFIG_DIR/platform-sync.conf" ]; then
    cp config/platform-sync/platform-sync.conf "$CONFIG_DIR/"
else
    echo "Configuration file already exists, skipping"
fi

# Install systemd units
echo "Installing systemd units"
cp config/platform-sync/credential-generator.service /etc/systemd/system/
cp config/platform-sync/credential-generator.timer /etc/systemd/system/
cp config/platform-sync/vault-k8s-sync.service /etc/systemd/system/
cp config/platform-sync/vault-k8s-sync.timer /etc/systemd/system/

# Set permissions
echo "Setting permissions"
chown -R "$SERVICE_USER:$SERVICE_GROUP" "$INSTALL_DIR"
chown -R "$SERVICE_USER:$SERVICE_GROUP" "$CONFIG_DIR"
chown -R "$SERVICE_USER:$SERVICE_GROUP" /run/platform-sync
chmod 600 "$CONFIG_DIR/platform-sync.conf"

# Reload systemd
echo "Reloading systemd"
systemctl daemon-reload

# Enable timers
echo "Enabling timers"
systemctl enable credential-generator.timer
systemctl enable vault-k8s-sync.timer

echo "=== Installation complete ==="
echo ""
echo "Next steps:"
echo "1. Edit $CONFIG_DIR/platform-sync.conf with your Vault address"
echo "2. Run: systemctl start credential-generator.timer"
echo "3. Run: systemctl start vault-k8s-sync.timer"
echo "4. Check status: systemctl status vault-k8s-sync"
echo "5. View logs: journalctl -u vault-k8s-sync -f"
