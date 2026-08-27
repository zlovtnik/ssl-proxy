#!/usr/bin/env bash
# Install platform-sync on Ubuntu server
# Run as root or with sudo

set -euo pipefail

INSTALL_DIR="/opt/platform-sync"
CONFIG_DIR="/etc/platform-sync"
SERVICE_USER="platform-sync"
SERVICE_GROUP="platform-sync"
VAULT_TOKEN_SOURCE="${VAULT_TOKEN_SOURCE:-}"
VAULT_CA_SOURCE="${VAULT_CA_SOURCE:-}"

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

# Install external Vault credentials without ever copying them into Git.
if [ -n "$VAULT_TOKEN_SOURCE" ]; then
    install -o root -g root -m 600 "$VAULT_TOKEN_SOURCE" "$CONFIG_DIR/vault-token"
elif [ ! -f "$CONFIG_DIR/vault-token" ]; then
    echo "ERROR: Set VAULT_TOKEN_SOURCE to the renewable read-only token file." >&2
    exit 1
fi
if [ -n "$VAULT_CA_SOURCE" ]; then
    install -o root -g root -m 600 "$VAULT_CA_SOURCE" "$CONFIG_DIR/vault-ca.crt"
elif [ ! -f "$CONFIG_DIR/vault-ca.crt" ]; then
    echo "ERROR: Set VAULT_CA_SOURCE to the Vault CA certificate." >&2
    exit 1
fi

# Install systemd units
echo "Installing systemd units"
cp config/platform-sync/credential-generator.service /etc/systemd/system/
cp config/platform-sync/vault-k8s-sync.service /etc/systemd/system/
cp config/platform-sync/vault-k8s-sync.timer /etc/systemd/system/

# Set permissions
echo "Setting permissions"
chown -R "$SERVICE_USER:$SERVICE_GROUP" "$INSTALL_DIR"
chown root:"$SERVICE_GROUP" "$CONFIG_DIR" "$CONFIG_DIR/platform-sync.conf"
chmod 750 "$CONFIG_DIR"
chmod 640 "$CONFIG_DIR/platform-sync.conf"
chown root:root "$CONFIG_DIR/vault-token" "$CONFIG_DIR/vault-ca.crt"
chmod 600 "$CONFIG_DIR/vault-token" "$CONFIG_DIR/vault-ca.crt"

# Reload systemd
echo "Reloading systemd"
systemctl daemon-reload

# Enable the single sync timer. Its service requires credential-generator.
echo "Enabling timer"
systemctl enable vault-k8s-sync.timer

echo "=== Installation complete ==="
echo ""
echo "Next steps:"
echo "1. Edit $CONFIG_DIR/platform-sync.conf if the Vault address changed"
echo "2. Run: systemctl start vault-k8s-sync.timer"
echo "3. Run the first sync now: systemctl start vault-k8s-sync.service"
echo "4. Check status: systemctl status vault-k8s-sync"
echo "5. View logs: journalctl -u vault-k8s-sync -f"
