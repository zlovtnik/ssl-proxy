#!/usr/bin/env bash
# Install platform-sync on Ubuntu server
# Run as root or with sudo

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
INSTALL_DIR="/opt/platform-sync"
CONFIG_DIR="/etc/platform-sync"
SERVICE_USER="platform-sync"
SERVICE_GROUP="platform-sync"
VAULT_TOKEN_SOURCE="${VAULT_TOKEN_SOURCE:-}"
VAULT_CA_SOURCE="${VAULT_CA_SOURCE:-}"
GO_BUILDER_IMAGE="docker.io/library/golang:1.25-alpine@sha256:1ae0735f00daffa3aaf1363a5184c0d2dc55c78e3db4ec70241cdac97bf84b59"
DEFAULT_CONFIG="$REPO_ROOT/config/platform-sync/platform-sync.conf.example"

echo "=== Platform Sync Installer ==="

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "ERROR: Please run as root or with sudo" >&2
    exit 1
fi

if [ ! -f "$DEFAULT_CONFIG" ]; then
    echo "ERROR: Missing packaged configuration: $DEFAULT_CONFIG" >&2
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
if command -v go >/dev/null 2>&1; then
    echo "Building binaries with host Go"
    (
        cd "$REPO_ROOT/services/platform-sync"
        go build -trimpath -mod=readonly -buildvcs=false -o "$INSTALL_DIR/bin/platform-sync" .
        go build -trimpath -mod=readonly -buildvcs=false -o "$INSTALL_DIR/bin/cred-gen" ./cmd/cred-gen
    )
elif command -v docker >/dev/null 2>&1; then
    echo "Host Go not found; building binaries with pinned Go container"
    build_dir="$(mktemp -d)"
    trap 'rm -rf "$build_dir"' EXIT
    docker run --rm \
        --pull=missing \
        --read-only \
        --cap-drop=ALL \
        --security-opt=no-new-privileges \
        --pids-limit=512 \
        --memory=2g \
        --cpus=2 \
        --tmpfs /tmp:rw,noexec,nosuid,size=1073741824 \
        --env CGO_ENABLED=0 \
        --env GOCACHE=/tmp/go-build \
        --env GOMODCACHE=/tmp/go-mod \
        --env GOTOOLCHAIN=local \
        --env HOME=/tmp/home \
        --mount "type=bind,src=$REPO_ROOT/services/platform-sync,dst=/src,readonly" \
        --mount "type=bind,src=$build_dir,dst=/out" \
        --workdir /src \
        "$GO_BUILDER_IMAGE" \
        sh -ec 'go build -trimpath -mod=readonly -buildvcs=false -o /out/platform-sync . && go build -trimpath -mod=readonly -buildvcs=false -o /out/cred-gen ./cmd/cred-gen'
    install -m 755 "$build_dir/platform-sync" "$INSTALL_DIR/bin/platform-sync"
    install -m 755 "$build_dir/cred-gen" "$INSTALL_DIR/bin/cred-gen"
    rm -rf "$build_dir"
    trap - EXIT
else
    echo "ERROR: Install Go 1.25+ or Docker before running this installer." >&2
    exit 1
fi

chmod 755 "$INSTALL_DIR/bin/platform-sync"
chmod 755 "$INSTALL_DIR/bin/cred-gen"

# Install contract
echo "Installing contract"
cp "$REPO_ROOT/cyber-stack/platform-input-contract.yaml" "$INSTALL_DIR/contract/"

# Install configuration
echo "Installing configuration"
if [ ! -f "$CONFIG_DIR/platform-sync.conf" ]; then
    install -m 640 "$DEFAULT_CONFIG" "$CONFIG_DIR/platform-sync.conf"
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
cp "$REPO_ROOT/config/platform-sync/credential-generator.service" /etc/systemd/system/
cp "$REPO_ROOT/config/platform-sync/vault-k8s-sync.service" /etc/systemd/system/
cp "$REPO_ROOT/config/platform-sync/vault-k8s-sync.timer" /etc/systemd/system/

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
