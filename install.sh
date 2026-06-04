#!/usr/bin/env bash
#
# Orbit Station — One-Click Raspberry Pi Installer
#
# Usage:  chmod +x install.sh && ./install.sh
#
set -euo pipefail

ORBIT_DIR="$(cd "$(dirname "$0")" && pwd)"
ORBIT_USER="$(whoami)"
ORBIT_PORT="${ORBIT_PORT:-8443}"
KUBO_VERSION="0.28.0"

info()  { echo -e "\033[1;34m[orbit]\033[0m $*"; }
ok()    { echo -e "\033[1;32m[orbit]\033[0m $*"; }
warn()  { echo -e "\033[1;33m[orbit]\033[0m $*"; }
err()   { echo -e "\033[1;31m[orbit]\033[0m $*" >&2; }

# -----------------------------------------------------------
# 1. Ensure Python 3.11+ is available
# -----------------------------------------------------------
_find_python() {
    for cmd in python3.12 python3.11 python3; do
        if command -v "$cmd" &>/dev/null; then
            ver=$("$cmd" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
            major="${ver%%.*}"
            minor="${ver##*.}"
            if [ "$major" -ge 3 ] && [ "$minor" -ge 11 ]; then
                PYTHON="$cmd"
                return 0
            fi
        fi
    done
    return 1
}

info "Checking Python version..."
PYTHON=""
ver=""

if ! _find_python; then
    info "Python 3.11+ not found. Installing via apt..."
    sudo apt-get update -qq
    sudo apt-get install -y -qq python3 python3-venv python3-pip
    if ! _find_python; then
        err "Could not install Python 3.11+. Your OS may ship an older version."
        err "Try: sudo apt install python3.11 python3.11-venv"
        exit 1
    fi
fi
ok "Using $PYTHON ($ver)"

# -----------------------------------------------------------
# 2. System dependencies
# -----------------------------------------------------------
info "Installing system dependencies..."
sudo apt-get update -qq
sudo apt-get install -y -qq git curl openssl ufw python3-venv libsodium-dev

# -----------------------------------------------------------
# 3a. Install IPFS (Kubo) if not present
# -----------------------------------------------------------
if ! command -v ipfs &>/dev/null; then
    info "Installing IPFS (Kubo v${KUBO_VERSION})..."

    ARCH="$(uname -m)"
    case "$ARCH" in
        aarch64|arm64) IPFS_ARCH="arm64" ;;
        armv7l|armhf)  IPFS_ARCH="arm"   ;;
        x86_64)        IPFS_ARCH="amd64" ;;
        *)             err "Unsupported architecture: $ARCH"; exit 1 ;;
    esac

    TARBALL="kubo_v${KUBO_VERSION}_linux-${IPFS_ARCH}.tar.gz"
    DOWNLOAD_URL="https://dist.ipfs.tech/kubo/v${KUBO_VERSION}/${TARBALL}"

    cd /tmp
    curl -fsSL -o "$TARBALL" "$DOWNLOAD_URL"
    tar xzf "$TARBALL"
    sudo mv kubo/ipfs /usr/local/bin/ipfs
    rm -rf kubo "$TARBALL"
    cd "$ORBIT_DIR"

    ok "IPFS installed: $(ipfs --version)"
else
    ok "IPFS already installed: $(ipfs --version)"
fi

# -----------------------------------------------------------
# 3b. Install cloudflared if not present
# -----------------------------------------------------------
CF_SKIP=""
if ! command -v cloudflared &>/dev/null; then
    info "Installing cloudflared..."

    ARCH="$(uname -m)"
    case "$ARCH" in
        aarch64|arm64) CF_ARCH="arm64"  ;;
        armv7l|armhf)  CF_ARCH="arm"    ;;
        x86_64)        CF_ARCH="amd64"  ;;
        *)             warn "Unsupported architecture for cloudflared: $ARCH. Skipping tunnel setup."; CF_SKIP=1 ;;
    esac

    if [ -z "${CF_SKIP}" ]; then
        CF_URL="https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${CF_ARCH}"
        curl -fsSL -o /tmp/cloudflared "$CF_URL"
        sudo install -m 755 /tmp/cloudflared /usr/local/bin/cloudflared
        rm -f /tmp/cloudflared
        ok "cloudflared installed: $(cloudflared --version)"
    fi
else
    ok "cloudflared already installed: $(cloudflared --version)"
fi

# -----------------------------------------------------------
# 4. Initialize IPFS (if needed)
# -----------------------------------------------------------
if [ ! -d "$HOME/.ipfs" ]; then
    info "Initializing IPFS with lowpower profile..."
    ipfs init --profile=lowpower

    # Bind API to localhost only (security)
    ipfs config Addresses.API /ip4/127.0.0.1/tcp/5001
    ipfs config Addresses.Gateway /ip4/127.0.0.1/tcp/8080
    ok "IPFS initialized"
else
    ok "IPFS already initialized"
fi

# -----------------------------------------------------------
# 5. Python venv + dependencies
# -----------------------------------------------------------
info "Setting up Python virtual environment..."
if [ ! -d "$ORBIT_DIR/.venv" ]; then
    "$PYTHON" -m venv "$ORBIT_DIR/.venv"
fi
source "$ORBIT_DIR/.venv/bin/activate"

pip install --quiet --upgrade pip
# Includes the post-quantum libs kyber-py (ML-KEM-768) and dilithium-py (ML-DSA-65).
# Both are pure-Python and ship on piwheels, so no compiler/native build is needed on a Pi.
pip install --quiet -r "$ORBIT_DIR/requirements.txt"
ok "Python dependencies installed"

# -----------------------------------------------------------
# 6. Environment config
# -----------------------------------------------------------
if [ ! -f "$ORBIT_DIR/.env" ]; then
    cat > "$ORBIT_DIR/.env" <<'ENVFILE'
# Orbit Station Configuration

# --- Identity ---
# Password for encrypting the station private key (leave empty for no encryption)
ORBIT_PASSWORD=

# --- Server ---
ORBIT_PORT=8443
ORBIT_HOST=0.0.0.0

# --- TLS ---
# Auto-generated on first run if missing
SSL_CERTFILE=./orbit_data/ssl/cert.pem
SSL_KEYFILE=./orbit_data/ssl/key.pem

# --- IPFS ---
IPFS_API_URL=http://127.0.0.1:5001
IPFS_TIMEOUT=30
IPFS_MAX_RETRIES=3

# --- Limits ---
# Max upload size in bytes (default: 100 MB)
MAX_UPLOAD_SIZE=104857600

# --- CORS ---
# Comma-separated origins (use * for dev)
CORS_ORIGINS=*

# --- Logging ---
# DEBUG, INFO, WARNING, ERROR
LOG_LEVEL=INFO

# --- Cloudflare Tunnel ---
# Enable Cloudflare Quick Tunnel for public access (no account needed)
CLOUDFLARE_TUNNEL_ENABLED=false
# Metrics port for cloudflared (used to detect tunnel URL)
CLOUDFLARE_METRICS_PORT=40469

# --- Data ---
ORBIT_BASE_DIR=./orbit_data
ENVFILE
    ok "Created .env with defaults (edit as needed)"
else
    ok ".env already exists"
fi

# Enable Cloudflare tunnel for fresh installs
if [ -z "${CF_SKIP}" ] && grep -q "CLOUDFLARE_TUNNEL_ENABLED=false" "$ORBIT_DIR/.env" 2>/dev/null; then
    sed -i 's/CLOUDFLARE_TUNNEL_ENABLED=false/CLOUDFLARE_TUNNEL_ENABLED=true/' "$ORBIT_DIR/.env"
    ok "Cloudflare tunnel enabled in .env"
fi

# -----------------------------------------------------------
# 7. Bootstrap identity (first run)
# -----------------------------------------------------------
info "Bootstrapping identity..."
"$ORBIT_DIR/.venv/bin/python" -c "
import sys; sys.path.insert(0, '$ORBIT_DIR')
from orbit_node.identity import load_identity
load_identity()
print('Identity ready')
"
ok "Identity bootstrapped"

# -----------------------------------------------------------
# 8. Systemd: IPFS service
# -----------------------------------------------------------
info "Creating systemd services..."

sudo tee /etc/systemd/system/ipfs.service > /dev/null <<UNIT
[Unit]
Description=IPFS Daemon
After=network.target

[Service]
Type=simple
User=${ORBIT_USER}
Environment="IPFS_PATH=${HOME}/.ipfs"
ExecStart=/usr/local/bin/ipfs daemon --enable-gc
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT

# -----------------------------------------------------------
# 9. Systemd: Orbit service
# -----------------------------------------------------------
sudo tee /etc/systemd/system/orbit.service > /dev/null <<UNIT
[Unit]
Description=Orbit Station
After=ipfs.service network.target
Requires=ipfs.service

[Service]
Type=simple
User=${ORBIT_USER}
WorkingDirectory=${ORBIT_DIR}
EnvironmentFile=${ORBIT_DIR}/.env
ExecStart=${ORBIT_DIR}/.venv/bin/python ${ORBIT_DIR}/run.py
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT

# -----------------------------------------------------------
# 10. Systemd: Cloudflare Quick Tunnel
# -----------------------------------------------------------
if [ -z "${CF_SKIP}" ] && command -v cloudflared &>/dev/null; then

sudo tee /etc/systemd/system/cloudflared-tunnel.service > /dev/null <<UNIT
[Unit]
Description=Cloudflare Quick Tunnel
After=orbit.service
Requires=orbit.service

[Service]
Type=simple
User=${ORBIT_USER}
ExecStart=/usr/local/bin/cloudflared tunnel --url https://localhost:${ORBIT_PORT} --no-tls-verify --metrics localhost:40469
Restart=on-failure
RestartSec=30
StartLimitIntervalSec=300
StartLimitBurst=5

[Install]
WantedBy=multi-user.target
UNIT

fi

sudo systemctl daemon-reload

# -----------------------------------------------------------
# 11. Firewall
# -----------------------------------------------------------
info "Configuring firewall..."
sudo ufw allow "${ORBIT_PORT}/tcp" comment "Orbit Station" 2>/dev/null || true
sudo ufw --force enable 2>/dev/null || true
ok "Firewall: port ${ORBIT_PORT}/tcp allowed"

# -----------------------------------------------------------
# 12. Enable and start services
# -----------------------------------------------------------
info "Starting services..."
sudo systemctl enable ipfs.service orbit.service
sudo systemctl start ipfs.service
sleep 3  # give IPFS a moment to start
sudo systemctl start orbit.service

if [ -f /etc/systemd/system/cloudflared-tunnel.service ]; then
    sudo systemctl enable cloudflared-tunnel.service
    sleep 2  # give orbit a moment to bind
    sudo systemctl start cloudflared-tunnel.service
fi

# -----------------------------------------------------------
# Done
# -----------------------------------------------------------
echo ""
ok "============================================"
ok "  Orbit Station installed successfully!"
ok "============================================"
echo ""
info "Services:"
echo "  IPFS:       $(systemctl is-active ipfs.service)"
echo "  Orbit:      $(systemctl is-active orbit.service)"
if systemctl is-enabled cloudflared-tunnel.service &>/dev/null; then
    echo "  Tunnel:     $(systemctl is-active cloudflared-tunnel.service)"
fi
echo ""

# Show IPFS peer ID (the station's permanent address)
PEER_ID=$(ipfs id -f='<id>' 2>/dev/null || echo "unknown")
info "Your IPFS Peer ID (permanent station address):"
echo "  $PEER_ID"
echo ""
info "Followers can discover your station via IPNS:"
echo "  https://ipfs.io/ipns/${PEER_ID}"
echo ""

if systemctl is-enabled cloudflared-tunnel.service &>/dev/null; then
    info "Your tunnel URL will appear in the Orbit logs within ~30 seconds:"
    echo "  sudo journalctl -u orbit -f | grep 'Tunnel endpoint'"
    echo ""
    info "LAN access (direct):"
    echo "  https://$(hostname -I | awk '{print $1}'):${ORBIT_PORT}/health"
    echo ""
    info "Useful commands:"
    echo "  sudo systemctl status orbit              # check status"
    echo "  sudo journalctl -u orbit -f              # view logs"
    echo "  sudo journalctl -u cloudflared-tunnel -f  # tunnel logs"
    echo "  sudo systemctl restart orbit             # restart"
    echo ""
    info "Next steps:"
    echo "  1. Edit .env to set ORBIT_PASSWORD"
    echo "  2. Your station is publicly reachable via Cloudflare tunnel (no port forwarding needed!)"
    echo "  3. Share your Peer ID with followers — they can always find you via IPNS"
    echo "  4. Connect your Orbit client app"
else
    info "Access your station:"
    echo "  https://$(hostname -I | awk '{print $1}'):${ORBIT_PORT}/health"
    echo ""
    info "Useful commands:"
    echo "  sudo systemctl status orbit     # check status"
    echo "  sudo journalctl -u orbit -f     # view logs"
    echo "  sudo systemctl restart orbit    # restart"
    echo ""
    info "Next steps:"
    echo "  1. Edit .env to set ORBIT_PASSWORD and other config"
    echo "  2. Set up port forwarding on your router for port ${ORBIT_PORT}"
    echo "  3. Connect your Orbit client app"
fi
echo ""
