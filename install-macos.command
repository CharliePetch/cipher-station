#!/bin/bash
#
# Orbit Station — one-click macOS installer (double-clickable .command).
#
# Installs IPFS (Kubo) + cloudflared, sets up the Python environment, initializes
# a dedicated IPFS repo, registers launchd services for the IPFS daemon, the
# Orbit station, the Cloudflare tunnel, and the menu bar app — then starts them.
#
# No sudo required: binaries land in ~/.orbit/bin and services run as LaunchAgents
# in your user session.
#
set -euo pipefail

ORBIT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ORBIT_DIR"

# -----------------------------------------------------------
# Settings
# -----------------------------------------------------------
KUBO_VERSION="0.28.0"
BIN_DIR="$HOME/.orbit/bin"
IPFS_REPO="$HOME/.orbit/ipfs"
LA_DIR="$HOME/Library/LaunchAgents"
LOG_DIR="$ORBIT_DIR/orbit_data/logs"
ORBIT_PORT="${ORBIT_PORT:-8443}"
UID_NUM="$(id -u)"

info() { printf '\033[1;34m[orbit]\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m[orbit]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[orbit]\033[0m %s\n' "$*"; }
err()  { printf '\033[1;31m[orbit]\033[0m %s\n' "$*" >&2; }

mkdir -p "$BIN_DIR" "$IPFS_REPO" "$LOG_DIR" "$LA_DIR"

# -----------------------------------------------------------
# 1. Architecture
# -----------------------------------------------------------
ARCH="$(uname -m)"
case "$ARCH" in
  arm64)  DARWIN_ARCH="arm64" ;;
  x86_64) DARWIN_ARCH="amd64" ;;
  *) err "Unsupported architecture: $ARCH"; exit 1 ;;
esac
info "Detected macOS / $ARCH ($DARWIN_ARCH)"

# -----------------------------------------------------------
# 2. Python 3.11+
# -----------------------------------------------------------
PYTHON=""
find_python() {
  local c v maj min
  for c in python3.12 python3.11 python3; do
    if command -v "$c" >/dev/null 2>&1; then
      v="$("$c" -c 'import sys;print("%d.%d"%sys.version_info[:2])' 2>/dev/null || echo "0.0")"
      maj="${v%%.*}"; min="${v##*.}"
      if [ "$maj" -ge 3 ] && [ "$min" -ge 11 ]; then PYTHON="$c"; return 0; fi
    fi
  done
  return 1
}
if ! find_python; then
  if command -v brew >/dev/null 2>&1; then
    info "Installing Python 3.11 via Homebrew..."
    brew install python@3.11
    find_python || { err "Python 3.11+ still not found after brew install."; exit 1; }
  else
    err "Python 3.11+ is required."
    err "Install it from https://www.python.org/downloads/macos/ (or install Homebrew), then re-run."
    exit 1
  fi
fi
ok "Using $PYTHON ($("$PYTHON" -c 'import sys;print("%d.%d.%d"%sys.version_info[:3])'))"

# -----------------------------------------------------------
# 3. IPFS (Kubo)
# -----------------------------------------------------------
if [ ! -x "$BIN_DIR/ipfs" ]; then
  info "Downloading IPFS (Kubo v$KUBO_VERSION)..."
  TARBALL="kubo_v${KUBO_VERSION}_darwin-${DARWIN_ARCH}.tar.gz"
  curl -fsSL -o "/tmp/$TARBALL" "https://dist.ipfs.tech/kubo/v${KUBO_VERSION}/${TARBALL}"
  tar -xzf "/tmp/$TARBALL" -C /tmp
  mv /tmp/kubo/ipfs "$BIN_DIR/ipfs"
  chmod +x "$BIN_DIR/ipfs"
  rm -rf /tmp/kubo "/tmp/$TARBALL"
  ok "IPFS installed to $BIN_DIR/ipfs"
else
  ok "IPFS already present at $BIN_DIR/ipfs"
fi
IPFS_BIN="$BIN_DIR/ipfs"

# -----------------------------------------------------------
# 4. cloudflared (optional public tunnel)
# -----------------------------------------------------------
CF_ENABLED=1
if [ ! -x "$BIN_DIR/cloudflared" ]; then
  info "Downloading cloudflared..."
  CF_TGZ="cloudflared-darwin-${DARWIN_ARCH}.tgz"
  if curl -fsSL -o "/tmp/$CF_TGZ" \
        "https://github.com/cloudflare/cloudflared/releases/latest/download/$CF_TGZ"; then
    tar -xzf "/tmp/$CF_TGZ" -C /tmp
    mv /tmp/cloudflared "$BIN_DIR/cloudflared"
    chmod +x "$BIN_DIR/cloudflared"
    rm -f "/tmp/$CF_TGZ"
    ok "cloudflared installed"
  else
    warn "Could not download cloudflared — the public tunnel will be disabled."
    CF_ENABLED=0
  fi
else
  ok "cloudflared already present"
fi

# -----------------------------------------------------------
# 5. Python environment
# -----------------------------------------------------------
info "Setting up the Python environment..."
if [ ! -d "$ORBIT_DIR/.venv" ]; then
  "$PYTHON" -m venv "$ORBIT_DIR/.venv"
fi
PYBIN="$ORBIT_DIR/.venv/bin/python"
"$ORBIT_DIR/.venv/bin/pip" install --quiet --upgrade pip
"$ORBIT_DIR/.venv/bin/pip" install --quiet -r "$ORBIT_DIR/requirements.txt"
# rumps powers the menu bar app (macOS only — kept out of requirements.txt).
"$ORBIT_DIR/.venv/bin/pip" install --quiet rumps
ok "Python dependencies installed (incl. rumps for the menu bar app)"

# -----------------------------------------------------------
# 6. Initialize the IPFS repo
# -----------------------------------------------------------
if [ ! -f "$IPFS_REPO/config" ]; then
  info "Initializing IPFS repo at $IPFS_REPO..."
  IPFS_PATH="$IPFS_REPO" "$IPFS_BIN" init --profile=lowpower >/dev/null
  IPFS_PATH="$IPFS_REPO" "$IPFS_BIN" config Addresses.API /ip4/127.0.0.1/tcp/5001
  IPFS_PATH="$IPFS_REPO" "$IPFS_BIN" config Addresses.Gateway /ip4/127.0.0.1/tcp/8080
  ok "IPFS repo initialized (API bound to localhost)"
else
  ok "IPFS repo already initialized"
fi

# -----------------------------------------------------------
# 7. Environment config
# -----------------------------------------------------------
if [ ! -f "$ORBIT_DIR/.env" ]; then
  CF_FLAG="false"; [ "$CF_ENABLED" = "1" ] && CF_FLAG="true"
  cat > "$ORBIT_DIR/.env" <<ENVFILE
# Orbit Station (macOS) configuration
ORBIT_PASSWORD=
ORBIT_PQC_BACKEND=auto
ORBIT_PORT=$ORBIT_PORT
ORBIT_HOST=0.0.0.0
IPFS_API_URL=http://127.0.0.1:5001
MAX_UPLOAD_SIZE=104857600
CORS_ORIGINS=*
LOG_LEVEL=INFO
# Follow requests land as 'Pending' until approved (set 1 only for dev).
ORBIT_DEV_AUTO_ACCEPT_FOLLOWS=0
CLOUDFLARE_TUNNEL_ENABLED=$CF_FLAG
CLOUDFLARE_METRICS_PORT=40469
ORBIT_BASE_DIR=./orbit_data
ENVFILE
  ok "Created .env"
else
  ok ".env already exists"
fi

# -----------------------------------------------------------
# 8. Bootstrap the station identity
# -----------------------------------------------------------
info "Bootstrapping station identity..."
( cd "$ORBIT_DIR" && "$PYBIN" -c \
  "from orbit_node.identity import load_identity; load_identity(); print('identity ready')" )
ok "Identity ready"

# -----------------------------------------------------------
# 9. launchd services
# -----------------------------------------------------------
AGENT_PATH="$BIN_DIR:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"

write_plist() {
  # $1 = label ; remaining = body (already-formed <dict> inner XML)
  local label="$1"; shift
  cat > "$LA_DIR/$label.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$label</string>
$*
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ProcessType</key><string>Background</string>
</dict>
</plist>
PLIST
}

info "Writing launchd services..."

# IPFS daemon
write_plist "com.orbit.ipfs" "\
  <key>ProgramArguments</key><array>
    <string>$IPFS_BIN</string><string>daemon</string><string>--enable-gc</string>
  </array>
  <key>EnvironmentVariables</key><dict>
    <key>IPFS_PATH</key><string>$IPFS_REPO</string>
    <key>PATH</key><string>$AGENT_PATH</string>
  </dict>
  <key>StandardOutPath</key><string>$LOG_DIR/ipfs.log</string>
  <key>StandardErrorPath</key><string>$LOG_DIR/ipfs.log</string>"

# Orbit station — station log lands in orbit.log (the tray reads PINs from it)
write_plist "com.orbit.station" "\
  <key>ProgramArguments</key><array>
    <string>$PYBIN</string><string>$ORBIT_DIR/run.py</string>
  </array>
  <key>WorkingDirectory</key><string>$ORBIT_DIR</string>
  <key>EnvironmentVariables</key><dict>
    <key>IPFS_PATH</key><string>$IPFS_REPO</string>
    <key>PATH</key><string>$AGENT_PATH</string>
  </dict>
  <key>StandardOutPath</key><string>$LOG_DIR/orbit.log</string>
  <key>StandardErrorPath</key><string>$LOG_DIR/orbit.log</string>"

# Cloudflare tunnel (optional)
if [ "$CF_ENABLED" = "1" ]; then
  write_plist "com.orbit.tunnel" "\
  <key>ProgramArguments</key><array>
    <string>$BIN_DIR/cloudflared</string><string>tunnel</string>
    <string>--url</string><string>https://localhost:$ORBIT_PORT</string>
    <string>--no-tls-verify</string>
    <string>--metrics</string><string>localhost:40469</string>
  </array>
  <key>EnvironmentVariables</key><dict>
    <key>PATH</key><string>$AGENT_PATH</string>
  </dict>
  <key>StandardOutPath</key><string>$LOG_DIR/tunnel.log</string>
  <key>StandardErrorPath</key><string>$LOG_DIR/tunnel.log</string>"
fi

# Menu bar app
write_plist "com.orbit.tray" "\
  <key>ProgramArguments</key><array>
    <string>$PYBIN</string><string>-m</string><string>orbit_node.tray</string>
  </array>
  <key>WorkingDirectory</key><string>$ORBIT_DIR</string>
  <key>EnvironmentVariables</key><dict>
    <key>IPFS_PATH</key><string>$IPFS_REPO</string>
    <key>ORBIT_IPFS_BIN</key><string>$IPFS_BIN</string>
    <key>ORBIT_LOG_FILE</key><string>$LOG_DIR/orbit.log</string>
    <key>PATH</key><string>$AGENT_PATH</string>
  </dict>
  <key>StandardOutPath</key><string>$LOG_DIR/tray.log</string>
  <key>StandardErrorPath</key><string>$LOG_DIR/tray.log</string>"

# -----------------------------------------------------------
# 10. Load (start) the services
# -----------------------------------------------------------
load_agent() {
  local label="$1"
  [ -f "$LA_DIR/$label.plist" ] || return 0
  launchctl unload "$LA_DIR/$label.plist" 2>/dev/null || true
  launchctl load -w "$LA_DIR/$label.plist"
  ok "started $label"
}

info "Starting services..."
load_agent "com.orbit.ipfs"
sleep 3
load_agent "com.orbit.station"
[ "$CF_ENABLED" = "1" ] && load_agent "com.orbit.tunnel"
load_agent "com.orbit.tray"

# -----------------------------------------------------------
# Done
# -----------------------------------------------------------
PEER_ID="$(IPFS_PATH="$IPFS_REPO" "$IPFS_BIN" id -f='<id>' 2>/dev/null || echo 'starting…')"

echo ""
ok "============================================"
ok "  Orbit Station installed on macOS!"
ok "============================================"
echo ""
info "Look for the 🛰 icon in your menu bar (top-right) for status, pairing PINs,"
info "the Cloudflare URL, and storage controls."
echo ""
info "Your IPFS Peer ID (permanent station address):"
echo "    $PEER_ID"
echo ""
info "Local access:   https://localhost:$ORBIT_PORT/health"
if [ "$CF_ENABLED" = "1" ]; then
  info "Public URL:     appears in the menu bar within ~30s (or: tail -f \"$LOG_DIR/orbit.log\")"
fi
echo ""
info "Manage services:"
echo "    launchctl list | grep com.orbit"
echo "    launchctl kickstart -k gui/$UID_NUM/com.orbit.station   # restart the station"
echo "    launchctl unload ~/Library/LaunchAgents/com.orbit.*.plist  # stop everything"
echo ""
info "Logs: $LOG_DIR"
echo ""
