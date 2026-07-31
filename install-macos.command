#!/bin/bash
#
# Cipher Station — one-click macOS installer (double-clickable .command).
#
# Installs IPFS (Kubo) + cloudflared, sets up the Python environment, initializes
# a dedicated IPFS repo, registers launchd services for the IPFS daemon, the
# Cipher Station station, the Cloudflare tunnel, and the menu bar app — then starts them.
#
# No sudo required: binaries land in ~/.cipherstation/bin and services run as LaunchAgents
# in your user session.
#
# Optional environment variables (both unset == the historical layout, unchanged):
#
#   CIPHER_DATA_ROOT    Absolute path to a mounted volume that should hold all
#                       station state. On macOS this is typically an external or
#                       secondary drive under /Volumes, e.g.:
#                         CIPHER_DATA_ROOT=/Volumes/CipherData ./install-macos.command
#                       When set:   IPFS repo    -> $CIPHER_DATA_ROOT/ipfs
#                                   station data -> $CIPHER_DATA_ROOT/station
#                       When unset: IPFS repo    -> ~/.cipherstation/ipfs
#                                   station data -> <repo>/cipher_station_data
#
#   CIPHER_STORAGE_MAX  Optional IPFS datastore cap, e.g. "25GB". Applied on every
#                       run. Unset leaves kubo's own default alone.
#
set -euo pipefail

CIPHER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$CIPHER_DIR"

# -----------------------------------------------------------
# Settings
# -----------------------------------------------------------
KUBO_VERSION="0.28.0"
BIN_DIR="$HOME/.cipherstation/bin"
LA_DIR="$HOME/Library/LaunchAgents"
CIPHER_PORT="${CIPHER_PORT:-8443}"
UID_NUM="$(id -u)"

info() { printf '\033[1;34m[cipher station]\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m[cipher station]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[cipher station]\033[0m %s\n' "$*"; }
err()  { printf '\033[1;31m[cipher station]\033[0m %s\n' "$*" >&2; }

# -----------------------------------------------------------
# Data location (opt-in: CIPHER_DATA_ROOT)
#
# Unset  -> the historical layout, byte-for-byte unchanged.
# Set    -> everything stateful moves onto the given volume, so the whole
#           station can live on an external drive (and travel with it).
# -----------------------------------------------------------
DATA_ROOT="${CIPHER_DATA_ROOT:-}"
if [ -n "$DATA_ROOT" ]; then
  if [ ! -d "$DATA_ROOT" ]; then
    err "CIPHER_DATA_ROOT is set to '$DATA_ROOT', but that directory does not exist."
    err "Mount the drive first (external drives appear under /Volumes), then re-run."
    exit 1
  fi
  if [ ! -w "$DATA_ROOT" ]; then
    err "CIPHER_DATA_ROOT '$DATA_ROOT' exists but is not writable by $(whoami)."
    err "Fix its permissions (a read-only or Time Machine volume will not work), then re-run."
    exit 1
  fi
  # Paths are embedded raw in the launchd plists below, so reject the two
  # characters XML cannot carry unescaped rather than emit an unloadable plist.
  case "$DATA_ROOT" in
    *[\&\<]*)
      err "CIPHER_DATA_ROOT contains '&' or '<', which cannot go into a launchd plist."
      err "Rename the volume (Finder > rename), then re-run."
      exit 1
      ;;
  esac
  DATA_ROOT="$(cd "$DATA_ROOT" && pwd -P)"
  IPFS_REPO="$DATA_ROOT/ipfs"
  STATION_DATA="$DATA_ROOT/station"
  info "Data root: $DATA_ROOT (IPFS repo -> $IPFS_REPO, station data -> $STATION_DATA)"
  case "$DATA_ROOT" in
    /Volumes/*)
      # launchd has no RequiresMountsFor= equivalent, so the services carry
      # their own pre-flight check (see cipher-preflight below).
      warn "Services will refuse to start while this volume is unmounted — mount it before login."
      ;;
  esac
else
  IPFS_REPO="$HOME/.cipherstation/ipfs"
  STATION_DATA="$CIPHER_DIR/cipher_station_data"
fi
LOG_DIR="$STATION_DATA/logs"

# IPFS_PATH is exported ONLY for a data-root install, where everything this
# script spawns genuinely has to target the volume. With CIPHER_DATA_ROOT unset
# the caller's environment is left EXACTLY as they had it — a self-hoster with
# `export IPFS_PATH=/Volumes/SSD/ipfs` in their shell profile keeps that value
# for whatever else they run, as with every previous version of this installer.
# The ipfs calls below (init, config, id) carry their own explicit IPFS_PATH=
# prefix, as they always have, so they stay pinned to $IPFS_REPO either way.
if [ -n "$DATA_ROOT" ]; then
  export IPFS_PATH="$IPFS_REPO"
fi

# $IPFS_REPO is deliberately NOT created here. Step 6 treats a present-but-empty
# repo directory as fatal — that is what a volume which failed to mount looks
# like — so pre-creating it would brick every retry after an install that
# aborted anywhere in between: the second run would find the empty directory the
# FIRST run made and refuse to continue. Nothing before step 6 needs it, and
# kubo's own `ipfs init` creates it when it is genuinely required.
#
# The snapshot is kept so step 6 reads a value captured before any directory
# creation, whatever later edits add.
IPFS_REPO_PREEXISTED=""
[ -d "$IPFS_REPO" ] && IPFS_REPO_PREEXISTED=1

mkdir -p "$BIN_DIR" "$LOG_DIR" "$LA_DIR"

if [ -n "$DATA_ROOT" ]; then
  # Station private keys will live here, so keep the tree owner-only — and check
  # it stuck: exFAT/FAT/NTFS volumes silently drop POSIX permissions, which would
  # leave the keys readable by anyone who plugs the drive into any machine.
  chmod 700 "$STATION_DATA" 2>/dev/null || true
  if [ "$(stat -f '%OLp' "$STATION_DATA" 2>/dev/null || echo '?')" != "700" ]; then
    warn "$DATA_ROOT does not preserve POSIX permissions (exFAT/FAT/NTFS?)."
    warn "Station private keys stored there are readable by anyone holding the drive."
    warn "Prefer an APFS / Mac OS Extended volume, or turn on encryption for this one."
  fi
fi

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
if [ ! -d "$CIPHER_DIR/.venv" ]; then
  "$PYTHON" -m venv "$CIPHER_DIR/.venv"
fi
PYBIN="$CIPHER_DIR/.venv/bin/python"
"$CIPHER_DIR/.venv/bin/pip" install --quiet --upgrade pip
"$CIPHER_DIR/.venv/bin/pip" install --quiet -r "$CIPHER_DIR/requirements.txt"
# rumps powers the menu bar app (macOS only — kept out of requirements.txt).
"$CIPHER_DIR/.venv/bin/pip" install --quiet rumps
ok "Python dependencies installed (incl. rumps for the menu bar app)"

# -----------------------------------------------------------
# 6. Initialize the IPFS repo
# -----------------------------------------------------------
# Deciding whether the repo needs initializing. The two paths deliberately use
# DIFFERENT predicates:
#
#   data-root: the config file. The mkdir -p above legitimately pre-creates an
#              empty $IPFS_REPO on a freshly formatted volume, so directory
#              presence proves nothing there.
#   legacy:    whether the directory was already there before this run (the
#              original predicate, via the pre-mkdir snapshot). The two
#              predicates diverge in exactly one state — directory already
#              present, no config — and on macOS that state is what an external
#              volume mounted at ~/.cipherstation/ipfs looks like when it failed
#              to mount: the mountpoint lingers as an empty folder. Running
#              `ipfs init` there would mint a brand-new PeerID onto the boot
#              disk and orphan every IPNS record this station ever published.
#              Losing an identity must never be the silent default, so stop.
IPFS_NEEDS_INIT=""
if [ -n "$DATA_ROOT" ]; then
  if [ ! -f "$IPFS_REPO/config" ]; then
    IPFS_NEEDS_INIT=1
  fi
else
  if [ -z "$IPFS_REPO_PREEXISTED" ]; then
    IPFS_NEEDS_INIT=1
  elif [ ! -f "$IPFS_REPO/config" ]; then
    err "$IPFS_REPO exists but contains no IPFS config file."
    err "That is what an unmounted drive looks like — e.g. an external volume"
    err "mounted at that path that did not come up (check Disk Utility, or"
    err "re-attach the drive)."
    err ""
    err "Refusing to run 'ipfs init': it would mint a NEW PeerID and orphan every"
    err "IPNS record this station has published."
    err ""
    err "  - If a drive belongs there, mount it and re-run this installer."
    err "  - If this really is a stale empty directory and you WANT a new identity,"
    err "    remove it yourself (rm -rf \"$IPFS_REPO\") and re-run."
    exit 1
  fi
fi

if [ -n "$IPFS_NEEDS_INIT" ]; then
  # Moving to a data volume must not silently fork the station's identity.
  if [ -n "$DATA_ROOT" ] && [ -f "$HOME/.cipherstation/ipfs/config" ]; then
    warn "An IPFS repo already exists at $HOME/.cipherstation/ipfs, but none on the data volume."
    warn "A fresh repo means a NEW peer ID — followers can no longer find this station."
    warn "To keep the existing identity: stop the services, then"
    warn "  rm -rf \"$IPFS_REPO\" && cp -a \"$HOME/.cipherstation/ipfs\" \"$IPFS_REPO\""
    warn "and re-run this installer. Ignore this if you meant to start a new station."
  fi
  info "Initializing IPFS repo at $IPFS_REPO..."
  IPFS_PATH="$IPFS_REPO" "$IPFS_BIN" init --profile=lowpower >/dev/null
  IPFS_PATH="$IPFS_REPO" "$IPFS_BIN" config Addresses.API /ip4/127.0.0.1/tcp/5001
  IPFS_PATH="$IPFS_REPO" "$IPFS_BIN" config Addresses.Gateway /ip4/127.0.0.1/tcp/8080
  ok "IPFS repo initialized (API bound to localhost)"
else
  ok "IPFS repo already initialized"
fi

# Datastore cap (opt-in). Applied on every run so re-running with a new value
# takes effect; unset leaves kubo's own default untouched.
if [ -n "${CIPHER_STORAGE_MAX:-}" ]; then
  info "Setting IPFS Datastore.StorageMax=$CIPHER_STORAGE_MAX"
  IPFS_PATH="$IPFS_REPO" "$IPFS_BIN" config Datastore.StorageMax "$CIPHER_STORAGE_MAX"
fi

# -----------------------------------------------------------
# 7. Environment config
#
# CIPHER_BASE_DIR must end up as the ABSOLUTE station data path whenever a data
# root is in play — a relative "./cipher_station_data" is resolved against the
# project, not the volume. The heredoc below is UNquoted (<<ENVFILE, not
# <<'ENVFILE' as in install.sh) so $ENV_BASE_DIR genuinely interpolates; keep it
# that way or the literal string lands in .env.
# -----------------------------------------------------------
ENV_BASE_DIR="./cipher_station_data"
[ -n "$DATA_ROOT" ] && ENV_BASE_DIR="$STATION_DATA"

# Earlier builds of this installer pre-created $STATION_DATA/backups and wrote it
# into .env as CIPHER_BACKUP_DEST. That directory is on the SAME MOUNT as the live
# station data, which cipher_station.backup now refuses — so anything already in
# there is a plaintext key archive sitting on the very volume it was meant to
# survive. Say so; never delete a user's archives from under them.
if [ -n "$DATA_ROOT" ] && [ -d "$STATION_DATA/backups" ] \
   && [ -n "$(ls -A "$STATION_DATA/backups" 2>/dev/null)" ]; then
  warn "$STATION_DATA/backups contains archives from an earlier install."
  warn "It sits on the data volume itself, so it is no longer a usable destination."
  warn "Those archives may be UNENCRYPTED and contain private keys — move them to a"
  warn "separate drive, then remove that directory."
fi

if [ ! -f "$CIPHER_DIR/.env" ]; then
  CF_FLAG="false"; [ "$CF_ENABLED" = "1" ] && CF_FLAG="true"
  cat > "$CIPHER_DIR/.env" <<ENVFILE
# Cipher Station (macOS) configuration
CIPHER_PASSWORD=
CIPHER_PQC_BACKEND=auto
CIPHER_PORT=$CIPHER_PORT
CIPHER_HOST=0.0.0.0
IPFS_API_URL=http://127.0.0.1:5001
MAX_UPLOAD_SIZE=104857600
CORS_ORIGINS=*
LOG_LEVEL=INFO
# Follow requests land as 'Pending' until approved (set 1 only for dev).
CIPHER_DEV_AUTO_ACCEPT_FOLLOWS=0
CLOUDFLARE_TUNNEL_ENABLED=$CF_FLAG
CLOUDFLARE_METRICS_PORT=40469
CIPHER_BASE_DIR=$ENV_BASE_DIR
ENVFILE
  if [ -n "$DATA_ROOT" ]; then
    cat >> "$CIPHER_DIR/.env" <<'ENVFILE'
# --- Backup ---
# Deliberately BLANK. cipher_station.backup refuses any destination on the same
# mount as the live station data: such a copy dies with that volume, and an
# unencrypted one drops the private keys next to the originals. Both
# <volume>/station/backups and <volume>/backups are therefore rejected — do not
# "fix" this by filling one in.
#
# Blank means "use a detected removable drive if there is exactly one, otherwise
# do nothing" — and detection can no longer land on the data volume. Detection
# looks for removable mounts and may not spot an external drive mounted under
# /Volumes, so on macOS set an explicit path if you want backups unattended.
#
# For routine backups, point this at a directory on a DIFFERENT drive:
#   CIPHER_BACKUP_DEST=/Volumes/CipherBackup/cipher-station
# or pass it per run:
#   .venv/bin/python -m cipher_station.backup create --dest /Volumes/CipherBackup --passphrase '...'
# Without --passphrase the archive is UNENCRYPTED: it holds mlkem.bin, mldsa.bin,
# the .env and the IPFS private key in the clear.
CIPHER_BACKUP_DEST=
ENVFILE
  fi
  ok "Created .env"
else
  ok ".env already exists"
  # An existing .env is never rewritten wholesale, but a stale CIPHER_BASE_DIR
  # would quietly split the station: IPFS on the volume, keys/DB back in the repo.
  if [ -n "$DATA_ROOT" ]; then
    CUR_BASE="$(sed -n 's/^[[:space:]]*CIPHER_BASE_DIR=//p' "$CIPHER_DIR/.env" | tail -n1)"
    if [ "$CUR_BASE" != "$STATION_DATA" ]; then
      warn "CIPHER_DATA_ROOT is set, but .env has CIPHER_BASE_DIR=${CUR_BASE:-<unset>}"
      if [ "$CUR_BASE" = "./cipher_station_data" ]; then
        # Only the untouched default is rewritten. Escape the replacement so a
        # volume name containing & or \ can't corrupt the file.
        SED_SAFE="$(printf '%s' "$STATION_DATA" | sed 's/[&\\#]/\\&/g')"
        cp "$CIPHER_DIR/.env" "$CIPHER_DIR/.env.bak"
        sed -i '' "s#^[[:space:]]*CIPHER_BASE_DIR=.*#CIPHER_BASE_DIR=$SED_SAFE#" "$CIPHER_DIR/.env"
        ok "Updated .env to CIPHER_BASE_DIR=$STATION_DATA (previous file saved as .env.bak)"
        warn "Existing data in $CIPHER_DIR/cipher_station_data is NOT moved — copy it to"
        warn "$STATION_DATA yourself, or restore from a backup, before the station starts."
      else
        warn "Leaving your customised value alone. The services are pinned to"
        warn "CIPHER_BASE_DIR=$STATION_DATA regardless, so edit .env to match if that is wrong."
      fi
    fi
    # Blank is the correct default (see the .env comment above), so the only thing
    # worth flagging is a destination that lands back on the data volume — which
    # cipher_station.backup refuses, making every `backup create` fail.
    if grep -q '^[[:space:]]*CIPHER_BACKUP_DEST=[^[:space:]]' "$CIPHER_DIR/.env"; then
      CUR_DEST="$(sed -n 's/^[[:space:]]*CIPHER_BACKUP_DEST=//p' "$CIPHER_DIR/.env" | tail -n1)"
      case "$CUR_DEST" in
        "$DATA_ROOT"|"$DATA_ROOT"/*)
          warn ".env has CIPHER_BACKUP_DEST=$CUR_DEST, which is on the data volume."
          warn "cipher_station.backup rejects same-mount destinations (a backup that dies"
          warn "with the disk it backs up, holding unencrypted keys), so backups will fail."
          warn "Blank the line to fall back to removable-drive detection, or point it at a"
          warn "directory on a DIFFERENT drive, e.g. /Volumes/CipherBackup/cipher-station."
          ;;
      esac
    else
      info "CIPHER_BACKUP_DEST is blank — the safe default: a detected removable drive, and"
      info "nothing at all otherwise. Detection may not spot a /Volumes drive, so for backups"
      info "you can rely on, set a path on ANOTHER drive (never on $DATA_ROOT), e.g."
      info "  CIPHER_BACKUP_DEST=/Volumes/CipherBackup/cipher-station"
    fi
  fi
fi

# The station and tray read .env from the project dir, but a real environment
# variable takes precedence over it — so pin the data dir for this installer's
# own identity bootstrap and (below) for the launchd services.
[ -n "$DATA_ROOT" ] && export CIPHER_BASE_DIR="$STATION_DATA"

# -----------------------------------------------------------
# 8. Bootstrap the station identity
# -----------------------------------------------------------
info "Bootstrapping station identity..."
( cd "$CIPHER_DIR" && "$PYBIN" -c \
  "from cipher_station.identity import load_identity; load_identity(); print('identity ready')" )
ok "Identity ready"

# -----------------------------------------------------------
# 9. launchd services
# -----------------------------------------------------------
AGENT_PATH="$BIN_DIR:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"

# launchd has no equivalent of systemd's RequiresMountsFor=: at login it starts
# these jobs whether or not the data volume is mounted. Left unguarded, `ipfs
# daemon` would then initialize a FRESH repo — a brand new peer identity — on the
# empty mountpoint, and the station would come up with no keys. So when
# CIPHER_DATA_ROOT is in use, every data-dependent job is exec'd through this
# pre-flight wrapper, which refuses to start until the volume is really there.
#
# KeepAlive is unconditional, so launchd simply retries (throttled to ~10s) and
# the service starts on the first retry after the drive is mounted — no re-install
# needed. Each refusal is logged to ~/.cipherstation/preflight.log, because the
# normal logs live on the volume and are unreachable exactly when this fires.
PREFLIGHT_ARG=""
BASE_DIR_ENV=""
if [ -n "$DATA_ROOT" ]; then
  PREFLIGHT="$BIN_DIR/cipher-preflight"
  {
    printf '%s\n' '#!/bin/bash' \
                  '# Generated by install-macos.command — do not edit; re-run the installer.' \
                  'set -u'
    printf 'DATA_ROOT=%q\n'    "$DATA_ROOT"
    printf 'IPFS_REPO=%q\n'    "$IPFS_REPO"
    printf 'STATION_DATA=%q\n' "$STATION_DATA"
    cat <<'PREFLIGHT'
FALLBACK_LOG="$HOME/.cipherstation/preflight.log"

# $IPFS_REPO/config is the exact file whose absence would make `ipfs init` run,
# so test for it rather than for a bare directory (an unmounted /Volumes path can
# linger as an empty folder).
if [ ! -f "$IPFS_REPO/config" ] || [ ! -d "$STATION_DATA" ]; then
    mkdir -p "$(dirname "$FALLBACK_LOG")"
    printf '[%s] data volume not mounted (%s) — refusing to start: %s\n' \
        "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$DATA_ROOT" "${1:-?}" >> "$FALLBACK_LOG"
    exit 78   # EX_CONFIG. Never fall through: a new IPFS identity is unrecoverable.
fi

export IPFS_PATH="$IPFS_REPO"
export CIPHER_BASE_DIR="$STATION_DATA"
exec "$@"
PREFLIGHT
  } > "$PREFLIGHT"
  chmod +x "$PREFLIGHT"
  PREFLIGHT_ARG="<string>$PREFLIGHT</string>"
  # A real env var beats .env (python-dotenv does not override), so pin the data
  # dir in the plists too — a stale .env can never redirect keys off the volume.
  BASE_DIR_ENV="
    <key>CIPHER_BASE_DIR</key><string>$STATION_DATA</string>"
  ok "Pre-flight guard installed: $PREFLIGHT"
fi

write_plist() {
  # $1 = label ; $2 = "--keepalive-crash-only" (optional) ; remaining = body
  #
  # KeepAlive defaults to unconditional <true/>: always relaunch, even after a
  # clean exit — correct for always-on daemons (ipfs/station/tunnel).
  # --keepalive-crash-only restarts only on a crash (nonzero exit), so a
  # deliberate quit (e.g. the tray's "Quit Cipher Station" menu item) actually sticks.
  local label="$1"; shift
  local keepalive="<true/>"
  if [ "${1:-}" = "--keepalive-crash-only" ]; then
    keepalive="<dict><key>SuccessfulExit</key><false/></dict>"
    shift
  fi
  cat > "$LA_DIR/$label.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$label</string>
$*
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key>$keepalive
  <key>ProcessType</key><string>Background</string>
</dict>
</plist>
PLIST
}

info "Writing launchd services..."

# IPFS daemon
write_plist "com.cipherstation.ipfs" "\
  <key>ProgramArguments</key><array>
    ${PREFLIGHT_ARG}<string>$IPFS_BIN</string><string>daemon</string><string>--enable-gc</string>
  </array>
  <key>EnvironmentVariables</key><dict>
    <key>IPFS_PATH</key><string>$IPFS_REPO</string>
    <key>PATH</key><string>$AGENT_PATH</string>
  </dict>
  <key>StandardOutPath</key><string>$LOG_DIR/ipfs.log</string>
  <key>StandardErrorPath</key><string>$LOG_DIR/ipfs.log</string>"

# Cipher Station station — station log lands in cipherstation.log (the tray reads PINs from it)
write_plist "com.cipherstation.station" "\
  <key>ProgramArguments</key><array>
    ${PREFLIGHT_ARG}<string>$PYBIN</string><string>$CIPHER_DIR/run.py</string>
  </array>
  <key>WorkingDirectory</key><string>$CIPHER_DIR</string>
  <key>EnvironmentVariables</key><dict>
    <key>IPFS_PATH</key><string>$IPFS_REPO</string>${BASE_DIR_ENV}
    <key>PATH</key><string>$AGENT_PATH</string>
  </dict>
  <key>StandardOutPath</key><string>$LOG_DIR/cipherstation.log</string>
  <key>StandardErrorPath</key><string>$LOG_DIR/cipherstation.log</string>"

# Cloudflare tunnel (optional)
if [ "$CF_ENABLED" = "1" ]; then
  write_plist "com.cipherstation.tunnel" "\
  <key>ProgramArguments</key><array>
    <string>$BIN_DIR/cloudflared</string><string>tunnel</string>
    <string>--url</string><string>https://localhost:$CIPHER_PORT</string>
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
write_plist "com.cipherstation.tray" --keepalive-crash-only "\
  <key>ProgramArguments</key><array>
    ${PREFLIGHT_ARG}<string>$PYBIN</string><string>-m</string><string>cipher_station.tray</string>
  </array>
  <key>WorkingDirectory</key><string>$CIPHER_DIR</string>
  <key>EnvironmentVariables</key><dict>
    <key>IPFS_PATH</key><string>$IPFS_REPO</string>${BASE_DIR_ENV}
    <key>CIPHER_IPFS_BIN</key><string>$IPFS_BIN</string>
    <key>CIPHER_LOG_FILE</key><string>$LOG_DIR/cipherstation.log</string>
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
load_agent "com.cipherstation.ipfs"
sleep 3
load_agent "com.cipherstation.station"
[ "$CF_ENABLED" = "1" ] && load_agent "com.cipherstation.tunnel"
load_agent "com.cipherstation.tray"

# -----------------------------------------------------------
# Done
# -----------------------------------------------------------
PEER_ID="$(IPFS_PATH="$IPFS_REPO" "$IPFS_BIN" id -f='<id>' 2>/dev/null || echo 'starting…')"

echo ""
ok "============================================"
ok "  Cipher Station installed on macOS!"
ok "============================================"
echo ""
info "Look for the 🛰 icon in your menu bar (top-right) for status, pairing PINs,"
info "the Cloudflare URL, and storage controls."
echo ""
info "Your IPFS Peer ID (permanent station address):"
echo "    $PEER_ID"
echo ""
info "Local access:   https://localhost:$CIPHER_PORT/health"
if [ "$CF_ENABLED" = "1" ]; then
  info "Public URL:     appears in the menu bar within ~30s (or: tail -f \"$LOG_DIR/cipherstation.log\")"
fi
echo ""
info "Manage services:"
echo "    launchctl list | grep com.cipherstation"
echo "    launchctl kickstart -k gui/$UID_NUM/com.cipherstation.station   # restart the station"
echo "    launchctl unload ~/Library/LaunchAgents/com.cipherstation.*.plist  # stop everything"
echo ""
info "Logs: $LOG_DIR"
if [ -n "$DATA_ROOT" ]; then
  echo ""
  info "Data volume: $DATA_ROOT"
  echo "    IPFS repo:    $IPFS_REPO"
  echo "    Station data: $STATION_DATA"
  [ -n "${CIPHER_STORAGE_MAX:-}" ] && echo "    IPFS cap:     $CIPHER_STORAGE_MAX (Datastore.StorageMax)"
  warn "Keep this volume mounted. If it is missing at login the services refuse to"
  warn "start (by design — starting without it would create a new IPFS identity)."
  echo "    Refusals are logged to: $HOME/.cipherstation/preflight.log"
  echo "    After mounting, they recover on their own within ~10s, or force it with:"
  echo "      launchctl kickstart -k gui/$UID_NUM/com.cipherstation.ipfs"
fi
echo ""
