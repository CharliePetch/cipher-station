#!/usr/bin/env bash
#
# Cipher Station — One-Click Raspberry Pi Installer
#
# Usage:  chmod +x install.sh && ./install.sh
#
set -euo pipefail

CIPHER_DIR="$(cd "$(dirname "$0")" && pwd)"
CIPHER_USER="$(whoami)"
CIPHER_PORT="${CIPHER_PORT:-8443}"
KUBO_VERSION="0.28.0"

# -----------------------------------------------------------
# Data root (opt-in). Hosted boxes keep everything that must survive a rebuild
# on one mounted volume; a Pi/self-host install is untouched.
#
#   CIPHER_DATA_ROOT unset   -> IPFS repo   $HOME/.ipfs
#                               station data <repo>/cipher_station_data
#   CIPHER_DATA_ROOT=/path   -> IPFS repo   /path/ipfs
#                               station data /path/station
#
# CIPHER_STORAGE_MAX (e.g. "25GB") caps the kubo datastore to the volume's
# size. Unset leaves kubo's own default alone.
# Validation of the path happens right after the log helpers are defined.
# -----------------------------------------------------------
CIPHER_DATA_ROOT="${CIPHER_DATA_ROOT:-}"
CIPHER_STORAGE_MAX="${CIPHER_STORAGE_MAX:-}"
if [ -n "$CIPHER_DATA_ROOT" ]; then
    IPFS_REPO="$CIPHER_DATA_ROOT/ipfs"
    STATION_DATA="$CIPHER_DATA_ROOT/station"
else
    IPFS_REPO="$HOME/.ipfs"
    STATION_DATA="$CIPHER_DIR/cipher_station_data"
fi

# -----------------------------------------------------------
# Argument parsing
#   --restore            restore from a backup auto-detected on a mounted USB
#   --restore=<path>     restore from a specific backup archive
#   --restore <path>     (space-separated form also accepted)
# -----------------------------------------------------------
RESTORE_ARG=""
_args=("$@")
_i=0
while [ "$_i" -lt "${#_args[@]}" ]; do
    _a="${_args[$_i]}"
    case "$_a" in
        --restore=*) RESTORE_ARG="${_a#*=}" ;;
        --restore)
            _next="${_args[$((_i+1))]:-}"
            if [ -n "$_next" ] && [ "${_next#-}" = "$_next" ]; then
                RESTORE_ARG="$_next"; _i=$((_i+1))
            else
                RESTORE_ARG="auto"
            fi
            ;;
    esac
    _i=$((_i+1))
done

info()  { echo -e "\033[1;34m[cipher station]\033[0m $*"; }
ok()    { echo -e "\033[1;32m[cipher station]\033[0m $*"; }
warn()  { echo -e "\033[1;33m[cipher station]\033[0m $*"; }
err()   { echo -e "\033[1;31m[cipher station]\033[0m $*" >&2; }

# -----------------------------------------------------------
# Validate the data root before anything writes to it. A typo'd or unmounted
# path must fail here — not halfway through, with keys scattered onto a root
# disk that gets thrown away.
# -----------------------------------------------------------
if [ -n "$CIPHER_DATA_ROOT" ]; then
    case "$CIPHER_DATA_ROOT" in
        /*) ;;
        *)  err "CIPHER_DATA_ROOT must be an absolute path (got: $CIPHER_DATA_ROOT)"; exit 1 ;;
    esac
    if [ ! -d "$CIPHER_DATA_ROOT" ]; then
        err "CIPHER_DATA_ROOT does not exist: $CIPHER_DATA_ROOT"
        err "Mount the data volume there first, then re-run."
        exit 1
    fi
    if command -v mountpoint >/dev/null 2>&1 && ! mountpoint -q "$CIPHER_DATA_ROOT"; then
        warn "$CIPHER_DATA_ROOT is not a mount point — data will land on the root filesystem."
        warn "That works, but nothing there survives rebuilding the machine."
    fi
    mkdir -p "$IPFS_REPO" "$STATION_DATA" 2>/dev/null || true
    if [ ! -w "$IPFS_REPO" ] || [ ! -w "$STATION_DATA" ]; then
        err "CIPHER_DATA_ROOT is not writable by ${CIPHER_USER}: $CIPHER_DATA_ROOT"
        err "Fix ownership (sudo chown -R ${CIPHER_USER} $CIPHER_DATA_ROOT) and re-run."
        exit 1
    fi
    # config.py reads CIPHER_BASE_DIR from the environment first and .env second
    # (load_dotenv does not override real env vars), and .env is not written
    # until step 6 — so every python call below (restore, identity bootstrap)
    # needs this exported to land on the volume. Deliberately NOT exported when
    # CIPHER_DATA_ROOT is unset, so an existing .env keeps winning.
    export CIPHER_BASE_DIR="$STATION_DATA"
    info "Data root: $CIPHER_DATA_ROOT (ipfs: $IPFS_REPO, station: $STATION_DATA)"
fi

# -----------------------------------------------------------
# Distro support: detect the package manager + require systemd.
# Works on Debian/Ubuntu (apt), Fedora/RHEL (dnf), Arch (pacman), openSUSE (zypper).
# -----------------------------------------------------------
PKG=""
for _pm in apt-get dnf zypper pacman; do
    if command -v "$_pm" >/dev/null 2>&1; then PKG="$_pm"; break; fi
done

if ! command -v systemctl >/dev/null 2>&1; then
    err "This installer needs systemd (systemctl not found)."
    err "On macOS, run ./install-macos.command instead. Non-systemd Linux (Alpine/Void/OpenRC) isn't supported by the one-click path."
    exit 1
fi
if [ -z "$PKG" ]; then
    err "No supported package manager found (need apt, dnf, zypper, or pacman)."
    err "Install these yourself, then re-run: python 3.11+, venv, pip, git, curl, openssl (libsodium dev headers optional)."
    exit 1
fi

# Install build/runtime deps, mapping package names per distro. The first set
# must succeed; libsodium dev headers + a compiler are best-effort (PyNaCl ships
# wheels, so a source build is only a fallback).
install_system_deps() {
    case "$PKG" in
        apt-get)
            sudo apt-get update -qq
            sudo apt-get install -y -qq python3 python3-venv python3-pip git curl openssl ca-certificates
            sudo apt-get install -y -qq libsodium-dev build-essential 2>/dev/null || true
            ;;
        dnf)
            sudo dnf install -y -q python3 python3-pip git curl openssl ca-certificates
            sudo dnf install -y -q libsodium-devel gcc 2>/dev/null || true
            ;;
        zypper)
            sudo zypper --non-interactive install python3 python3-pip git curl openssl ca-certificates
            sudo zypper --non-interactive install libsodium-devel gcc 2>/dev/null || true
            ;;
        pacman)
            sudo pacman -Sy --noconfirm --needed python python-pip git curl openssl ca-certificates
            sudo pacman -S --noconfirm --needed libsodium base-devel 2>/dev/null || true
            ;;
    esac
}

# Open the Cipher Station port with whatever firewall the distro ships (best-effort).
configure_firewall() {
    if command -v ufw >/dev/null 2>&1; then
        sudo ufw allow "${CIPHER_PORT}/tcp" comment "Cipher Station" 2>/dev/null || true
        sudo ufw --force enable 2>/dev/null || true
        ok "Firewall (ufw): ${CIPHER_PORT}/tcp allowed"
    elif command -v firewall-cmd >/dev/null 2>&1; then
        sudo firewall-cmd --permanent --add-port="${CIPHER_PORT}/tcp" >/dev/null 2>&1 || true
        sudo firewall-cmd --reload >/dev/null 2>&1 || true
        ok "Firewall (firewalld): ${CIPHER_PORT}/tcp allowed"
    else
        warn "No ufw/firewalld detected — skipping firewall setup. Open ${CIPHER_PORT}/tcp yourself if you run a firewall."
    fi
}

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

info "Installing system dependencies via $PKG (python3, git, curl, openssl, ...)..."
PYTHON=""
ver=""

install_system_deps

if ! _find_python; then
    err "Python 3.11+ not found, even after installing python3 via $PKG."
    err "Your distro may ship an older Python 3 by default — install python3.11+ (and its venv module), then re-run."
    exit 1
fi
ok "Using $PYTHON ($ver)"

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
    cd "$CIPHER_DIR"

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
# IPFS_PATH is exported ONLY for a data-root install, where we genuinely need
# every `ipfs` call below (including `ipfs id` at the end) to target the volume.
# With CIPHER_DATA_ROOT unset the environment is left EXACTLY as the caller had
# it — a self-hoster with `export IPFS_PATH=/mnt/ssd/ipfs` in their profile
# keeps hitting that repo, as they did with every previous version of this
# installer. Pinning it here would silently retarget them at $HOME/.ipfs.
if [ -n "$CIPHER_DATA_ROOT" ]; then
    export IPFS_PATH="$IPFS_REPO"
fi

# Deciding whether the repo needs initializing. The two paths deliberately use
# DIFFERENT predicates:
#
#   data-root:  the config file. mkdir -p above legitimately pre-creates an
#               empty $IPFS_REPO on a fresh volume, so directory presence
#               proves nothing there.
#   legacy:     directory presence — the original predicate, unchanged — but
#               applied to the repo the `ipfs` BINARY will use, which is not
#               automatically $IPFS_REPO. We deliberately do not pin IPFS_PATH
#               on this path, so an ambient IPFS_PATH decides where `ipfs init`
#               lands; a guard that inspects $HOME/.ipfs while init would act on
#               /mnt/ssd/ipfs is checking a directory the script never touches.
#
# The legacy predicates diverge in exactly one state (dir exists, no config),
# and on a self-host box that state is what an UNMOUNTED mountpoint looks like:
# a USB/SSD mounted at the repo path that did not enumerate at boot. Running
# `ipfs init` there would mint a brand-new PeerID onto the boot media and orphan
# every IPNS record the station ever published. Losing an identity must never be
# the silent default, so we stop instead.
IPFS_NEEDS_INIT=""
if [ -n "$CIPHER_DATA_ROOT" ]; then
    if [ ! -f "$IPFS_REPO/config" ]; then
        IPFS_NEEDS_INIT=1
    fi
else
    # Resolve the repo exactly the way kubo does: IPFS_PATH when set and
    # non-empty, else $HOME/.ipfs. Purely ambient here — the export above runs
    # only on the data-root path.
    IPFS_CLI_REPO="${IPFS_PATH:-$HOME/.ipfs}"

    # Guard, against the repo `ipfs init` would actually touch.
    if [ -d "$IPFS_CLI_REPO" ] && [ ! -f "$IPFS_CLI_REPO/config" ]; then
        err "$IPFS_CLI_REPO exists but contains no IPFS config file."
        if [ -n "${IPFS_PATH:-}" ]; then
            err "(That path comes from IPFS_PATH in your environment, which is where"
            err "'ipfs init' would run — not \$HOME/.ipfs.)"
        fi
        err "That is what an unmounted drive looks like — e.g. a USB/SSD mounted at"
        err "$IPFS_CLI_REPO that did not come up at boot."
        err ""
        err "Refusing to run 'ipfs init': it would mint a NEW PeerID and orphan every"
        err "IPNS record this station has published."
        err ""
        err "No IPFS repo has been created or modified. Pick the case that applies:"
        err "  - A drive belongs there: mount it and re-run this installer."
        err "    (check with: lsblk / mount / dmesg | tail)"
        if [ -n "${IPFS_PATH:-}" ]; then
            err "  - Wrong repo: point IPFS_PATH at the right one — or 'unset IPFS_PATH'"
            err "    to fall back to \$HOME/.ipfs — and re-run."
        fi
        err "  - This really is a stale empty directory and you WANT a brand-new"
        err "    station identity: remove it yourself, then re-run:"
        err "        rm -rf $IPFS_CLI_REPO"
        err "    Anything published under the old PeerID becomes unreachable."
        exit 1
    fi

    if [ "$IPFS_CLI_REPO" = "$IPFS_REPO" ]; then
        # The ordinary self-host case: the CLI and the systemd units agree.
        if [ ! -d "$IPFS_REPO" ]; then
            IPFS_NEEDS_INIT=1
        fi
    elif [ -f "$IPFS_REPO/config" ]; then
        # The units below pin IPFS_PATH=$IPFS_REPO, as every previous version of
        # this installer did, and that repo is already initialized — so the
        # station keeps the identity it has. Nothing to init; say plainly which
        # repo wins, because `ipfs` typed in this shell answers for the other one.
        warn "IPFS_PATH in your environment points at $IPFS_CLI_REPO,"
        warn "but the systemd services this installer writes run against $IPFS_REPO"
        warn "(unchanged from every previous version of this installer)."
        warn "Both repos are left alone; your station serves the identity in $IPFS_REPO."
        warn "To put the IPFS repo AND the station data on the other disk instead, re-run"
        warn "with the supported knob:  CIPHER_DATA_ROOT=<dir> ./install.sh"
        warn "  (that gives <dir>/ipfs for the repo and <dir>/station for station data)"
    else
        # Diverging AND the service repo is uninitialized: there is no reading of
        # this that the installer can act on safely.
        err "IPFS_PATH in your environment points at $IPFS_CLI_REPO, but the systemd"
        err "services this installer writes run against $IPFS_REPO, which holds no"
        err "IPFS repo."
        err ""
        err "Refusing to guess: 'ipfs init' would follow your environment and"
        err "initialize $IPFS_CLI_REPO, which the daemon never reads — while"
        err "initializing $IPFS_REPO instead would mint a SECOND station identity"
        err "beside the repo your environment already points at."
        err ""
        err "No IPFS repo has been created or modified. Choose one:"
        err "  - Run the station on $IPFS_CLI_REPO: re-run with"
        err "        CIPHER_DATA_ROOT=<dir> ./install.sh"
        err "    which uses <dir>/ipfs as the repo (and <dir>/station for station data)."
        err "  - Run the station on $IPFS_REPO:"
        err "        unset IPFS_PATH && ./install.sh"
        exit 1
    fi
fi

if [ -n "$IPFS_NEEDS_INIT" ]; then
    # Truthful on both paths now: the data-root path pinned IPFS_PATH itself, and
    # the legacy path only reaches here when the caller's environment resolves to
    # this very repo.
    info "Initializing IPFS with lowpower profile ($IPFS_REPO)..."
    ipfs init --profile=lowpower

    # Bind API to localhost only (security)
    ipfs config Addresses.API /ip4/127.0.0.1/tcp/5001
    ipfs config Addresses.Gateway /ip4/127.0.0.1/tcp/8080
    ok "IPFS initialized"
else
    ok "IPFS already initialized"
fi

# Applied on every run, not just first init, so bumping a hosting tier and
# re-running actually raises the cap. Unset leaves kubo's default untouched.
#
# Pinned to $IPFS_REPO explicitly rather than left bare: the systemd units below
# always run with IPFS_PATH=$IPFS_REPO, so that is the repo whose cap matters. A
# bare call would instead follow the caller's ambient IPFS_PATH, which on the
# divergent-repo path (warned about above) is a DIFFERENT repo the daemon never
# reads — silently capping the wrong datastore and leaving the real one uncapped.
if [ -n "$CIPHER_STORAGE_MAX" ]; then
    IPFS_PATH="$IPFS_REPO" ipfs config Datastore.StorageMax "$CIPHER_STORAGE_MAX"
    ok "IPFS datastore cap: $CIPHER_STORAGE_MAX ($IPFS_REPO)"
fi

# -----------------------------------------------------------
# 5. Python venv + dependencies
# -----------------------------------------------------------
info "Setting up Python virtual environment..."
if [ ! -d "$CIPHER_DIR/.venv" ]; then
    "$PYTHON" -m venv "$CIPHER_DIR/.venv"
fi
source "$CIPHER_DIR/.venv/bin/activate"

pip install --quiet --upgrade pip
# Includes the post-quantum libs kyber-py (ML-KEM-768) and dilithium-py (ML-DSA-65).
# Both are pure-Python and ship on piwheels, so no compiler/native build is needed on a Pi.
pip install --quiet -r "$CIPHER_DIR/requirements.txt"
ok "Python dependencies installed"

# -----------------------------------------------------------
# 5b. Restore from backup (optional, --restore)
#     Runs before identity bootstrap so the restored keys + IPFS peer identity
#     + pinned content are reinstated instead of generating a fresh station.
#     This runs BEFORE .env is written (step 6), so the restore destination
#     comes from the CIPHER_BASE_DIR exported near the top when
#     CIPHER_DATA_ROOT is set — otherwise from an existing .env, as before.
# -----------------------------------------------------------
RESTORED=""
if [ -n "$RESTORE_ARG" ]; then
    info "Restore mode: locating backup archive..."
    if [ "$RESTORE_ARG" = "auto" ]; then
        ARCHIVE="$(ls -t /media/${CIPHER_USER}/*/cipherstation-backup-*.tar.gz* \
                          /media/*/cipherstation-backup-*.tar.gz* \
                          /mnt/*/cipherstation-backup-*.tar.gz* 2>/dev/null | head -n1 || true)"
        if [ -z "$ARCHIVE" ]; then
            err "No backup archive found on a mounted USB drive (looked in /media and /mnt)."
            exit 1
        fi
    else
        ARCHIVE="$RESTORE_ARG"
    fi
    if [ ! -f "$ARCHIVE" ]; then
        err "Backup archive not found: $ARCHIVE"
        exit 1
    fi
    info "Restoring from: $ARCHIVE"
    if printf '%s' "$ARCHIVE" | grep -q '\.enc$'; then
        read -rsp "Backup passphrase: " _BK_PASS; echo
        IPFS_PATH="$IPFS_REPO" "$CIPHER_DIR/.venv/bin/python" -m cipher_station.backup \
            restore --archive "$ARCHIVE" --force --passphrase "$_BK_PASS"
        unset _BK_PASS
    else
        IPFS_PATH="$IPFS_REPO" "$CIPHER_DIR/.venv/bin/python" -m cipher_station.backup \
            restore --archive "$ARCHIVE" --force
    fi
    RESTORED=1
    ok "Restore complete: identity, data, and pinned content reinstated"
fi

# -----------------------------------------------------------
# 6. Environment config
#
# The heredoc below is QUOTED (<<'ENVFILE'), so the shell expands nothing
# inside it — that is deliberate, the block is a literal template. The two
# values that must differ per-install are emitted as __TOKEN__ placeholders and
# substituted with sed right after, using '#' as the sed delimiter so absolute
# paths (full of '/') need no escaping.
# -----------------------------------------------------------
if [ -n "$CIPHER_DATA_ROOT" ]; then
    ENV_BASE_DIR="$STATION_DATA"
else
    # Unchanged from every previous install: a project-relative data dir
    # (config.py resolves it against the repo, not the cwd, so moving the repo
    # still works).
    ENV_BASE_DIR="./cipher_station_data"
fi

# BACKUP DESTINATION POLICY — blank on BOTH paths, deliberately.
#
# backup.py refuses any destination that resolves onto the SAME MOUNT POINT as
# the live station data: a backup on the same disk protects against nothing
# (one disk dies, both die), and on a hosted box it would drop unencrypted
# private keys onto the customer's own data volume. That guard also covers the
# sibling case (<data-root>/backups next to <data-root>/station).
#
# Because the guard makes auto-detect safe, blank is the right value everywhere:
#   blank == "use a removable drive if one is plugged in, otherwise do nothing".
#   - Pi:     BASE_DIR is on the root fs, a USB at /media/<user>/X is a
#             DIFFERENT mount -> still allowed, the USB workflow keeps working.
#   - Hosted: /mnt/cipher-data/backups is the SAME mount as the station data
#             -> refused by backup.py. Nothing to hand-configure here, and
#             naming a path the installer never creates only breaks `create`.
ENV_BACKUP_DEST=""

if [ ! -f "$CIPHER_DIR/.env" ]; then
    cat > "$CIPHER_DIR/.env" <<'ENVFILE'
# Cipher Station Configuration

# --- Identity ---
# Password for encrypting the station private key (leave empty for no encryption)
CIPHER_PASSWORD=

# --- Post-quantum backend ---
# auto   = use the constant-time liboqs backend if installed, else pure-Python (default)
# liboqs = require the hardened liboqs backend (pip install oqs; needs cmake + compiler)
# python = force pure-Python kyber-py/dilithium-py (no native build)
CIPHER_PQC_BACKEND=auto

# --- Server ---
CIPHER_PORT=8443
CIPHER_HOST=0.0.0.0

# --- TLS ---
# Auto-generated on first run if missing.
# These are used verbatim (config.py does not resolve them against
# CIPHER_BASE_DIR), so they track the data dir explicitly.
SSL_CERTFILE=__CIPHER_STATION_DATA__/ssl/cert.pem
SSL_KEYFILE=__CIPHER_STATION_DATA__/ssl/key.pem

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

# --- Follow requests ---
# Inbound /inbox follow requests are UNAUTHENTICATED. By default they are
# recorded as "Pending" and grant NO access until you approve them
# (POST /followers/approve). Set to 1 ONLY in a dev environment to auto-accept
# follow requests and immediately grant content access — never in production.
CIPHER_DEV_AUTO_ACCEPT_FOLLOWS=0

# --- Device pairing brute-force limits ---
# Global throttle on /delegate/confirm so the 6-digit PIN can't be brute-forced
# by cycling unauthenticated pairing sessions. Tune only if you understand the
# trade-off (a guess flood can briefly lock out legitimate pairing).
# CIPHER_PAIRING_MAX_FAILURES=25
# CIPHER_PAIRING_LOCKOUT_WINDOW=900
# CIPHER_PAIRING_MAX_PENDING_SESSIONS=20

# --- Logging ---
# DEBUG, INFO, WARNING, ERROR
LOG_LEVEL=INFO

# --- Cloudflare Tunnel ---
# Enable Cloudflare Quick Tunnel for public access (no account needed)
CLOUDFLARE_TUNNEL_ENABLED=false
# Metrics port for cloudflared (used to detect tunnel URL)
CLOUDFLARE_METRICS_PORT=40469

# --- Backup ---
# Destination directory for `cipher_station.backup create` and the scheduled
# cipherstation-backup.timer. Leave blank to auto-detect a single mounted USB drive
# under /media/<user>. Set to a fixed mount point to be explicit.
#
# SECURITY: whatever you put here, backup.py REFUSES any destination that lands
# on the same mount point as CIPHER_BASE_DIR below. A backup on the same disk as
# the live data protects against nothing, and it would leave an unencrypted copy
# of the station's private keys next to the originals. That also rules out the
# obvious-looking sibling directory (<data-root>/backups). Point this at a
# genuinely separate disk, or leave it blank and plug in a removable drive.
CIPHER_BACKUP_DEST=__CIPHER_BACKUP_DEST__

# --- Data ---
# Where the station stores keys, the database, manifests, and public.json.
# Relative paths are resolved against the project directory (where run.py lives),
# NOT the current working directory — so "./cipher_station_data" always means
# "<project>/cipher_station_data" regardless of how the service is launched.
# Set an absolute path here to store data elsewhere (e.g. /var/lib/cipher station).
CIPHER_BASE_DIR=__CIPHER_STATION_DATA__
ENVFILE
    sed -i "s#__CIPHER_STATION_DATA__#${ENV_BASE_DIR}#g; s#__CIPHER_BACKUP_DEST__#${ENV_BACKUP_DEST}#g" "$CIPHER_DIR/.env"
    ok "Created .env with defaults (edit as needed)"
else
    ok ".env already exists"
    # An existing .env is never rewritten, so these are two INDEPENDENT checks
    # with DIFFERENT conditions. Folding the backup-dest check into the base-dir
    # condition hid it from exactly the installs that needed it: a box already
    # carrying the correct CIPHER_BASE_DIR matched the grep and skipped the whole
    # block. Nesting it under CIPHER_DATA_ROOT hid it from the other half — a
    # self-host/Pi upgrade whose .env still names a backup directory that no
    # longer exists is exactly as broken, and gets no warning from a hosted-only
    # check.

    # (a) CIPHER_BASE_DIR — hosted only. A box installed without
    # CIPHER_DATA_ROOT and re-run with it would keep its old value: systemd
    # would point IPFS at the volume while the station kept writing keys and the
    # database to the old location. Warn rather than silently editing someone's
    # config.
    if [ -n "$CIPHER_DATA_ROOT" ]; then
        if ! grep -q "^CIPHER_BASE_DIR=${STATION_DATA}\$" "$CIPHER_DIR/.env"; then
            warn "Existing .env does not point CIPHER_BASE_DIR at ${STATION_DATA}."
            warn "Station data will stay wherever that .env says — NOT on ${CIPHER_DATA_ROOT}."
            warn "Edit ${CIPHER_DIR}/.env by hand, then: sudo systemctl restart cipherstation"
            warn "  CIPHER_BASE_DIR=${STATION_DATA}"
            warn "  SSL_CERTFILE=${STATION_DATA}/ssl/cert.pem"
            warn "  SSL_KEYFILE=${STATION_DATA}/ssl/key.pem"
        fi
    fi

    # (b) CIPHER_BACKUP_DEST — checked on EVERY upgrade, hosted or not. Blank is
    # CORRECT and stays silent (auto-detect can no longer select the data volume
    # — backup.py refuses same-mount destinations). What needs surfacing is a
    # non-blank value that cannot work: one on the data volume itself (hosted
    # only, since that is the only path with a data volume), or one pointing at a
    # directory nothing ever created — such as the /mnt/cipher-backup that
    # earlier revisions of this installer wrote onto Pi/self-host boxes too.
    _bk_dest="$(grep -m1 '^CIPHER_BACKUP_DEST=' "$CIPHER_DIR/.env" 2>/dev/null | cut -d= -f2- || true)"
    # systemd reads this file as an EnvironmentFile, where "quoted values" are
    # legal, so strip one layer of surrounding quotes before testing the path.
    case "$_bk_dest" in
        \"*\") _bk_dest="${_bk_dest#\"}"; _bk_dest="${_bk_dest%\"}" ;;
        \'*\') _bk_dest="${_bk_dest#\'}"; _bk_dest="${_bk_dest%\'}" ;;
    esac
    if [ -n "$_bk_dest" ]; then
        # Tested separately rather than as a case pattern: with CIPHER_DATA_ROOT
        # unset, "$CIPHER_DATA_ROOT"/* would collapse to the pattern /* and match
        # every absolute path.
        _bk_on_data_root=""
        if [ -n "$CIPHER_DATA_ROOT" ]; then
            case "$_bk_dest" in
                "$CIPHER_DATA_ROOT"|"$CIPHER_DATA_ROOT"/*) _bk_on_data_root=1 ;;
            esac
        fi
        if [ -n "$_bk_on_data_root" ]; then
            warn "Existing .env sets CIPHER_BACKUP_DEST=${_bk_dest}, which is on the"
            warn "data volume (${CIPHER_DATA_ROOT}) — the same mount as the live station data."
            warn "backup.py refuses that: one disk dies and both copies die with it."
            warn "Point it at a genuinely separate disk, or blank it out in ${CIPHER_DIR}/.env:"
            warn "  CIPHER_BACKUP_DEST="
        elif [ ! -d "$_bk_dest" ]; then
            warn "Existing .env sets CIPHER_BACKUP_DEST=${_bk_dest}, but that directory"
            warn "does not exist — every backup run will fail until it is mounted."
            warn "Mount a separate disk there, or blank it out in ${CIPHER_DIR}/.env:"
            warn "  CIPHER_BACKUP_DEST=      # auto-detect a removable drive instead"
        fi
        unset _bk_on_data_root
    fi
    unset _bk_dest
fi

# Enable Cloudflare tunnel for fresh installs
if [ -z "${CF_SKIP}" ] && grep -q "CLOUDFLARE_TUNNEL_ENABLED=false" "$CIPHER_DIR/.env" 2>/dev/null; then
    sed -i 's/CLOUDFLARE_TUNNEL_ENABLED=false/CLOUDFLARE_TUNNEL_ENABLED=true/' "$CIPHER_DIR/.env"
    ok "Cloudflare tunnel enabled in .env"
fi

# -----------------------------------------------------------
# 7. Bootstrap identity (first run)
# -----------------------------------------------------------
if [ -n "$RESTORED" ]; then
    ok "Identity restored from backup (skipping fresh bootstrap)"
else
    info "Bootstrapping identity..."
    "$CIPHER_DIR/.venv/bin/python" -c "
import sys; sys.path.insert(0, '$CIPHER_DIR')
from cipher_station.identity import load_identity
load_identity()
print('Identity ready')
"
    ok "Identity bootstrapped"
fi

# -----------------------------------------------------------
# 8. Systemd: IPFS service
# -----------------------------------------------------------
info "Creating systemd services..."

# REBOOT SAFETY: hosted volumes are mounted with 'nofail', so a volume that
# fails to attach would otherwise let kubo start against an empty path, re-init,
# and mint a BRAND NEW PeerID — orphaning every IPNS record the station ever
# published. RequiresMountsFor makes systemd refuse to start these units until
# the mount is actually there.
#
# The value carries its own leading newline and is appended to an existing
# [Unit] line, so with CIPHER_DATA_ROOT unset the line disappears entirely
# (not merely goes blank) and self-host units stay byte-for-byte as before.
MOUNT_REQ=""
if [ -n "$CIPHER_DATA_ROOT" ]; then
    MOUNT_REQ=$'\n'"RequiresMountsFor=${CIPHER_DATA_ROOT}"
fi

sudo tee /etc/systemd/system/ipfs.service > /dev/null <<UNIT
[Unit]
Description=IPFS Daemon
After=network.target${MOUNT_REQ}

[Service]
Type=simple
User=${CIPHER_USER}
Environment="IPFS_PATH=${IPFS_REPO}"
ExecStart=/usr/local/bin/ipfs daemon --enable-gc
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT

# -----------------------------------------------------------
# 9. Systemd: Cipher Station service
# -----------------------------------------------------------
sudo tee /etc/systemd/system/cipherstation.service > /dev/null <<UNIT
[Unit]
Description=Cipher Station
After=ipfs.service network.target
Requires=ipfs.service${MOUNT_REQ}

[Service]
Type=simple
User=${CIPHER_USER}
WorkingDirectory=${CIPHER_DIR}
EnvironmentFile=${CIPHER_DIR}/.env
ExecStart=${CIPHER_DIR}/.venv/bin/python ${CIPHER_DIR}/run.py
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
After=cipherstation.service
Requires=cipherstation.service

[Service]
Type=simple
User=${CIPHER_USER}
ExecStart=/usr/local/bin/cloudflared tunnel --url https://localhost:${CIPHER_PORT} --no-tls-verify --metrics localhost:40469
Restart=on-failure
RestartSec=30
StartLimitIntervalSec=300
StartLimitBurst=5

[Install]
WantedBy=multi-user.target
UNIT

fi

# -----------------------------------------------------------
# 10b. Systemd: scheduled USB backup (oneshot service + daily timer)
# -----------------------------------------------------------
sudo tee /etc/systemd/system/cipherstation-backup.service > /dev/null <<UNIT
[Unit]
Description=Cipher Station Backup
After=ipfs.service cipherstation.service
Wants=ipfs.service${MOUNT_REQ}

[Service]
Type=oneshot
User=${CIPHER_USER}
WorkingDirectory=${CIPHER_DIR}
EnvironmentFile=${CIPHER_DIR}/.env
Environment="IPFS_PATH=${IPFS_REPO}"
# --if-present makes this a no-op (exit 0) when no USB drive is mounted.
ExecStart=${CIPHER_DIR}/.venv/bin/python -m cipher_station.backup create --if-present
UNIT

sudo tee /etc/systemd/system/cipherstation-backup.timer > /dev/null <<UNIT
[Unit]
Description=Daily Cipher Station Backup

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
UNIT

sudo systemctl daemon-reload

# -----------------------------------------------------------
# 11. Firewall
# -----------------------------------------------------------
info "Configuring firewall..."
configure_firewall

# -----------------------------------------------------------
# 12. Enable and start services
# -----------------------------------------------------------
info "Starting services..."
sudo systemctl enable ipfs.service cipherstation.service
# Hosted re-runs use restart, not start: a re-run is how a tier upgrade lands,
# and kubo only reads Datastore.StorageMax (and systemd only re-reads a rewritten
# unit) at start. `start` on an already-running daemon would silently no-op.
# Self-host installs keep the original `start` so a re-run never bounces a live
# station.
SVC_START="start"
if [ -n "$CIPHER_DATA_ROOT" ]; then SVC_START="restart"; fi
sudo systemctl "$SVC_START" ipfs.service
sleep 3  # give IPFS a moment to start
sudo systemctl "$SVC_START" cipherstation.service

# Enable the daily backup timer (no-ops when no USB drive is present).
# Hosted installs get it actively DISABLED, not merely "not enabled": the unit
# above is rewritten and daemon-reloaded on every run, so on a box where the
# timer was already enabled it would keep firing daily while this installer
# claimed otherwise. There is nothing safe for it to write to — the data volume
# is the same mount as the live data, which backup.py refuses.
if [ -n "$CIPHER_DATA_ROOT" ]; then
    sudo systemctl disable --now cipherstation-backup.timer 2>/dev/null || true
    warn "Scheduled backups DISABLED (no separate backup disk on this box)."
    warn "The unit still exists. To turn it on, attach a disk on a DIFFERENT mount"
    warn "from ${CIPHER_DATA_ROOT}, set CIPHER_BACKUP_DEST to it in ${CIPHER_DIR}/.env, then:"
    warn "  sudo systemctl enable --now cipherstation-backup.timer"
else
    sudo systemctl enable cipherstation-backup.timer 2>/dev/null || true
    sudo systemctl start cipherstation-backup.timer 2>/dev/null || true
fi

if [ -f /etc/systemd/system/cloudflared-tunnel.service ]; then
    sudo systemctl enable cloudflared-tunnel.service
    sleep 2  # give cipher station a moment to bind
    sudo systemctl start cloudflared-tunnel.service
fi

# -----------------------------------------------------------
# Done
# -----------------------------------------------------------
echo ""
ok "============================================"
ok "  Cipher Station installed successfully!"
ok "============================================"
echo ""
info "Services:"
echo "  IPFS:       $(systemctl is-active ipfs.service)"
echo "  Cipher Station:      $(systemctl is-active cipherstation.service)"
if systemctl is-enabled cloudflared-tunnel.service &>/dev/null; then
    echo "  Tunnel:     $(systemctl is-active cloudflared-tunnel.service)"
fi
echo ""

# Show IPFS peer ID (the station's permanent address). IPFS_PATH is pinned to
# the repo the SERVICES use, which is what this banner claims to report — a bare
# `ipfs id` follows the caller's ambient IPFS_PATH and would print the identity
# of some other repo. Identical to the old bare call whenever IPFS_PATH is unset
# (kubo's own default is $HOME/.ipfs) or already pinned by the data-root path.
PEER_ID=$(IPFS_PATH="$IPFS_REPO" ipfs id -f='<id>' 2>/dev/null || echo "unknown")
info "Your IPFS Peer ID (permanent station address):"
echo "  $PEER_ID"
echo ""
info "Followers can discover your station via IPNS:"
echo "  https://ipfs.io/ipns/${PEER_ID}"
echo ""

info "Backup & restore (protects against microSD failure):"
if [ -n "$CIPHER_DATA_ROOT" ]; then
    # No USB on a hosted box, and a backup written anywhere under
    # ${CIPHER_DATA_ROOT} is on the same mount as the live data, which backup.py
    # refuses. Don't print a `backup create` line that cannot succeed as shown.
    echo "  A backup must land on a DIFFERENT disk from ${CIPHER_DATA_ROOT}."
    echo "  Same-mount destinations are refused: one disk dies, both copies die."
    echo "  1. Attach a separate volume and mount it (e.g. /mnt/cipher-backup)."
    echo "  2. Set CIPHER_BACKUP_DEST to that mount in ${CIPHER_DIR}/.env"
    echo "  3. Back up on demand:"
    echo "       ${CIPHER_DIR}/.venv/bin/python -m cipher_station.backup create"
    echo "     ...or turn the daily timer back on (it is DISABLED right now):"
    echo "       sudo systemctl enable --now cipherstation-backup.timer"
else
    echo "  Plug in a USB drive, then back up on demand:"
    echo "    ${CIPHER_DIR}/.venv/bin/python -m cipher_station.backup create"
    echo "  A daily backup also runs automatically when a USB drive is mounted (cipherstation-backup.timer)."
fi
echo "  Recover onto a fresh card/box with:"
echo "    ./install.sh --restore        # auto-detect a backup on a mounted USB"
echo "    ./install.sh --restore=/path/to/cipherstation-backup-*.tar.gz"
echo ""

if systemctl is-enabled cloudflared-tunnel.service &>/dev/null; then
    info "Your tunnel URL will appear in the Cipher Station logs within ~30 seconds:"
    echo "  sudo journalctl -u cipher station -f | grep 'Tunnel endpoint'"
    echo ""
    info "LAN access (direct):"
    echo "  https://$(hostname -I | awk '{print $1}'):${CIPHER_PORT}/health"
    echo ""
    info "Useful commands:"
    echo "  sudo systemctl status cipher station              # check status"
    echo "  sudo journalctl -u cipher station -f              # view logs"
    echo "  sudo journalctl -u cloudflared-tunnel -f  # tunnel logs"
    echo "  sudo systemctl restart cipher station             # restart"
    echo ""
    info "Next steps:"
    echo "  1. Edit .env to set CIPHER_PASSWORD"
    echo "  2. Your station is publicly reachable via Cloudflare tunnel (no port forwarding needed!)"
    echo "  3. Share your Peer ID with followers — they can always find you via IPNS"
    echo "  4. Connect your Cipher Station client app"
else
    info "Access your station:"
    echo "  https://$(hostname -I | awk '{print $1}'):${CIPHER_PORT}/health"
    echo ""
    info "Useful commands:"
    echo "  sudo systemctl status cipher station     # check status"
    echo "  sudo journalctl -u cipher station -f     # view logs"
    echo "  sudo systemctl restart cipher station    # restart"
    echo ""
    info "Next steps:"
    echo "  1. Edit .env to set CIPHER_PASSWORD and other config"
    echo "  2. Set up port forwarding on your router for port ${CIPHER_PORT}"
    echo "  3. Connect your Cipher Station client app"
fi
echo ""
