import os
import logging
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
# Anchor the data directory to the project itself (the folder containing
# install.sh / run.py, i.e. the parent of this package) rather than to the
# current working directory. This makes the station's data location stable no
# matter where the process is launched from or what systemd sets as the cwd.
#
#   - CIPHER_BASE_DIR unset            -> <project>/cipher_station_data
#   - CIPHER_BASE_DIR set (absolute)   -> used as-is
#   - CIPHER_BASE_DIR set (relative)   -> resolved against <project>, not cwd
PROJECT_ROOT = Path(__file__).resolve().parent.parent

_base_dir_env = os.getenv("CIPHER_BASE_DIR")
if _base_dir_env:
    _base = Path(_base_dir_env).expanduser()
    BASE_DIR = _base if _base.is_absolute() else (PROJECT_ROOT / _base).resolve()
else:
    BASE_DIR = PROJECT_ROOT / "cipher_station_data"

KEYS_DIR = BASE_DIR / "keys"
DB_PATH = BASE_DIR / "cipherstation.db"
PUBLIC_JSON_PATH = BASE_DIR / "public.json"
MANIFEST_DIR = BASE_DIR / "manifests"

# ---------------------------------------------------------------------------
# Identity
# ---------------------------------------------------------------------------
CIPHER_PASSWORD = os.getenv("CIPHER_PASSWORD", "")

# ---------------------------------------------------------------------------
# IPFS
# ---------------------------------------------------------------------------
IPFS_API = os.getenv("IPFS_API_URL", "http://127.0.0.1:5001")
IPFS_TIMEOUT = int(os.getenv("IPFS_TIMEOUT", "30"))
IPFS_MAX_RETRIES = int(os.getenv("IPFS_MAX_RETRIES", "3"))

# The node's own HTTP gateway. Both installers bind it to 127.0.0.1:8080 (never
# publicly exposed). GET /content/{cid} streams already-pinned bytes from here
# rather than from the API, because the gateway supplies Content-Length, honours
# HTTP Range, and implements `Cache-Control: only-if-cached` — which makes a
# local-only read enforceable (412 instead of a network fetch).
IPFS_GATEWAY = os.getenv("IPFS_GATEWAY_URL", "http://127.0.0.1:8080").rstrip("/")

# GET /fetch/{cid}: owner-authenticated retrieval of arbitrary CIDs through
# this node's own IPFS connection (bitswap/DHT), bypassing public gateways
# and their rate limits entirely. The route is ENABLED by default (it only
# serves the owner's own paired devices); the knobs that affect the node's
# footprint (pinning) default to the conservative side. See main.py for the
# route's threat model.
#   FETCH_ENABLED        — master switch. "true" (default) serves paired
#                          delegates; "false" turns the route into a plain 404.
#   FETCH_MAX_BYTES      — refuse objects larger than this (default 512 MB).
#                          Checked via `ipfs files stat` BEFORE any content
#                          blocks are pulled, so a delegate cannot fill the
#                          datastore by asking for something enormous.
#   FETCH_TIMEOUT        — seconds allowed for EACH of the two network waits
#                          (root resolution for the size check, then DHT walk
#                          + first byte of the stream). Default 120; a dead
#                          CID costs at most ~2x this, never a worker forever.
#   FETCH_MAX_CONCURRENT — how many /fetch requests may be in flight at once
#                          (default 4). Every fetch holds a threadpool worker
#                          for its whole DHT walk + stream; without a cap a
#                          handful of dead CIDs could starve every other
#                          route. Excess requests get 503 + Retry-After.
#   FETCH_PIN            — "true" to keep fetched content pinned locally
#                          (default "false": fetched blocks are cache, gc-able).
#                          Pinning happens AFTER the stream has been fully
#                          delivered, never on the request's critical path.
FETCH_ENABLED = os.getenv("CIPHER_FETCH_ENABLED", "true").lower() == "true"
FETCH_MAX_BYTES = int(os.getenv("CIPHER_FETCH_MAX_BYTES", str(512 * 1024 * 1024)))
FETCH_TIMEOUT = int(os.getenv("CIPHER_FETCH_TIMEOUT", "120"))
FETCH_MAX_CONCURRENT = int(os.getenv("CIPHER_FETCH_MAX_CONCURRENT", "4"))
FETCH_PIN = os.getenv("CIPHER_FETCH_PIN", "false").lower() == "true"

# ---------------------------------------------------------------------------
# Server
# ---------------------------------------------------------------------------
CIPHER_PORT = int(os.getenv("CIPHER_PORT", "8443"))
CIPHER_HOST = os.getenv("CIPHER_HOST", "0.0.0.0")

# Admin panel: its own uvicorn listener, ALWAYS bound to 127.0.0.1 (plain
# HTTP, no proxy-headers). Never exposed through the tunnel; remote access is
# an SSH tunnel (ssh -L 8444:localhost:8444 user@station).
CIPHER_PANEL_PORT = int(os.getenv("CIPHER_PANEL_PORT", "8444"))
CIPHER_PANEL_HOST = "127.0.0.1"
SSL_CERTFILE = os.getenv("SSL_CERTFILE", str(BASE_DIR / "ssl" / "cert.pem"))
SSL_KEYFILE = os.getenv("SSL_KEYFILE", str(BASE_DIR / "ssl" / "key.pem"))

# ---------------------------------------------------------------------------
# Limits
# ---------------------------------------------------------------------------
MAX_UPLOAD_SIZE = int(os.getenv("MAX_UPLOAD_SIZE", str(100 * 1024 * 1024)))  # 100 MB
CORS_ORIGINS = os.getenv("CORS_ORIGINS", "*").split(",")

# ---------------------------------------------------------------------------
# Cloudflare Tunnel
# ---------------------------------------------------------------------------
CLOUDFLARE_TUNNEL_ENABLED = os.getenv("CLOUDFLARE_TUNNEL_ENABLED", "false").lower() in ("true", "1", "yes")
CLOUDFLARE_METRICS_PORT = int(os.getenv("CLOUDFLARE_METRICS_PORT", "40469"))

# Permanent public URL (named tunnel / custom domain / static DNS). When set,
# it wins over quick-tunnel discovery: the tunnel monitor writes THIS value
# into public.json["endpoint"] and skips the cloudflared metrics polling.
# Leave unset to use the auto-detected trycloudflare.com quick-tunnel URL.
CIPHER_PUBLIC_URL = (os.getenv("CIPHER_PUBLIC_URL") or "").strip() or None

# ---------------------------------------------------------------------------
# Federation (peer pin replication) — consumer-side mirroring of other
# stations' already-published (public) manifests. Never decrypts anything,
# never needs a peer's secret key; see cipher_station/federation.py.
# ---------------------------------------------------------------------------
# Background sync interval, in seconds. 0 disables the background loop
# entirely (manual "sync now" via the panel still works).
CIPHER_FEDERATION_SYNC_INTERVAL_SECONDS = int(
    os.getenv("CIPHER_FEDERATION_SYNC_INTERVAL_SECONDS", "3600")
)

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s  %(name)-28s  %(levelname)-7s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def ensure_directories():
    KEYS_DIR.mkdir(parents=True, exist_ok=True)
    MANIFEST_DIR.mkdir(parents=True, exist_ok=True)
    BASE_DIR.mkdir(parents=True, exist_ok=True)
