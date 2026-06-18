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
#   - ORBIT_BASE_DIR unset            -> <project>/orbit_data
#   - ORBIT_BASE_DIR set (absolute)   -> used as-is
#   - ORBIT_BASE_DIR set (relative)   -> resolved against <project>, not cwd
PROJECT_ROOT = Path(__file__).resolve().parent.parent

_base_dir_env = os.getenv("ORBIT_BASE_DIR")
if _base_dir_env:
    _base = Path(_base_dir_env).expanduser()
    BASE_DIR = _base if _base.is_absolute() else (PROJECT_ROOT / _base).resolve()
else:
    BASE_DIR = PROJECT_ROOT / "orbit_data"

KEYS_DIR = BASE_DIR / "keys"
DB_PATH = BASE_DIR / "orbit.db"
PUBLIC_JSON_PATH = BASE_DIR / "public.json"
MANIFEST_DIR = BASE_DIR / "manifests"

# ---------------------------------------------------------------------------
# Identity
# ---------------------------------------------------------------------------
ORBIT_PASSWORD = os.getenv("ORBIT_PASSWORD", "")

# ---------------------------------------------------------------------------
# IPFS
# ---------------------------------------------------------------------------
IPFS_API = os.getenv("IPFS_API_URL", "http://127.0.0.1:5001")
IPFS_TIMEOUT = int(os.getenv("IPFS_TIMEOUT", "30"))
IPFS_MAX_RETRIES = int(os.getenv("IPFS_MAX_RETRIES", "3"))

# ---------------------------------------------------------------------------
# Server
# ---------------------------------------------------------------------------
ORBIT_PORT = int(os.getenv("ORBIT_PORT", "8443"))
ORBIT_HOST = os.getenv("ORBIT_HOST", "0.0.0.0")
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
