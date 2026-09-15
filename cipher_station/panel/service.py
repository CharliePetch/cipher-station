# cipher_station/panel/service.py
"""
Status + configuration logic backing the admin panel (feature area A).

Everything here is read from / written through the SAME mechanisms the rest of
the station uses: public.json via storage.write_json under STATE_LOCK, the
IPFS daemon via ipfs_client, profile fields via profile.update_profile_fields,
and .env for process-level settings (rewritten atomically; changes that need a
restart are reported as such, never applied by stealth).
"""

import json
import logging
import os
import re
import subprocess
import time

import requests

from cipher_station import config as cfg
from cipher_station.config import PROJECT_ROOT

logger = logging.getLogger(__name__)

# Process start time — uptime of the station process (the panel runs inside it).
_STARTED_AT = time.time()

SIZE_RE = re.compile(r"(?i)^\s*\d+(\.\d+)?\s*[kmgt]?b\s*$")

ENV_PATH = PROJECT_ROOT / ".env"

# .env keys the panel may edit. Anything else in the file is preserved verbatim.
EDITABLE_ENV_KEYS = ("CLOUDFLARE_TUNNEL_ENABLED", "CIPHER_PUBLIC_URL")


# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------

def _git_commit() -> str | None:
    try:
        out = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=PROJECT_ROOT, capture_output=True, text=True, timeout=5,
        )
        return out.stdout.strip() or None if out.returncode == 0 else None
    except (OSError, subprocess.SubprocessError):
        return None


def _read_public_json() -> dict:
    try:
        return json.loads(cfg.PUBLIC_JSON_PATH.read_text())
    except Exception:
        return {}


def get_status() -> dict:
    """Everything the dashboard shows in one call."""
    pub = _read_public_json()

    ipfs = {"running": False}
    try:
        from cipher_station.ipfs_client import ipfs_repo_stat
        repo = ipfs_repo_stat()
        used = repo.get("RepoSize", 0)
        cap = repo.get("StorageMax", 0)
        ipfs = {
            "running": True,
            "repo_size_bytes": used,
            "storage_max_bytes": cap,
            "num_objects": repo.get("NumObjects", 0),
            "used_percent": round((used / cap) * 100, 2) if cap else 0,
        }
    except Exception as exc:
        ipfs["error"] = str(exc)

    from cipher_station.profile import PROFILE_CLIENT
    from cipher_station.manifest import get_client_profile
    try:
        profile = get_client_profile(client=PROFILE_CLIENT)
    except Exception:
        profile = {}

    return {
        "running": True,  # the panel answered, so the station is up
        "version": "1.0.0",
        "commit": _git_commit(),
        "uptime_seconds": int(time.time() - _STARTED_AT),
        "uid": pub.get("uid"),
        "peer_id": pub.get("ipfs_peer_id"),
        "ipns_name": pub.get("ipns_name"),
        "endpoint": pub.get("endpoint"),
        "manifest_pointer": pub.get("manifest_pointer"),
        "ipfs": ipfs,
        "profile": profile,
        # NOTE: pairing PINs are deliberately NOT exposed here — a leaked PIN
        # allows account takeover via /delegate/start. Read them from the
        # station log on the box itself.
        "tunnel": {
            "quick_tunnel_enabled": cfg.CLOUDFLARE_TUNNEL_ENABLED,
            "permanent_url": cfg.CIPHER_PUBLIC_URL,
        },
    }


# ---------------------------------------------------------------------------
# IPFS storage cap (Datastore.StorageMax — same mechanism the macOS tray uses,
# but over the HTTP API instead of shelling out to the ipfs CLI)
# ---------------------------------------------------------------------------

def get_storage_max() -> str | None:
    try:
        r = requests.post(
            f"{cfg.IPFS_API}/api/v0/config",
            params={"arg": "Datastore.StorageMax"},
            timeout=cfg.IPFS_TIMEOUT,
        )
        r.raise_for_status()
        return r.json().get("Value")
    except Exception as exc:
        logger.warning("Could not read Datastore.StorageMax: %s", exc)
        return None


def set_storage_max(value: str) -> None:
    """Set the IPFS repo cap. Raises ValueError on a bad size string."""
    value = (value or "").strip()
    if not SIZE_RE.match(value):
        raise ValueError("Storage cap must look like 10GB, 50GB or 500GB")
    # kubo's config-set repeats the "arg" key: arg=<key>&arg=<value>.
    r = requests.post(
        f"{cfg.IPFS_API}/api/v0/config",
        params=[("arg", "Datastore.StorageMax"), ("arg", value)],
        timeout=cfg.IPFS_TIMEOUT,
    )
    r.raise_for_status()


# ---------------------------------------------------------------------------
# Station config (.env-backed settings + station name)
# ---------------------------------------------------------------------------

def get_config() -> dict:
    from cipher_station.profile import PROFILE_CLIENT
    from cipher_station.manifest import get_client_profile
    pub = _read_public_json()
    return {
        "alias": pub.get("alias"),
        "profile": get_client_profile(client=PROFILE_CLIENT),
        "endpoint": pub.get("endpoint"),
        "cloudflare_tunnel_enabled": cfg.CLOUDFLARE_TUNNEL_ENABLED,
        "permanent_url": cfg.CIPHER_PUBLIC_URL,
        "ipfs_storage_max": get_storage_max(),
        "restart_command": "sudo systemctl restart cipherstation",
        "ipfs_restart_command": "sudo systemctl restart ipfs",
    }


def set_alias(alias: str | None) -> dict:
    """Station display name — stored as public.json['alias'], atomically."""
    from cipher_station.storage import write_json, STATE_LOCK
    if alias is not None:
        alias = alias.strip() or None
        if alias and len(alias) > 80:
            raise ValueError("alias must be <= 80 characters")
    with STATE_LOCK:
        if not cfg.PUBLIC_JSON_PATH.exists():
            raise ValueError("public.json not found — station identity missing")
        obj = json.loads(cfg.PUBLIC_JSON_PATH.read_text())
        obj["alias"] = alias
        write_json(cfg.PUBLIC_JSON_PATH, obj)
    from cipher_station.ipns_publisher import request_publish
    request_publish()
    return {"alias": alias}


_URL_RE = re.compile(r"^https?://[A-Za-z0-9.-]+(:\d+)?(/.*)?$")


def update_env_settings(*, cloudflare_tunnel_enabled: bool | None = None,
                        permanent_url: str | None = None,
                        clear_permanent_url: bool = False) -> dict:
    """
    Update the panel-editable subset of .env, atomically (temp + rename).
    Returns {"changed": [...], "restart_required": bool}. These settings are
    read at process start, so changes take effect after a station restart —
    the panel surfaces the exact systemctl command instead of restarting
    anything itself.
    """
    changes: dict[str, str | None] = {}
    if cloudflare_tunnel_enabled is not None:
        changes["CLOUDFLARE_TUNNEL_ENABLED"] = "true" if cloudflare_tunnel_enabled else "false"
    if clear_permanent_url:
        changes["CIPHER_PUBLIC_URL"] = None
    elif permanent_url is not None:
        permanent_url = permanent_url.strip()
        if permanent_url and not _URL_RE.match(permanent_url):
            raise ValueError("permanent_url must be a http(s):// URL")
        changes["CIPHER_PUBLIC_URL"] = permanent_url or None

    if not changes:
        return {"changed": [], "restart_required": False}

    _rewrite_env(changes)
    return {"changed": sorted(changes), "restart_required": True,
            "restart_command": "sudo systemctl restart cipherstation"}


def _rewrite_env(changes: dict[str, str | None]) -> None:
    """Apply key changes to .env, preserving every other line, atomically."""
    import tempfile

    lines: list[str] = []
    if ENV_PATH.exists():
        lines = ENV_PATH.read_text().splitlines()

    remaining = dict(changes)
    out: list[str] = []
    for line in lines:
        stripped = line.strip()
        key = stripped.split("=", 1)[0].strip() if "=" in stripped and not stripped.startswith("#") else None
        if key in remaining:
            value = remaining.pop(key)
            if value is not None:
                out.append(f"{key}={value}")
            # None -> drop the line (unset)
        else:
            out.append(line)
    for key, value in remaining.items():
        if value is not None:
            out.append(f"{key}={value}")

    content = "\n".join(out) + ("\n" if out else "")
    fd, tmp = tempfile.mkstemp(prefix=".env.", suffix=".tmp", dir=ENV_PATH.parent)
    try:
        with os.fdopen(fd, "w") as f:
            f.write(content)
        os.replace(tmp, ENV_PATH)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


# ---------------------------------------------------------------------------
# Federation (peer pin replication) — thin glue over cipher_station.federation.
# The panel API layer (router.py) only ever calls through here, same as every
# other feature area in this file.
# ---------------------------------------------------------------------------

def federation_status() -> dict:
    from cipher_station import federation
    return federation.get_status()


def federation_add_peer(peer_id: str, label: str | None, quota_gb: float) -> dict:
    from cipher_station import federation
    return federation.add_peer(peer_id, label, quota_gb)


def federation_remove_peer(peer_id: str) -> dict:
    from cipher_station import federation
    return federation.remove_peer(peer_id)


def federation_sync_all() -> list[dict]:
    from cipher_station import federation
    return federation.sync_all()


def federation_sync_peer(peer_id: str) -> dict:
    from cipher_station import federation
    return federation.sync_peer(peer_id)
