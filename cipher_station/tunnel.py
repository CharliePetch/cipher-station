# cipher_station/tunnel.py
#
# Cloudflare Quick Tunnel detection + IPNS endpoint publishing.
#
# On startup, spawns a daemon thread that:
#   1. Polls cloudflared's metrics endpoint to discover the tunnel URL
#   2. Writes the URL into public.json["endpoint"]
#   3. Publishes public.json to IPFS and the CID to IPNS
#   4. Re-checks every 60s to detect URL changes (e.g., after cloudflared restart)

import json
import logging
import threading
import time

import requests

from cipher_station.config import (
    CLOUDFLARE_TUNNEL_ENABLED,
    CLOUDFLARE_METRICS_PORT,
    PUBLIC_JSON_PATH,
)

logger = logging.getLogger(__name__)

_METRICS_URL = f"http://localhost:{CLOUDFLARE_METRICS_PORT}/quicktunnel"

# Phase 1: rapid polling to detect initial tunnel URL
_INITIAL_DELAY = 5       # seconds before first poll
_POLL_INTERVAL = 3       # seconds between rapid polls
_MAX_ATTEMPTS = 40       # ~2 minutes of rapid polling

# Phase 2: periodic re-check interval
_RECHECK_INTERVAL = 60   # seconds


def _fetch_tunnel_hostname() -> str | None:
    """
    Query cloudflared's metrics endpoint for the quick tunnel hostname.
    Returns the full URL (e.g., "https://verb-noun-thing.trycloudflare.com")
    or None if not yet available.
    """
    try:
        resp = requests.get(_METRICS_URL, timeout=5)
        resp.raise_for_status()
        hostname = resp.json().get("hostname")
        if hostname:
            return f"https://{hostname}"
    except Exception as exc:
        logger.debug("Tunnel metrics not yet available: %s", exc)
    return None


def _update_endpoint(endpoint_url: str) -> None:
    """
    Write the tunnel URL into public.json["endpoint"], then publish
    the updated public.json to IPFS and update the IPNS pointer.

    Follows the same read-modify-write pattern as manifest.py and graph.py.
    Skips all writes if the endpoint hasn't changed.
    """
    # --- Read current public.json ---
    try:
        if PUBLIC_JSON_PATH.exists():
            obj = json.loads(PUBLIC_JSON_PATH.read_text())
        else:
            obj = {}
    except Exception as exc:
        logger.error("Failed to read public.json: %s", exc)
        obj = {}

    old_endpoint = obj.get("endpoint")
    if old_endpoint == endpoint_url:
        logger.debug("Tunnel endpoint unchanged, skipping update")
        return

    # --- Write updated endpoint ---
    obj["endpoint"] = endpoint_url
    PUBLIC_JSON_PATH.write_text(json.dumps(obj, indent=2))
    logger.info("Tunnel endpoint updated in public.json: %s", endpoint_url)

    # --- Publish to IPFS + IPNS ---
    from cipher_station.ipfs_client import publish_public_json_to_ipns
    publish_public_json_to_ipns()


def _poll_and_update():
    """
    Background worker: detects the tunnel URL and keeps it up to date.

    Phase 1: Rapid polling every 3s until the tunnel URL is found (~2 min max).
    Phase 2: Periodic re-check every 60s to detect URL changes on cloudflared restart.
    """
    time.sleep(_INITIAL_DELAY)

    # Phase 1: initial detection
    for attempt in range(1, _MAX_ATTEMPTS + 1):
        url = _fetch_tunnel_hostname()
        if url:
            _update_endpoint(url)
            break
        logger.debug("Tunnel poll attempt %d/%d...", attempt, _MAX_ATTEMPTS)
        time.sleep(_POLL_INTERVAL)
    else:
        logger.warning(
            "Cloudflare tunnel not detected after %d attempts. "
            "Will continue checking periodically.",
            _MAX_ATTEMPTS,
        )

    # Phase 2: periodic re-check for URL changes
    while True:
        time.sleep(_RECHECK_INTERVAL)
        url = _fetch_tunnel_hostname()
        if url:
            _update_endpoint(url)  # no-op if unchanged


def start_tunnel_monitor():
    """
    Called from the FastAPI startup hook.
    Spawns a daemon thread that monitors the Cloudflare tunnel URL
    and keeps public.json + IPNS in sync.
    """
    if not CLOUDFLARE_TUNNEL_ENABLED:
        logger.info("Cloudflare tunnel disabled (CLOUDFLARE_TUNNEL_ENABLED != true)")
        return

    logger.info("Starting Cloudflare tunnel monitor...")
    t = threading.Thread(target=_poll_and_update, daemon=True, name="tunnel-monitor")
    t.start()
