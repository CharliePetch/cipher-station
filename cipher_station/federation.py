# cipher_station/federation.py
"""
Federation (peer pin replication) — consumer-side mirroring.

Given a list of peer IPFS peer IDs and a per-peer disk quota, periodically
resolve each peer's IPNS record, walk their PUBLISHED manifest (already
public per PROTOCOL.md sections 8/17.3/18.5), and pin their content (post
blobs + envelope documents, as opaque ciphertext) locally, up to that peer's
quota. This gives mutual encrypted backup between stations: each station
holds ciphertext copies of the others' content without ever being able to
decrypt it.

Hard guarantee: this module NEVER decrypts anything and NEVER needs a peer's
secret key. It only ever calls IPFS resolve/get/pin/unpin operations on
opaque CIDs already present in a peer's own public manifest. If a change here
ever needs a peer's private key material, that is a protocol violation —
stop and flag it, do not build around it.

Reuses the existing IPFS HTTP client wrapper (cipher_station/ipfs_client.py)
for every network operation:
  - ipfs_name_resolve   — IPNS peer id -> /ipfs/<cid> (already existed;
                          used by the station's own discovery code paths)
  - ipfs_get_bytes      — fetch public.json / manifest / envelopes JSON
  - ipfs_object_stat    — cumulative size of a CID (already existed; same
                          helper /storage and /fetch use for size gating)
  - ipfs_pin_add        — recursive pin
  - ipfs_unpin          — recursive unpin
No second IPFS HTTP client is created here.
"""

import json
import logging
import re
import threading
import time

from cipher_station.config import BASE_DIR
from cipher_station.storage import write_json, STATE_LOCK
from cipher_station.ipfs_client import (
    IPFSError,
    ipfs_get_bytes,
    ipfs_name_resolve,
    ipfs_object_stat,
    ipfs_pin_add,
    ipfs_unpin,
)

logger = logging.getLogger(__name__)

FEDERATION_PATH = BASE_DIR / "federation.json"
FEDERATION_STATE_PATH = BASE_DIR / "federation_state.json"

# Loose libp2p peer id shape check: base58btc (Qm..., 12D3Koo...) and base36
# CIDv1 peer ids are all plain alphanumeric. Not a real multihash/CID decode
# — deliberately cheap, per the spec ("do not over-engineer libp2p id
# parsing"). Long enough to reject obvious junk, short enough not to reject
# a real peer id.
_PEER_ID_RE = re.compile(r"^[A-Za-z0-9]{20,128}$")


def _is_plausible_peer_id(peer_id) -> bool:
    return isinstance(peer_id, str) and bool(_PEER_ID_RE.match(peer_id))


# ---------------------------------------------------------------------------
# federation.json — configured peers
# ---------------------------------------------------------------------------

def _load_peers_doc() -> dict:
    if FEDERATION_PATH.exists():
        try:
            obj = json.loads(FEDERATION_PATH.read_text())
            if isinstance(obj, dict) and isinstance(obj.get("peers"), list):
                return obj
        except Exception as exc:
            logger.error("federation.json unreadable, treating as empty: %s", exc)
    return {"peers": []}


def list_peers() -> list[dict]:
    """Configured peers: [{peer_id, label, quota_bytes}, ...]."""
    return _load_peers_doc()["peers"]


def add_peer(peer_id: str, label: str | None = None, quota_gb: float = 0.0) -> dict:
    """
    Add (or update, if peer_id already exists) a federation peer. Idempotent
    by peer_id: re-adding updates label/quota rather than duplicating.
    Written atomically (temp file + rename), same pattern as public.json.
    """
    if not _is_plausible_peer_id(peer_id):
        raise ValueError(f"not a plausible peer id: {peer_id!r}")
    try:
        quota_bytes = int(float(quota_gb) * 1024 ** 3)
    except (TypeError, ValueError):
        raise ValueError(f"quota_gb must be a number: {quota_gb!r}")
    if quota_bytes < 0:
        raise ValueError("quota_gb must be >= 0")

    label = (label or None)
    if label is not None:
        label = str(label).strip() or None

    entry = {"peer_id": peer_id, "label": label, "quota_bytes": quota_bytes}

    with STATE_LOCK:
        doc = _load_peers_doc()
        peers = doc["peers"]
        existing = next((p for p in peers if p.get("peer_id") == peer_id), None)
        if existing is not None:
            existing.update(entry)
        else:
            peers.append(entry)
        write_json(FEDERATION_PATH, doc)

    return entry


def remove_peer(peer_id: str) -> dict:
    """Remove a configured peer and drop its sync state. Idempotent."""
    with STATE_LOCK:
        doc = _load_peers_doc()
        before = len(doc["peers"])
        doc["peers"] = [p for p in doc["peers"] if p.get("peer_id") != peer_id]
        removed = before - len(doc["peers"])
        write_json(FEDERATION_PATH, doc)

        state = _load_state()
        if peer_id in state:
            state.pop(peer_id, None)
            _save_state(state)

    return {"peer_id": peer_id, "removed": removed > 0}


# ---------------------------------------------------------------------------
# federation_state.json — what we currently hold pinned per peer
# ---------------------------------------------------------------------------

def _load_state() -> dict:
    if FEDERATION_STATE_PATH.exists():
        try:
            obj = json.loads(FEDERATION_STATE_PATH.read_text())
            if isinstance(obj, dict):
                return obj
        except Exception as exc:
            logger.error("federation_state.json unreadable, treating as empty: %s", exc)
    return {}


def _save_state(state: dict) -> None:
    write_json(FEDERATION_STATE_PATH, state)


# ---------------------------------------------------------------------------
# Sync
# ---------------------------------------------------------------------------

def _candidate_cids(manifest: dict) -> list[str]:
    """
    Every CID a peer's manifest references, in manifest (oldest-first) order,
    deduplicated. Mirrors manifest.station_content_cids()'s post-scanning
    logic, but reads a REMOTE peer's manifest rather than our own.
    """
    cids: list[str] = []
    seen: set[str] = set()
    for bucket in (manifest.get("clients") or {}).values():
        if not isinstance(bucket, dict):
            continue
        for post in bucket.get("posts") or []:
            if not isinstance(post, dict):
                continue
            for key in ("post_cid", "envelopes_cid"):
                cid = post.get(key)
                if isinstance(cid, str) and cid and cid not in seen:
                    seen.add(cid)
                    cids.append(cid)
    return cids


def sync_peer(peer_id: str) -> dict:
    """
    Sync one peer: resolve their IPNS record, fetch public.json + manifest,
    unpin CIDs we hold that they no longer publish, then pin new CIDs
    (oldest-manifest-order first) until the next one would exceed the peer's
    quota_bytes. Already-pinned content is never evicted to make room for
    new content (this is a backup, not a cache).

    Never raises: any resolve/fetch failure is returned as
    {"error": "..."} in the summary dict, exactly like a quota-stop or an
    individual pin/stat failure — the caller (sync_all, the panel route)
    never needs to catch anything from this function.

    Only ever touches opaque CIDs via IPFS resolve/get/pin/unpin. Never
    imports or calls any envelope-opening/decryption function.
    """
    peer = next((p for p in list_peers() if p.get("peer_id") == peer_id), None)
    if peer is None:
        return {
            "peer_id": peer_id, "label": None, "pinned_count": 0,
            "pinned_bytes": 0, "quota_bytes": 0, "skipped_count": 0,
            "error": "peer not configured",
        }

    label = peer.get("label")
    quota_bytes = int(peer.get("quota_bytes", 0))

    try:
        path = ipfs_name_resolve(peer_id)  # "/ipfs/<cid>"
        pub_cid = path.rsplit("/", 1)[-1] if path else None
        if not pub_cid:
            raise IPFSError(f"unexpected name_resolve result: {path!r}")
        pub = json.loads(ipfs_get_bytes(pub_cid))
        manifest_cid = pub.get("manifest_pointer")
        if not manifest_cid:
            raise IPFSError("peer has not published a manifest_pointer yet")
        manifest = json.loads(ipfs_get_bytes(manifest_cid))
    except Exception as exc:
        logger.warning("federation sync_peer(%s): resolve/fetch failed: %s", peer_id, exc)
        return {
            "peer_id": peer_id, "label": label, "pinned_count": 0,
            "pinned_bytes": 0, "quota_bytes": quota_bytes, "skipped_count": 0,
            "error": f"resolve failed: {exc}",
        }

    candidate_cids = _candidate_cids(manifest)
    current_set = set(candidate_cids)

    with STATE_LOCK:
        state = _load_state()
        peer_state = dict(state.get(peer_id, {}))

        # --- Diff: unpin anything we hold for this peer that they no
        # longer publish. ---
        for old_cid in list(peer_state.keys()):
            if old_cid in current_set:
                continue
            try:
                ipfs_unpin(old_cid)
            except Exception as exc:
                logger.warning(
                    "federation sync_peer(%s): unpin failed for %s: %s",
                    peer_id, old_cid, exc,
                )
            peer_state.pop(old_cid, None)

        # --- Pin new CIDs, oldest-manifest-order first, stopping (never
        # evicting) once the next one would exceed quota. ---
        pinned_bytes = sum(v.get("size", 0) for v in peer_state.values())
        now = int(time.time())
        for cid in candidate_cids:
            if cid in peer_state:
                continue
            try:
                stat = ipfs_object_stat(cid, retry=False)
                size = int(stat.get("CumulativeSize", 0))
            except Exception as exc:
                logger.warning(
                    "federation sync_peer(%s): stat failed for %s: %s",
                    peer_id, cid, exc,
                )
                continue
            if pinned_bytes + size > quota_bytes:
                logger.info(
                    "federation sync_peer(%s): quota reached (%d/%d bytes), stopping",
                    peer_id, pinned_bytes, quota_bytes,
                )
                break
            try:
                ipfs_pin_add(cid)
            except Exception as exc:
                logger.warning(
                    "federation sync_peer(%s): pin failed for %s: %s",
                    peer_id, cid, exc,
                )
                continue
            peer_state[cid] = {"size": size, "pinned_at": now}
            pinned_bytes += size

        state[peer_id] = peer_state
        _save_state(state)

    skipped_count = sum(1 for cid in candidate_cids if cid not in peer_state)

    return {
        "peer_id": peer_id,
        "label": label,
        "pinned_count": len(peer_state),
        "pinned_bytes": pinned_bytes,
        "quota_bytes": quota_bytes,
        "skipped_count": skipped_count,
        "error": None,
    }


def sync_all() -> list[dict]:
    """Sync every configured peer. One peer's failure never aborts the rest."""
    results = []
    for peer in list_peers():
        peer_id = peer.get("peer_id")
        try:
            results.append(sync_peer(peer_id))
        except Exception as exc:
            # sync_peer is designed to never raise, but a broken peer must
            # never take the rest of the batch down even if it somehow does.
            logger.warning("federation sync_all: peer %s raised: %s", peer_id, exc)
            results.append({
                "peer_id": peer_id, "label": peer.get("label"),
                "pinned_count": 0, "pinned_bytes": 0,
                "quota_bytes": peer.get("quota_bytes", 0),
                "skipped_count": 0, "error": str(exc),
            })
    return results


def get_status() -> dict:
    """
    Cheap status read for the panel: configured peers + current pinned
    bytes/count/last-synced-at from federation_state.json. Never re-syncs.
    """
    state = _load_state()
    peers_status = []
    for peer in list_peers():
        peer_id = peer.get("peer_id")
        pstate = state.get(peer_id, {})
        pinned_bytes = sum(v.get("size", 0) for v in pstate.values())
        pinned_count = len(pstate)
        last_synced_at = max(
            (v.get("pinned_at", 0) for v in pstate.values()), default=None
        )
        peers_status.append({
            "peer_id": peer_id,
            "label": peer.get("label"),
            "quota_bytes": peer.get("quota_bytes", 0),
            "pinned_bytes": pinned_bytes,
            "pinned_count": pinned_count,
            "last_synced_at": last_synced_at,
        })
    return {"peers": peers_status}


# ---------------------------------------------------------------------------
# Background scheduler — same pattern as cipher_station/tunnel.py's monitor
# thread: a daemon thread started from FastAPI startup, sleeping between
# syncs. A federation sync failure is logged and never crashes the app.
# ---------------------------------------------------------------------------

def _federation_sync_loop(interval_seconds: int) -> None:
    while True:
        time.sleep(interval_seconds)
        try:
            results = sync_all()
        except Exception as exc:
            logger.warning("federation background sync_all failed: %s", exc)
            continue
        for r in results:
            if r.get("error"):
                logger.warning(
                    "federation sync: peer %s (%s): %s",
                    r.get("peer_id"), r.get("label"), r.get("error"),
                )
            else:
                logger.info(
                    "federation sync: peer %s (%s) pinned=%d bytes=%d skipped=%d",
                    r.get("peer_id"), r.get("label"),
                    r.get("pinned_count", 0), r.get("pinned_bytes", 0),
                    r.get("skipped_count", 0),
                )


def start_federation_monitor() -> None:
    """
    Called from the FastAPI startup hook (main.py), mirroring
    tunnel.start_tunnel_monitor(). CIPHER_FEDERATION_SYNC_INTERVAL_SECONDS=0
    disables the background loop entirely; manual "sync now" via the panel
    still works either way.
    """
    from cipher_station.config import CIPHER_FEDERATION_SYNC_INTERVAL_SECONDS
    interval = CIPHER_FEDERATION_SYNC_INTERVAL_SECONDS
    if interval <= 0:
        logger.info(
            "Federation background sync disabled "
            "(CIPHER_FEDERATION_SYNC_INTERVAL_SECONDS=0)"
        )
        return
    t = threading.Thread(
        target=_federation_sync_loop, args=(interval,),
        daemon=True, name="federation-monitor",
    )
    t.start()
    logger.info("Federation background sync started (interval=%ds)", interval)
