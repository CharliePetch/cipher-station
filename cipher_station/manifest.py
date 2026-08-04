# cipher_station/manifest.py

import json
import logging
import time
from typing import Optional, Literal

from cipher_station.config import MANIFEST_DIR, PUBLIC_JSON_PATH

logger = logging.getLogger(__name__)
from cipher_station import pqcrypto
from cipher_station.storage import write_json
from cipher_station.envelopes import encrypt_key_for_follower
from cipher_station.ipfs_client import ipfs_add_bytes, ipfs_unpin, ipfs_repo_gc, publish_public_json_to_ipns

MANIFEST_PATH = MANIFEST_DIR / "manifest.json"

AudienceMode = Literal["self", "specific", "all", "public"]


# -----------------------------
# Manifest shape helpers
# -----------------------------

def _normalize_manifest_shape(manifest: dict, *, default_client: Optional[str] = None) -> dict:
    """
    Normalize manifest to the new shape:

    {
      "clients": {
        "<client>": { "posts": [ ... ] }
      }
    }

    Back-compat:
      - If we load an old shape like {"client":"cipherframe","posts":[...]}
        we migrate it in-memory to the new clients map.
      - If we load {"posts":[...]} with no client, we place it under default_client
        if provided, else under "default".
    """
    if not isinstance(manifest, dict):
        manifest = {}

    # Already new shape
    if isinstance(manifest.get("clients"), dict):
        # Ensure each client entry has "posts"
        for c, obj in manifest["clients"].items():
            if not isinstance(obj, dict):
                manifest["clients"][c] = {"posts": []}
                continue
            obj.setdefault("posts", [])
            if not isinstance(obj["posts"], list):
                obj["posts"] = []
        return manifest

    # Old shape: {"client": "...", "posts": [...]}
    old_posts = manifest.get("posts")
    if not isinstance(old_posts, list):
        old_posts = []

    old_client = manifest.get("client")
    if not isinstance(old_client, str) or not old_client.strip():
        old_client = (default_client or "default").strip()

    return {
        "clients": {
            old_client: {"posts": old_posts}
        }
    }


def load_manifest(*, client: Optional[str] = None) -> dict:
    """
    Loads manifest.json and normalizes to new shape.
    """
    if MANIFEST_PATH.exists():
        try:
            obj = json.loads(MANIFEST_PATH.read_text())
            return _normalize_manifest_shape(obj, default_client=client)
        except Exception as e:
            logger.error(f"Failed to load manifest.json: {e}")

    # default empty manifest in new shape
    return _normalize_manifest_shape({}, default_client=client)


def save_manifest(manifest: dict, *, client: Optional[str] = None):
    """
    Saves manifest in new shape only.
    """
    manifest = _normalize_manifest_shape(manifest, default_client=client)
    write_json(MANIFEST_PATH, manifest)


def _publish_manifest_to_ipfs(manifest: dict) -> str:
    manifest_bytes = json.dumps(manifest, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return ipfs_add_bytes(manifest_bytes)


def _update_public_json_manifest_pointer(manifest_cid: str) -> dict:
    try:
        public_obj = json.loads(PUBLIC_JSON_PATH.read_text()) if PUBLIC_JSON_PATH.exists() else {}
    except Exception as e:
        logger.error(f"Failed to load public.json (will recreate): {e}")
        public_obj = {}

    public_obj["manifest_pointer"] = manifest_cid
    write_json(PUBLIC_JSON_PATH, public_obj)

    # Republish to IPFS + IPNS so the decentralized pointer stays current
    publish_public_json_to_ipns()

    return public_obj


# -----------------------------
# Envelopes publishing
# -----------------------------

def _publish_envelopes_to_ipfs(post_cid: str, envelopes: dict) -> str:
    """
    Publish per-post envelopes JSON to IPFS, return CID.
    (This file can remain versioned independently from the manifest.)
    """
    payload = {
        "v": 1,
        "post_cid": post_cid,
        "envelopes": envelopes,  # uid -> sealed_box_hex
    }
    raw = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return ipfs_add_bytes(raw)


# -----------------------------
# Public API
# -----------------------------

def add_post_to_manifest(
    post_cid: str,
    followers: list,
    sym_key: bytes,
    metadata: dict | None = None,          # kept for compat; not stored
    metadata_enc: str | None = None,
    *,
    audience_mode: AudienceMode = "all",
    audience_uids: Optional[list[str]] = None,
    client: Optional[str] = None,          # REQUIRED conceptually; defaults to "default" if missing
    created_at: int | None = None,         # preserve original timestamp on privacy flips
) -> dict:
    """
    New behavior:
      - Build per-follower envelopes dict (uid -> sealed_box_hex)
      - Publish envelopes JSON to IPFS -> envelopes_cid
      - Store envelopes_cid + envelopes_count + audience_mode (+ audience_uids) in the CLIENT's posts list
      - Publish manifest to IPFS + update public.json["manifest_pointer"]

    Manifest layout:
      {
        "clients": {
          "<client>": { "posts": [ ... ] }
        }
      }
    """
    if audience_mode not in ("self", "specific", "all"):
        raise ValueError(f"Invalid audience_mode: {audience_mode}")

    if audience_mode == "specific":
        if audience_uids is None:
            audience_uids = []
        if not isinstance(audience_uids, list) or not all(isinstance(u, str) and u.strip() for u in audience_uids):
            raise ValueError("audience_uids must be a list[str] (non-empty strings) when audience_mode='specific'")
        audience_uids = sorted({u.strip() for u in audience_uids})

    # Decide client bucket
    client_key = (client or "default").strip()
    if not client_key:
        client_key = "default"

    # -------------------------------------
    # 1) Build per-follower encrypted envelopes
    # -------------------------------------
    envelopes: dict[str, str] = {}  # uid -> sealed_box_hex

    for follower in followers:
        uid = follower.get("uid")
        mlkem_pub_hex = follower.get("mlkem_public_key")

        if not uid or not isinstance(uid, str):
            continue

        if not isinstance(mlkem_pub_hex, str) or len(mlkem_pub_hex) != pqcrypto.MLKEM_PUBLIC_HEX:
            logger.warning(f"Skipping follower {uid}: invalid ML-KEM pubkey")
            continue

        encrypted_hex = encrypt_key_for_follower(sym_key, mlkem_pub_hex)
        if encrypted_hex is None:
            logger.warning(f"Failed envelope for follower {uid}")
            continue

        envelopes[uid] = encrypted_hex

    # -------------------------------------
    # 2) Publish envelopes JSON to IPFS
    # -------------------------------------
    envelopes_cid = _publish_envelopes_to_ipfs(post_cid, envelopes)

    # -------------------------------------
    # 3) Build post entry
    # -------------------------------------
    entry: dict = {
        "post_cid": post_cid,
        "audience_mode": audience_mode,
        "envelopes_cid": envelopes_cid,
        "envelopes_count": len(envelopes),
        "created_at": created_at if created_at is not None else int(time.time()),
    }

    if audience_mode == "specific":
        entry["audience_uids"] = audience_uids or []

    if metadata_enc is not None:
        if not isinstance(metadata_enc, str):
            raise ValueError("metadata_enc must be a hex string or None")
        entry["metadata"] = metadata_enc  # encrypted metadata

    return _append_entry_and_publish(entry, client_key)


def add_public_post_to_manifest(
    post_cid: str,
    metadata: dict | None = None,
    *,
    client: Optional[str] = None,
    created_at: int | None = None,         # preserve original timestamp on privacy flips
) -> dict:
    """
    Append a PUBLIC (unencrypted) post to the manifest.

    Public posts carry no envelopes and no symmetric key — the content at
    `post_cid` is plaintext on IPFS and readable by anyone. Metadata, if any,
    is stored in the clear. The `encrypted: false` flag distinguishes these
    entries from the encrypted ones (whose `metadata` is a hex blob).
    """
    client_key = (client or "default").strip() or "default"

    entry: dict = {
        "post_cid": post_cid,
        "audience_mode": "public",
        "encrypted": False,
        "envelopes_cid": None,
        "envelopes_count": 0,
        "created_at": created_at if created_at is not None else int(time.time()),
    }
    if metadata is not None:
        if not isinstance(metadata, dict):
            raise ValueError("metadata must be a dict or None")
        entry["metadata"] = metadata  # plaintext (NOT a hex blob)

    return _append_entry_and_publish(entry, client_key)


def _append_entry_and_publish(entry: dict, client_key: str) -> dict:
    """
    Append a post entry to the client's bucket, save locally, publish the
    manifest to IPFS, and update the public.json pointer (+ IPNS).
    """
    # Guarantee every entry carries a creation timestamp (covers both the
    # encrypted and public paths; preserved if a caller already set one).
    entry.setdefault("created_at", int(time.time()))

    manifest = load_manifest(client=client_key)
    manifest = _normalize_manifest_shape(manifest, default_client=client_key)

    manifest["clients"].setdefault(client_key, {"posts": []})
    if not isinstance(manifest["clients"][client_key], dict):
        manifest["clients"][client_key] = {"posts": []}

    manifest["clients"][client_key].setdefault("posts", [])
    if not isinstance(manifest["clients"][client_key]["posts"], list):
        manifest["clients"][client_key]["posts"] = []

    manifest["clients"][client_key]["posts"].append(entry)
    save_manifest(manifest, client=client_key)

    manifest_cid = _publish_manifest_to_ipfs(manifest)
    _update_public_json_manifest_pointer(manifest_cid)

    return manifest


# -----------------------------
# Client profile (lives in the manifest, NOT public.json)
# -----------------------------

# The Instagram-style profile chrome is client data, namespaced per client in
# the manifest — it does NOT belong in public.json (the station's protocol
# identity document).
CLIENT_PROFILE_FIELDS = (
    "display_name", "username", "bio", "link",
    "avatar_cid", "account_privacy", "default_audience_mode",
)


def get_client_profile(client: Optional[str] = None) -> dict:
    """Return the profile object stored in a client's manifest bucket (or {})."""
    client_key = (client or "default").strip() or "default"
    manifest = load_manifest(client=client_key)
    bucket = manifest.get("clients", {}).get(client_key, {})
    prof = bucket.get("profile") if isinstance(bucket, dict) else None
    return dict(prof) if isinstance(prof, dict) else {}


def set_client_profile(fields: dict, *, client: Optional[str] = None) -> dict:
    """
    Merge ``fields`` into the client's manifest ``profile`` object, then publish
    the manifest to IPFS + update the public.json pointer (+ IPNS) — exactly like
    a post mutation. Returns the updated profile dict.
    """
    client_key = (client or "default").strip() or "default"

    manifest = load_manifest(client=client_key)
    manifest = _normalize_manifest_shape(manifest, default_client=client_key)

    bucket = manifest["clients"].setdefault(client_key, {"posts": []})
    if not isinstance(bucket, dict):
        bucket = {"posts": []}
        manifest["clients"][client_key] = bucket
    bucket.setdefault("posts", [])

    profile = bucket.get("profile")
    if not isinstance(profile, dict):
        profile = {}
    profile.update(fields)
    profile["updated_at"] = int(time.time())
    bucket["profile"] = profile

    save_manifest(manifest, client=client_key)
    manifest_cid = _publish_manifest_to_ipfs(manifest)
    _update_public_json_manifest_pointer(manifest_cid)

    return profile


# -----------------------------
# Ownership: which CIDs did THIS station publish?
# -----------------------------

# Artifact pointers the station writes into public.json. Everything else it
# publishes is referenced from the manifest.
PUBLIC_JSON_CID_FIELDS = (
    "manifest_pointer",
    "following_cid",
    "followers_cid",
    "follow_decoder_envelopes_cid",
)


def station_content_cids() -> set[str]:
    """
    Every CID this station published and still references.

    Sources — the complete set of places the station records something it added
    to IPFS:
      * manifest: clients.<client>.posts[].post_cid / .envelopes_cid
      * manifest: clients.<client>.profile.avatar_cid
      * public.json: manifest_pointer, following_cid, followers_cid,
        follow_decoder_envelopes_cid

    Deliberately NOT a "did IPFS pin this" check: pinned-ness would also cover
    content the node happens to have cached or that a previous owner pinned.
    Referenced-by-our-own-state is the narrower, cheaper answer.
    """
    cids: set[str] = set()

    manifest = load_manifest()
    for bucket in (manifest.get("clients") or {}).values():
        if not isinstance(bucket, dict):
            continue
        for post in bucket.get("posts") or []:
            if not isinstance(post, dict):
                continue
            for key in ("post_cid", "envelopes_cid"):
                value = post.get(key)
                if isinstance(value, str) and value:
                    cids.add(value)
        profile = bucket.get("profile")
        if isinstance(profile, dict):
            avatar = profile.get("avatar_cid")
            if isinstance(avatar, str) and avatar:
                cids.add(avatar)

    try:
        public_obj = json.loads(PUBLIC_JSON_PATH.read_text()) if PUBLIC_JSON_PATH.exists() else {}
    except Exception as exc:
        logger.warning("station_content_cids: could not read public.json: %s", exc)
        public_obj = {}

    if isinstance(public_obj, dict):
        for key in PUBLIC_JSON_CID_FIELDS:
            value = public_obj.get(key)
            if isinstance(value, str) and value:
                cids.add(value)

    return cids


def station_owns_cid(cid: str) -> bool:
    """
    Whether `cid` is one this station published (exact string match against
    ``station_content_cids()``).

    Recomputed per call — both inputs are small local JSON files, and a cache
    would go stale the moment a post is created or deleted.
    """
    if not isinstance(cid, str) or not cid:
        return False
    return cid in station_content_cids()


def remove_post_from_manifest(
    post_cid: str,
    *,
    client: Optional[str] = None,
) -> dict:
    """
    Remove a post from the manifest by its post_cid.

    - Searches the given client bucket (or all buckets if client is None)
    - Removes the matching post entry
    - Re-publishes manifest to IPFS + updates public.json pointer + IPNS

    Returns dict with status info.
    """
    manifest = load_manifest(client=client)

    found = False
    searched_client = None
    removed_entry = None

    if client:
        client_key = client.strip() or "default"
        bucket = manifest.get("clients", {}).get(client_key, {})
        posts = bucket.get("posts", [])
        kept = []
        for p in posts:
            if p.get("post_cid") == post_cid and removed_entry is None:
                removed_entry = p
            else:
                kept.append(p)
        if removed_entry is not None:
            bucket["posts"] = kept
            found = True
            searched_client = client_key
    else:
        # Search all client buckets
        for ck, bucket in manifest.get("clients", {}).items():
            posts = bucket.get("posts", [])
            kept = []
            for p in posts:
                if p.get("post_cid") == post_cid and removed_entry is None:
                    removed_entry = p
                else:
                    kept.append(p)
            if removed_entry is not None:
                bucket["posts"] = kept
                found = True
                searched_client = ck
                break

    if not found:
        return {"status": "not_found", "post_cid": post_cid}

    save_manifest(manifest, client=searched_client)

    manifest_cid = _publish_manifest_to_ipfs(manifest)
    _update_public_json_manifest_pointer(manifest_cid)

    # Unpin the deleted post's content and envelopes from IPFS
    unpinned_cids = []
    for cid_key in ("post_cid", "envelopes_cid"):
        cid = removed_entry.get(cid_key)
        if cid:
            try:
                ipfs_unpin(cid)
                unpinned_cids.append(cid)
            except Exception as exc:
                logger.warning("Failed to unpin %s (%s): %s", cid_key, cid, exc)

    # Run garbage collection to reclaim disk space
    gc_count = 0
    if unpinned_cids:
        try:
            removed = ipfs_repo_gc()
            gc_count = len(removed)
        except Exception as exc:
            logger.warning("IPFS garbage collection failed: %s", exc)

    remaining = sum(
        len(b.get("posts", []))
        for b in manifest.get("clients", {}).values()
    )

    return {
        "status": "deleted",
        "post_cid": post_cid,
        "client": searched_client,
        "manifest_posts": remaining,
        "unpinned": unpinned_cids,
        "gc_objects_removed": gc_count,
    }
