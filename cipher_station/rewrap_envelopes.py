# cipher_station/rewrap_envelopes.py

import json
from typing import Dict, List, Tuple, Optional

from nacl.secret import SecretBox

from cipher_station import pqcrypto
from cipher_station.config import PUBLIC_JSON_PATH
from cipher_station.envelopes import open_envelope, encrypt_key_for_follower
from cipher_station.followers import list_followers
from cipher_station.ipfs_client import ipfs_get_bytes
from cipher_station.manifest import (
    load_manifest,
    save_manifest,
    _publish_envelopes_to_ipfs,
    _publish_manifest_to_ipfs,
    _update_public_json_manifest_pointer,
)


def _load_self_uid() -> str:
    if not PUBLIC_JSON_PATH.exists():
        raise FileNotFoundError(f"public.json not found at {PUBLIC_JSON_PATH}")
    obj = json.loads(PUBLIC_JSON_PATH.read_text())
    uid = obj.get("uid")
    if not uid or not isinstance(uid, str):
        raise ValueError("public.json missing valid 'uid'")
    return uid


def _dedupe_allowed_followers(followers: List[dict]) -> List[dict]:
    """
    list_followers() returns device-level entries.
    For manifest envelopes we want ONE envelope per uid (user-level),
    because device-level access is handled via delegated /rewrap.
    """
    by_uid: Dict[str, dict] = {}
    for f in followers:
        if f.get("allowed") != "Allowed":
            continue

        uid = f.get("uid")
        if not uid or not isinstance(uid, str):
            continue

        if uid not in by_uid:
            by_uid[uid] = f
            continue

        # Prefer "root" device if present (device_uid == uid)
        if f.get("device_uid") == uid and by_uid[uid].get("device_uid") != uid:
            by_uid[uid] = f

    return list(by_uid.values())


def _load_envelopes_map_from_ipfs(envelopes_cid: str) -> Dict[str, str]:
    """
    Accepts both payload shapes:
      - {"envelopes": {...}}
      - {"v":1,"post_cid":"...","envelopes": {...}}
    """
    raw = ipfs_get_bytes(envelopes_cid)
    obj = json.loads(raw.decode("utf-8"))
    env = obj.get("envelopes", {})
    return env if isinstance(env, dict) else {}


def _iter_client_posts(manifest: dict):
    """
    NEW schema only:
      manifest["clients"][client_name]["posts"] -> list[entry]
    Yields: (client_name, posts_list, entry_index, entry_dict)
    """
    clients = manifest.get("clients")
    if not isinstance(clients, dict):
        return

    for client_name, client_obj in clients.items():
        if not isinstance(client_obj, dict):
            continue
        posts = client_obj.get("posts")
        if not isinstance(posts, list):
            continue
        for idx, entry in enumerate(posts):
            if isinstance(entry, dict):
                yield client_name, posts, idx, entry


def _get_post_cid(entry: dict) -> Optional[str]:
    cid = entry.get("post_cid") or entry.get("cid")
    return cid if isinstance(cid, str) and cid else None


def _get_root_envelope_hex_for_uid(entry: dict, uid: str) -> Optional[str]:
    envelopes_cid = entry.get("envelopes_cid")
    if isinstance(envelopes_cid, str) and envelopes_cid:
        env_map = _load_envelopes_map_from_ipfs(envelopes_cid)
        val = env_map.get(uid)
        if isinstance(val, str) and val:
            return val
    return None


def rewrap_all_posts(mlkem_sk: bytes, debug: bool = False) -> dict:
    """
    Rewrap follower envelopes for every post in the manifest **where audience_mode == "all"**,
    republish per-post envelopes JSON to IPFS,
    then republish manifest + update public.json pointer.

    NEW manifest schema only (clients -> posts).
    """
    self_uid = _load_self_uid()

    followers = _dedupe_allowed_followers(list_followers())
    follower_keys: List[Tuple[str, str]] = []
    for f in followers:
        uid = f.get("uid")
        pk = f.get("mlkem_public_key")
        if isinstance(uid, str) and uid and isinstance(pk, str) and len(pk) == pqcrypto.MLKEM_PUBLIC_HEX:
            follower_keys.append((uid, pk))

    manifest = load_manifest()
    posts_total = 0
    updated_posts = 0
    skipped_posts = 0

    skip_counts = {
        "missing_post_cid": 0,
        "missing_envelopes_cid": 0,
        "audience_not_all": 0,
        "missing_root_envelope": 0,
        "open_envelope_failed": 0,
        "bad_sym_key_len": 0,
        "publish_failed": 0,
    }
    skipped_details: List[dict] = []

    for client_name, posts_list, idx, entry in _iter_client_posts(manifest):
        posts_total += 1

        audience_mode = entry.get("audience_mode", "all")
        if audience_mode != "all":
            skipped_posts += 1
            skip_counts["audience_not_all"] += 1
            if debug:
                skipped_details.append({
                    "client": client_name,
                    "index": idx,
                    "post_cid": _get_post_cid(entry),
                    "reason": f"audience_mode={audience_mode} (skipped)",
                })
            continue

        post_cid = _get_post_cid(entry)
        if not post_cid:
            skipped_posts += 1
            skip_counts["missing_post_cid"] += 1
            if debug:
                skipped_details.append({
                    "client": client_name,
                    "index": idx,
                    "reason": "missing_post_cid",
                    "entry_keys": sorted(list(entry.keys())),
                })
            continue

        envelopes_cid = entry.get("envelopes_cid")
        if not isinstance(envelopes_cid, str) or not envelopes_cid:
            skipped_posts += 1
            skip_counts["missing_envelopes_cid"] += 1
            if debug:
                skipped_details.append({
                    "client": client_name,
                    "index": idx,
                    "post_cid": post_cid,
                    "reason": "missing_envelopes_cid",
                })
            continue

        root_env_hex = _get_root_envelope_hex_for_uid(entry, self_uid)
        if not root_env_hex:
            skipped_posts += 1
            skip_counts["missing_root_envelope"] += 1
            if debug:
                skipped_details.append({
                    "client": client_name,
                    "index": idx,
                    "post_cid": post_cid,
                    "reason": "missing_root_envelope_for_self_uid",
                    "self_uid": self_uid,
                })
            continue

        try:
            sym_key = open_envelope(mlkem_sk, root_env_hex)
        except Exception as e:
            sym_key = None
            skipped_posts += 1
            skip_counts["open_envelope_failed"] += 1
            if debug:
                skipped_details.append({
                    "client": client_name,
                    "index": idx,
                    "post_cid": post_cid,
                    "reason": "open_envelope_exception",
                    "error": repr(e),
                })
            continue

        if not sym_key or len(sym_key) != SecretBox.KEY_SIZE:
            skipped_posts += 1
            skip_counts["bad_sym_key_len"] += 1
            if debug:
                skipped_details.append({
                    "client": client_name,
                    "index": idx,
                    "post_cid": post_cid,
                    "reason": "bad_sym_key_len",
                    "got_len": (len(sym_key) if sym_key else None),
                    "expected_len": SecretBox.KEY_SIZE,
                })
            continue

        new_env: Dict[str, str] = {}
        for f_uid, f_pubkey_hex in follower_keys:
            enc_hex = encrypt_key_for_follower(sym_key, f_pubkey_hex)
            if enc_hex:
                new_env[f_uid] = enc_hex

        try:
            new_envelopes_cid = _publish_envelopes_to_ipfs(post_cid, new_env)
        except Exception as e:
            skipped_posts += 1
            skip_counts["publish_failed"] += 1
            if debug:
                skipped_details.append({
                    "client": client_name,
                    "index": idx,
                    "post_cid": post_cid,
                    "reason": "publish_envelopes_failed",
                    "error": repr(e),
                })
            continue

        # Update entry in place
        entry["post_cid"] = post_cid
        entry["envelopes_cid"] = new_envelopes_cid
        entry["envelopes_count"] = len(new_env)
        entry.pop("envelopes", None)

        posts_list[idx] = entry
        updated_posts += 1

    from cipher_station.storage import STATE_LOCK
    with STATE_LOCK:
        save_manifest(manifest)
        manifest_cid = _publish_manifest_to_ipfs(manifest)
        _update_public_json_manifest_pointer(manifest_cid)

    out = {
        "status": "rewrap_manifest_ok",
        "followers_allowed": len(follower_keys),
        "posts_total": posts_total,
        "posts_updated": updated_posts,
        "posts_skipped": skipped_posts,
        "manifest_cid": manifest_cid,
        "skip_counts": skip_counts,
    }
    if debug:
        out["skipped_details"] = skipped_details
    return out
