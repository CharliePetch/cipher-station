# orbit_node/rewrap.py

import json
from typing import Optional, Tuple, Dict

from nacl.secret import SecretBox

from orbit_node import pqcrypto
from orbit_node.manifest import load_manifest
from orbit_node.ipfs_client import ipfs_get_bytes
from orbit_node.envelopes import open_envelope, encrypt_key_for_follower
from orbit_node.followers import list_follower_devices


def _load_envelopes_map_from_ipfs(envelopes_cid: str) -> Dict[str, str]:
    """
    Accepts both:
      - {"envelopes": {...}}
      - {"v":1,"post_cid":"...","envelopes": {...}}
    """
    raw = ipfs_get_bytes(envelopes_cid)
    obj = json.loads(raw.decode("utf-8"))
    env = obj.get("envelopes", {})
    return env if isinstance(env, dict) else {}


def _iter_posts_new_schema(manifest: dict):
    """
    NEW schema:
      manifest["clients"][client]["posts"] -> list[entry]
    Yields: (client_name, entry)
    """
    clients = manifest.get("clients")
    if not isinstance(clients, dict):
        raise ValueError("manifest missing top-level 'clients' dict (new schema)")

    for client_name, client_obj in clients.items():
        if not isinstance(client_obj, dict):
            continue
        posts = client_obj.get("posts", [])
        if not isinstance(posts, list):
            continue
        for entry in posts:
            if isinstance(entry, dict):
                yield client_name, entry


def _find_post_entry(manifest: dict, post_cid: str) -> Tuple[str, dict]:
    for client_name, entry in _iter_posts_new_schema(manifest):
        cid = entry.get("post_cid") or entry.get("cid")
        if cid == post_cid:
            return client_name, entry
    raise KeyError(f"post_cid {post_cid} not found")


def _get_device_public_key_hex(uid: str, device_uid: str) -> str:
    """
    Looks up the delegate device's ML-KEM (content) public key from the local DB.
    """
    rows = list_follower_devices(uid) or []
    for r in rows:
        if not isinstance(r, dict):
            continue
        if r.get("device_uid") == device_uid:
            pk = r.get("mlkem_public_key")
            if isinstance(pk, str) and len(pk) == pqcrypto.MLKEM_PUBLIC_HEX:
                return pk
            raise ValueError(f"Device {device_uid} found but has invalid mlkem_public_key")

    raise KeyError(f"Unknown device_uid {device_uid} for uid {uid}")


def handle_rewrap_request(station_mlkem_sk: bytes, msg: dict) -> dict:
    """
    NEW manifest schema only.

    Input msg:
      {
        "uid": "...",
        "device_uid": "...",
        "post_cid": "...",
        "envelopes_cid": "..."   # optional
      }

    Output (success):
      {"status":"rewrap_ok","uid":...,"device_uid":...,"post_cid":...,"envelope":<hex>}
    """
    uid = msg.get("uid")
    device_uid = msg.get("device_uid")
    post_cid = msg.get("post_cid")
    envelopes_cid_override = msg.get("envelopes_cid")

    if not isinstance(uid, str) or not uid:
        return {"error": "missing uid"}
    if not isinstance(device_uid, str) or not device_uid:
        return {"error": "missing device_uid"}
    if not isinstance(post_cid, str) or not post_cid:
        return {"error": "missing post_cid"}

    manifest = load_manifest()
    try:
        _client, entry = _find_post_entry(manifest, post_cid)
    except KeyError as e:
        return {"error": str(e).strip("'")}

    envelopes_cid = envelopes_cid_override or entry.get("envelopes_cid")
    if not isinstance(envelopes_cid, str) or not envelopes_cid:
        return {"error": f"post_cid {post_cid} missing envelopes_cid"}

    # 1) Load envelopes map and get the *root/self* envelope for uid
    env_map = _load_envelopes_map_from_ipfs(envelopes_cid)
    root_env_hex = env_map.get(uid)
    if not isinstance(root_env_hex, str) or not root_env_hex:
        return {"error": f"root envelope missing for uid {uid} on post_cid {post_cid}"}

    # 2) Open root envelope -> sym key
    try:
        sym_key = open_envelope(station_mlkem_sk, root_env_hex)
    except Exception as e:
        return {"error": f"open_envelope failed: {e!r}"}

    if not sym_key or len(sym_key) != SecretBox.KEY_SIZE:
        return {"error": f"bad sym key length: {len(sym_key) if sym_key else None}"}

    # 3) Encrypt sym key to delegate device public key
    try:
        device_pk_hex = _get_device_public_key_hex(uid, device_uid)
    except Exception as e:
        return {"error": f"device key lookup failed: {e}"}

    delegate_env_hex = encrypt_key_for_follower(sym_key, device_pk_hex)
    if not delegate_env_hex:
        return {"error": "failed to create delegate envelope"}

    return {
        "status": "rewrap_ok",
        "uid": uid,
        "device_uid": device_uid,
        "post_cid": post_cid,
        "envelope": delegate_env_hex,
    }
