# cipher_station/posts.py
import json
import logging
import time
from typing import Literal, Optional

from nacl.secret import SecretBox
from nacl.utils import random as nacl_random

from cipher_station.ipfs_client import ipfs_add_bytes, ipfs_get_bytes
from cipher_station.followers import list_followers
from cipher_station.manifest import add_post_to_manifest, add_public_post_to_manifest, load_manifest, remove_post_from_manifest
from cipher_station.identity import get_identity
from cipher_station.envelopes import open_envelope, encrypt_key_for_follower

logger = logging.getLogger(__name__)

# Back-compat: older clients used "all_followers".
# "public" posts are stored UNENCRYPTED on IPFS with no envelopes.
AudienceMode = Literal["self", "specific", "all", "all_followers", "public"]


def _normalize_audience_mode(mode: str) -> Literal["self", "specific", "all", "public"]:
    if mode == "all_followers":
        return "all"
    if mode in ("self", "specific", "all", "public"):
        return mode  # type: ignore[return-value]
    raise ValueError(f"Invalid audience_mode: {mode}")


def _encrypt_metadata(metadata: dict, sym_key: bytes) -> str:
    """
    Encrypt metadata dict with the same SecretBox key used for the post.
    Returns hex string (nonce+ciphertext).
    """
    raw = json.dumps(metadata, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    box = SecretBox(sym_key)
    ct = box.encrypt(raw)  # includes nonce
    return ct.hex()


def _dedupe_followers_for_user_level_envelopes(followers: list[dict]) -> list[dict]:
    """
    Reduce device-level follower rows -> ONE row per uid for user-level envelopes.

    Preference:
      1) allowed == "Allowed"
      2) device_uid == uid (treat as "root" device when present)
      3) otherwise: first Allowed row for that uid

    Rationale:
      - Your envelopes JSON is keyed by uid (not device_uid).
      - Passing multiple devices per uid causes overwrites, and can make "self"
        envelope end up sealed to the wrong device key.
    """
    allowed = [f for f in followers if isinstance(f, dict) and f.get("allowed") == "Allowed"]

    by_uid: dict[str, dict] = {}
    for f in allowed:
        uid = f.get("uid")
        if not uid or not isinstance(uid, str):
            continue

        cur = by_uid.get(uid)
        if cur is None:
            by_uid[uid] = f
            continue

        cur_is_root = (cur.get("device_uid") == uid)
        new_is_root = (f.get("device_uid") == uid)
        if (not cur_is_root) and new_is_root:
            by_uid[uid] = f

    return [by_uid[k] for k in sorted(by_uid.keys())]


def _force_self_row(
    *,
    followers: list[dict],
    self_uid: str,
    station_mlkem_pub_hex: str,
    pub_json: dict,
) -> list[dict]:
    """
    Ensure exactly one 'self' row exists and it is sealed to the station's
    ML-KEM public key (so the station can later recover the key for reshare/rewrap).
    """
    followers = [f for f in followers if f.get("uid") != self_uid]
    followers.insert(
        0,
        {
            "uid": self_uid,
            "mlkem_public_key": station_mlkem_pub_hex,  # key that matches station mlkem_sk
            "device_uid": self_uid,                     # treat as "root" device
            "alias": pub_json.get("alias"),
            "allowed": "Allowed",
            "endpoint": pub_json.get("endpoint"),
            "ipns_id": pub_json.get("ipfs_peer_id"),    # permanent IPNS discovery address
        },
    )
    return followers


def _filter_followers_for_audience(
    *,
    followers_user_level: list[dict],
    self_uid: str,
    audience_mode: Literal["self", "specific", "all"],
    audience_uids: Optional[list[str]],
) -> list[dict]:
    """
    Return subset of followers_user_level to receive envelopes.

    followers_user_level is expected to already be:
      - Allowed-only
      - deduped to one row per uid
      - NOT including self yet (we add self separately)
    """
    if audience_mode in ("self", "public"):
        return []  # self handled separately; public has no envelopes at all

    if audience_mode == "all":
        return followers_user_level

    # audience_mode == "specific"
    uids = audience_uids or []
    uids = [u.strip() for u in uids if isinstance(u, str) and u.strip()]

    want = set(uids) - {self_uid}
    if not want:
        return []

    by_uid = {f.get("uid"): f for f in followers_user_level if isinstance(f, dict)}
    selected = [by_uid[uid] for uid in sorted(want) if uid in by_uid]

    missing = sorted(want - set(by_uid.keys()))
    if missing:
        raise ValueError(
            "Specific audience contains uids that are not Allowed followers (or unknown): "
            + ", ".join(missing)
        )

    return selected


def handle_new_post(
    file_bytes: bytes,
    metadata: dict | str | None = None,
    *,
    audience_mode: AudienceMode = "all",
    audience_uids: Optional[list[str]] = None,
    client: str | None = None,
    created_at: int | None = None,
    self_envelope: str | None = None,
):
    """
    Upload post bytes to IPFS, generate envelopes, and append to manifest.

    Post visibility is controlled by audience_mode:
      - "self": only self gets an envelope
      - "specific": self + specified Allowed follower uids
      - "all" / (legacy "all_followers"): self + all Allowed followers
      - "public": NO encryption — file is uploaded as-is and is readable by anyone
                  via IPFS (no envelopes, plaintext metadata)

    Symmetric key origin (non-public modes only) — two callers, two modes:
      - Client-driven (the normal /post route): `self_envelope` is the sym_key
        ML-KEM-sealed to the STATION's own public key, produced on-device.
        `file_bytes` is already SecretBox-encrypted by the client, and
        `metadata` (if any) is already an encrypted hex string. The station
        only decapsulates the small envelope to recover sym_key for fanning
        out follower envelopes — it never receives plaintext content or a key
        sent outside a post-quantum-wrapped channel. This is what closes the
        harvest-now-decrypt-later gap that plaintext-over-classical-TLS would
        otherwise leave open.
      - Station-driven (e.g. the private<->public migration in privacy.py,
        which only ever re-packages content the station already holds): omit
        `self_envelope`; the station generates a fresh key and encrypts here,
        exactly as before. `metadata`, if given, is a plaintext dict.

    Notes:
      - Envelopes are published as a separate JSON to IPFS
      - Manifest stores envelopes_cid (not envelopes inline)
      - Followers list is deduped to ONE device per uid
      - Self uid is forced to the station ML-KEM public key (not delegate device)
      - created_at, when provided, is written verbatim onto the new manifest
        entry (else int(time.time())). The privacy flip passes the original
        timestamp through so a migrated post keeps its creation time.
    """
    # Load the station identity (source of truth for "self")
    ident = get_identity()
    station_mlkem_pub_hex = ident.mlkem_pub_hex
    pub_json = ident.public_json
    self_uid = ident.uid
    if not self_uid or not isinstance(self_uid, str):
        raise ValueError("Identity missing uid in public.json")

    # ✅ normalize legacy value
    aud_mode = _normalize_audience_mode(audience_mode)

    # ------------------------------------------------------------------
    # PUBLIC posts: no encryption, no envelopes, plaintext metadata.
    # ------------------------------------------------------------------
    if aud_mode == "public":
        cid = ipfs_add_bytes(file_bytes)
        logger.info(f"Public (unencrypted) post uploaded: CID={cid}")
        manifest = add_public_post_to_manifest(
            post_cid=cid,
            metadata=metadata if isinstance(metadata, dict) else None,
            client=client,
            created_at=created_at,
        )
        return {
            "status": "post_ok",
            "cid": cid,
            "envelopes_cid": None,
            "audience_mode": "public",
            "encrypted": False,
            "audience_uids": None,
            "followers_raw": 0,
            "followers_used": 0,
            "manifest_posts": sum(len(b.get("posts", [])) for b in manifest.get("clients", {}).values()),
        }

    # 1) Recover (client-driven) or generate (station-driven) the symmetric key.
    if self_envelope is not None:
        sym_key = open_envelope(ident.mlkem_sk, self_envelope)
        if not sym_key or len(sym_key) != SecretBox.KEY_SIZE:
            raise ValueError("Failed to recover symmetric key from self_envelope")
        encrypted_blob = file_bytes  # already SecretBox-encrypted client-side
    else:
        sym_key = nacl_random(SecretBox.KEY_SIZE)
        encrypted_blob = SecretBox(sym_key).encrypt(file_bytes)

    # 2) Upload encrypted blob to IPFS
    cid = ipfs_add_bytes(encrypted_blob)
    logger.info(f"Encrypted post uploaded: CID={cid}")

    # 4) Followers (device-level) -> dedupe to user-level Allowed followers
    followers_raw = list_followers()
    followers_user_level = _dedupe_followers_for_user_level_envelopes(followers_raw)

    # 4a) Remove self from follower list prior to audience selection (self is forced separately)
    followers_user_level = [f for f in followers_user_level if f.get("uid") != self_uid]

    # 4b) Apply audience filter to non-self recipients
    recipients = _filter_followers_for_audience(
        followers_user_level=followers_user_level,
        self_uid=self_uid,
        audience_mode=aud_mode,
        audience_uids=audience_uids,
    )

    # 4c) Force "self" envelope to the station ML-KEM public key
    followers_for_envelopes = _force_self_row(
        followers=recipients,
        self_uid=self_uid,
        station_mlkem_pub_hex=station_mlkem_pub_hex,
        pub_json=pub_json,
    )

    # 5) Metadata (optional): pre-encrypted hex from the client (self_envelope
    # path), or a plaintext dict encrypted here (station-driven path).
    metadata_enc = None
    if metadata is not None:
        if self_envelope is not None:
            if not isinstance(metadata, str):
                raise ValueError("metadata must be a pre-encrypted hex string when self_envelope is provided")
            metadata_enc = metadata
        else:
            if not isinstance(metadata, dict):
                raise ValueError("metadata must be a dict when self_envelope is not provided")
            metadata_enc = _encrypt_metadata(metadata, sym_key)

    # 6) Write manifest entry (store encrypted metadata only)
    manifest = add_post_to_manifest(
        post_cid=cid,
        followers=followers_for_envelopes,
        sym_key=sym_key,
        metadata_enc=metadata_enc,
        audience_mode=aud_mode,        # "self" | "specific" | "all"
        audience_uids=audience_uids,   # list[str] if specific
        client=client,                 # client app name (e.g., "cipherframe", "drive")
        created_at=created_at,         # preserve original timestamp on privacy flips
    )

    # 7) Pull the envelopes CID from the new entry (just appended) in the
    #    client bucket of the new manifest shape {"clients": {<client>: {"posts": [...]}}}.
    client_key = (client or "default").strip() or "default"
    envelopes_cid = None
    try:
        envelopes_cid = manifest["clients"][client_key]["posts"][-1].get("envelopes_cid")
    except Exception:
        pass

    total_posts = sum(len(b.get("posts", [])) for b in manifest.get("clients", {}).values())

    return {
        "status": "post_ok",
        "cid": cid,
        "envelopes_cid": envelopes_cid,
        "audience_mode": aud_mode,
        "audience_uids": (audience_uids or []) if aud_mode == "specific" else None,
        "followers_raw": len(followers_raw),
        "followers_used": len(followers_for_envelopes),
        "manifest_posts": total_posts,
    }


def handle_reshare_post(
    post_cid: str,
    *,
    audience_mode: AudienceMode = "specific",
    audience_uids: Optional[list[str]] = None,
    client: Optional[str] = None,
) -> dict:
    """
    Update a post's audience by removing and re-creating its manifest entry
    with new envelopes.

    The station recovers the symmetric key from its own ML-KEM envelope,
    then re-encrypts for the new audience set.
    """
    ident = get_identity()
    station_mlkem_pub_hex = ident.mlkem_pub_hex
    pub_json = ident.public_json
    self_uid = ident.uid
    if not self_uid:
        raise ValueError("Identity missing uid")

    aud_mode = _normalize_audience_mode(audience_mode)
    if aud_mode == "public":
        # Converting an encrypted post to public (or resharing a public post)
        # is out of scope: a public post has no recoverable symmetric key here.
        raise ValueError("Resharing to/from 'public' is not supported; create a new public post instead")

    # 1) Find the existing post entry in the manifest
    manifest = load_manifest(client=client)
    client_key = (client or "default").strip() or "default"

    # Search for the post
    old_entry = None
    for ck, bucket in manifest.get("clients", {}).items():
        for entry in bucket.get("posts", []):
            if entry.get("post_cid") == post_cid:
                old_entry = entry
                client_key = ck
                break
        if old_entry:
            break

    if not old_entry:
        return {"status": "not_found", "post_cid": post_cid}

    old_envelopes_cid = old_entry.get("envelopes_cid")
    old_metadata_enc = old_entry.get("metadata")

    # 2) Recover the symmetric key from the station's own envelope
    if not old_envelopes_cid:
        return {"status": "error", "detail": "Post has no envelopes_cid"}

    raw = ipfs_get_bytes(old_envelopes_cid)
    env_obj = json.loads(raw.decode("utf-8"))
    envelopes_map = env_obj.get("envelopes", {})

    self_envelope_hex = envelopes_map.get(self_uid)
    if not self_envelope_hex:
        return {"status": "error", "detail": "No self envelope found; cannot recover key"}

    sym_key = open_envelope(ident.mlkem_sk, self_envelope_hex)
    if not sym_key or len(sym_key) != SecretBox.KEY_SIZE:
        return {"status": "error", "detail": "Failed to recover symmetric key"}

    # 3) Build new follower list for the new audience
    followers_raw = list_followers()
    followers_user_level = _dedupe_followers_for_user_level_envelopes(followers_raw)
    followers_user_level = [f for f in followers_user_level if f.get("uid") != self_uid]

    recipients = _filter_followers_for_audience(
        followers_user_level=followers_user_level,
        self_uid=self_uid,
        audience_mode=aud_mode,
        audience_uids=audience_uids,
    )

    followers_for_envelopes = _force_self_row(
        followers=recipients,
        self_uid=self_uid,
        station_mlkem_pub_hex=station_mlkem_pub_hex,
        pub_json=pub_json,
    )

    # 4) Remove old entry from manifest
    remove_post_from_manifest(post_cid, client=client_key)

    # 5) Re-add with new audience (same post_cid, same metadata, new envelopes)
    manifest = add_post_to_manifest(
        post_cid=post_cid,
        followers=followers_for_envelopes,
        sym_key=sym_key,
        metadata_enc=old_metadata_enc,
        audience_mode=aud_mode,
        audience_uids=audience_uids,
        client=client_key,
    )

    return {
        "status": "shared",
        "post_cid": post_cid,
        "audience_mode": aud_mode,
        "audience_uids": (audience_uids or []) if aud_mode == "specific" else None,
        "envelopes_count": len(followers_for_envelopes),
    }
