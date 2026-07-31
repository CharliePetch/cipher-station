# cipher_station/privacy.py
"""
Account-wide privacy flips for the cipherframe client.

Flipping to "private" migrates every PUBLIC (plaintext) post in a client bucket
into an ENCRYPTED post (with self + audience envelopes), then drops the old
plaintext CIDs. Flipping back to "public" reverses the migration: the station
recovers each post's symmetric key from its own envelope, decrypts the blob (and
metadata), and re-publishes it as a plaintext public post.

Each post is migrated independently — a single failure is recorded and skipped,
never aborting the whole flip. Original creation timestamps are preserved so a
migrated post keeps its place in the timeline.
"""

import json
import logging
from typing import Optional

from nacl.secret import SecretBox

from cipher_station.identity import get_identity, load_public_identity
from cipher_station.manifest import load_manifest, remove_post_from_manifest, set_client_profile
from cipher_station.posts import handle_new_post
from cipher_station.envelopes import open_envelope
from cipher_station.ipfs_client import ipfs_get_bytes

logger = logging.getLogger(__name__)


def _client_posts(client: str) -> list[dict]:
    """Return a snapshot (copy) of the client bucket's post entries."""
    manifest = load_manifest(client=client)
    bucket = manifest.get("clients", {}).get(client, {})
    posts = bucket.get("posts", [])
    return list(posts) if isinstance(posts, list) else []


def _flip_to_private(
    client: str,
    audience_mode: str,
    audience_uids: Optional[list[str]],
) -> list[dict]:
    """
    Migrate every PUBLIC post in the client bucket to an encrypted post.

    Snapshot the list first (we mutate the manifest as we go). For each public
    entry: re-fetch the plaintext, re-post it encrypted (preserving created_at
    and plaintext metadata), then remove the old public entry (unpins + GCs).
    """
    migrated: list[dict] = []

    for entry in _client_posts(client):
        if entry.get("audience_mode") != "public":
            continue

        old_cid = entry.get("post_cid")
        old_created = entry.get("created_at")
        try:
            plaintext = ipfs_get_bytes(old_cid)

            md = entry.get("metadata")
            md = md if isinstance(md, dict) else None  # public metadata is a plaintext dict

            res = handle_new_post(
                plaintext,
                metadata=md,
                audience_mode=audience_mode,
                audience_uids=audience_uids,
                client=client,
                created_at=old_created,
            )

            remove_post_from_manifest(old_cid, client=client)
            migrated.append({"old_cid": old_cid, "new_cid": res["cid"], "status": "ok"})
        except Exception as e:
            logger.warning("privacy flip (private) failed for %s: %s", old_cid, e)
            migrated.append({"old_cid": old_cid, "status": "error", "error": str(e)})

    return migrated


def _flip_to_public(client: str) -> list[dict]:
    """
    Migrate every ENCRYPTED post in the client bucket back to a public post.

    For each encrypted entry the station recovers the symmetric key from its own
    envelope (exactly like handle_reshare_post), decrypts the blob and metadata,
    and re-posts as plaintext public (preserving created_at), then removes the
    old encrypted entry.
    """
    ident = get_identity()
    self_uid = ident.uid

    migrated: list[dict] = []

    for entry in _client_posts(client):
        # Normalize legacy "all_followers" (written by older binaries) so those
        # encrypted posts still migrate back to public.
        mode = entry.get("audience_mode")
        if mode == "all_followers":
            mode = "all"
        if mode not in ("self", "specific", "all"):
            continue

        post_cid = entry.get("post_cid")
        envelopes_cid = entry.get("envelopes_cid")
        if not envelopes_cid:
            migrated.append({"old_cid": post_cid, "status": "skipped",
                             "error": "no envelopes_cid"})
            continue

        try:
            # 1) Recover the symmetric key from the SELF envelope.
            raw = ipfs_get_bytes(envelopes_cid)
            env_obj = json.loads(raw.decode("utf-8"))
            env_map = env_obj.get("envelopes", {})
            self_env = env_map.get(self_uid)
            if not self_env:
                migrated.append({"old_cid": post_cid, "status": "skipped",
                                 "error": "no self envelope"})
                continue

            sym_key = open_envelope(ident.mlkem_sk, self_env)
            if not sym_key or len(sym_key) != SecretBox.KEY_SIZE:
                migrated.append({"old_cid": post_cid, "status": "skipped",
                                 "error": "failed to recover symmetric key"})
                continue

            box = SecretBox(sym_key)

            # 2) Decrypt the post blob.
            plaintext = box.decrypt(ipfs_get_bytes(post_cid))

            # 3) Decrypt metadata if present (encrypted metadata is a hex str).
            md = None
            md_enc = entry.get("metadata")
            if isinstance(md_enc, str):
                md_raw = box.decrypt(bytes.fromhex(md_enc))
                md = json.loads(md_raw.decode("utf-8"))
                if not isinstance(md, dict):
                    md = None

            # 4) Re-post as plaintext public, preserving the timestamp.
            res = handle_new_post(
                plaintext,
                metadata=md,
                audience_mode="public",
                client=client,
                created_at=entry.get("created_at"),
            )

            remove_post_from_manifest(post_cid, client=client)
            migrated.append({"old_cid": post_cid, "new_cid": res["cid"], "status": "ok"})
        except Exception as e:
            logger.warning("privacy flip (public) failed for %s: %s", post_cid, e)
            migrated.append({"old_cid": post_cid, "status": "error", "error": str(e)})

    return migrated


def flip_account_privacy(
    mode: str,
    audience_mode: str = "all",
    audience_uids: Optional[list[str]] = None,
    client: str = "cipherframe",
) -> dict:
    """
    Flip the account between "public" and "private", migrating existing posts.

    mode == "private":
      Every PUBLIC post in the client bucket is re-published encrypted (self +
      audience envelopes). account_privacy -> "private",
      default_audience_mode -> "all".

    mode == "public":
      Every ENCRYPTED post in the client bucket is re-published as plaintext
      public. account_privacy -> "public", default_audience_mode -> "public".

    Per-post failures are recorded and skipped. Returns a summary including the
    new account settings, per-post migration records, the count of successful
    migrations, and the resulting manifest pointer.
    """
    if mode not in ("private", "public"):
        raise ValueError(f"Invalid mode: {mode}")

    if mode == "private":
        migrated = _flip_to_private(client, audience_mode, audience_uids)
        new_privacy = "private"
        new_default_audience = "all"
    else:
        migrated = _flip_to_public(client)
        new_privacy = "public"
        new_default_audience = "public"

    # Persist the new account settings into the manifest client profile (this
    # also republishes the manifest + public.json pointer to IPNS).
    set_client_profile(
        {"account_privacy": new_privacy, "default_audience_mode": new_default_audience},
        client=client,
    )

    migrated_count = sum(1 for m in migrated if m.get("status") == "ok")

    # Re-read the (now current) manifest pointer after all migrations.
    manifest_cid = load_public_identity().get("manifest_pointer")

    logger.info(
        "Account privacy flipped to %s (client=%s, migrated=%d)",
        new_privacy, client, migrated_count,
    )

    return {
        "status": "privacy_flipped",
        "account_privacy": new_privacy,
        "default_audience_mode": new_default_audience,
        "migrated": migrated,
        "migrated_count": migrated_count,
        "manifest_cid": manifest_cid,
    }
