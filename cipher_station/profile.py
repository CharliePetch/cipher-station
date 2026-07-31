# cipher_station/profile.py

import logging
import re

from cipher_station.identity import load_public_identity
from cipher_station.manifest import load_manifest, get_client_profile, set_client_profile
from cipher_station.followers import list_followers
from cipher_station.following import list_following

# The client that owns the social profile (display name, bio, avatar, privacy).
# Profile metadata lives in the manifest under this client bucket, not public.json.
PROFILE_CLIENT = "cipherframe"

logger = logging.getLogger(__name__)

# Validation bounds for editable profile fields.
_MAX_DISPLAY_NAME = 80
_MAX_BIO = 300
_MAX_LINK = 200
_USERNAME_RE = re.compile(r"^[A-Za-z0-9._]{1,30}$")
_LINK_RE = re.compile(r"^https?://", re.IGNORECASE)


def _manifest_post_counts(manifest: dict) -> tuple[int, dict[str, int]]:
    """
    Returns: (total_posts, counts_by_client)

    Supports both schemas:
      - NEW: {"clients": {"cipherframe": {"posts":[...]}, ...}}
      - OLD: {"client":"cipherframe", "posts":[...]}
    """
    if not isinstance(manifest, dict):
        return 0, {}

    # New schema
    clients = manifest.get("clients")
    if isinstance(clients, dict):
        by_client: dict[str, int] = {}
        total = 0
        for name, obj in clients.items():
            if not isinstance(name, str) or not name.strip():
                continue
            posts = []
            if isinstance(obj, dict):
                posts = obj.get("posts", [])
            n = len(posts) if isinstance(posts, list) else 0
            by_client[name] = n
            total += n
        return total, by_client

    # Old schema
    posts = manifest.get("posts", [])
    n = len(posts) if isinstance(posts, list) else 0
    client = manifest.get("client") or "default"
    if not isinstance(client, str) or not client.strip():
        client = "default"
    return n, {client: n}


def _followers_count(self_uid: str | None) -> int:
    """
    Count distinct Allowed follower uids, deduping device rows to uids and
    excluding the station's own uid.
    """
    seen: set[str] = set()
    for f in list_followers():
        uid = f.get("uid")
        if not uid or uid == self_uid:
            continue
        if f.get("allowed") != "Allowed":
            continue
        seen.add(uid)
    return len(seen)


def get_public_profile() -> dict:
    """
    Public (no-auth) station profile consumed by the cipherframe client.

    Combines public.json fields (identity, social-profile metadata, privacy
    settings) with derived counts (posts from the manifest, followers/following
    from the local DB).
    """
    info = load_public_identity()

    uid = info.get("uid")
    manifest_pointer = info.get("manifest_pointer")

    manifest = load_manifest() or {}

    total, by_client = _manifest_post_counts(manifest)

    return {
        "uid": uid,
        "mlkem_public_key": info.get("mlkem_public_key"),  # ML-KEM-768 (content)
        "mldsa_public_key": info.get("mldsa_public_key"),  # ML-DSA-65 (auth)
        "endpoint": info.get("endpoint"),
        "ipfs_peer_id": info.get("ipfs_peer_id"),       # base58 libp2p peer id
        "ipns_name": info.get("ipns_name"),             # base36 IPNS name (k51…), gateway-ready
        "manifest_cid": manifest_pointer,

        # NOTE: the Instagram-style profile (display_name, username, bio, link,
        # avatar_cid, account_privacy, default_audience_mode) is CLIENT data and
        # lives in the manifest at clients.<client>.profile — NOT here.

        # social counts (protocol-level: derived from the follow graph)
        "followers_count": _followers_count(uid),
        "following_count": len(list_following()),

        # post counts
        "manifest_posts": total,
        "manifest_posts_total": total,
        "manifest_posts_by_client": by_client,
    }


# ---------------------------------------------------------------------------
# Mutations (owner-only paths) — write to the manifest client profile.
# ---------------------------------------------------------------------------

def _validate_and_normalize(field: str, raw) -> str | None:
    """
    Trim a provided value; return None if it trims to empty (clears the field),
    else the validated string. Raises ValueError on validation failure (the
    route maps this to HTTP 400).
    """
    if raw is None:
        return None
    if not isinstance(raw, str):
        raise ValueError(f"{field} must be a string")

    value = raw.strip()
    if value == "":
        return None  # empty clears the field

    if field == "display_name":
        if len(value) > _MAX_DISPLAY_NAME:
            raise ValueError(f"display_name must be <= {_MAX_DISPLAY_NAME} characters")
    elif field == "username":
        if not _USERNAME_RE.match(value):
            raise ValueError(
                "username must match ^[A-Za-z0-9._]{1,30}$"
            )
    elif field == "bio":
        if len(value) > _MAX_BIO:
            raise ValueError(f"bio must be <= {_MAX_BIO} characters")
    elif field == "link":
        if len(value) > _MAX_LINK:
            raise ValueError(f"link must be <= {_MAX_LINK} characters")
        if not _LINK_RE.match(value):
            raise ValueError("link must be a http(s):// URL")
    else:
        raise ValueError(f"Unknown profile field: {field}")

    return value


def update_profile_fields(client: str = PROFILE_CLIENT, **kwargs) -> dict:
    """
    Update editable profile fields in the manifest's client profile (owner-only).

    Only keys explicitly present in kwargs are touched. Each provided value is
    trimmed; a value that trims to empty clears the field (stores null).
    Validation failures raise ValueError (the route returns HTTP 400).

    Persists into clients.<client>.profile in the manifest, republishes the
    manifest to IPFS + IPNS, and returns the updated profile dict.
    """
    editable = ("display_name", "username", "bio", "link")

    fields: dict = {}
    for field in editable:
        if field in kwargs:
            fields[field] = _validate_and_normalize(field, kwargs[field])

    if not fields:
        return get_client_profile(client=client)

    profile = set_client_profile(fields, client=client)
    logger.info("Profile fields updated in manifest: %s", sorted(fields))
    return profile


def set_avatar_cid(cid: str, client: str = PROFILE_CLIENT) -> dict:
    """
    Set the client profile's avatar_cid (a public, plaintext IPFS CID) in the
    manifest and republish. Returns the updated profile dict.
    """
    profile = set_client_profile({"avatar_cid": cid}, client=client)
    logger.info("Avatar CID set in manifest: %s", cid)
    return profile
