# orbit_node/profile.py

from orbit_node.identity import load_public_identity
from orbit_node.manifest import load_manifest


def _manifest_post_counts(manifest: dict) -> tuple[int, dict[str, int]]:
    """
    Returns: (total_posts, counts_by_client)

    Supports both schemas:
      - NEW: {"clients": {"orbitstagram": {"posts":[...]}, ...}}
      - OLD: {"client":"orbitstagram", "posts":[...]}
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


def get_public_profile():
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
        "ipfs_peer_id": info.get("ipfs_peer_id"),
        "manifest_cid": manifest_pointer,

        # post counts
        "manifest_posts": total,
        "manifest_posts_total": total,
        "manifest_posts_by_client": by_client,
    }
