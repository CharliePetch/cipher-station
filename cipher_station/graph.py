# cipher_station/graph.py

import json
import uuid
from nacl.secret import SecretBox
from nacl.utils import random as nacl_random

from cipher_station.config import PUBLIC_JSON_PATH, BASE_DIR
from cipher_station.ipfs_client import ipfs_add_bytes
from cipher_station.ipns_publisher import request_publish
from cipher_station.storage import write_json, STATE_LOCK
from cipher_station.followers import list_followers
from cipher_station.following import list_following
from cipher_station.envelopes import encrypt_key_for_follower


# ---------------------------------------------------------
# ENCRYPTION HELPERS
# ---------------------------------------------------------

def encrypt_json_graph(obj: dict, key: bytes) -> bytes:
    """Encrypts a graph JSON dict with SecretBox."""
    box = SecretBox(key)
    raw = json.dumps(obj).encode()
    return box.encrypt(raw)


def publish_encrypted(obj: dict, key: bytes) -> str:
    """Encrypt and publish graph JSON to IPFS. Returns CID."""
    encrypted_bytes = encrypt_json_graph(obj, key)
    return ipfs_add_bytes(encrypted_bytes)


# ---------------------------------------------------------
# REBUILD GRAPHS + ENVELOPES WITH EPHEMERAL KEY
# ---------------------------------------------------------

def rebuild_graphs_and_envelopes():
    """
    Rebuilds:
      - following_cid
      - followers_cid
      - follow_decoder_envelopes_cid

    AND writes unencrypted versions to /cipher_station_data/ for local inspection.
    """

    # 1. Generate a new symmetric key
    key = nacl_random(SecretBox.KEY_SIZE)

    # ------------------------------------------------------
    # 2. Outbound following graph
    # ------------------------------------------------------
    following = list_following()
    following_graph = {
        "version": 1,
        "updated_at": uuid.uuid4().hex,
        "following": following
    }
    following_cid = publish_encrypted(following_graph, key)

    # Write plaintext following graph locally
    (BASE_DIR / "following.json").write_text(
        json.dumps(following_graph, indent=2)
    )

    # ------------------------------------------------------
    # 3. Inbound followers graph (allowed only)
    # ------------------------------------------------------
    all_followers = list_followers()
    allowed_followers = [f for f in all_followers if f.get("allowed") == "Allowed"]

    followers_graph = {
        "version": 1,
        "updated_at": uuid.uuid4().hex,
        "followers": allowed_followers
    }
    followers_cid = publish_encrypted(followers_graph, key)

    # Write plaintext followers graph locally
    (BASE_DIR / "followers.json").write_text(
        json.dumps(followers_graph, indent=2)
    )

    # ------------------------------------------------------
    # 4. Build decoder envelopes for allowed followers
    # ------------------------------------------------------
    envelopes = {}

    for f in allowed_followers:
        follower_uid = f["uid"]
        follower_pubkey = f["mlkem_public_key"]
        device_uid = f["device_uid"]

        envelopes.setdefault(follower_uid, [])
        envelope_hex = encrypt_key_for_follower(key, follower_pubkey)

        envelopes[follower_uid].append({
            "device_uid": device_uid,
            "envelope": envelope_hex
        })

    envelope_obj = {
        "version": 1,
        "envelopes": envelopes
    }
    envelope_bytes = json.dumps(envelope_obj).encode()
    follow_decoder_envelopes_cid = ipfs_add_bytes(envelope_bytes)

    # Write plaintext envelopes locally
    (BASE_DIR / "follow_envelopes.json").write_text(
        json.dumps(envelope_obj, indent=2)
    )

    # ------------------------------------------------------
    # 5. Write all 3 CIDs to public.json
    # ------------------------------------------------------
    with STATE_LOCK:
        public_json = json.loads(PUBLIC_JSON_PATH.read_text())

        public_json["following_cid"] = following_cid
        public_json["followers_cid"] = followers_cid
        public_json["follow_decoder_envelopes_cid"] = follow_decoder_envelopes_cid

        write_json(PUBLIC_JSON_PATH, public_json)

    # Republish to IPFS + IPNS so the decentralized pointer stays current
    # (queued to the background worker — never blocks the request thread)
    request_publish()

    return {
        "following_cid": following_cid,
        "followers_cid": followers_cid,
        "follow_decoder_envelopes_cid": follow_decoder_envelopes_cid
    }
