# cipher_station/inbox.py

import logging
import os

from cipher_station import pqcrypto
from cipher_station.identity import get_identity

logger = logging.getLogger(__name__)
from cipher_station.followers import (
    add_follower_device,
    list_follower_devices,
)
from cipher_station.rewrap_envelopes import rewrap_all_posts


# -----------------------------
# Safety knobs (dev-friendly)
# -----------------------------
MAX_DEVICES_PER_FOLLOWER = int(os.getenv("CIPHER_MAX_DEVICES_PER_FOLLOWER", "20"))
# If set to "0", disables expensive rewrap_all_posts on follow changes (handy in dev)
AUTO_REWRAP_ON_FOLLOW_CHANGE = os.getenv("CIPHER_AUTO_REWRAP_ON_FOLLOW_CHANGE", "1") != "0"

# ---------------------------------------------------------------------------
# DEV-ONLY: auto-accept inbound follow requests.
#
# /inbox follow requests are UNAUTHENTICATED. When this flag is on, a follow
# request is immediately promoted to "Allowed" and granted content envelopes for
# every "all"-audience post — i.e. anyone who can reach the station can read your
# "all" content with no approval. That is convenient while bootstrapping a dev
# environment but is a full access-control bypass in production.
#
# Default OFF (fail-closed): follow requests are recorded as "Pending" and the
# owner must approve them (POST /followers/approve) before any access is granted.
# Set CIPHER_DEV_AUTO_ACCEPT_FOLLOWS=1 to restore the old auto-accept behavior.
# ---------------------------------------------------------------------------
DEV_AUTO_ACCEPT_FOLLOWS = os.getenv(
    "CIPHER_DEV_AUTO_ACCEPT_FOLLOWS", "0"
).strip().lower() in ("1", "true", "yes", "on")

if DEV_AUTO_ACCEPT_FOLLOWS:
    logger.warning(
        "CIPHER_DEV_AUTO_ACCEPT_FOLLOWS is ON — inbound follow requests are "
        "auto-approved and granted content access. Do NOT use this in production."
    )


def _is_hex(s: str) -> bool:
    try:
        bytes.fromhex(s)
        return True
    except Exception:
        return False


def _is_mlkem_pub(s) -> bool:
    return isinstance(s, str) and len(s) == pqcrypto.MLKEM_PUBLIC_HEX and _is_hex(s)


def _is_mldsa_pub(s) -> bool:
    return isinstance(s, str) and len(s) == pqcrypto.MLDSA_PUBLIC_HEX and _is_hex(s)


def process_inbox_message(mlkem_sk: bytes, message: dict):
    """
    Handles inbox messages:
      - follow_request   (multi-device)
      - post_key_update  (future)
      - manifest_update  (future)

    Behavior:
      - when a follower is newly approved/added (or key changed),
        can trigger follower-envelope rewrap across all posts
        (updates envelopes_cid in each post + republishes manifest pointer)

    mlkem_sk is the station's ML-KEM secret, used to recover each post's
    symmetric key during a rewrap.
    """

    mtype = message.get("type")

    # ---------------------------------------------------------
    # FOLLOW REQUEST (dev auto-accept)
    # ---------------------------------------------------------
    if mtype == "follow_request":
        follower_uid = message.get("uid")
        if not follower_uid:
            return {"error": "follow_request missing uid"}

        # ---------------------------------------------------------
        # SECURITY: never allow follow_request to modify *our own* uid.
        # Prevents an attacker from injecting themselves as a "device"
        # under our uid.
        # ---------------------------------------------------------
        try:
            ident = get_identity()
            my_uid = ident.uid
            if follower_uid == my_uid:
                return {"error": "follow_request cannot target local uid"}
        except Exception as e:
            return {"error": f"identity_load_failed: {e}"}

        changed = False

        # Approval state for newly-registered devices. In production (default)
        # follow requests are recorded as "Pending" and grant no access until the
        # owner approves them; the dev flag restores immediate auto-accept.
        new_allowed = "Allowed" if DEV_AUTO_ACCEPT_FOLLOWS else "Pending"

        # IPNS peer ID (permanent discovery address) if provided
        follower_ipns_id = message.get("ipns_id")

        # Case A: Multi-device follow request payload
        if "devices" in message and message["devices"] is not None:
            devices = message["devices"]
            if not isinstance(devices, list):
                return {"error": "devices field must be a list"}

            existing_rows = list_follower_devices(follower_uid)
            existing = {
                d["device_uid"]: d.get("mlkem_public_key")
                for d in existing_rows
                if d.get("device_uid")
            }

            new_additions = 0

            for dev in devices:
                device_uid = dev.get("device_uid")
                mlkem_pk = dev.get("mlkem_public_key")
                mldsa_pk = dev.get("mldsa_public_key")

                if not device_uid or not mlkem_pk:
                    return {"error": f"Malformed device entry: {dev}"}
                if not _is_mlkem_pub(mlkem_pk):
                    return {"error": f"Bad mlkem_public_key for device {device_uid} (expected {pqcrypto.MLKEM_PUBLIC_HEX} hex chars)"}
                if mldsa_pk is not None and not _is_mldsa_pub(mldsa_pk):
                    return {"error": f"Bad mldsa_public_key for device {device_uid} (expected {pqcrypto.MLDSA_PUBLIC_HEX} hex chars)"}

                # Idempotent: an UNAUTHENTICATED request must never modify a
                # device that is already registered. Otherwise anyone could
                # rotate an Allowed follower's content key to their own (hijack)
                # or flip approval state. Re-requests for known devices are
                # no-ops; a real key rotation must go through owner re-approval.
                if device_uid in existing:
                    continue

                if (len(existing) + new_additions) >= MAX_DEVICES_PER_FOLLOWER:
                    return {"error": f"too many devices for follower (cap={MAX_DEVICES_PER_FOLLOWER})"}
                new_additions += 1

                add_follower_device(
                    follower_uid, device_uid, mlkem_public_key=mlkem_pk,
                    mldsa_public_key=mldsa_pk, ipns_id=follower_ipns_id,
                    allowed=new_allowed,
                )

            # Only an actual grant of access (dev auto-accept) warrants a rewrap.
            if DEV_AUTO_ACCEPT_FOLLOWS and new_additions > 0:
                changed = True

            result = {
                "status": ("follow_accepted_multi_device" if DEV_AUTO_ACCEPT_FOLLOWS
                           else "follow_request_pending_multi_device"),
                "rewrap_triggered": changed,
                "devices_added": new_additions,
                "pending_approval": (0 if DEV_AUTO_ACCEPT_FOLLOWS else new_additions),
            }

        # Case B: Legacy single-device follow request
        else:
            mlkem_pk = message.get("mlkem_public_key")
            mldsa_pk = message.get("mldsa_public_key")
            if not _is_mlkem_pub(mlkem_pk):
                return {"error": f"follow_request mlkem_public_key must be {pqcrypto.MLKEM_PUBLIC_HEX} hex chars"}
            if mldsa_pk is not None and not _is_mldsa_pub(mldsa_pk):
                return {"error": f"follow_request mldsa_public_key must be {pqcrypto.MLDSA_PUBLIC_HEX} hex chars"}

            existing_devices = list_follower_devices(follower_uid)
            existing_uids = {d.get("device_uid") for d in existing_devices}

            # Idempotent for an already-registered device (see Case A rationale).
            if follower_uid in existing_uids:
                return {"status": "follow_request_already_registered", "uid": follower_uid}

            if len(existing_devices) >= MAX_DEVICES_PER_FOLLOWER:
                return {"error": f"too many devices for follower (cap={MAX_DEVICES_PER_FOLLOWER})"}

            add_follower_device(
                follower_uid, device_uid=follower_uid, mlkem_public_key=mlkem_pk,
                mldsa_public_key=mldsa_pk, ipns_id=follower_ipns_id,
                allowed=new_allowed,
            )

            if DEV_AUTO_ACCEPT_FOLLOWS:
                changed = True

            result = {
                "status": ("follow_accepted" if DEV_AUTO_ACCEPT_FOLLOWS
                           else "follow_request_pending"),
                "rewrap_triggered": changed,
                "pending_approval": (0 if DEV_AUTO_ACCEPT_FOLLOWS else 1),
            }

        # If we changed follower state, optionally rewrap follower envelopes for every post
        if changed and AUTO_REWRAP_ON_FOLLOW_CHANGE:
            try:
                result["rewrap"] = rewrap_all_posts(mlkem_sk)
            except Exception as e:
                result["rewrap_error"] = str(e)

        if changed and not AUTO_REWRAP_ON_FOLLOW_CHANGE:
            result["rewrap_skipped"] = True

        return result

    # ---------------------------------------------------------
    elif mtype == "post_key_update":
        return {"status": "unhandled_post_key_update"}

    elif mtype == "manifest_update":
        return {"status": "unhandled_manifest_update"}

    return {"error": f"Unknown inbox message type: {mtype}"}
