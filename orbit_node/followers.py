# orbit_node/followers.py

from typing import List, Dict
from orbit_node.database import get_db


# ---------------------------------------------------------
# INSERT HELPERS
# ---------------------------------------------------------

def add_follower_device(
    uid: str,
    device_uid: str,
    mlkem_public_key: str,
    mldsa_public_key: str = None,
    alias: str = None,
    allowed: str = "Allowed",
    endpoint: str = None,
    ipns_id: str = None,
) -> None:
    """
    Registers a device-level follower entry.

    mlkem_public_key : ML-KEM-768 key used to seal content envelopes (required).
    mldsa_public_key : ML-DSA-65 key used to verify this device's signed requests
                       (required for delegate devices that authenticate; may be
                       NULL for read-only content followers).
    """
    db = get_db()
    db.execute(
        """
        INSERT OR REPLACE INTO followers(
            uid, device_uid, mlkem_public_key, mldsa_public_key, alias, allowed, endpoint, ipns_id
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (uid, device_uid, mlkem_public_key, mldsa_public_key, alias, allowed, endpoint, ipns_id)
    )
    db.commit()


def add_follower(uid: str, mlkem_public_key: str, mldsa_public_key: str = None) -> None:
    """
    Legacy fallback path: follower without device info.
    Uses uid as the device_uid and NULL endpoint.
    """
    add_follower_device(uid, device_uid=uid, mlkem_public_key=mlkem_public_key,
                        mldsa_public_key=mldsa_public_key)


def remove_follower(uid: str) -> None:
    """
    Removes all follower device entries for a given user UID.
    """
    db = get_db()
    db.execute("DELETE FROM followers WHERE uid = ?", (uid,))
    db.commit()


# ---------------------------------------------------------
# LIST HELPERS
# ---------------------------------------------------------

def _row_to_follower(r) -> Dict:
    return {
        "uid": r["uid"],
        "device_uid": r["device_uid"],
        "mlkem_public_key": r["mlkem_public_key"],
        "mldsa_public_key": r["mldsa_public_key"],
        "alias": r["alias"],
        "allowed": r["allowed"],
        "endpoint": r["endpoint"],
        "ipns_id": r["ipns_id"],
    }


def list_followers() -> List[Dict]:
    """Return all follower device entries."""
    db = get_db()
    rows = db.execute(
        """
        SELECT uid, device_uid, mlkem_public_key, mldsa_public_key, alias, allowed, endpoint, ipns_id
        FROM followers
        ORDER BY uid, device_uid
        """
    ).fetchall()
    return [_row_to_follower(r) for r in rows]


def list_follower_devices(uid: str) -> List[Dict]:
    """Return all devices for a single follower."""
    db = get_db()
    rows = db.execute(
        """
        SELECT uid, device_uid, mlkem_public_key, mldsa_public_key, alias, allowed, endpoint, ipns_id
        FROM followers
        WHERE uid = ?
        ORDER BY device_uid
        """,
        (uid,)
    ).fetchall()
    return [_row_to_follower(r) for r in rows]


def list_all_public_keys() -> List[str]:
    """
    Return all ML-KEM public keys across all followers.
    Useful for envelope regeneration.
    """
    db = get_db()
    rows = db.execute("SELECT mlkem_public_key FROM followers").fetchall()
    return [r["mlkem_public_key"] for r in rows]
