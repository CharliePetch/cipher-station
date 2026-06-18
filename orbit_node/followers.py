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
    allowed: str = "Pending",
    endpoint: str = None,
    ipns_id: str = None,
) -> None:
    """
    Registers a device-level follower entry.

    mlkem_public_key : ML-KEM-768 key used to seal content envelopes (required).
    mldsa_public_key : ML-DSA-65 key used to verify this device's signed requests
                       (required for delegate devices that authenticate; may be
                       NULL for read-only content followers).
    allowed          : approval state. Defaults to "Pending" (fail-closed) — a
                       newly-registered follower gets NO content envelopes and
                       cannot authenticate until an owner promotes it to
                       "Allowed" (see approve_follower). Callers that legitimately
                       create an already-trusted principal (the station's own
                       identity, a PIN-paired delegate device) pass
                       allowed="Allowed" explicitly.
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


def remove_follower(uid: str, device_uid: str = None) -> dict:
    """
    Remove a follower. With device_uid, removes that single device row; without
    it, removes every device registered under uid.

    Returns {"removed": <rows deleted>, "removed_allowed": <bool>} where
    removed_allowed is True if any removed device was "Allowed" — the caller uses
    this to decide whether a content/graph rewrap is warranted (rejecting a
    Pending request needs none, since it never held envelopes).
    """
    db = get_db()

    if device_uid is not None:
        rows = db.execute(
            "SELECT allowed FROM followers WHERE uid=? AND device_uid=?",
            (uid, device_uid),
        ).fetchall()
    else:
        rows = db.execute("SELECT allowed FROM followers WHERE uid=?", (uid,)).fetchall()

    removed_allowed = any(r["allowed"] == "Allowed" for r in rows)

    if device_uid is not None:
        cur = db.execute(
            "DELETE FROM followers WHERE uid=? AND device_uid=?", (uid, device_uid)
        )
    else:
        cur = db.execute("DELETE FROM followers WHERE uid=?", (uid,))
    db.commit()

    return {"removed": cur.rowcount, "removed_allowed": removed_allowed}


def approve_follower(uid: str, device_uid: str = None) -> int:
    """
    Promote a pending follower to "Allowed".

    This is the *only* sanctioned way a follower becomes Allowed (and therefore
    receives content envelopes / can authenticate). It must be invoked from an
    owner-authenticated path. Pass device_uid to approve a single device, or
    omit it to approve every device registered under uid.

    Returns the number of rows updated.
    """
    db = get_db()
    if device_uid is not None:
        cur = db.execute(
            "UPDATE followers SET allowed = 'Allowed' WHERE uid = ? AND device_uid = ?",
            (uid, device_uid),
        )
    else:
        cur = db.execute(
            "UPDATE followers SET allowed = 'Allowed' WHERE uid = ?",
            (uid,),
        )
    db.commit()
    return cur.rowcount


def list_pending_followers() -> List[Dict]:
    """Return follower device entries awaiting owner approval (allowed != 'Allowed')."""
    db = get_db()
    rows = db.execute(
        """
        SELECT uid, device_uid, mlkem_public_key, mldsa_public_key, alias, allowed, endpoint, ipns_id
        FROM followers
        WHERE allowed != 'Allowed'
        ORDER BY uid, device_uid
        """
    ).fetchall()
    return [_row_to_follower(r) for r in rows]


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
