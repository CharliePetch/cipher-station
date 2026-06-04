# orbit_node/following.py

from typing import Dict, List
from orbit_node.database import get_db


def follow_user(uid: str, mlkem_public_key: str, endpoint: str,
                mldsa_public_key: str = None, ipns_id: str = None) -> None:
    """
    Registers an outbound follow relationship.
    Stores the target's ML-KEM public key (content) and optionally their
    ML-DSA public key. ipns_id is the target's IPFS peer ID for IPNS discovery.
    """
    db = get_db()
    db.execute(
        """
        INSERT OR REPLACE INTO following(uid, mlkem_public_key, mldsa_public_key, endpoint, ipns_id)
        VALUES (?, ?, ?, ?, ?)
        """,
        (uid, mlkem_public_key, mldsa_public_key, endpoint, ipns_id)
    )
    db.commit()


def unfollow_user(uid: str) -> None:
    """
    Deletes an outbound follow relationship.
    """
    db = get_db()
    db.execute("DELETE FROM following WHERE uid = ?", (uid,))
    db.commit()


def list_following() -> List[Dict]:
    """Returns a list of all outbound follow relationships."""
    db = get_db()
    rows = db.execute(
        "SELECT uid, mlkem_public_key, mldsa_public_key, endpoint, ipns_id FROM following ORDER BY uid"
    ).fetchall()
    return [dict(r) for r in rows]


def get_following(uid: str) -> Dict | None:
    """Returns a single outbound follow record for a user."""
    db = get_db()
    row = db.execute(
        "SELECT uid, mlkem_public_key, mldsa_public_key, endpoint, ipns_id FROM following WHERE uid = ?",
        (uid,)
    ).fetchone()
    return dict(row) if row else None
