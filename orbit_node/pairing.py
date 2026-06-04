# orbit_node/pairing.py

import hashlib
import secrets
import time
from dataclasses import dataclass

from orbit_node import pqcrypto
from orbit_node.database import get_db

PIN_LEN = 6
TTL_SECONDS = 5 * 60
MAX_ATTEMPTS = 5

def _init_schema():
    conn = get_db()
    conn.execute("""
    CREATE TABLE IF NOT EXISTS pairing_sessions (
        pairing_id TEXT PRIMARY KEY,
        created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        device_uid TEXT NOT NULL,
        device_mlkem_public_key TEXT NOT NULL,
        device_mldsa_public_key TEXT NOT NULL,
        salt_hex TEXT NOT NULL,
        pin_hash_hex TEXT NOT NULL,
        attempts INTEGER NOT NULL DEFAULT 0,
        status TEXT NOT NULL DEFAULT 'pending'
    )
    """)
    conn.commit()

def _is_hex(s: str) -> bool:
    try:
        bytes.fromhex(s)
        return True
    except Exception:
        return False

def _hash_pin(pin: str, salt: bytes) -> bytes:
    # Slow-ish hash to make online guessing less attractive
    return hashlib.scrypt(pin.encode("utf-8"), salt=salt, n=2**14, r=8, p=1, dklen=32)

@dataclass(frozen=True)
class PairingSession:
    pairing_id: str
    pin: str
    expires_at: int

def create_pairing_session(device_uid: str, device_mlkem_public_key: str,
                           device_mldsa_public_key: str) -> PairingSession:
    _init_schema()

    if not device_uid:
        raise ValueError("device_uid required")

    if (not device_mlkem_public_key
            or len(device_mlkem_public_key) != pqcrypto.MLKEM_PUBLIC_HEX
            or not _is_hex(device_mlkem_public_key)):
        raise ValueError(f"device_mlkem_public_key must be {pqcrypto.MLKEM_PUBLIC_HEX} hex chars")

    if (not device_mldsa_public_key
            or len(device_mldsa_public_key) != pqcrypto.MLDSA_PUBLIC_HEX
            or not _is_hex(device_mldsa_public_key)):
        raise ValueError(f"device_mldsa_public_key must be {pqcrypto.MLDSA_PUBLIC_HEX} hex chars")

    now = int(time.time())
    pairing_id = secrets.token_urlsafe(18)
    pin = f"{secrets.randbelow(10**PIN_LEN):0{PIN_LEN}d}"
    expires_at = now + TTL_SECONDS

    salt = secrets.token_bytes(16)
    pin_hash = _hash_pin(pin, salt)

    conn = get_db()
    conn.execute(
        """
        INSERT INTO pairing_sessions
        (pairing_id, created_at, expires_at, device_uid, device_mlkem_public_key,
         device_mldsa_public_key, salt_hex, pin_hash_hex, attempts, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, 'pending')
        """,
        (pairing_id, now, expires_at, device_uid, device_mlkem_public_key,
         device_mldsa_public_key, salt.hex(), pin_hash.hex())
    )
    conn.commit()

    return PairingSession(pairing_id=pairing_id, pin=pin, expires_at=expires_at)

def confirm_pairing_session(pairing_id: str, pin: str) -> tuple[str, str, str]:
    """
    Returns (device_uid, device_mlkem_public_key, device_mldsa_public_key)
    if PIN matches and session is valid.
    """
    _init_schema()
    conn = get_db()

    row = conn.execute(
        """
        SELECT device_uid, device_mlkem_public_key, device_mldsa_public_key,
               expires_at, salt_hex, pin_hash_hex, attempts, status
        FROM pairing_sessions
        WHERE pairing_id=?
        """,
        (pairing_id,)
    ).fetchone()

    if not row:
        raise ValueError("pairing_id not found")

    (device_uid, device_mlkem_public_key, device_mldsa_public_key,
     expires_at, salt_hex, pin_hash_hex, attempts, status) = row
    now = int(time.time())

    if status != "pending":
        raise ValueError(f"pairing session is not pending (status={status})")

    if now > int(expires_at):
        conn.execute("UPDATE pairing_sessions SET status='expired' WHERE pairing_id=?", (pairing_id,))
        conn.commit()
        raise ValueError("pairing session expired")

    if int(attempts) >= MAX_ATTEMPTS:
        conn.execute("UPDATE pairing_sessions SET status='locked' WHERE pairing_id=?", (pairing_id,))
        conn.commit()
        raise ValueError("pairing session locked (too many attempts)")

    salt = bytes.fromhex(salt_hex)
    expected = bytes.fromhex(pin_hash_hex)
    got = _hash_pin(pin, salt)

    if not secrets.compare_digest(expected, got):
        conn.execute(
            "UPDATE pairing_sessions SET attempts = attempts + 1 WHERE pairing_id=?",
            (pairing_id,)
        )
        conn.commit()
        raise ValueError("invalid PIN")

    conn.execute(
        "UPDATE pairing_sessions SET status='confirmed' WHERE pairing_id=?",
        (pairing_id,)
    )
    conn.commit()

    return device_uid, device_mlkem_public_key, device_mldsa_public_key
