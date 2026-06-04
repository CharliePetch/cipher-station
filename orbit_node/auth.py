# orbit_node/auth.py
import base64
import hmac
import logging
import time
from fastapi import Header, HTTPException, Request

from orbit_node import pqcrypto
from orbit_node.followers import list_follower_devices
from orbit_node.database import get_db

logger = logging.getLogger(__name__)

MAX_SKEW_SECONDS = 60
NONCE_TTL_SECONDS = 60 * 60 * 24  # keep for 24h


def _canonical(method: str, path: str, uid: str, device_uid: str, ts: str, nonce: str, body_sha256: str) -> bytes:
    """
    Must match the client exactly:
      METHOD\nPATH\nUID\nDEVICE_UID\nTS\nNONCE\nBODY_SHA256
    The device signs this string with its ML-DSA-65 secret key.
    """
    s = "\n".join([method.upper(), path, uid, device_uid, ts, nonce, body_sha256])
    return s.encode("utf-8")


def _nonce_seen(uid: str, device_uid: str, nonce: str) -> bool:
    db = get_db()
    cur = db.cursor()
    cur.execute(
        "SELECT 1 FROM auth_nonces WHERE uid=? AND device_uid=? AND nonce=?",
        (uid, device_uid, nonce),
    )
    return cur.fetchone() is not None


def _remember_nonce(uid: str, device_uid: str, nonce: str, ts: int):
    db = get_db()
    cur = db.cursor()
    cur.execute(
        "INSERT OR REPLACE INTO auth_nonces(uid, device_uid, nonce, ts) VALUES(?,?,?,?)",
        (uid, device_uid, nonce, ts),
    )
    db.commit()


def _cleanup_nonces(now_ts: int):
    cutoff = now_ts - NONCE_TTL_SECONDS
    db = get_db()
    cur = db.cursor()
    cur.execute("DELETE FROM auth_nonces WHERE ts < ?", (cutoff,))
    db.commit()


async def require_delegate(
    request: Request,
    x_orbit_uid: str = Header(..., alias="x-orbit-uid"),
    x_orbit_device: str = Header(..., alias="x-orbit-device"),
    x_orbit_ts: str = Header(..., alias="x-orbit-ts"),
    x_orbit_nonce: str = Header(..., alias="x-orbit-nonce"),
    x_orbit_body_sha256: str = Header(..., alias="x-orbit-body-sha256"),
    x_orbit_sig: str = Header(..., alias="x-orbit-sig"),
):
    # 1) time window
    try:
        ts_i = int(x_orbit_ts)
    except Exception:
        raise HTTPException(401, "bad timestamp")

    now = int(time.time())
    if abs(now - ts_i) > MAX_SKEW_SECONDS:
        raise HTTPException(401, "stale request")

    # optional cleanup occasionally
    if (now % 100) == 0:
        try:
            _cleanup_nonces(now)
        except Exception:
            pass

    # 2) device must be authorized (+ Allowed) and have an ML-DSA auth key
    devices = list_follower_devices(x_orbit_uid)
    dev = next(
        (d for d in devices if d.get("device_uid") == x_orbit_device and d.get("allowed") == "Allowed"),
        None,
    )
    if not dev:
        raise HTTPException(403, "device not authorized")

    mldsa_pub_hex = dev.get("mldsa_public_key")
    if not mldsa_pub_hex:
        raise HTTPException(403, "device has no auth (ML-DSA) public key")

    # 3) replay protection (check before recording; store only after auth succeeds)
    if _nonce_seen(x_orbit_uid, x_orbit_device, x_orbit_nonce):
        raise HTTPException(401, "replay")

    # 4) body-hash check WITHOUT consuming stream (set by the capture middleware)
    cached_sha = getattr(request.state, "raw_body_sha256", None)
    if cached_sha is not None:
        if not hmac.compare_digest(cached_sha, x_orbit_body_sha256.lower()):
            raise HTTPException(401, "bad body hash")
    # else: skip (assumes TLS / trusted path); still bound into the signed string.

    # 5) verify ML-DSA-65 signature over the canonical request string
    try:
        mldsa_pub = bytes.fromhex(mldsa_pub_hex)
    except ValueError:
        raise HTTPException(401, "bad device auth public key")
    if len(mldsa_pub) != pqcrypto.MLDSA_PUBLIC_BYTES:
        raise HTTPException(401, "bad device auth public key length")

    try:
        sig = base64.b64decode(x_orbit_sig, validate=True)
    except Exception:
        raise HTTPException(401, "bad signature encoding")

    msg = _canonical(
        request.method,
        request.url.path,
        x_orbit_uid,
        x_orbit_device,
        x_orbit_ts,
        x_orbit_nonce,
        x_orbit_body_sha256.lower(),
    )

    if not pqcrypto.verify(mldsa_pub, msg, sig):
        raise HTTPException(401, "bad auth")

    # 6) remember nonce only after successful verification
    _remember_nonce(x_orbit_uid, x_orbit_device, x_orbit_nonce, ts_i)

    return {"uid": x_orbit_uid, "device_uid": x_orbit_device}
