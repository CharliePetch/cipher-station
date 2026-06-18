# orbit_node/identity.py

import json
import logging
import uuid
from dataclasses import dataclass
from pathlib import Path

from orbit_node import pqcrypto
from orbit_node.crypto import encrypt_private_keys, decrypt_private_keys
from orbit_node.config import KEYS_DIR, PUBLIC_JSON_PATH, ORBIT_PASSWORD, ensure_directories

logger = logging.getLogger(__name__)

# Secret-key files. Each stores  public_key || secret_key  so the public key is
# always recoverable from the file alone (optionally encrypted-at-rest when
# ORBIT_PASSWORD is set). X25519 (the old 64-byte private.bin) is gone.
MLKEM_KEY_PATH = KEYS_DIR / "mlkem.bin"   # ek(1184) || dk(2400)
MLDSA_KEY_PATH = KEYS_DIR / "mldsa.bin"   # pk(1952) || sk(4032)

_MLKEM_BUNDLE_LEN = pqcrypto.MLKEM_PUBLIC_BYTES + pqcrypto.MLKEM_SECRET_BYTES
_MLDSA_BUNDLE_LEN = pqcrypto.MLDSA_PUBLIC_BYTES + pqcrypto.MLDSA_SECRET_BYTES

# Cached identity
_cached_identity = None


@dataclass(frozen=True)
class Identity:
    """The station's post-quantum identity."""
    mlkem_sk: bytes        # ML-KEM-768 decapsulation key (content)
    mldsa_sk: bytes        # ML-DSA-65 secret key (auth signing)
    mlkem_pub_hex: str     # ML-KEM-768 encapsulation key (hex)
    mldsa_pub_hex: str     # ML-DSA-65 public key (hex)
    public_json: dict

    @property
    def uid(self) -> str | None:
        return self.public_json.get("uid")


# -----------------------------------------------------------
# Key file helpers (with optional encryption-at-rest)
# -----------------------------------------------------------

def _write_key_bundle(path: Path, pub: bytes, sec: bytes, password: str | None) -> None:
    KEYS_DIR.mkdir(parents=True, exist_ok=True)
    blob = pub + sec
    if password:
        blob = encrypt_private_keys(blob, password)
    path.write_bytes(blob)


def _read_key_bundle(path: Path, expected_len: int, pub_len: int,
                     password: str | None) -> tuple[bytes, bytes]:
    raw = path.read_bytes()
    if password:
        raw = decrypt_private_keys(raw, password)
    if len(raw) != expected_len:
        raise ValueError(
            f"{path.name} is {len(raw)} bytes after decoding, expected {expected_len}. "
            "If ORBIT_PASSWORD changed, the key cannot be decrypted."
        )
    return raw[:pub_len], raw[pub_len:]


# -----------------------------------------------------------
# public.json
# -----------------------------------------------------------

def _write_public_json(obj: dict, mlkem_pub_hex: str, mldsa_pub_hex: str) -> dict:
    obj["mlkem_public_key"] = mlkem_pub_hex
    obj["mldsa_public_key"] = mldsa_pub_hex
    obj.pop("public_key", None)  # remove legacy X25519 field if present
    PUBLIC_JSON_PATH.write_text(json.dumps(obj, indent=2))
    return obj


# -----------------------------------------------------------
# Cached identity accessor (used by all server modules)
# -----------------------------------------------------------

def get_identity() -> Identity:
    """Return the cached station Identity, loading from disk on first call."""
    global _cached_identity
    if _cached_identity is None:
        _cached_identity = load_identity(password=ORBIT_PASSWORD or None)
        logger.info("Identity loaded and cached")
    return _cached_identity


# -----------------------------------------------------------
# Load / bootstrap
# -----------------------------------------------------------

def load_identity(password: str | None = None) -> Identity:
    """Load (or bootstrap) the station's ML-KEM + ML-DSA identity."""
    ensure_directories()

    if MLKEM_KEY_PATH.exists() and MLDSA_KEY_PATH.exists():
        mlkem_pub, mlkem_sk = _read_key_bundle(
            MLKEM_KEY_PATH, _MLKEM_BUNDLE_LEN, pqcrypto.MLKEM_PUBLIC_BYTES, password
        )
        mldsa_pub, mldsa_sk = _read_key_bundle(
            MLDSA_KEY_PATH, _MLDSA_BUNDLE_LEN, pqcrypto.MLDSA_PUBLIC_BYTES, password
        )
        public_json = _load_public_json(mlkem_pub.hex(), mldsa_pub.hex())
        return Identity(mlkem_sk, mldsa_sk, mlkem_pub.hex(), mldsa_pub.hex(), public_json)

    return bootstrap_identity(password=password)


def _load_public_json(mlkem_pub_hex: str, mldsa_pub_hex: str) -> dict:
    if PUBLIC_JSON_PATH.exists():
        obj = json.loads(PUBLIC_JSON_PATH.read_text())
    else:
        obj = {"uid": str(uuid.uuid4()), "alias": None, "endpoint": None,
               "manifest_pointer": None, "followers_cid": None,
               "following_cid": None, "follow_decoder_envelopes_cid": None}
    return _write_public_json(obj, mlkem_pub_hex, mldsa_pub_hex)  # force consistency


def load_public_identity() -> dict:
    """
    Return the *current* public.json from disk.

    public.json is mutated on disk after the cached Identity is first loaded:
    every new post rewrites ``manifest_pointer`` (manifest._update_public_json_
    manifest_pointer), the Cloudflare monitor rewrites ``endpoint``, and graph
    rebuilds rewrite the ``*_cid`` pointers. ``Identity.public_json`` is only a
    startup snapshot, so reading it would make ``/profile`` hand clients a stale
    manifest pointer (and endpoint). Re-read the file each call; fall back to the
    cached snapshot only if the file is unreadable.
    """
    ident = get_identity()  # ensures the identity is bootstrapped + cached
    try:
        return json.loads(PUBLIC_JSON_PATH.read_text())
    except Exception as e:
        logger.warning("load_public_identity: falling back to cached public.json (%s)", e)
        return ident.public_json


def bootstrap_identity(password: str | None = None) -> Identity:
    """Generate a fresh post-quantum identity (ML-KEM + ML-DSA keypairs + UUID)."""
    ensure_directories()

    mlkem_pub, mlkem_sk = pqcrypto.generate_mlkem_keypair()
    mldsa_pub, mldsa_sk = pqcrypto.generate_mldsa_keypair()

    _write_key_bundle(MLKEM_KEY_PATH, mlkem_pub, mlkem_sk, password)
    _write_key_bundle(MLDSA_KEY_PATH, mldsa_pub, mldsa_sk, password)

    uid = str(uuid.uuid4())
    public_json = {
        "alias": None,
        "uid": uid,
        "mlkem_public_key": mlkem_pub.hex(),
        "mldsa_public_key": mldsa_pub.hex(),
        "endpoint": None,
        "manifest_pointer": None,
        # encrypted social graph pointers (initially empty)
        "followers_cid": None,
        "following_cid": None,
        "follow_decoder_envelopes_cid": None,
    }
    PUBLIC_JSON_PATH.write_text(json.dumps(public_json, indent=2))
    logger.info(f"Identity bootstrapped (post-quantum): uid={uid}")

    return Identity(mlkem_sk, mldsa_sk, mlkem_pub.hex(), mldsa_pub.hex(), public_json)
