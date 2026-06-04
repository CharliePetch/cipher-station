# orbit_node/pqcrypto.py
"""
Post-quantum cryptographic primitives for Orbit.

Two schemes, both NIST-standardized and implemented in pure Python (so they
install cleanly on a Raspberry Pi via piwheels with no native build):

  * ML-KEM-768  (FIPS 203, via kyber-py)   -> content envelopes / key wrapping
  * ML-DSA-65   (FIPS 204, via dilithium-py) -> device-auth request signatures

ML-KEM is a Key Encapsulation Mechanism: it produces a *random* shared secret,
it does not encrypt a caller-chosen plaintext. To wrap a chosen 32-byte post
key we use the standard KEM-DEM construction:

    encaps(recipient_pub) -> (shared_secret, kem_ct)
    wrap_key = BLAKE2b(shared_secret, person="orbit-kem")
    sealed   = SecretBox(wrap_key).encrypt(post_key)
    envelope = len(kem_ct) || kem_ct || sealed        (hex-encoded)

The symmetric layer (SecretBox / XSalsa20-Poly1305, 256-bit key) is already
quantum-resistant on its own; the KEM only protects the wrapping step.

NOTE: kyber-py / dilithium-py are pure-Python and NOT constant-time. In Orbit's
model decapsulation and signing happen on the client device (never as a
server-side oracle for an attacker), so timing side-channels are low-risk here.
This is not, however, a hardened production crypto stack.
"""

import hashlib
import logging

from nacl.secret import SecretBox
from kyber_py.ml_kem import ML_KEM_768
from dilithium_py.ml_dsa import ML_DSA_65

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Algorithm parameter sizes (bytes) — used for input validation.
# ---------------------------------------------------------------------------
MLKEM_PUBLIC_BYTES = 1184   # encapsulation key (ek)
MLKEM_SECRET_BYTES = 2400   # decapsulation key (dk)
MLKEM_CT_BYTES = 1088       # KEM ciphertext

MLDSA_PUBLIC_BYTES = 1952
MLDSA_SECRET_BYTES = 4032

# Convenience: expected hex-string lengths for public keys.
MLKEM_PUBLIC_HEX = MLKEM_PUBLIC_BYTES * 2   # 2368
MLDSA_PUBLIC_HEX = MLDSA_PUBLIC_BYTES * 2   # 3904

_KEM_PERSON = b"orbit-kem"


# ---------------------------------------------------------------------------
# Key generation
# ---------------------------------------------------------------------------

def generate_mlkem_keypair() -> tuple[bytes, bytes]:
    """Return (public_key, secret_key) for ML-KEM-768 (content encryption)."""
    ek, dk = ML_KEM_768.keygen()
    return ek, dk


def generate_mldsa_keypair() -> tuple[bytes, bytes]:
    """Return (public_key, secret_key) for ML-DSA-65 (auth signatures)."""
    pk, sk = ML_DSA_65.keygen()
    return pk, sk


# ---------------------------------------------------------------------------
# ML-KEM-768 content envelopes (KEM-DEM)
# ---------------------------------------------------------------------------

def _wrap_key_from_shared(shared_secret: bytes) -> bytes:
    return hashlib.blake2b(shared_secret, digest_size=32, person=_KEM_PERSON).digest()


def seal_key(sym_key: bytes, mlkem_pub_hex: str) -> str | None:
    """
    Wrap a 32-byte post symmetric key to a recipient's ML-KEM-768 public key.

    Returns a hex envelope (len-prefixed kem_ct || SecretBox(wrap_key, sym_key)),
    or None if the public key is malformed.
    """
    key_hex = mlkem_pub_hex.strip().lower()
    if len(key_hex) != MLKEM_PUBLIC_HEX:
        logger.warning("Skipping recipient (bad ML-KEM pubkey length): %d", len(key_hex))
        return None
    try:
        ek = bytes.fromhex(key_hex)
    except ValueError:
        logger.warning("Skipping recipient (non-hex ML-KEM pubkey)")
        return None

    shared_secret, kem_ct = ML_KEM_768.encaps(ek)
    wrap_key = _wrap_key_from_shared(shared_secret)
    sealed = SecretBox(wrap_key).encrypt(sym_key)

    envelope = len(kem_ct).to_bytes(2, "big") + kem_ct + sealed
    return envelope.hex()


def open_key(mlkem_secret: bytes, envelope_hex: str) -> bytes | None:
    """
    Recover a wrapped symmetric key using an ML-KEM-768 secret (decapsulation) key.
    Returns the symmetric key bytes, or None on any failure.
    """
    try:
        raw = bytes.fromhex(envelope_hex)
        ct_len = int.from_bytes(raw[:2], "big")
        kem_ct = raw[2:2 + ct_len]
        sealed = raw[2 + ct_len:]
        if len(kem_ct) != ct_len:
            raise ValueError("truncated KEM ciphertext")

        shared_secret = ML_KEM_768.decaps(mlkem_secret, kem_ct)
        wrap_key = _wrap_key_from_shared(shared_secret)
        return SecretBox(wrap_key).decrypt(sealed)
    except Exception as e:
        logger.error("ML-KEM envelope open failed: %s", e)
        return None


# ---------------------------------------------------------------------------
# ML-DSA-65 auth signatures
# ---------------------------------------------------------------------------

def sign(mldsa_secret: bytes, msg: bytes) -> bytes:
    """Sign a message with an ML-DSA-65 secret key. Returns the signature bytes."""
    return ML_DSA_65.sign(mldsa_secret, msg)


def verify(mldsa_pub: bytes, msg: bytes, sig: bytes) -> bool:
    """Verify an ML-DSA-65 signature. Returns False on any error (never raises)."""
    try:
        return bool(ML_DSA_65.verify(mldsa_pub, msg, sig))
    except Exception as e:
        logger.debug("ML-DSA verify error: %s", e)
        return False
