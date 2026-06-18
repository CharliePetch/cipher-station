# orbit_node/pqcrypto.py
"""
Post-quantum cryptographic primitives for Orbit.

Two NIST-standardized schemes:
  * ML-KEM-768  (FIPS 203)  -> content envelopes / key wrapping
  * ML-DSA-65   (FIPS 204)  -> device-auth request signatures

ML-KEM is a Key Encapsulation Mechanism: it produces a *random* shared secret,
it does not encrypt a caller-chosen plaintext. To wrap a chosen 32-byte post
key we use the standard KEM-DEM construction:

    shared_secret, kem_ct = ML-KEM.encaps(recipient_pub)
    wrap_key = BLAKE2b(shared_secret, person="orbit-kem")
    sealed   = SecretBox(wrap_key).encrypt(post_key)
    envelope = len(kem_ct) || kem_ct || sealed        (hex-encoded)

The symmetric layer (SecretBox / XSalsa20-Poly1305, 256-bit key) is already
quantum-resistant; the KEM only protects the wrapping step.

Backends
--------
The actual ML-KEM / ML-DSA math is provided by a pluggable backend:

  * "liboqs"  -> the Open Quantum Safe C library (constant-time, hardened),
                 via the `oqs` Python binding. Preferred when available.
  * "python"  -> pure-Python kyber-py / dilithium-py. Always available, installs
                 with no native build (piwheels-friendly on a Raspberry Pi), but
                 NOT constant-time / self-described as educational.

Selection is controlled by the ORBIT_PQC_BACKEND env var:
  * "auto" (default) -> use liboqs if it imports AND passes a self-test, else python
  * "liboqs"         -> require liboqs (raises if unavailable)
  * "python"         -> force pure-Python

Both backends implement the same FIPS standards with identical key/ciphertext/
signature encodings, so envelopes and signatures are interoperable across them
and the KEM-DEM wire format is backend-independent.
"""

import hashlib
import logging
import os

from nacl.secret import SecretBox

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
_MLKEM_ALG = "ML-KEM-768"
_MLDSA_ALG = "ML-DSA-65"


# ===========================================================================
# Backends
#
# Each backend exposes the same normalized interface:
#   mlkem_keygen()        -> (public_bytes, secret_bytes)
#   mlkem_encaps(pub)     -> (shared_secret, ciphertext)
#   mlkem_decaps(sec, ct) -> shared_secret
#   mldsa_keygen()        -> (public_bytes, secret_bytes)
#   mldsa_sign(sec, msg)  -> signature_bytes
#   mldsa_verify(pub, msg, sig) -> bool
# ===========================================================================

class _PurePythonBackend:
    name = "python"

    def __init__(self):
        from kyber_py.ml_kem import ML_KEM_768
        from dilithium_py.ml_dsa import ML_DSA_65
        self._kem = ML_KEM_768
        self._sig = ML_DSA_65

    def mlkem_keygen(self):
        ek, dk = self._kem.keygen()
        return ek, dk

    def mlkem_encaps(self, pub):
        # kyber-py returns (shared_secret, ciphertext)
        ss, ct = self._kem.encaps(pub)
        return ss, ct

    def mlkem_decaps(self, sec, ct):
        return self._kem.decaps(sec, ct)

    def mldsa_keygen(self):
        pk, sk = self._sig.keygen()
        return pk, sk

    def mldsa_sign(self, sec, msg):
        return self._sig.sign(sec, msg)

    def mldsa_verify(self, pub, msg, sig):
        return bool(self._sig.verify(pub, msg, sig))


class _LiboqsBackend:
    name = "liboqs"

    def __init__(self):
        import oqs  # raises ImportError if the binding/native lib is absent
        self._oqs = oqs
        if _MLKEM_ALG not in oqs.get_enabled_kem_mechanisms():
            raise RuntimeError(f"{_MLKEM_ALG} not enabled in this liboqs build")
        if _MLDSA_ALG not in oqs.get_enabled_sig_mechanisms():
            raise RuntimeError(f"{_MLDSA_ALG} not enabled in this liboqs build")

    def mlkem_keygen(self):
        with self._oqs.KeyEncapsulation(_MLKEM_ALG) as kem:
            pub = kem.generate_keypair()
            sec = kem.export_secret_key()
        return pub, sec

    def mlkem_encaps(self, pub):
        # liboqs returns (ciphertext, shared_secret) — normalize to (ss, ct)
        with self._oqs.KeyEncapsulation(_MLKEM_ALG) as kem:
            ct, ss = kem.encap_secret(pub)
        return ss, ct

    def mlkem_decaps(self, sec, ct):
        with self._oqs.KeyEncapsulation(_MLKEM_ALG, secret_key=sec) as kem:
            return kem.decap_secret(ct)

    def mldsa_keygen(self):
        with self._oqs.Signature(_MLDSA_ALG) as sig:
            pub = sig.generate_keypair()
            sec = sig.export_secret_key()
        return pub, sec

    def mldsa_sign(self, sec, msg):
        with self._oqs.Signature(_MLDSA_ALG, secret_key=sec) as sig:
            return sig.sign(msg)

    def mldsa_verify(self, pub, msg, sig):
        with self._oqs.Signature(_MLDSA_ALG) as verifier:
            return bool(verifier.verify(msg, sig, pub))


def _self_test(backend) -> None:
    """Round-trip both schemes so a broken/incompatible backend never goes live."""
    pub, sec = backend.mlkem_keygen()
    ss, ct = backend.mlkem_encaps(pub)
    if backend.mlkem_decaps(sec, ct) != ss or len(ss) != 32:
        raise RuntimeError("ML-KEM self-test failed")
    pk, sk = backend.mldsa_keygen()
    msg = b"orbit-pqc-backend-selftest"
    sig = backend.mldsa_sign(sk, msg)
    if not backend.mldsa_verify(pk, msg, sig) or backend.mldsa_verify(pk, msg + b"x", sig):
        raise RuntimeError("ML-DSA self-test failed")


def _select_backend():
    pref = os.getenv("ORBIT_PQC_BACKEND", "auto").strip().lower()

    if pref in ("python", "pure", "kyber-py"):
        b = _PurePythonBackend()
        logger.info("PQC backend: pure-Python (forced)")
        return b

    if pref in ("liboqs", "oqs"):
        b = _LiboqsBackend()       # explicit request: let failure surface
        _self_test(b)
        logger.info("PQC backend: liboqs (constant-time, forced)")
        return b

    # auto: prefer the hardened backend, fall back gracefully
    try:
        b = _LiboqsBackend()
        _self_test(b)
        logger.info("PQC backend: liboqs (constant-time)")
        return b
    except Exception as e:
        logger.info("PQC backend: pure-Python (liboqs unavailable: %s)", e)
        return _PurePythonBackend()


_BACKEND = _select_backend()


def active_backend() -> str:
    """Return the name of the active PQC backend: 'liboqs' or 'python'."""
    return _BACKEND.name


# ---------------------------------------------------------------------------
# Key generation
# ---------------------------------------------------------------------------

def generate_mlkem_keypair() -> tuple[bytes, bytes]:
    """Return (public_key, secret_key) for ML-KEM-768 (content encryption)."""
    return _BACKEND.mlkem_keygen()


def generate_mldsa_keypair() -> tuple[bytes, bytes]:
    """Return (public_key, secret_key) for ML-DSA-65 (auth signatures)."""
    return _BACKEND.mldsa_keygen()


# ---------------------------------------------------------------------------
# ML-KEM-768 content envelopes (KEM-DEM) — wire format is backend-independent
# ---------------------------------------------------------------------------

def _wrap_key_from_shared(shared_secret: bytes) -> bytes:
    return hashlib.blake2b(shared_secret, digest_size=32, person=_KEM_PERSON).digest()


def seal_key(sym_key: bytes, mlkem_pub_hex: str) -> str | None:
    """
    Wrap a 32-byte post symmetric key to a recipient's ML-KEM-768 public key.
    Returns a hex envelope, or None if the public key is malformed.
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

    shared_secret, kem_ct = _BACKEND.mlkem_encaps(ek)
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

        shared_secret = _BACKEND.mlkem_decaps(mlkem_secret, kem_ct)
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
    return _BACKEND.mldsa_sign(mldsa_secret, msg)


def verify(mldsa_pub: bytes, msg: bytes, sig: bytes) -> bool:
    """Verify an ML-DSA-65 signature. Returns False on any error (never raises)."""
    try:
        return bool(_BACKEND.mldsa_verify(mldsa_pub, msg, sig))
    except Exception as e:
        logger.debug("ML-DSA verify error: %s", e)
        return False
