"""
Content envelopes: wrap a post's symmetric key to a recipient's public key.

Post-quantum (ML-KEM-768) via cipher_station.pqcrypto. A recipient "public key" here
is an ML-KEM-768 encapsulation key (hex, 2368 chars). The wire format is the
length-prefixed KEM-DEM envelope produced by pqcrypto.seal_key.
"""

import logging

from cipher_station import pqcrypto

logger = logging.getLogger(__name__)


def create_symmetric_key() -> bytes:
    """Create a 32-byte symmetric key for encrypting a post."""
    from nacl.secret import SecretBox
    from nacl.utils import random as nacl_random
    return nacl_random(SecretBox.KEY_SIZE)


def encrypt_key_for_follower(sym_key: bytes, follower_mlkem_pub_hex: str) -> str | None:
    """
    Wrap sym_key to a follower's ML-KEM-768 public key.
    Returns the hex envelope, or None if the key is invalid.
    """
    return pqcrypto.seal_key(sym_key, follower_mlkem_pub_hex)


def open_envelope(mlkem_secret: bytes, envelope_hex: str) -> bytes | None:
    """
    Decrypt an ML-KEM envelope (hex) with the recipient's ML-KEM secret key.
    Returns the recovered symmetric key, or None on failure.
    """
    return pqcrypto.open_key(mlkem_secret, envelope_hex)
