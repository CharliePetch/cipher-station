"""
Low-level key material helpers.

Post-quantum key generation and content/auth primitives live in
`cipher_station.pqcrypto` (ML-KEM-768 + ML-DSA-65). This module keeps only the
password-based **encryption-at-rest** wrapper used to protect the station's
secret key files on disk (Argon2i + SecretBox), which is algorithm-agnostic.
"""

import nacl.utils
from nacl.secret import SecretBox
from nacl.pwhash import argon2i


def encrypt_private_keys(private_bytes: bytes, password: str) -> bytes:
    """Encrypt secret-key bytes at rest with an Argon2i-derived SecretBox key."""
    salt = nacl.utils.random(16)
    key = argon2i.kdf(32, password.encode(), salt)
    box = SecretBox(key)
    encrypted = box.encrypt(private_bytes)
    return salt + encrypted


def decrypt_private_keys(bundle: bytes, password: str) -> bytes:
    """Reverse of encrypt_private_keys."""
    salt = bundle[:16]
    ciphertext = bundle[16:]
    key = argon2i.kdf(32, password.encode(), salt)
    box = SecretBox(key)
    return box.decrypt(ciphertext)
