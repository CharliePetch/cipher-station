# tests/test_crypto.py

import os
import pytest
from nacl.secret import SecretBox
from nacl.utils import random as nacl_random

from cipher_station.crypto import encrypt_private_keys, decrypt_private_keys
from cipher_station import pqcrypto


class TestPQCKeygen:
    def test_mlkem_sizes(self):
        pub, sec = pqcrypto.generate_mlkem_keypair()
        assert len(pub) == pqcrypto.MLKEM_PUBLIC_BYTES
        assert len(sec) == pqcrypto.MLKEM_SECRET_BYTES

    def test_mldsa_sizes(self):
        pub, sec = pqcrypto.generate_mldsa_keypair()
        assert len(pub) == pqcrypto.MLDSA_PUBLIC_BYTES
        assert len(sec) == pqcrypto.MLDSA_SECRET_BYTES

    def test_distinct_keys(self):
        p1, _ = pqcrypto.generate_mlkem_keypair()
        p2, _ = pqcrypto.generate_mlkem_keypair()
        assert p1 != p2


class TestSecretBox:
    def test_round_trip(self):
        key = nacl_random(SecretBox.KEY_SIZE)
        box = SecretBox(key)
        plaintext = b"hello cipher station"
        ct = box.encrypt(plaintext)
        assert box.decrypt(ct) == plaintext

    def test_wrong_key_fails(self):
        key1 = nacl_random(SecretBox.KEY_SIZE)
        key2 = nacl_random(SecretBox.KEY_SIZE)
        ct = SecretBox(key1).encrypt(b"secret data")
        with pytest.raises(Exception):
            SecretBox(key2).decrypt(ct)

    def test_different_ciphertexts(self):
        key = nacl_random(SecretBox.KEY_SIZE)
        box = SecretBox(key)
        ct1 = box.encrypt(b"same data")
        ct2 = box.encrypt(b"same data")
        assert ct1 != ct2  # nonce makes them different


class TestArgon2iKeyEncryption:
    def test_round_trip(self):
        raw = os.urandom(32)
        password = "test-password-123"
        bundle = encrypt_private_keys(raw, password)
        decrypted = decrypt_private_keys(bundle, password)
        assert decrypted == raw

    def test_large_bundle_round_trip(self):
        # ML-DSA secret keys are ~4 KB; ensure the at-rest wrapper handles them.
        raw = os.urandom(pqcrypto.MLDSA_SECRET_BYTES)
        bundle = encrypt_private_keys(raw, "pw")
        assert decrypt_private_keys(bundle, "pw") == raw

    def test_wrong_password_fails(self):
        raw = os.urandom(32)
        bundle = encrypt_private_keys(raw, "correct")
        with pytest.raises(Exception):
            decrypt_private_keys(bundle, "wrong")

    def test_bundle_format(self):
        bundle = encrypt_private_keys(os.urandom(32), "pw")
        # salt (16) + nonce (24) + encrypted (32) + mac (16) = 88
        assert len(bundle) == 16 + 24 + 32 + 16
