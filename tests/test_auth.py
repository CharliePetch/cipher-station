# tests/test_auth.py

import time

import pytest

from cipher_station.auth import _canonical
from cipher_station import pqcrypto


class TestCanonicalString:
    def test_basic_format(self):
        result = _canonical("POST", "/upload", "uid1", "dev1", "12345", "nonce1", "abcd")
        expected = b"POST\n/upload\nuid1\ndev1\n12345\nnonce1\nabcd"
        assert result == expected

    def test_method_uppercased(self):
        result = _canonical("get", "/path", "u", "d", "0", "n", "h")
        assert result.startswith(b"GET\n")

    def test_all_fields_present(self):
        result = _canonical("DELETE", "/api/v1", "user", "device", "999", "abc", "sha")
        parts = result.decode().split("\n")
        assert parts == ["DELETE", "/api/v1", "user", "device", "999", "abc", "sha"]


class TestMLDSASignVerify:
    def test_sign_and_verify(self, mldsa_keypair):
        sk, pk = mldsa_keypair
        msg = _canonical("POST", "/post", "uid1", "dev1", "12345", "nonce1", "bodysha")
        sig = pqcrypto.sign(sk, msg)
        assert pqcrypto.verify(pk, msg, sig)

    def test_wrong_key_fails(self, mldsa_keypair):
        sk, _ = mldsa_keypair
        _, wrong_pk = pqcrypto.generate_mldsa_keypair()
        msg = _canonical("POST", "/post", "uid1", "dev1", "12345", "nonce1", "bodysha")
        sig = pqcrypto.sign(sk, msg)
        assert not pqcrypto.verify(wrong_pk, msg, sig)

    def test_tampered_message_fails(self, mldsa_keypair):
        sk, pk = mldsa_keypair
        msg = _canonical("POST", "/post", "uid1", "dev1", "12345", "nonce1", "bodysha")
        tampered = _canonical("POST", "/post", "uid1", "dev1", "12345", "nonce1", "TAMPERED")
        sig = pqcrypto.sign(sk, msg)
        assert pqcrypto.verify(pk, msg, sig)
        assert not pqcrypto.verify(pk, tampered, sig)

    def test_verify_never_raises_on_garbage(self, mldsa_keypair):
        _, pk = mldsa_keypair
        assert pqcrypto.verify(pk, b"msg", b"not-a-signature") is False
        assert pqcrypto.verify(b"short-pubkey", b"msg", b"sig") is False


class TestNonceReplay:
    def test_nonce_seen_and_remember(self):
        from cipher_station.auth import _nonce_seen, _remember_nonce

        uid, dev, nonce = "user1", "device1", "unique-nonce-123"
        ts = int(time.time())

        assert not _nonce_seen(uid, dev, nonce)
        _remember_nonce(uid, dev, nonce, ts)
        assert _nonce_seen(uid, dev, nonce)

    def test_different_nonce_not_seen(self):
        from cipher_station.auth import _nonce_seen, _remember_nonce

        uid, dev = "user1", "device1"
        _remember_nonce(uid, dev, "nonce-A", int(time.time()))
        assert not _nonce_seen(uid, dev, "nonce-B")
