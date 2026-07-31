# tests/test_backend.py

import pytest

from cipher_station import pqcrypto
from cipher_station.pqcrypto import _PurePythonBackend, _self_test


class TestBackendSelection:
    def test_active_backend_is_known(self):
        assert pqcrypto.active_backend() in ("python", "liboqs")

    def test_python_backend_passes_selftest(self):
        _self_test(_PurePythonBackend())  # must not raise

    def test_python_backend_sizes(self):
        b = _PurePythonBackend()
        pub, sec = b.mlkem_keygen()
        assert len(pub) == pqcrypto.MLKEM_PUBLIC_BYTES
        assert len(sec) == pqcrypto.MLKEM_SECRET_BYTES
        pk, sk = b.mldsa_keygen()
        assert len(pk) == pqcrypto.MLDSA_PUBLIC_BYTES
        assert len(sk) == pqcrypto.MLDSA_SECRET_BYTES


class TestCrossBackendInterop:
    """
    Both backends implement the same FIPS standards, so keys/ciphertexts/
    signatures must interoperate. Skipped automatically when liboqs is absent.
    """

    def _backends(self):
        pytest.importorskip("oqs")
        from cipher_station.pqcrypto import _LiboqsBackend
        return _PurePythonBackend(), _LiboqsBackend()

    def test_kem_interop_both_directions(self):
        py, oq = self._backends()
        # public key from python, encapsulate with liboqs, decapsulate with python
        pub, sec = py.mlkem_keygen()
        ss, ct = oq.mlkem_encaps(pub)
        assert py.mlkem_decaps(sec, ct) == ss
        # and the reverse
        pub2, sec2 = oq.mlkem_keygen()
        ss2, ct2 = py.mlkem_encaps(pub2)
        assert oq.mlkem_decaps(sec2, ct2) == ss2

    def test_signature_interop_both_directions(self):
        py, oq = self._backends()
        msg = b"cipherstation-cross-backend-message"
        pk, sk = py.mldsa_keygen()
        assert oq.mldsa_verify(pk, msg, py.mldsa_sign(sk, msg))
        pk2, sk2 = oq.mldsa_keygen()
        assert py.mldsa_verify(pk2, msg, oq.mldsa_sign(sk2, msg))

    def test_envelope_interop(self):
        """An envelope sealed via one backend opens via the other (same wire format)."""
        py, oq = self._backends()
        from nacl.utils import random as nacl_random
        from nacl.secret import SecretBox

        # Seal with liboqs by temporarily swapping the module backend, open with python.
        pub, sec = py.mlkem_keygen()
        sym = nacl_random(SecretBox.KEY_SIZE)
        orig = pqcrypto._BACKEND
        try:
            pqcrypto._BACKEND = oq
            env = pqcrypto.seal_key(sym, pub.hex())
            pqcrypto._BACKEND = py
            assert pqcrypto.open_key(sec, env) == sym
        finally:
            pqcrypto._BACKEND = orig
