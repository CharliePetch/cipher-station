# tests/conftest.py

import os
import pytest
from pathlib import Path


@pytest.fixture(autouse=True)
def temp_cipher_station_dir(tmp_path, monkeypatch):
    """
    Point all Cipher Station data dirs to a fresh temp directory per test.
    """
    monkeypatch.setenv("CIPHER_BASE_DIR", str(tmp_path / "cipher_station_data"))
    monkeypatch.setenv("CIPHER_PASSWORD", "")

    import cipher_station.config as cfg
    monkeypatch.setattr(cfg, "BASE_DIR", tmp_path / "cipher_station_data")
    monkeypatch.setattr(cfg, "KEYS_DIR", tmp_path / "cipher_station_data" / "keys")
    monkeypatch.setattr(cfg, "DB_PATH", tmp_path / "cipher_station_data" / "cipherstation.db")
    monkeypatch.setattr(cfg, "PUBLIC_JSON_PATH", tmp_path / "cipher_station_data" / "public.json")
    monkeypatch.setattr(cfg, "MANIFEST_DIR", tmp_path / "cipher_station_data" / "manifests")

    (tmp_path / "cipher_station_data").mkdir(parents=True, exist_ok=True)
    (tmp_path / "cipher_station_data" / "keys").mkdir(parents=True, exist_ok=True)
    (tmp_path / "cipher_station_data" / "manifests").mkdir(parents=True, exist_ok=True)

    # Reset cached identity between tests
    import cipher_station.identity as ident
    monkeypatch.setattr(ident, "_cached_identity", None)

    # CRITICAL: several modules bind config paths at IMPORT time
    # (e.g. identity.PUBLIC_JSON_PATH, identity.MLKEM_KEY_PATH, manifest.MANIFEST_PATH),
    # so monkeypatching cfg.* alone does NOT redirect them. Without these, a test
    # that writes public.json / keys / the manifest would clobber the REAL station
    # data on a machine running a live station. Redirect every such binding here.
    base = tmp_path / "cipher_station_data"
    monkeypatch.setattr(ident, "KEYS_DIR", base / "keys", raising=False)
    monkeypatch.setattr(ident, "PUBLIC_JSON_PATH", base / "public.json", raising=False)
    monkeypatch.setattr(ident, "MLKEM_KEY_PATH", base / "keys" / "mlkem.bin", raising=False)
    monkeypatch.setattr(ident, "MLDSA_KEY_PATH", base / "keys" / "mldsa.bin", raising=False)

    import cipher_station.manifest as manifest_mod
    monkeypatch.setattr(manifest_mod, "PUBLIC_JSON_PATH", base / "public.json", raising=False)
    monkeypatch.setattr(manifest_mod, "MANIFEST_DIR", base / "manifests", raising=False)
    monkeypatch.setattr(manifest_mod, "MANIFEST_PATH", base / "manifests" / "manifest.json", raising=False)

    # profile.py and privacy.py both bind PUBLIC_JSON_PATH at import time (they
    # write public.json directly for profile/avatar/privacy mutations), so the
    # cfg.* patch above does not redirect them. Without these a profile update or
    # privacy flip would clobber the REAL station's public.json.
    import cipher_station.profile as profile_mod
    monkeypatch.setattr(profile_mod, "PUBLIC_JSON_PATH", base / "public.json", raising=False)

    import cipher_station.privacy as privacy_mod
    monkeypatch.setattr(privacy_mod, "PUBLIC_JSON_PATH", base / "public.json", raising=False)

    for modname in ("cipher_station.graph", "cipher_station.rewrap_envelopes", "cipher_station.tunnel"):
        try:
            mod = __import__(modname, fromlist=["_"])
        except Exception:
            continue
        if hasattr(mod, "PUBLIC_JSON_PATH"):
            monkeypatch.setattr(mod, "PUBLIC_JSON_PATH", base / "public.json", raising=False)
        if hasattr(mod, "BASE_DIR"):
            monkeypatch.setattr(mod, "BASE_DIR", base, raising=False)

    # Reset DB connection between tests (close this thread's connection first)
    import cipher_station.database as db_mod
    db_mod.reset_connection()
    # Patch DB_PATH on the database module too (it binds at import time)
    monkeypatch.setattr(db_mod, "DB_PATH", tmp_path / "cipher_station_data" / "cipherstation.db")

    yield tmp_path


@pytest.fixture
def test_keypair():
    """A fresh ML-KEM-768 keypair: (secret_key_bytes, public_key_hex)."""
    from cipher_station import pqcrypto
    pub, sec = pqcrypto.generate_mlkem_keypair()
    return sec, pub.hex()


@pytest.fixture
def second_keypair():
    """A second independent ML-KEM-768 keypair."""
    from cipher_station import pqcrypto
    pub, sec = pqcrypto.generate_mlkem_keypair()
    return sec, pub.hex()


@pytest.fixture
def mldsa_keypair():
    """A fresh ML-DSA-65 keypair: (secret_key_bytes, public_key_bytes)."""
    from cipher_station import pqcrypto
    pub, sec = pqcrypto.generate_mldsa_keypair()
    return sec, pub
