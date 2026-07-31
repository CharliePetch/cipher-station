# tests/test_profile.py
"""
Regression tests for the stale-manifest bug: load_public_identity() must reflect
the *current* on-disk public.json (which new posts rewrite), not the cached
startup snapshot.

These tests are fully hermetic — they monkeypatch identity.PUBLIC_JSON_PATH to a
temp file and seed a cached Identity, so they never read or write real station
data (the bug that let an earlier version of this test clobber a live public.json).
"""

import json

import cipher_station.identity as identity
from cipher_station.identity import Identity, load_public_identity


def _seed_cache(monkeypatch, public_json: dict) -> None:
    monkeypatch.setattr(
        identity, "_cached_identity",
        Identity(b"", b"", "aa", "bb", public_json),
    )


def test_load_public_identity_reflects_disk_not_cache(tmp_path, monkeypatch):
    pj = tmp_path / "public.json"
    monkeypatch.setattr(identity, "PUBLIC_JSON_PATH", pj)

    # Cached snapshot is intentionally STALE (as it is after the first post).
    stale = {"uid": "u", "manifest_pointer": "QmSTALEsnapshot",
             "mlkem_public_key": "aa", "mldsa_public_key": "bb"}
    _seed_cache(monkeypatch, stale)

    # Disk has a newer pointer than the cached snapshot.
    pj.write_text(json.dumps({**stale, "manifest_pointer": "QmFRESHondisk"}))

    # The cache stays stale (that's the bug)...
    assert identity._cached_identity.public_json["manifest_pointer"] == "QmSTALEsnapshot"
    # ...but load_public_identity() must re-read the file.
    assert load_public_identity()["manifest_pointer"] == "QmFRESHondisk"


def test_load_public_identity_falls_back_to_cache_when_unreadable(tmp_path, monkeypatch):
    # Point at a non-existent file; the read fails and we fall back to the cache.
    monkeypatch.setattr(identity, "PUBLIC_JSON_PATH", tmp_path / "does-not-exist.json")
    _seed_cache(monkeypatch, {"uid": "u", "manifest_pointer": "QmCACHEonly",
                              "mlkem_public_key": "aa", "mldsa_public_key": "bb"})

    assert load_public_identity()["manifest_pointer"] == "QmCACHEonly"
