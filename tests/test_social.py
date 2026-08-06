# tests/test_social.py
"""
Tests for the cipherframe social endpoints: profile fields + GET /profile,
profile update / avatar, created_at on manifest entries, following listing,
and the account privacy flip (both directions).

Fully offline and hermetic: the autouse temp_cipher_station_dir fixture (conftest.py)
redirects all data paths to a temp dir and patches every module that binds
PUBLIC_JSON_PATH at import time, so nothing here ever touches the live station
data. IPFS is stubbed with an in-memory content store (fake_ipfs below) so no
network/IPFS calls happen.
"""

import hashlib
import json

import pytest
from nacl.secret import SecretBox
from nacl.utils import random as nacl_random

import cipher_station.posts as posts_mod
import cipher_station.manifest as manifest_mod
import cipher_station.privacy as privacy_mod
import cipher_station.profile as profile_mod
from cipher_station.identity import get_identity, load_public_identity
from cipher_station.manifest import load_manifest, get_client_profile
from cipher_station.followers import add_follower_device
from cipher_station.following import follow_user
from cipher_station.posts import handle_new_post
from cipher_station.envelopes import encrypt_key_for_follower
from cipher_station.profile import (
    get_public_profile,
    update_profile_fields,
    set_avatar_cid,
)
from cipher_station.privacy import flip_account_privacy

_DUMMY_MLKEM_HEX = "aa" * 1184


def _client_side_encrypt(plaintext: bytes, metadata: dict | None = None):
    """
    Mimic what a client now does before calling POST /post: generate the
    per-post key, encrypt the file (and metadata) with it, and seal the key
    to the STATION's own ML-KEM public key (the "self_envelope"). Returns
    kwargs ready to splat into handle_new_post(**kwargs).
    """
    sym_key = nacl_random(SecretBox.KEY_SIZE)
    box = SecretBox(sym_key)
    station_mlkem_pub_hex = get_identity().mlkem_pub_hex
    self_envelope = encrypt_key_for_follower(sym_key, station_mlkem_pub_hex)

    metadata_enc = None
    if metadata is not None:
        raw = json.dumps(metadata, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        metadata_enc = box.encrypt(raw).hex()

    return {
        "file_bytes": box.encrypt(plaintext),
        "metadata": metadata_enc,
        "self_envelope": self_envelope,
    }


@pytest.fixture
def fake_ipfs(monkeypatch):
    """
    In-memory IPFS: ipfs_add_bytes stores bytes under a deterministic fake CID
    and returns it; ipfs_get_bytes reads them back. Publish/unpin/GC are no-ops.

    The real IPFS functions are imported BY NAME into several modules at import
    time, so each binding must be patched individually (patching ipfs_client
    alone would not redirect posts_mod.ipfs_add_bytes etc.).
    """
    store: dict[str, bytes] = {}

    def fake_add(data: bytes) -> str:
        cid = "Qm" + hashlib.sha256(data).hexdigest()
        store[cid] = data
        return cid

    def fake_get(cid: str) -> bytes:
        if cid not in store:
            raise KeyError(f"CID not in fake IPFS store: {cid}")
        return store[cid]

    def fake_publish() -> None:
        return None

    def fake_unpin(cid: str) -> bool:
        return True

    def fake_gc() -> list:
        return []

    # posts.py
    monkeypatch.setattr(posts_mod, "ipfs_add_bytes", fake_add)
    monkeypatch.setattr(posts_mod, "ipfs_get_bytes", fake_get)
    # manifest.py
    monkeypatch.setattr(manifest_mod, "ipfs_add_bytes", fake_add)
    monkeypatch.setattr(manifest_mod, "ipfs_unpin", fake_unpin)
    monkeypatch.setattr(manifest_mod, "ipfs_repo_gc", fake_gc)
    # manifest.py now queues IPNS publishing to the background worker; stub the
    # queueing call so tests never spin up the publisher thread.
    monkeypatch.setattr(manifest_mod, "request_publish", fake_publish)
    # privacy.py (profile + privacy now publish via manifest.set_client_profile,
    # so only manifest.py's publish binding needs patching — done above)
    monkeypatch.setattr(privacy_mod, "ipfs_get_bytes", fake_get)

    return store


def _seed_follower(uid: str = "follower-1") -> None:
    """Register one Allowed follower so encrypted posts have a real recipient."""
    add_follower_device(
        uid,
        device_uid=uid,
        mlkem_public_key=_DUMMY_MLKEM_HEX,
        mldsa_public_key=None,
        alias=None,
        allowed="Allowed",
    )


def _cipherframe_posts() -> list:
    manifest = load_manifest(client="cipherframe")
    return manifest.get("clients", {}).get("cipherframe", {}).get("posts", [])


# ---------------------------------------------------------------------------
# 1. Profile defaults
# ---------------------------------------------------------------------------

class TestProfileMetadataLocation:
    """Client profile chrome lives in the manifest, NOT public.json/`/profile`."""

    def test_public_json_is_protocol_only(self, fake_ipfs):
        get_identity()  # bootstrap
        pj = load_public_identity()
        for k in ("display_name", "username", "bio", "link", "avatar_cid",
                  "account_privacy", "default_audience_mode"):
            assert k not in pj
        for k in ("uid", "mlkem_public_key", "mldsa_public_key"):
            assert k in pj

    def test_get_profile_excludes_client_metadata(self, fake_ipfs):
        prof = get_public_profile()
        for k in ("display_name", "username", "bio", "link", "avatar_cid",
                  "account_privacy", "default_audience_mode"):
            assert k not in prof
        # protocol identity + derived counts remain
        for key in (
            "uid", "mlkem_public_key", "mldsa_public_key", "endpoint",
            "ipfs_peer_id", "manifest_cid", "manifest_posts",
            "followers_count", "following_count",
        ):
            assert key in prof

    def test_legacy_profile_fields_stripped_on_load(self, fake_ipfs, monkeypatch):
        import cipher_station.identity as ident
        get_identity()  # bootstrap a valid keypair + file
        obj = json.loads(ident.PUBLIC_JSON_PATH.read_text())
        # Simulate an old public.json that carried client-profile fields.
        obj["display_name"] = "Legacy Name"
        obj["account_privacy"] = "private"
        obj["alias"] = "kept-alias"
        ident.PUBLIC_JSON_PATH.write_text(json.dumps(obj))

        # Force a reload so _load_public_json strips them.
        monkeypatch.setattr(ident, "_cached_identity", None)
        pj = get_identity().public_json
        assert pj["alias"] == "kept-alias"            # protocol field preserved
        assert "display_name" not in pj               # client field stripped
        assert "account_privacy" not in pj


# ---------------------------------------------------------------------------
# 2. update_profile_fields
# ---------------------------------------------------------------------------

class TestUpdateProfileFields:
    def test_sets_fields(self, fake_ipfs):
        prof = update_profile_fields(
            display_name="Charlie P",
            username="charlie.p_01",
            bio="hello world",
            link="https://example.com",
        )
        assert prof["display_name"] == "Charlie P"
        assert prof["username"] == "charlie.p_01"
        assert prof["bio"] == "hello world"
        assert prof["link"] == "https://example.com"
        # stored in the manifest client profile, not public.json
        assert get_client_profile(client="cipherframe")["username"] == "charlie.p_01"
        assert "username" not in load_public_identity()
        assert "username" not in get_public_profile()

    def test_trims_value(self, fake_ipfs):
        prof = update_profile_fields(display_name="  spaced  ")
        assert prof["display_name"] == "spaced"

    def test_empty_string_clears_to_null(self, fake_ipfs):
        update_profile_fields(display_name="Name", bio="b")
        prof = update_profile_fields(display_name="   ", bio="")
        assert prof["display_name"] is None
        assert prof["bio"] is None

    def test_omitted_field_unchanged(self, fake_ipfs):
        update_profile_fields(display_name="Keep", username="keepuser")
        prof = update_profile_fields(bio="only bio")
        assert prof["display_name"] == "Keep"
        assert prof["username"] == "keepuser"
        assert prof["bio"] == "only bio"

    def test_bad_username_raises(self, fake_ipfs):
        with pytest.raises(ValueError):
            update_profile_fields(username="has spaces")
        with pytest.raises(ValueError):
            update_profile_fields(username="bad/char")
        with pytest.raises(ValueError):
            update_profile_fields(username="x" * 31)

    def test_bad_link_raises(self, fake_ipfs):
        with pytest.raises(ValueError):
            update_profile_fields(link="ftp://example.com")
        with pytest.raises(ValueError):
            update_profile_fields(link="not-a-url")
        with pytest.raises(ValueError):
            update_profile_fields(link="https://" + "a" * 200)

    def test_long_display_name_and_bio_raise(self, fake_ipfs):
        with pytest.raises(ValueError):
            update_profile_fields(display_name="x" * 81)
        with pytest.raises(ValueError):
            update_profile_fields(bio="x" * 301)


# ---------------------------------------------------------------------------
# 3. set_avatar_cid
# ---------------------------------------------------------------------------

class TestAvatar:
    def test_set_avatar_cid(self, fake_ipfs):
        prof = set_avatar_cid("QmAvatar123")
        assert prof["avatar_cid"] == "QmAvatar123"
        assert get_client_profile(client="cipherframe")["avatar_cid"] == "QmAvatar123"
        assert "avatar_cid" not in load_public_identity()


# ---------------------------------------------------------------------------
# 4. created_at on manifest entries
# ---------------------------------------------------------------------------

class TestCreatedAt:
    def test_public_post_has_created_at(self, fake_ipfs):
        handle_new_post(b"hello", metadata={"caption": "hi"},
                        audience_mode="public", client="cipherframe")
        posts = _cipherframe_posts()
        assert len(posts) == 1
        assert isinstance(posts[0]["created_at"], int)

    def test_encrypted_post_has_created_at(self, fake_ipfs):
        _seed_follower()
        enc = _client_side_encrypt(b"secret", metadata={"caption": "hi"})
        handle_new_post(enc["file_bytes"], metadata=enc["metadata"],
                        audience_mode="all", client="cipherframe",
                        self_envelope=enc["self_envelope"])
        posts = _cipherframe_posts()
        assert len(posts) == 1
        assert isinstance(posts[0]["created_at"], int)

    def test_created_at_preserved_when_provided(self, fake_ipfs):
        handle_new_post(b"hello", audience_mode="public",
                        client="cipherframe", created_at=1234567890)
        posts = _cipherframe_posts()
        assert posts[0]["created_at"] == 1234567890


# ---------------------------------------------------------------------------
# 5. following_count / GET /following source
# ---------------------------------------------------------------------------

class TestFollowing:
    def test_following_count_and_listing(self, fake_ipfs):
        get_identity()
        follow_user(
            "target-uid",
            mlkem_public_key=_DUMMY_MLKEM_HEX,
            endpoint="https://target.example",
            mldsa_public_key=None,
            ipns_id="ipns-xyz",
        )
        prof = get_public_profile()
        assert prof["following_count"] == 1

        from cipher_station.following import list_following
        rows = list_following()
        assert any(r["uid"] == "target-uid" for r in rows)
        row = next(r for r in rows if r["uid"] == "target-uid")
        assert row["endpoint"] == "https://target.example"
        assert row["ipns_id"] == "ipns-xyz"

    def test_followers_count_dedupes_and_excludes_self(self, fake_ipfs):
        self_uid = get_identity().uid
        # self row exists implicitly only if added; add it to ensure exclusion works
        add_follower_device(self_uid, device_uid=self_uid,
                            mlkem_public_key=_DUMMY_MLKEM_HEX, allowed="Allowed")
        # one follower with two devices -> counts once
        add_follower_device("f1", device_uid="f1", mlkem_public_key=_DUMMY_MLKEM_HEX,
                            allowed="Allowed")
        add_follower_device("f1", device_uid="f1-phone", mlkem_public_key=_DUMMY_MLKEM_HEX,
                            allowed="Allowed")
        # a pending follower -> not counted
        add_follower_device("f2", device_uid="f2", mlkem_public_key=_DUMMY_MLKEM_HEX,
                            allowed="Pending")
        prof = get_public_profile()
        assert prof["followers_count"] == 1


# ---------------------------------------------------------------------------
# 6 & 7. Privacy flip (private <-> public)
# ---------------------------------------------------------------------------

class TestPrivacyFlip:
    def _seed_public_posts(self):
        handle_new_post(b"image-bytes-1", metadata={"caption": "first"},
                        audience_mode="public", client="cipherframe",
                        created_at=1111111111)
        handle_new_post(b"image-bytes-2", metadata={"caption": "second"},
                        audience_mode="public", client="cipherframe",
                        created_at=2222222222)

    def test_flip_to_private(self, fake_ipfs):
        _seed_follower()
        self._seed_public_posts()

        before = _cipherframe_posts()
        assert all(p["audience_mode"] == "public" for p in before)
        public_cids_before = {p["post_cid"] for p in before}

        result = flip_account_privacy("private", client="cipherframe")

        assert result["status"] == "privacy_flipped"
        assert result["account_privacy"] == "private"
        assert result["default_audience_mode"] == "all"
        assert result["migrated_count"] == 2

        after = _cipherframe_posts()
        assert len(after) == 2
        # all old public CIDs are gone
        assert not (public_cids_before & {p["post_cid"] for p in after})
        # all new entries are encrypted "all"
        for p in after:
            assert p["audience_mode"] == "all"
            # encrypted entries carry no "encrypted" flag (only public ones set it False)
            assert p.get("encrypted") is not False
            assert p["envelopes_count"] >= 1     # self-envelope is forced
            assert isinstance(p.get("metadata"), str)  # metadata now a hex blob
        # created_at preserved
        assert sorted(p["created_at"] for p in after) == [1111111111, 2222222222]

        # the manifest client profile reflects the new privacy state (not public.json)
        prof = get_client_profile(client="cipherframe")
        assert prof["account_privacy"] == "private"
        assert prof["default_audience_mode"] == "all"
        assert "account_privacy" not in load_public_identity()

    def test_flip_round_trip_back_to_public(self, fake_ipfs):
        _seed_follower()
        self._seed_public_posts()

        flip_account_privacy("private", client="cipherframe")
        result = flip_account_privacy("public", client="cipherframe")

        assert result["account_privacy"] == "public"
        assert result["default_audience_mode"] == "public"
        assert result["migrated_count"] == 2

        after = _cipherframe_posts()
        assert len(after) == 2
        for p in after:
            assert p["audience_mode"] == "public"
            assert p["encrypted"] is False
            assert isinstance(p.get("metadata"), dict)  # plaintext metadata again
        # captions and timestamps survive the round trip
        captions = {p["metadata"]["caption"] for p in after}
        assert captions == {"first", "second"}
        assert sorted(p["created_at"] for p in after) == [1111111111, 2222222222]

        prof = get_client_profile(client="cipherframe")
        assert prof["account_privacy"] == "public"
        assert prof["default_audience_mode"] == "public"
