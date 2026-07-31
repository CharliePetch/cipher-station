# tests/test_envelopes.py

import pytest
from nacl.secret import SecretBox

from cipher_station.envelopes import (
    create_symmetric_key,
    encrypt_key_for_follower,
    open_envelope,
)
from cipher_station.posts import (
    _dedupe_followers_for_user_level_envelopes,
    _filter_followers_for_audience,
    _normalize_audience_mode,
)

# A correctly-sized dummy ML-KEM public key (content not validated by dedupe/filter).
_DUMMY_MLKEM_HEX = "aa" * 1184


class TestEnvelopeCreateOpen:
    def test_round_trip(self, test_keypair):
        mlkem_sk, pk_hex = test_keypair
        sym_key = create_symmetric_key()

        envelope_hex = encrypt_key_for_follower(sym_key, pk_hex)
        assert envelope_hex is not None

        recovered = open_envelope(mlkem_sk, envelope_hex)
        assert recovered == sym_key

    def test_wrong_key_returns_none(self, test_keypair, second_keypair):
        _, pk_hex = test_keypair
        wrong_sk, _ = second_keypair

        sym_key = create_symmetric_key()
        envelope_hex = encrypt_key_for_follower(sym_key, pk_hex)

        assert open_envelope(wrong_sk, envelope_hex) is None

    def test_tampered_envelope_returns_none(self, test_keypair):
        mlkem_sk, pk_hex = test_keypair
        envelope_hex = encrypt_key_for_follower(create_symmetric_key(), pk_hex)
        bad = bytearray(bytes.fromhex(envelope_hex))
        bad[-1] ^= 1
        assert open_envelope(mlkem_sk, bad.hex()) is None

    def test_invalid_pubkey_returns_none(self):
        sym_key = create_symmetric_key()
        assert encrypt_key_for_follower(sym_key, "tooshort") is None
        assert encrypt_key_for_follower(sym_key, "zz" * 1184) is None  # right length, non-hex

    def test_symmetric_key_size(self):
        assert len(create_symmetric_key()) == SecretBox.KEY_SIZE


class TestUserLevelDedup:
    def _make_follower(self, uid, device_uid=None, mlkem_public_key=None, allowed="Allowed"):
        return {
            "uid": uid,
            "device_uid": device_uid or uid,
            "mlkem_public_key": mlkem_public_key or _DUMMY_MLKEM_HEX,
            "allowed": allowed,
        }

    def test_single_device_passes_through(self):
        result = _dedupe_followers_for_user_level_envelopes([self._make_follower("alice")])
        assert len(result) == 1 and result[0]["uid"] == "alice"

    def test_multiple_devices_same_uid_deduped(self):
        f1 = self._make_follower("bob", device_uid="bob")
        f2 = self._make_follower("bob", device_uid="bob-phone")
        result = _dedupe_followers_for_user_level_envelopes([f1, f2])
        assert len(result) == 1 and result[0]["uid"] == "bob"

    def test_root_device_preferred(self):
        f1 = self._make_follower("carol", device_uid="carol-phone")
        f2 = self._make_follower("carol", device_uid="carol")
        result = _dedupe_followers_for_user_level_envelopes([f1, f2])
        assert len(result) == 1 and result[0]["device_uid"] == "carol"

    def test_blocked_followers_excluded(self):
        f1 = self._make_follower("dave", allowed="Blocked")
        f2 = self._make_follower("eve", allowed="Allowed")
        result = _dedupe_followers_for_user_level_envelopes([f1, f2])
        assert len(result) == 1 and result[0]["uid"] == "eve"

    def test_multiple_uids_sorted(self):
        fs = [self._make_follower(u) for u in ("charlie", "alice", "bob")]
        result = _dedupe_followers_for_user_level_envelopes(fs)
        assert [r["uid"] for r in result] == ["alice", "bob", "charlie"]


class TestAudienceFiltering:
    def _make_follower(self, uid):
        return {"uid": uid, "device_uid": uid,
                "mlkem_public_key": _DUMMY_MLKEM_HEX, "allowed": "Allowed"}

    def test_self_mode_returns_empty(self):
        followers = [self._make_follower("alice"), self._make_follower("bob")]
        result = _filter_followers_for_audience(
            followers_user_level=followers, self_uid="me",
            audience_mode="self", audience_uids=None)
        assert result == []

    def test_public_mode_returns_empty(self):
        followers = [self._make_follower("alice"), self._make_follower("bob")]
        result = _filter_followers_for_audience(
            followers_user_level=followers, self_uid="me",
            audience_mode="public", audience_uids=None)
        assert result == []

    def test_all_mode_returns_all(self):
        followers = [self._make_follower("alice"), self._make_follower("bob")]
        result = _filter_followers_for_audience(
            followers_user_level=followers, self_uid="me",
            audience_mode="all", audience_uids=None)
        assert len(result) == 2

    def test_specific_mode_filters(self):
        followers = [self._make_follower(u) for u in ("alice", "bob", "carol")]
        result = _filter_followers_for_audience(
            followers_user_level=followers, self_uid="me",
            audience_mode="specific", audience_uids=["alice", "carol"])
        assert sorted(r["uid"] for r in result) == ["alice", "carol"]

    def test_specific_mode_excludes_self(self):
        followers = [self._make_follower("me"), self._make_follower("alice")]
        result = _filter_followers_for_audience(
            followers_user_level=followers, self_uid="me",
            audience_mode="specific", audience_uids=["me", "alice"])
        uids = [r["uid"] for r in result]
        assert "me" not in uids and "alice" in uids

    def test_specific_mode_unknown_uid_raises(self):
        followers = [self._make_follower("alice")]
        with pytest.raises(ValueError, match="not Allowed followers"):
            _filter_followers_for_audience(
                followers_user_level=followers, self_uid="me",
                audience_mode="specific", audience_uids=["alice", "unknown-user"])


class TestAudienceModeNormalization:
    def test_public_accepted(self):
        assert _normalize_audience_mode("public") == "public"

    def test_legacy_all_followers(self):
        assert _normalize_audience_mode("all_followers") == "all"

    def test_invalid_raises(self):
        with pytest.raises(ValueError):
            _normalize_audience_mode("bogus")
