# tests/test_authz.py
"""
Authorization-model regression tests for the security hardening:

  * unauthenticated follow requests are Pending (no access) by default
  * the dev flag restores auto-accept
  * a replayed follow request can't hijack/modify an existing device
  * require_owner rejects non-owner delegates
  * the device-pairing PIN has a global brute-force lockout
"""

import asyncio

import pytest
from fastapi import HTTPException

from cipher_station import pqcrypto


def _keys():
    """Return (mlkem_pub_hex, mldsa_pub_hex) of the correct on-wire lengths."""
    ek, _ = pqcrypto.generate_mlkem_keypair()
    pk, _ = pqcrypto.generate_mldsa_keypair()
    return ek.hex(), pk.hex()


class TestFollowRequestApproval:
    def test_prod_follow_request_is_pending_and_no_rewrap(self, monkeypatch):
        import cipher_station.inbox as inbox
        from cipher_station.followers import list_follower_devices
        from cipher_station.identity import get_identity

        monkeypatch.setattr(inbox, "DEV_AUTO_ACCEPT_FOLLOWS", False)
        ident = get_identity()
        mlkem_hex, mldsa_hex = _keys()

        res = inbox.process_inbox_message(ident.mlkem_sk, {
            "type": "follow_request", "uid": "attacker",
            "mlkem_public_key": mlkem_hex, "mldsa_public_key": mldsa_hex,
        })

        assert res["status"] == "follow_request_pending"
        assert res["rewrap_triggered"] is False
        # No rewrap means no IPFS calls were attempted (the test runs without a daemon).
        assert "rewrap" not in res

        devs = list_follower_devices("attacker")
        assert len(devs) == 1
        assert devs[0]["allowed"] == "Pending"

    def test_dev_flag_auto_accepts(self, monkeypatch):
        import cipher_station.inbox as inbox
        from cipher_station.followers import list_follower_devices
        from cipher_station.identity import get_identity

        monkeypatch.setattr(inbox, "DEV_AUTO_ACCEPT_FOLLOWS", True)
        # Keep the expensive (IPFS-touching) rewrap out of the unit test.
        monkeypatch.setattr(inbox, "AUTO_REWRAP_ON_FOLLOW_CHANGE", False)
        ident = get_identity()
        mlkem_hex, mldsa_hex = _keys()

        res = inbox.process_inbox_message(ident.mlkem_sk, {
            "type": "follow_request", "uid": "friend",
            "mlkem_public_key": mlkem_hex, "mldsa_public_key": mldsa_hex,
        })

        assert res["status"] == "follow_accepted"
        assert res["rewrap_triggered"] is True
        assert list_follower_devices("friend")[0]["allowed"] == "Allowed"

    def test_replay_cannot_hijack_existing_device(self, monkeypatch):
        import cipher_station.inbox as inbox
        from cipher_station.followers import list_follower_devices, approve_follower
        from cipher_station.identity import get_identity

        monkeypatch.setattr(inbox, "DEV_AUTO_ACCEPT_FOLLOWS", False)
        ident = get_identity()
        mlkem_hex, mldsa_hex = _keys()

        # Legit follow request -> Pending; owner approves it -> Allowed.
        inbox.process_inbox_message(ident.mlkem_sk, {
            "type": "follow_request", "uid": "bob",
            "mlkem_public_key": mlkem_hex, "mldsa_public_key": mldsa_hex,
        })
        assert approve_follower("bob") == 1
        assert list_follower_devices("bob")[0]["allowed"] == "Allowed"

        # Attacker replays with a DIFFERENT key, trying to overwrite bob's key
        # (and ride his Allowed status). It must be a no-op.
        evil_mlkem, evil_mldsa = _keys()
        res = inbox.process_inbox_message(ident.mlkem_sk, {
            "type": "follow_request", "uid": "bob",
            "mlkem_public_key": evil_mlkem, "mldsa_public_key": evil_mldsa,
        })

        assert res["status"] == "follow_request_already_registered"
        dev = list_follower_devices("bob")[0]
        assert dev["mlkem_public_key"] == mlkem_hex      # key unchanged
        assert dev["allowed"] == "Allowed"               # status preserved


class TestRemoveFollower:
    def test_remove_pending_reports_not_allowed(self, monkeypatch):
        import cipher_station.inbox as inbox
        from cipher_station.followers import list_follower_devices, remove_follower
        from cipher_station.identity import get_identity

        monkeypatch.setattr(inbox, "DEV_AUTO_ACCEPT_FOLLOWS", False)
        ident = get_identity()
        mlkem_hex, mldsa_hex = _keys()
        inbox.process_inbox_message(ident.mlkem_sk, {
            "type": "follow_request", "uid": "carol",
            "mlkem_public_key": mlkem_hex, "mldsa_public_key": mldsa_hex,
        })

        res = remove_follower("carol")
        assert res["removed"] == 1
        assert res["removed_allowed"] is False          # pending -> no rewrap needed
        assert list_follower_devices("carol") == []

    def test_remove_allowed_flags_rewrap(self, monkeypatch):
        import cipher_station.inbox as inbox
        from cipher_station.followers import approve_follower, remove_follower
        from cipher_station.identity import get_identity

        monkeypatch.setattr(inbox, "DEV_AUTO_ACCEPT_FOLLOWS", False)
        ident = get_identity()
        mlkem_hex, mldsa_hex = _keys()
        inbox.process_inbox_message(ident.mlkem_sk, {
            "type": "follow_request", "uid": "dave",
            "mlkem_public_key": mlkem_hex, "mldsa_public_key": mldsa_hex,
        })
        approve_follower("dave")

        res = remove_follower("dave")
        assert res["removed"] == 1
        assert res["removed_allowed"] is True           # revoking an Allowed follower -> rewrap


class TestRequireOwner:
    def test_rejects_non_owner(self):
        from cipher_station.auth import require_owner
        with pytest.raises(HTTPException) as exc:
            asyncio.run(require_owner({"uid": "not-the-owner", "device_uid": "x"}))
        assert exc.value.status_code == 403

    def test_accepts_owner(self):
        from cipher_station.auth import require_owner
        from cipher_station.identity import get_identity

        owner = get_identity().uid
        ctx = {"uid": owner, "device_uid": owner}
        assert asyncio.run(require_owner(ctx)) == ctx


class TestPairingBruteForce:
    def test_global_lockout_after_threshold(self, monkeypatch):
        import cipher_station.pairing as pairing

        # Tighten the global budget so the test is fast.
        monkeypatch.setattr(pairing, "GLOBAL_MAX_FAILURES", 3)
        mlkem_hex, mldsa_hex = _keys()

        sess = pairing.create_pairing_session("dev1", mlkem_hex, mldsa_hex)

        # Three wrong PINs each count toward the global failure budget.
        for _ in range(3):
            with pytest.raises(ValueError):
                pairing.confirm_pairing_session(sess.pairing_id, "000000")

        # The next attempt is globally throttled before any per-session work,
        # so cycling to a fresh session would not help the attacker either.
        with pytest.raises(pairing.PairingThrottled):
            pairing.confirm_pairing_session(sess.pairing_id, "000000")

        sess2 = pairing.create_pairing_session("dev2", mlkem_hex, mldsa_hex)
        with pytest.raises(pairing.PairingThrottled):
            pairing.confirm_pairing_session(sess2.pairing_id, "111111")
