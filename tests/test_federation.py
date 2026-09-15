# tests/test_federation.py
"""
Federation (peer pin replication) tests.

Covers:
- add_peer / remove_peer round-trip and idempotency.
- sync_peer against a MOCKED IPFS client: normal pin-up-to-quota,
  quota-reached-stops-adding, peer-removed-a-post triggers unpin, a peer
  that fails to resolve returns an error dict without raising.
- sync_all continues past one peer's failure.
- Panel API routes: status/add/remove/sync, and rejection without the
  panel token / from non-localhost (same pattern as tests/test_panel.py).
- sync_peer NEVER calls any envelope-decryption function — this feature only
  ever touches opaque CIDs via IPFS resolve/get/pin/unpin.
"""

import json

import pytest

import cipher_station.federation as federation
from tests.test_panel import (  # noqa: F401
    call_json, call_panel, LOCAL, REMOTE, panel_app, panel_env, fake_ipfs,
)


# ---------------------------------------------------------------------------
# Fake IPFS for federation: a dict of peer_id -> (public.json bytes, manifest
# bytes) plus a CID->bytes store, wired directly into federation.py's
# imported names (it imports functions by name from ipfs_client).
# ---------------------------------------------------------------------------

class FakeFederationIPFS:
    def __init__(self):
        self.blobs: dict[str, bytes] = {}
        self.sizes: dict[str, int] = {}
        self.ipns: dict[str, str] = {}   # peer_id -> "/ipfs/<cid>"
        self.pinned: dict[str, set] = {}  # not required, but handy for assertions
        self.pin_calls: list[str] = []
        self.unpin_calls: list[str] = []
        self.resolve_failures: set[str] = set()

    def add(self, cid: str, data: bytes, size: int | None = None) -> str:
        self.blobs[cid] = data
        self.sizes[cid] = size if size is not None else len(data)
        return cid

    def set_peer(self, peer_id: str, public_cid: str):
        self.ipns[peer_id] = f"/ipfs/{public_cid}"

    # -- functions matching ipfs_client's signatures --

    def name_resolve(self, name: str) -> str:
        if name in self.resolve_failures:
            raise federation.IPFSError(f"could not resolve {name}")
        if name not in self.ipns:
            raise federation.IPFSError(f"no IPNS record for {name}")
        return self.ipns[name]

    def get_bytes(self, cid: str) -> bytes:
        if cid not in self.blobs:
            raise federation.IPFSError(f"unknown CID {cid}")
        return self.blobs[cid]

    def object_stat(self, cid: str, *, timeout=None, retry=True) -> dict:
        if cid not in self.sizes:
            raise federation.IPFSError(f"cannot stat unknown CID {cid}")
        return {"Hash": cid, "CumulativeSize": self.sizes[cid]}

    def pin_add(self, cid: str, *, timeout=None) -> None:
        self.pin_calls.append(cid)

    def unpin(self, cid: str) -> bool:
        self.unpin_calls.append(cid)
        return True


def make_manifest(posts: list[dict]) -> dict:
    return {"clients": {"default": {"posts": posts}}}


def publish_peer(fake: FakeFederationIPFS, peer_id: str, posts: list[dict],
                  sizes: dict[str, int] | None = None):
    """Publish a fake peer's public.json + manifest + post/envelope blobs."""
    sizes = sizes or {}
    for i, post in enumerate(posts):
        pcid = post["post_cid"]
        fake.add(pcid, f"content-{pcid}".encode(), size=sizes.get(pcid, 100))
        if post.get("envelopes_cid"):
            ecid = post["envelopes_cid"]
            fake.add(ecid, f"envelopes-{ecid}".encode(), size=sizes.get(ecid, 10))
    manifest = make_manifest(posts)
    manifest_bytes = json.dumps(manifest).encode()
    manifest_cid = f"QmManifest{peer_id}"
    fake.add(manifest_cid, manifest_bytes)

    public_json = {"uid": f"uid-{peer_id}", "manifest_pointer": manifest_cid}
    public_cid = f"QmPublic{peer_id}"
    fake.add(public_cid, json.dumps(public_json).encode())
    fake.set_peer(peer_id, public_cid)


@pytest.fixture
def fake_fed_ipfs(monkeypatch):
    fake = FakeFederationIPFS()
    monkeypatch.setattr(federation, "ipfs_name_resolve", fake.name_resolve)
    monkeypatch.setattr(federation, "ipfs_get_bytes", fake.get_bytes)
    monkeypatch.setattr(federation, "ipfs_object_stat", fake.object_stat)
    monkeypatch.setattr(federation, "ipfs_pin_add", fake.pin_add)
    monkeypatch.setattr(federation, "ipfs_unpin", fake.unpin)
    return fake


PEER_A = "12D3KooWTestPeerAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
PEER_B = "12D3KooWTestPeerBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"


# ---------------------------------------------------------------------------
# 1. Peer CRUD
# ---------------------------------------------------------------------------

class TestPeerCRUD:
    def test_add_peer_roundtrip(self):
        entry = federation.add_peer(PEER_A, "Mom's station", 5.0)
        assert entry["peer_id"] == PEER_A
        assert entry["label"] == "Mom's station"
        assert entry["quota_bytes"] == 5 * 1024 ** 3

        peers = federation.list_peers()
        assert len(peers) == 1
        assert peers[0]["peer_id"] == PEER_A

    def test_add_peer_is_idempotent_by_peer_id(self):
        federation.add_peer(PEER_A, "Original label", 5.0)
        federation.add_peer(PEER_A, "Updated label", 10.0)

        peers = federation.list_peers()
        assert len(peers) == 1
        assert peers[0]["label"] == "Updated label"
        assert peers[0]["quota_bytes"] == 10 * 1024 ** 3

    def test_add_peer_rejects_bad_peer_id(self):
        with pytest.raises(ValueError):
            federation.add_peer("!!!not-a-peer-id!!!", None, 1.0)
        with pytest.raises(ValueError):
            federation.add_peer("", None, 1.0)

    def test_add_peer_rejects_negative_quota(self):
        with pytest.raises(ValueError):
            federation.add_peer(PEER_A, None, -1.0)

    def test_remove_peer_removes_entry(self):
        federation.add_peer(PEER_A, None, 1.0)
        federation.add_peer(PEER_B, None, 1.0)
        result = federation.remove_peer(PEER_A)
        assert result["removed"] is True

        peers = federation.list_peers()
        assert len(peers) == 1
        assert peers[0]["peer_id"] == PEER_B

    def test_remove_peer_is_idempotent(self):
        federation.add_peer(PEER_A, None, 1.0)
        federation.remove_peer(PEER_A)
        result = federation.remove_peer(PEER_A)
        assert result["removed"] is False

    def test_remove_peer_drops_sync_state(self, fake_fed_ipfs):
        federation.add_peer(PEER_A, None, 1.0)
        publish_peer(fake_fed_ipfs, PEER_A, [
            {"post_cid": "QmPostA1", "audience_mode": "public", "envelopes_cid": None},
        ])
        federation.sync_peer(PEER_A)
        assert federation.get_status()["peers"][0]["pinned_count"] == 1

        federation.remove_peer(PEER_A)
        state = federation._load_state()
        assert PEER_A not in state


# ---------------------------------------------------------------------------
# 2. sync_peer (mocked IPFS)
# ---------------------------------------------------------------------------

class TestSyncPeer:
    def test_normal_pin_up_to_quota(self, fake_fed_ipfs):
        federation.add_peer(PEER_A, "Peer A", quota_gb=1.0)  # 1 GiB quota
        publish_peer(fake_fed_ipfs, PEER_A, [
            {"post_cid": "QmPost1", "audience_mode": "public", "envelopes_cid": None},
            {"post_cid": "QmPost2", "audience_mode": "self", "envelopes_cid": "QmEnv2"},
        ], sizes={"QmPost1": 1000, "QmPost2": 2000, "QmEnv2": 100})

        result = federation.sync_peer(PEER_A)

        assert result["error"] is None
        assert result["pinned_count"] == 3  # QmPost1, QmPost2, QmEnv2
        assert result["pinned_bytes"] == 3100
        assert result["skipped_count"] == 0
        assert set(fake_fed_ipfs.pin_calls) == {"QmPost1", "QmPost2", "QmEnv2"}

    def test_quota_reached_stops_adding(self, fake_fed_ipfs):
        federation.add_peer(PEER_A, "Peer A", quota_gb=0.0)
        federation.add_peer(PEER_A, "Peer A", quota_gb=1500 / 1024 ** 3)  # ~1500 bytes
        publish_peer(fake_fed_ipfs, PEER_A, [
            {"post_cid": "QmPost1", "audience_mode": "public", "envelopes_cid": None},
            {"post_cid": "QmPost2", "audience_mode": "public", "envelopes_cid": None},
        ], sizes={"QmPost1": 1000, "QmPost2": 1000})

        result = federation.sync_peer(PEER_A)

        assert result["error"] is None
        # Only the first (oldest/manifest-order) post fits under quota.
        assert result["pinned_count"] == 1
        assert result["pinned_bytes"] == 1000
        assert result["skipped_count"] == 1
        assert fake_fed_ipfs.pin_calls == ["QmPost1"]

    def test_peer_removed_post_triggers_unpin(self, fake_fed_ipfs):
        federation.add_peer(PEER_A, "Peer A", quota_gb=1.0)
        publish_peer(fake_fed_ipfs, PEER_A, [
            {"post_cid": "QmPost1", "audience_mode": "public", "envelopes_cid": None},
            {"post_cid": "QmPost2", "audience_mode": "public", "envelopes_cid": None},
        ], sizes={"QmPost1": 100, "QmPost2": 100})
        federation.sync_peer(PEER_A)
        assert federation.get_status()["peers"][0]["pinned_count"] == 2

        # Peer republishes with QmPost2 removed.
        publish_peer(fake_fed_ipfs, PEER_A, [
            {"post_cid": "QmPost1", "audience_mode": "public", "envelopes_cid": None},
        ], sizes={"QmPost1": 100})
        result = federation.sync_peer(PEER_A)

        assert result["error"] is None
        assert result["pinned_count"] == 1
        assert "QmPost2" in fake_fed_ipfs.unpin_calls

    def test_resolve_failure_returns_error_without_raising(self, fake_fed_ipfs):
        federation.add_peer(PEER_A, "Unreachable peer", quota_gb=1.0)
        fake_fed_ipfs.resolve_failures.add(PEER_A)

        result = federation.sync_peer(PEER_A)

        assert result["error"] is not None
        assert "resolve failed" in result["error"]
        assert result["pinned_count"] == 0
        assert result["peer_id"] == PEER_A
        assert result["label"] == "Unreachable peer"

    def test_sync_peer_of_unconfigured_peer_is_error_not_raise(self, fake_fed_ipfs):
        result = federation.sync_peer("not-a-configured-peer-id")
        assert result["error"] == "peer not configured"

    def test_sync_peer_never_evicts_existing_pins_for_new_content(self, fake_fed_ipfs):
        """Backup, not a cache: existing pins are never evicted to fit new
        content when quota is already exhausted."""
        federation.add_peer(PEER_A, "Peer A", quota_gb=100 / 1024 ** 3)
        publish_peer(fake_fed_ipfs, PEER_A, [
            {"post_cid": "QmPost1", "audience_mode": "public", "envelopes_cid": None},
        ], sizes={"QmPost1": 100})
        federation.sync_peer(PEER_A)
        assert federation.get_status()["peers"][0]["pinned_count"] == 1

        publish_peer(fake_fed_ipfs, PEER_A, [
            {"post_cid": "QmPost1", "audience_mode": "public", "envelopes_cid": None},
            {"post_cid": "QmPost2", "audience_mode": "public", "envelopes_cid": None},
        ], sizes={"QmPost1": 100, "QmPost2": 100})
        result = federation.sync_peer(PEER_A)

        # QmPost1 stays pinned; QmPost2 does not fit and is skipped, not
        # forced in by evicting QmPost1.
        assert result["pinned_count"] == 1
        assert "QmPost1" not in fake_fed_ipfs.unpin_calls
        assert result["skipped_count"] == 1


# ---------------------------------------------------------------------------
# 3. sync_all
# ---------------------------------------------------------------------------

class TestSyncAll:
    def test_sync_all_continues_past_one_peer_failure(self, fake_fed_ipfs):
        federation.add_peer(PEER_A, "Broken peer", quota_gb=1.0)
        federation.add_peer(PEER_B, "Healthy peer", quota_gb=1.0)
        fake_fed_ipfs.resolve_failures.add(PEER_A)
        publish_peer(fake_fed_ipfs, PEER_B, [
            {"post_cid": "QmPostB1", "audience_mode": "public", "envelopes_cid": None},
        ], sizes={"QmPostB1": 100})

        results = federation.sync_all()

        assert len(results) == 2
        by_peer = {r["peer_id"]: r for r in results}
        assert by_peer[PEER_A]["error"] is not None
        assert by_peer[PEER_B]["error"] is None
        assert by_peer[PEER_B]["pinned_count"] == 1

    def test_sync_all_empty_peer_list(self):
        assert federation.sync_all() == []


# ---------------------------------------------------------------------------
# 4. get_status (no re-sync)
# ---------------------------------------------------------------------------

class TestGetStatus:
    def test_status_reflects_last_sync_without_resyncing(self, fake_fed_ipfs):
        federation.add_peer(PEER_A, "Peer A", quota_gb=1.0)
        publish_peer(fake_fed_ipfs, PEER_A, [
            {"post_cid": "QmPost1", "audience_mode": "public", "envelopes_cid": None},
        ], sizes={"QmPost1": 500})
        federation.sync_peer(PEER_A)

        fake_fed_ipfs.pin_calls.clear()
        status = federation.get_status()

        assert fake_fed_ipfs.pin_calls == []  # no re-sync happened
        peer_status = status["peers"][0]
        assert peer_status["pinned_count"] == 1
        assert peer_status["pinned_bytes"] == 500
        assert peer_status["last_synced_at"] is not None

    def test_status_for_never_synced_peer(self):
        federation.add_peer(PEER_A, "Peer A", quota_gb=1.0)
        status = federation.get_status()
        peer_status = status["peers"][0]
        assert peer_status["pinned_count"] == 0
        assert peer_status["pinned_bytes"] == 0
        assert peer_status["last_synced_at"] is None


# ---------------------------------------------------------------------------
# 5. Never touches envelope decryption
# ---------------------------------------------------------------------------

class TestNeverDecrypts:
    def test_sync_peer_never_calls_envelope_decryption(self, fake_fed_ipfs, monkeypatch):
        """This feature only ever pins opaque CIDs from a peer's own public
        manifest. It must never open/decrypt an envelope or need a secret key."""
        import cipher_station.envelopes as envelopes_mod

        called = {"open_envelope": False}

        def _poison(*a, **kw):
            called["open_envelope"] = True
            raise AssertionError("sync_peer must never decrypt envelopes")

        monkeypatch.setattr(envelopes_mod, "open_envelope", _poison, raising=False)
        # federation.py must not even import a decryption function to call —
        # confirm the module namespace has none of the known decrypt entry
        # points bound into it.
        for name in dir(federation):
            assert "decrypt" not in name.lower()
            assert "open_envelope" not in name.lower()

        federation.add_peer(PEER_A, "Peer A", quota_gb=1.0)
        publish_peer(fake_fed_ipfs, PEER_A, [
            {"post_cid": "QmPost1", "audience_mode": "self", "envelopes_cid": "QmEnv1"},
        ], sizes={"QmPost1": 100, "QmEnv1": 50})

        result = federation.sync_peer(PEER_A)

        assert result["error"] is None
        assert called["open_envelope"] is False


# ---------------------------------------------------------------------------
# 6. Panel API routes
# ---------------------------------------------------------------------------

class TestFederationPanelAPI:
    def test_status_empty(self, panel_app):
        status, obj = call_json(panel_app, "GET", "/admin/api/federation")
        assert status == 200
        assert obj == {"peers": []}

    def test_add_peer_via_api(self, panel_app):
        status, obj = call_json(
            panel_app, "POST", "/admin/api/federation/peers",
            {"peer_id": PEER_A, "label": "Peer A", "quota_gb": 5.0},
        )
        assert status == 200
        assert obj["peer_id"] == PEER_A
        assert obj["quota_bytes"] == 5 * 1024 ** 3

        status, obj = call_json(panel_app, "GET", "/admin/api/federation")
        assert status == 200
        assert len(obj["peers"]) == 1
        assert obj["peers"][0]["peer_id"] == PEER_A

    def test_add_peer_bad_id_is_400(self, panel_app):
        status, _ = call_json(
            panel_app, "POST", "/admin/api/federation/peers",
            {"peer_id": "", "label": None, "quota_gb": 1.0},
        )
        assert status == 400

    def test_remove_peer_via_api(self, panel_app):
        call_json(panel_app, "POST", "/admin/api/federation/peers",
                  {"peer_id": PEER_A, "label": None, "quota_gb": 1.0})
        status, obj = call_json(panel_app, "DELETE", f"/admin/api/federation/peers/{PEER_A}")
        assert status == 200
        assert obj["removed"] is True

        status, obj = call_json(panel_app, "GET", "/admin/api/federation")
        assert obj["peers"] == []

    def test_sync_all_via_api(self, panel_app, monkeypatch):
        import cipher_station.panel.service as service_mod
        monkeypatch.setattr(service_mod, "federation_sync_all",
                            lambda: [{"peer_id": "x", "error": None}])
        status, obj = call_json(panel_app, "POST", "/admin/api/federation/sync")
        assert status == 200
        assert obj == [{"peer_id": "x", "error": None}]

    def test_sync_single_peer_via_api(self, panel_app, monkeypatch):
        import cipher_station.panel.service as service_mod
        monkeypatch.setattr(
            service_mod, "federation_sync_peer",
            lambda peer_id: {"peer_id": peer_id, "error": None},
        )
        status, obj = call_json(panel_app, "POST", f"/admin/api/federation/sync/{PEER_A}")
        assert status == 200
        assert obj["peer_id"] == PEER_A

    # -- auth rejection, same pattern as test_panel.py --

    def test_status_rejected_without_token(self, panel_app):
        status, headers, _ = call_panel(
            panel_app, "GET", "/admin/api/federation", token=False)
        assert status == 401
        assert headers.get("www-authenticate") == "Bearer"

    def test_status_rejected_from_remote(self, panel_app):
        status, _, _ = call_panel(
            panel_app, "GET", "/admin/api/federation", client=REMOTE)
        assert status == 403

    def test_add_peer_rejected_without_token(self, panel_app):
        status, _ = call_json(
            panel_app, "POST", "/admin/api/federation/peers",
            {"peer_id": PEER_A, "label": None, "quota_gb": 1.0}, token=False)
        assert status == 401

    def test_sync_all_rejected_without_token(self, panel_app):
        status, headers, _ = call_panel(
            panel_app, "POST", "/admin/api/federation/sync", token=False)
        assert status == 401

    def test_remove_peer_rejected_from_remote(self, panel_app):
        status, _, _ = call_panel(
            panel_app, "DELETE", f"/admin/api/federation/peers/{PEER_A}",
            client=REMOTE)
        assert status == 403

    def test_federation_page_serves_without_token(self, panel_app):
        status, headers, body = call_panel(
            panel_app, "GET", "/admin", token=False)
        assert status == 200
        assert b"Federation" in body
