# tests/test_content.py
"""
Tests for GET /content/{cid} — the station serving its OWN already-pinned bytes
to its OWN paired delegate devices, so a client never has to ask a public
gateway to cold-fetch content this station is already holding.

The three properties that matter, and are asserted here:

  1. Only the owner's delegate devices get bytes (ML-DSA request signatures,
     the same scheme /rewrap and /post use).
  2. Only CIDs this station published are servable — otherwise an authenticated
     route would be a general-purpose IPFS proxy. A refused CID must not even
     reach the IPFS layer.
  3. The read is local-only; "we reference it but don't hold it" is a 404, not
     a network fetch.

Driven through the REAL ASGI app (middleware + auth dependency included) via a
tiny in-process ASGI caller, because this environment has no httpx and so no
starlette TestClient. IPFS is never contacted: ipfs_open_local_stream is stubbed
with an in-memory fake. The autouse temp_cipher_station_dir fixture (conftest.py)
keeps every path inside a temp dir, so the live station's data is untouched.
"""

import asyncio
import base64
import hashlib
import json
import time
import uuid

import pytest

import cipher_station.ipfs_client as ipfs_mod
import cipher_station.manifest as manifest_mod
from cipher_station import pqcrypto
from cipher_station.auth import _canonical
from cipher_station.followers import add_follower_device
from cipher_station.identity import get_identity
from cipher_station.main import app
from cipher_station.manifest import station_content_cids, station_owns_cid

# Syntactically valid CIDv0s (46 alphanumeric chars) — content is faked, so the
# bytes behind them never have to hash to these.
CID_POST = "QmPost" + "a" * 40
CID_ENVELOPES = "QmEnvl" + "b" * 40
CID_FOREIGN = "QmOthr" + "c" * 40
CID_AVATAR = "QmAvtr" + "d" * 40
CID_MANIFEST = "QmMnfs" + "e" * 40

BODY = b"encrypted-post-bytes-" * 1000


# ---------------------------------------------------------------------------
# In-process ASGI caller (no httpx in this environment)
# ---------------------------------------------------------------------------

def call_app(method: str, path: str, headers: dict | None = None):
    """Run one request through the real app. Returns (status, headers, body)."""
    scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "method": method,
        "scheme": "http",
        "path": path,
        "raw_path": path.encode(),
        "root_path": "",
        "query_string": b"",
        "headers": [(k.lower().encode(), str(v).encode()) for k, v in (headers or {}).items()],
        "client": ("127.0.0.1", 50000),
        "server": ("testserver", 80),
    }

    messages: list[dict] = []

    async def run():
        sent_body = False
        complete = asyncio.Event()

        async def receive():
            # One (empty) body message, then hold the "connection" open until
            # the response is fully sent. Disconnecting earlier would cancel
            # StreamingResponse mid-flight, which is a different scenario.
            nonlocal sent_body
            if not sent_body:
                sent_body = True
                return {"type": "http.request", "body": b"", "more_body": False}
            await complete.wait()
            return {"type": "http.disconnect"}

        async def send(message):
            messages.append(message)
            if message["type"] == "http.response.body" and not message.get("more_body", False):
                complete.set()

        await app(scope, receive, send)

    asyncio.run(run())

    start = next(m for m in messages if m["type"] == "http.response.start")
    body = b"".join(m.get("body", b"") for m in messages if m["type"] == "http.response.body")
    out_headers = {k.decode().lower(): v.decode() for k, v in start["headers"]}
    return start["status"], out_headers, body


def signed_headers(path: str, uid: str, device_uid: str, sk: bytes, *, method: str = "GET"):
    """Build the Section-12 ML-DSA auth headers for a bodyless request."""
    ts = str(int(time.time()))
    nonce = uuid.uuid4().hex
    body_sha = hashlib.sha256(b"").hexdigest()
    sig = pqcrypto.sign(sk, _canonical(method, path, uid, device_uid, ts, nonce, body_sha))
    return {
        "x-cipher-uid": uid,
        "x-cipher-device": device_uid,
        "x-cipher-ts": ts,
        "x-cipher-nonce": nonce,
        "x-cipher-body-sha256": body_sha,
        "x-cipher-sig": base64.b64encode(sig).decode(),
    }


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

class FakeUpstream:
    """Stand-in for the requests.Response the local gateway hands back."""

    def __init__(self, body: bytes, status: int = 200, headers: dict | None = None):
        self.status_code = status
        self.headers = headers if headers is not None else {"Content-Length": str(len(body))}
        self._body = body
        self.closed = False

    def iter_content(self, chunk_size=1):
        for i in range(0, len(self._body), chunk_size):
            yield self._body[i:i + chunk_size]

    def close(self):
        self.closed = True


@pytest.fixture
def owner_device():
    """Bootstrap the station identity + one Allowed delegate device of the owner."""
    ident = get_identity()
    uid = ident.uid
    device_uid = "delegate-device-1"
    pk, sk = pqcrypto.generate_mldsa_keypair()
    ek, _ = pqcrypto.generate_mlkem_keypair()
    add_follower_device(
        uid,
        device_uid,
        mlkem_public_key=ek.hex(),
        mldsa_public_key=pk.hex(),
        alias=None,
        allowed="Allowed",
    )
    return {"uid": uid, "device_uid": device_uid, "sk": sk}


@pytest.fixture
def owned_manifest():
    """Seed a manifest whose drive bucket holds CID_POST / CID_ENVELOPES."""
    manifest_mod.save_manifest({
        "clients": {
            "drive": {
                "posts": [{
                    "post_cid": CID_POST,
                    "envelopes_cid": CID_ENVELOPES,
                    "audience_mode": "all",
                    "envelopes_count": 1,
                    "created_at": 1,
                }],
            },
        },
    }, client="drive")


@pytest.fixture
def fake_gateway(monkeypatch):
    """
    Replace the local-gateway read. Records every CID it is asked for, so a test
    can assert the station never even tried to fetch a refused CID.
    """
    calls: list[dict] = []
    state = {"response": None, "raises": None}

    def fake_open(cid, *, range_header=None):
        calls.append({"cid": cid, "range": range_header})
        if state["raises"] is not None:
            raise state["raises"]
        return state["response"] or FakeUpstream(BODY)

    monkeypatch.setattr(ipfs_mod, "ipfs_open_local_stream", fake_open)
    return {"calls": calls, "state": state}


# ---------------------------------------------------------------------------
# 1. Authenticated success
# ---------------------------------------------------------------------------

class TestAuthenticatedFetch:
    def test_owner_device_gets_the_bytes(self, owner_device, owned_manifest, fake_gateway):
        path = f"/content/{CID_POST}"
        status, headers, body = call_app(
            "GET", path,
            signed_headers(path, owner_device["uid"], owner_device["device_uid"], owner_device["sk"]),
        )

        assert status == 200
        assert body == BODY
        assert headers["content-type"] == "application/octet-stream"
        assert headers["content-length"] == str(len(BODY))
        assert headers["accept-ranges"] == "bytes"
        assert fake_gateway["calls"] == [{"cid": CID_POST, "range": None}]

    def test_envelopes_cid_is_also_servable(self, owner_device, owned_manifest, fake_gateway):
        path = f"/content/{CID_ENVELOPES}"
        status, _, body = call_app(
            "GET", path,
            signed_headers(path, owner_device["uid"], owner_device["device_uid"], owner_device["sk"]),
        )
        assert status == 200
        assert body == BODY

    def test_response_is_streamed_not_buffered(self, owner_device, owned_manifest, fake_gateway):
        """The upstream body is consumed in chunks and the connection released."""
        upstream = FakeUpstream(BODY)
        fake_gateway["state"]["response"] = upstream

        path = f"/content/{CID_POST}"
        status, _, body = call_app(
            "GET", path,
            signed_headers(path, owner_device["uid"], owner_device["device_uid"], owner_device["sk"]),
        )

        assert status == 200
        assert body == BODY
        assert upstream.closed is True

    def test_range_request_is_passed_through(self, owner_device, owned_manifest, fake_gateway):
        """Range falls out of using the local gateway — 206 + Content-Range."""
        fake_gateway["state"]["response"] = FakeUpstream(
            BODY[10:110],
            status=206,
            headers={"Content-Length": "100", "Content-Range": f"bytes 10-109/{len(BODY)}"},
        )

        path = f"/content/{CID_POST}"
        headers = signed_headers(path, owner_device["uid"], owner_device["device_uid"], owner_device["sk"])
        headers["range"] = "bytes=10-109"
        status, out, body = call_app("GET", path, headers)

        assert status == 206
        assert body == BODY[10:110]
        assert out["content-range"] == f"bytes 10-109/{len(BODY)}"
        assert fake_gateway["calls"][0]["range"] == "bytes=10-109"


# ---------------------------------------------------------------------------
# 2. Unauthenticated / wrongly-authenticated rejection
# ---------------------------------------------------------------------------

class TestAuthRequired:
    def test_no_auth_headers_is_rejected(self, owner_device, owned_manifest, fake_gateway):
        status, _, _ = call_app("GET", f"/content/{CID_POST}")
        # Missing required headers are rejected by FastAPI's validation layer
        # before require_delegate runs — same as every other authed route.
        assert status == 422
        assert fake_gateway["calls"] == []      # nothing was read from IPFS

    def test_forged_signature_is_rejected(self, owner_device, owned_manifest, fake_gateway):
        _, wrong_sk = pqcrypto.generate_mldsa_keypair()
        path = f"/content/{CID_POST}"
        status, _, _ = call_app(
            "GET", path,
            signed_headers(path, owner_device["uid"], owner_device["device_uid"], wrong_sk),
        )
        assert status == 401
        assert fake_gateway["calls"] == []

    def test_unknown_device_is_rejected(self, owner_device, owned_manifest, fake_gateway):
        _, sk = pqcrypto.generate_mldsa_keypair()
        path = f"/content/{CID_POST}"
        status, _, _ = call_app(
            "GET", path,
            signed_headers(path, owner_device["uid"], "never-paired", sk),
        )
        assert status == 403
        assert fake_gateway["calls"] == []

    def test_non_owner_device_is_rejected(self, owner_device, owned_manifest, fake_gateway):
        """
        A follower's own Allowed device authenticates fine against
        require_delegate — require_owner is what keeps it off the owner's bytes.
        """
        pk, sk = pqcrypto.generate_mldsa_keypair()
        ek, _ = pqcrypto.generate_mlkem_keypair()
        add_follower_device(
            "some-follower-uid", "follower-device",
            mlkem_public_key=ek.hex(), mldsa_public_key=pk.hex(),
            alias=None, allowed="Allowed",
        )

        path = f"/content/{CID_POST}"
        status, _, _ = call_app(
            "GET", path,
            signed_headers(path, "some-follower-uid", "follower-device", sk),
        )
        assert status == 403
        assert fake_gateway["calls"] == []

    def test_replayed_nonce_is_rejected(self, owner_device, owned_manifest, fake_gateway):
        path = f"/content/{CID_POST}"
        headers = signed_headers(path, owner_device["uid"], owner_device["device_uid"], owner_device["sk"])

        assert call_app("GET", path, headers)[0] == 200
        assert call_app("GET", path, dict(headers))[0] == 401
        assert len(fake_gateway["calls"]) == 1


# ---------------------------------------------------------------------------
# 3. Membership check — no open proxy
# ---------------------------------------------------------------------------

class TestMembershipCheck:
    def test_cid_the_station_does_not_own_is_refused(self, owner_device, owned_manifest, fake_gateway):
        """
        The whole point of the check: an authenticated device cannot make the
        station serve (or go and fetch) content it never published.
        """
        path = f"/content/{CID_FOREIGN}"
        status, _, _ = call_app(
            "GET", path,
            signed_headers(path, owner_device["uid"], owner_device["device_uid"], owner_device["sk"]),
        )
        assert status == 404
        assert fake_gateway["calls"] == []      # never even asked IPFS for it

    def test_malformed_cid_never_reaches_ipfs(self, owner_device, owned_manifest, fake_gateway):
        path = "/content/..%2F..%2Fapi%2Fv0%2Fid"
        status, _, _ = call_app(
            "GET", path,
            signed_headers(path, owner_device["uid"], owner_device["device_uid"], owner_device["sk"]),
        )
        assert status == 404
        assert fake_gateway["calls"] == []

    def test_deleted_post_stops_being_servable(self, owner_device, owned_manifest, fake_gateway):
        """Membership follows the manifest: drop the entry, lose the access."""
        manifest_mod.save_manifest({"clients": {"drive": {"posts": []}}}, client="drive")

        path = f"/content/{CID_POST}"
        status, _, _ = call_app(
            "GET", path,
            signed_headers(path, owner_device["uid"], owner_device["device_uid"], owner_device["sk"]),
        )
        assert status == 404
        assert fake_gateway["calls"] == []


class TestStationContentCids:
    def test_collects_posts_profile_and_public_json_artifacts(self, owned_manifest):
        get_identity()  # ensure public.json exists

        # Add an avatar to the client profile bucket.
        manifest = manifest_mod.load_manifest(client="drive")
        manifest["clients"]["drive"]["profile"] = {"avatar_cid": CID_AVATAR}
        manifest_mod.save_manifest(manifest, client="drive")

        # And the artifact pointers the station keeps in public.json.
        public_obj = json.loads(manifest_mod.PUBLIC_JSON_PATH.read_text())
        public_obj["manifest_pointer"] = CID_MANIFEST
        manifest_mod.PUBLIC_JSON_PATH.write_text(json.dumps(public_obj, indent=2))

        cids = station_content_cids()
        assert {CID_POST, CID_ENVELOPES, CID_AVATAR, CID_MANIFEST} <= cids
        assert CID_FOREIGN not in cids

        assert station_owns_cid(CID_POST) is True
        assert station_owns_cid(CID_FOREIGN) is False
        assert station_owns_cid("") is False
        assert station_owns_cid(None) is False

    def test_empty_station_owns_nothing(self):
        assert station_owns_cid(CID_POST) is False


# ---------------------------------------------------------------------------
# 4. Unknown CID (owned, but not held locally) -> 404, never a network fetch
# ---------------------------------------------------------------------------

class TestLocalOnly:
    def test_owned_but_not_in_blockstore_is_404(self, owner_device, owned_manifest, fake_gateway):
        fake_gateway["state"]["raises"] = ipfs_mod.IPFSNotLocal("only-if-cached miss")

        path = f"/content/{CID_POST}"
        status, _, _ = call_app(
            "GET", path,
            signed_headers(path, owner_device["uid"], owner_device["device_uid"], owner_device["sk"]),
        )
        assert status == 404
        assert len(fake_gateway["calls"]) == 1

    def test_gateway_down_is_503_not_404(self, owner_device, owned_manifest, fake_gateway):
        """A missing daemon must not look like "this content doesn't exist"."""
        fake_gateway["state"]["raises"] = ipfs_mod.IPFSError("connection refused")

        path = f"/content/{CID_POST}"
        status, _, _ = call_app(
            "GET", path,
            signed_headers(path, owner_device["uid"], owner_device["device_uid"], owner_device["sk"]),
        )
        assert status == 503

    def test_unsatisfiable_range_is_416(self, owner_device, owned_manifest, fake_gateway):
        upstream = FakeUpstream(b"", status=416, headers={})
        fake_gateway["state"]["response"] = upstream

        path = f"/content/{CID_POST}"
        headers = signed_headers(path, owner_device["uid"], owner_device["device_uid"], owner_device["sk"])
        headers["range"] = "bytes=99999999-"
        status, _, _ = call_app("GET", path, headers)

        assert status == 416
        assert upstream.closed is True


class TestLocalOnlyReadHelpers:
    def test_cid_syntax_gate(self):
        assert ipfs_mod.is_plausible_cid(CID_POST) is True
        assert ipfs_mod.is_plausible_cid("bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi") is True
        assert ipfs_mod.is_plausible_cid("../../etc/passwd") is False
        assert ipfs_mod.is_plausible_cid("Qm/../secret") is False
        assert ipfs_mod.is_plausible_cid("short") is False

    def test_bad_cid_is_never_sent_anywhere(self, monkeypatch):
        """ipfs_open_local_stream refuses a non-CID before issuing any request."""
        def explode(*a, **kw):  # pragma: no cover - must not run
            raise AssertionError("an HTTP request was issued for a non-CID")

        monkeypatch.setattr(ipfs_mod.requests, "get", explode)
        with pytest.raises(ValueError):
            ipfs_mod.ipfs_open_local_stream("../../api/v0/id")

    def test_range_header_gate(self):
        assert ipfs_mod.is_valid_range_header("bytes=0-99") is True
        assert ipfs_mod.is_valid_range_header("bytes=100-") is True
        assert ipfs_mod.is_valid_range_header("bytes=0-99,200-299") is True
        assert ipfs_mod.is_valid_range_header("items=0-99") is False
        assert ipfs_mod.is_valid_range_header("bytes=0-99\r\nX-Evil: 1") is False
