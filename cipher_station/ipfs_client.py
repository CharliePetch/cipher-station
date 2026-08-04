# cipher_station/ipfs_client.py

import logging
import re
import time
from urllib.parse import quote

import requests

from cipher_station.config import (
    IPFS_API,
    IPFS_GATEWAY,
    IPFS_TIMEOUT,
    IPFS_MAX_RETRIES,
)

logger = logging.getLogger(__name__)


class IPFSError(Exception):
    """Raised when an IPFS operation fails after all retries."""
    pass


class IPFSNotLocal(IPFSError):
    """
    The requested CID is not in this node's local blockstore.

    Raised instead of going out to the network for it — see
    ``ipfs_open_local_stream``.
    """
    pass


def _with_retry(func):
    """
    Execute *func* with exponential-backoff retry on transient errors.
    Non-transient HTTP errors (4xx) are raised immediately.
    """
    last_exc = None
    for attempt in range(IPFS_MAX_RETRIES):
        try:
            return func()
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as exc:
            last_exc = exc
            if attempt < IPFS_MAX_RETRIES - 1:
                wait = 2 ** attempt
                logger.warning(
                    "IPFS retry %d/%d in %ds: %s", attempt + 1, IPFS_MAX_RETRIES, wait, exc
                )
                time.sleep(wait)
        except requests.exceptions.RequestException as exc:
            raise IPFSError(f"IPFS request error: {exc}") from exc

    raise IPFSError(
        f"IPFS failed after {IPFS_MAX_RETRIES} attempts: {last_exc}"
    ) from last_exc


def ipfs_add_bytes(data: bytes) -> str:
    """
    Upload raw binary content to IPFS.
    Returns the CID (string).
    """
    def _post():
        r = requests.post(
            f"{IPFS_API}/api/v0/add",
            files={"file": ("blob.bin", data)},
            timeout=IPFS_TIMEOUT,
        )
        r.raise_for_status()
        cid = r.json()["Hash"]
        logger.debug("IPFS add OK: %s (%d bytes)", cid, len(data))
        return cid

    return _with_retry(_post)


def ipfs_add_file(path: str) -> str:
    """
    Upload a local disk file to IPFS and return the CID.

    Currently has no callers. If you add one, record the resulting CID somewhere
    ``manifest.station_content_cids()`` looks — otherwise the content exists and
    is pinned but ``GET /content/{cid}`` will 404 it, because that route serves
    only CIDs this station's own state references.
    """
    with open(path, "rb") as f:
        return ipfs_add_bytes(f.read())


def ipfs_unpin(cid: str) -> bool:
    """
    Unpin a CID from the local IPFS node so it can be garbage-collected.
    Returns True if the unpin succeeded (or the CID was already unpinned).
    """
    def _post():
        r = requests.post(
            f"{IPFS_API}/api/v0/pin/rm",
            params={"arg": cid},
            timeout=IPFS_TIMEOUT,
        )
        if r.status_code == 500 and "not pinned" in r.text.lower():
            logger.debug("IPFS unpin: %s was already unpinned", cid)
            return True
        r.raise_for_status()
        logger.debug("IPFS unpin OK: %s", cid)
        return True

    return _with_retry(_post)


def ipfs_repo_gc() -> list[str]:
    """
    Run IPFS garbage collection to reclaim disk space from unpinned objects.
    Returns a list of CIDs that were removed.
    """
    def _post():
        r = requests.post(
            f"{IPFS_API}/api/v0/repo/gc",
            timeout=120,
        )
        r.raise_for_status()
        # The response is newline-delimited JSON objects
        removed = []
        for line in r.text.strip().splitlines():
            try:
                obj = __import__("json").loads(line)
                key = obj.get("Key", {})
                cid = key.get("/") if isinstance(key, dict) else None
                if cid:
                    removed.append(cid)
            except Exception:
                continue
        logger.info("IPFS GC completed: %d objects removed", len(removed))
        return removed

    return _with_retry(_post)


def ipfs_repo_stat() -> dict:
    """
    Get IPFS repo statistics (storage used, object count, etc.).
    Returns {"RepoSize": int, "StorageMax": int, "NumObjects": int, ...}.
    """
    def _post():
        r = requests.post(
            f"{IPFS_API}/api/v0/repo/stat",
            timeout=IPFS_TIMEOUT,
        )
        r.raise_for_status()
        return r.json()

    return _with_retry(_post)


def ipfs_object_stat(cid: str) -> dict:
    """
    Get stats for an individual IPFS object.
    Returns {"Hash": str, "CumulativeSize": int, "DataSize": int, ...}.
    CumulativeSize is the total size including linked objects.
    """
    def _post():
        r = requests.post(
            f"{IPFS_API}/api/v0/object/stat",
            params={"arg": cid},
            timeout=IPFS_TIMEOUT,
        )
        r.raise_for_status()
        return r.json()

    return _with_retry(_post)


def ipfs_get_bytes(cid: str) -> bytes:
    """
    Fetch raw binary data from IPFS.

    Buffers the whole object in memory and MAY fetch from the network. Fine for
    the small JSON documents the station reads (envelopes, graphs); use
    ``ipfs_open_local_stream`` for serving post blobs.
    """
    def _post():
        r = requests.post(
            f"{IPFS_API}/api/v0/cat",
            params={"arg": cid},
            timeout=IPFS_TIMEOUT,
        )
        r.raise_for_status()
        logger.debug("IPFS cat OK: %s (%d bytes)", cid, len(r.content))
        return r.content

    return _with_retry(_post)


# ---------------------------------------------------------------------------
# Local-only streaming read (backs GET /content/{cid})
# ---------------------------------------------------------------------------

# Both CIDv0 (base58btc, "Qm…", 46 chars) and CIDv1 (base32, "bafy…", 59+) are
# alphanumeric. Anything else cannot be a CID, and — since the value is
# interpolated into a gateway URL path — must never reach the request.
_CID_RE = re.compile(r"^[A-Za-z0-9]{46,128}$")

# `bytes=<a>-<b>` with either bound optional, optionally a comma-separated list.
_RANGE_RE = re.compile(r"^bytes=\d*-\d*(?:\s*,\s*\d*-\d*)*$")

CONTENT_CHUNK_SIZE = 64 * 1024


def is_plausible_cid(cid: str) -> bool:
    """Cheap syntactic check: could this string be a CID? (Not a decode.)"""
    return isinstance(cid, str) and bool(_CID_RE.match(cid))


def is_valid_range_header(value: str) -> bool:
    """Whether a client-supplied Range header is safe to pass to the gateway."""
    return isinstance(value, str) and len(value) <= 128 and bool(_RANGE_RE.match(value))


def ipfs_open_local_stream(cid: str, *, range_header: str | None = None):
    """
    Open a STREAMING read of `cid` from this node's own HTTP gateway, without
    going to the network for content the node does not already have.

    How far ``only-if-cached`` actually goes, because it is easy to over-trust:
    kubo evaluates it at the RESOLVED ROOT. A root the node lacks answers 412 in
    milliseconds and never touches the network — but once the root is cached,
    missing CHILD blocks are fetched over bitswap as normal (measured: ~20 MB
    pulled inside a request carrying the header). The guarantee that callers
    actually rely on is upstream of this function: the station added and
    recursively pinned everything ``station_owns_cid`` will admit, so it holds
    the whole DAG. Widen that set to content the station did not itself pin and
    this stops being a local read.

    Why the gateway and not ``/api/v0/cat``:
      * it sets Content-Length and honours HTTP Range (206 + Content-Range),
        so a resumable download needs no size bookkeeping here;
      * it implements ``Cache-Control: only-if-cached``, answering 412 in
        milliseconds when the blocks are not already local. ``/api/v0/cat`` can
        do local-only too (``offline=true``), but gives neither length nor Range.
    Both installers bind the gateway to 127.0.0.1:8080; it is not publicly
    exposed. Override with IPFS_GATEWAY_URL.

    Returns the open ``requests.Response`` — 200, 206 for a satisfied Range, or
    416 for an unsatisfiable one. THE CALLER OWNS IT and MUST call ``.close()``
    — iterate ``.iter_content()`` inside a try/finally.

    Raises:
        ValueError    — `cid` is not syntactically a CID (never sent anywhere).
        IPFSNotLocal  — the gateway has no local copy (412), or the CID is
                        unroutable/invalid (400/404/410/451). No network fetch
                        was attempted.
        IPFSError     — the gateway is unreachable or answered unexpectedly.
    """
    if not is_plausible_cid(cid):
        raise ValueError(f"not a CID: {cid!r}")

    headers = {
        # Never fetch from the network: 412 if it is not already in the
        # blockstore. This is what keeps an authenticated route from doubling
        # as "make the station go get arbitrary content off IPFS".
        "Cache-Control": "only-if-cached",
        # Keep Content-Length meaningful: no transport compression.
        "Accept-Encoding": "identity",
    }
    if range_header and is_valid_range_header(range_header):
        headers["Range"] = range_header

    url = f"{IPFS_GATEWAY}/ipfs/{quote(cid, safe='')}"

    try:
        resp = requests.get(
            url,
            headers=headers,
            stream=True,
            timeout=IPFS_TIMEOUT,
            allow_redirects=False,
        )
    except requests.exceptions.RequestException as exc:
        raise IPFSError(f"local IPFS gateway unreachable: {exc}") from exc

    if resp.status_code in (200, 206, 416):
        return resp

    status = resp.status_code
    resp.close()

    if status in (400, 404, 410, 412, 451):
        # 412 == only-if-cached miss (not held locally); the rest mean the
        # gateway will not serve this path at all.
        raise IPFSNotLocal(f"CID not available locally: {cid} (gateway {status})")

    raise IPFSError(f"local IPFS gateway returned {status} for {cid}")


# ---------------------------------------------------------------------------
# IPNS
# ---------------------------------------------------------------------------

def ipfs_name_publish(cid: str, lifetime: str = "720h", ttl: str = "1m0s") -> dict:
    """
    Publish a CID to IPNS under this node's peer ID (the 'self' key).
    Returns {"Name": "<peer-id>", "Value": "/ipfs/<cid>"}.
    Uses a longer timeout because IPNS DHT publishing is slow.

    `ttl` is the record's caching hint: a short TTL (1m) tells gateways and
    delegated routers to re-resolve sooner, reducing how long a stale record is
    served after the endpoint rotates. It is independent of `lifetime` (the
    record's validity window), which stays long so the record survives the node
    being offline.
    """
    def _post():
        r = requests.post(
            f"{IPFS_API}/api/v0/name/publish",
            params={"arg": cid, "lifetime": lifetime, "ttl": ttl},
            timeout=60,
        )
        r.raise_for_status()
        result = r.json()
        logger.info("IPNS publish OK: %s -> /ipfs/%s", result.get("Name", "?"), cid)
        return result

    return _with_retry(_post)


def ipfs_name_resolve(name: str) -> str:
    """
    Resolve an IPNS name to an /ipfs/CID path.
    Returns the path string, e.g. "/ipfs/QmXyz...".
    """
    def _post():
        r = requests.post(
            f"{IPFS_API}/api/v0/name/resolve",
            params={"arg": name},
            timeout=30,
        )
        r.raise_for_status()
        return r.json()["Path"]

    return _with_retry(_post)


def ipfs_id() -> dict:
    """
    Get this IPFS node's identity.
    Returns {"ID": "<peer-id>", "PublicKey": "...", "Addresses": [...]}.
    """
    def _post():
        r = requests.post(
            f"{IPFS_API}/api/v0/id",
            timeout=IPFS_TIMEOUT,
        )
        r.raise_for_status()
        return r.json()

    return _with_retry(_post)


def ipfs_self_ipns_name() -> str | None:
    """
    This node's IPNS name in base36 CIDv1 (``k51…``) form.

    This is the encoding public subdomain gateways accept verbatim
    (``https://<name>.ipns.dweb.link``); the base58 peer id (``12D3KooW…``)
    is not a valid DNS label and 500s there. Returned so the client can use the
    name directly for endpoint recovery without any base conversion.
    """
    def _post():
        r = requests.post(
            f"{IPFS_API}/api/v0/key/list?l=true&ipns-base=base36",
            timeout=IPFS_TIMEOUT,
        )
        r.raise_for_status()
        return r.json()

    try:
        data = _with_retry(_post)
        for key in data.get("Keys", []):
            if key.get("Name") == "self":
                return key.get("Id")
    except Exception as exc:
        logger.debug("Could not fetch base36 IPNS name: %s", exc)
    return None


# ---------------------------------------------------------------------------
# public.json → IPFS + IPNS (shared helper)
# ---------------------------------------------------------------------------

def publish_public_json_to_ipns() -> str | None:
    """
    Read public.json from disk, publish it to IPFS, then update the IPNS pointer.
    Returns the new CID, or None if publishing fails.

    Call this after ANY mutation to public.json (new post, graph rebuild, rewrap, etc.)
    so that the IPNS record always points to the latest state.
    """
    import json
    from cipher_station.config import PUBLIC_JSON_PATH

    try:
        if not PUBLIC_JSON_PATH.exists():
            logger.warning("publish_public_json_to_ipns: public.json not found, skipping")
            return None

        obj = json.loads(PUBLIC_JSON_PATH.read_text())

        # Ensure IPFS identity fields are current: the base58 peer id, plus the
        # base36 IPNS name (k51…) that the client uses for endpoint recovery
        # (directly usable on public gateways — no base conversion needed).
        try:
            node_info = ipfs_id()
            peer_id = node_info.get("ID")
            ipns_name = ipfs_self_ipns_name()
            changed = False
            if peer_id and obj.get("ipfs_peer_id") != peer_id:
                obj["ipfs_peer_id"] = peer_id
                changed = True
            if ipns_name and obj.get("ipns_name") != ipns_name:
                obj["ipns_name"] = ipns_name
                changed = True
            if changed:
                PUBLIC_JSON_PATH.write_text(json.dumps(obj, indent=2))
        except Exception as exc:
            logger.debug("Could not refresh IPFS identity fields: %s", exc)

        # Publish to IPFS
        public_json_bytes = json.dumps(obj, indent=2).encode("utf-8")
        cid = ipfs_add_bytes(public_json_bytes)
        logger.info("public.json published to IPFS: %s", cid)

        # Update IPNS pointer
        result = ipfs_name_publish(cid, lifetime="8760h")
        logger.info(
            "IPNS pointer updated: %s -> /ipfs/%s",
            result.get("Name", "?"), cid,
        )
        return cid

    except Exception as exc:
        logger.warning("IPNS publish failed (station still works via HTTP): %s", exc)
        return None
