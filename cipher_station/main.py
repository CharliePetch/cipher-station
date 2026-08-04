from fastapi import FastAPI, UploadFile, File, Form, Depends, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from starlette.responses import JSONResponse
from pydantic import BaseModel
import json
import hashlib
import logging

from cipher_station.config import ensure_directories, MAX_UPLOAD_SIZE, CORS_ORIGINS
from cipher_station.inbox import process_inbox_message
from cipher_station.rewrap import handle_rewrap_request

from cipher_station.posts import handle_new_post, handle_reshare_post
from cipher_station.manifest import remove_post_from_manifest
from cipher_station.profile import (
    get_public_profile,
    update_profile_fields,
    set_avatar_cid,
)
from cipher_station.privacy import flip_account_privacy
from cipher_station.following import follow_user, unfollow_user, list_following
from cipher_station.graph import rebuild_graphs_and_envelopes
from cipher_station.database import get_db
from cipher_station.identity import get_identity
from cipher_station.followers import (
    add_follower_device,
    list_followers,
    approve_follower,
    list_pending_followers,
    remove_follower,
)
from cipher_station.rewrap_envelopes import rewrap_all_posts
from cipher_station.pairing import create_pairing_session, confirm_pairing_session, PairingThrottled
from cipher_station.auth import require_delegate, require_owner
from cipher_station.tunnel import start_tunnel_monitor

logger = logging.getLogger(__name__)


class DelegateStart(BaseModel):
    device_uid: str
    mlkem_public_key: str   # ML-KEM-768 (content)
    mldsa_public_key: str   # ML-DSA-65 (auth)

class DelegateConfirm(BaseModel):
    pairing_id: str
    pin: str

class InboxMessage(BaseModel):
    type: str
    uid: str | None = None
    mlkem_public_key: str | None = None   # legacy single-device follow
    mldsa_public_key: str | None = None
    payload_hex: str | None = None
    devices: list[dict] | None = None
    ipns_id: str | None = None

class RewrapMessage(BaseModel):
    uid: str
    device_uid: str
    post_cid: str
    envelopes_cid: str | None = None

app = FastAPI(title="Cipher Station Node", version="1.0.0")

# --------------------------------------------
# CORS
# --------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --------------------------------------------
# Middleware: body SHA256 + upload size limit
# --------------------------------------------
@app.middleware("http")
async def capture_raw_body_sha256(request: Request, call_next):
    guarded_paths = {"/post", "/post/delete", "/post/share", "/rewrap", "/follow", "/unfollow", "/inbox"}
    if request.url.path in guarded_paths:
        cl = request.headers.get("content-length")
        if cl is not None and cl.isdigit() and int(cl) > MAX_UPLOAD_SIZE:
            return JSONResponse(
                status_code=413,
                content={"error": f"Request too large (max {MAX_UPLOAD_SIZE} bytes)"}
            )

        body = await request.body()
        request.state.raw_body_sha256 = hashlib.sha256(body).hexdigest()

        async def receive():
            return {"type": "http.request", "body": body, "more_body": False}

        request._receive = receive

    return await call_next(request)


@app.on_event("startup")
def startup():
    ensure_directories()
    get_db()

    # One-time migration: relocate client-profile fields that older builds wrote
    # into public.json over to the manifest (clients.cipherframe.profile). Runs
    # BEFORE get_identity() below strips them from public.json.
    try:
        from cipher_station.config import PUBLIC_JSON_PATH
        from cipher_station import manifest as _mf
        from cipher_station.profile import PROFILE_CLIENT
        if PUBLIC_JSON_PATH.exists():
            raw = json.loads(PUBLIC_JSON_PATH.read_text())
            legacy = {k: raw[k] for k in _mf.CLIENT_PROFILE_FIELDS
                      if k in raw and raw[k] is not None}
            if legacy:
                existing = _mf.get_client_profile(client=PROFILE_CLIENT)
                seed = {k: v for k, v in legacy.items() if k not in existing}
                if seed:
                    _mf.set_client_profile(seed, client=PROFILE_CLIENT)
                    logger.info("Migrated profile fields public.json -> manifest: %s", sorted(seed))
    except Exception as exc:
        logger.warning("Profile migration skipped: %s", exc)

    ident = get_identity()
    pub_json = ident.public_json
    uid = pub_json["uid"]
    device_uid = pub_json.get("device_uid", uid)

    try:
        add_follower_device(
            uid,
            device_uid,
            mlkem_public_key=ident.mlkem_pub_hex,
            mldsa_public_key=ident.mldsa_pub_hex,
            alias=pub_json.get("alias"),
            allowed="Allowed"
        )
    except Exception:
        pass

    logger.info(f"Station ready: uid={uid}, device_uid={device_uid}")

    # Start Cloudflare tunnel URL monitor (if enabled)
    start_tunnel_monitor()


# ---------------------------------------------------------
# HEALTH CHECK
# ---------------------------------------------------------
@app.get("/health")
def health_check():
    checks = {"database": False, "ipfs": False, "identity": False}

    try:
        db = get_db()
        db.execute("SELECT 1").fetchone()
        checks["database"] = True
    except Exception as e:
        logger.error(f"Health check DB failed: {e}")

    try:
        from cipher_station.ipfs_client import ipfs_add_bytes
        ipfs_add_bytes(b"health")
        checks["ipfs"] = True
    except Exception as e:
        logger.error(f"Health check IPFS failed: {e}")

    try:
        get_identity()
        checks["identity"] = True
    except Exception as e:
        logger.error(f"Health check identity failed: {e}")

    all_ok = all(checks.values())
    return JSONResponse(
        status_code=200 if all_ok else 503,
        content={"status": "healthy" if all_ok else "degraded", "checks": checks}
    )


# ---------------------------------------------------------
# STORAGE
# ---------------------------------------------------------
@app.get("/storage")
def storage_info():
    """
    Returns IPFS repo usage, device disk usage, per-client breakdowns,
    and computed percentages.
    """
    import shutil
    from cipher_station.ipfs_client import ipfs_repo_stat, ipfs_object_stat
    from cipher_station.manifest import load_manifest
    from cipher_station.config import BASE_DIR

    result = {}

    # IPFS repo stats
    repo_size = 0
    try:
        repo = ipfs_repo_stat()
        repo_size = repo.get("RepoSize", 0)
        storage_max = repo.get("StorageMax", 0)
        num_objects = repo.get("NumObjects", 0)
        repo_pct = round((repo_size / storage_max) * 100, 2) if storage_max > 0 else 0

        result["ipfs"] = {
            "repo_size_bytes": repo_size,
            "storage_max_bytes": storage_max,
            "num_objects": num_objects,
            "used_percent": repo_pct,
        }
    except Exception as e:
        logger.error(f"Failed to get IPFS repo stat: {e}")
        result["ipfs"] = {"error": str(e)}

    # Device disk stats (partition where cipher_station_data lives)
    try:
        disk = shutil.disk_usage(BASE_DIR)
        disk_pct = round((disk.used / disk.total) * 100, 2) if disk.total > 0 else 0

        result["device"] = {
            "total_bytes": disk.total,
            "used_bytes": disk.used,
            "free_bytes": disk.free,
            "used_percent": disk_pct,
        }
    except Exception as e:
        logger.error(f"Failed to get disk usage: {e}")
        result["device"] = {"error": str(e)}

    # Per-client storage breakdown from manifest
    try:
        manifest = load_manifest()
        clients_usage = {}
        total_content_bytes = 0

        for client_key, bucket in manifest.get("clients", {}).items():
            client_bytes = 0
            post_count = 0

            for post in bucket.get("posts", []):
                post_count += 1
                for cid_key in ("post_cid", "envelopes_cid"):
                    cid = post.get(cid_key)
                    if cid:
                        try:
                            stat = ipfs_object_stat(cid)
                            client_bytes += stat.get("CumulativeSize", 0)
                        except Exception:
                            pass

            total_content_bytes += client_bytes
            pct_of_repo = round((client_bytes / repo_size) * 100, 2) if repo_size > 0 else 0

            clients_usage[client_key] = {
                "size_bytes": client_bytes,
                "post_count": post_count,
                "percent_of_repo": pct_of_repo,
            }

        result["clients"] = clients_usage
        result["total_content_bytes"] = total_content_bytes
    except Exception as e:
        logger.error(f"Failed to compute per-client storage: {e}")
        result["clients"] = {"error": str(e)}

    return result


# ---------------------------------------------------------
# CONTENT
#
# Serves already-pinned bytes straight off this station, so a delegate never
# has to ask a public gateway to go find content the station is already
# holding. (Public gateways must cold-fetch the blocks over bitswap from this
# node; on a thinly-peered box that is slow and, for large objects, routinely
# truncates mid-body — which surfaces on iOS as "network connection lost".)
#
# Two things keep this from being an open IPFS proxy:
#   1. require_owner — only the station owner's own paired delegate devices.
#   2. station_owns_cid — only CIDs this station published (see manifest.py).
# The read is local in the way that matters, but not by fiat: only-if-cached is
# evaluated at the ROOT, so a root we lack is a fast 404 and never a pull, while
# a cached root with absent children would still fetch them over bitswap. What
# makes that unreachable is the set above — the station added and recursively
# pinned everything station_owns_cid admits, so it holds the whole DAG. Widen
# that set to content the station did not pin and this stops being true.
# ---------------------------------------------------------
@app.get("/content/{cid}")
def get_content(cid: str, request: Request, delegate=Depends(require_owner)):
    from cipher_station.ipfs_client import (
        CONTENT_CHUNK_SIZE,
        IPFSNotLocal,
        ipfs_open_local_stream,
        is_plausible_cid,
    )
    from cipher_station.manifest import station_owns_cid
    from starlette.responses import StreamingResponse

    # Malformed, unknown, and not-held-locally all answer the same 404: the
    # station will not confirm which of the three it was.
    if not is_plausible_cid(cid) or not station_owns_cid(cid):
        logger.info("GET /content/%s rejected: not published by this station", cid)
        raise HTTPException(status_code=404, detail="content not found")

    try:
        upstream = ipfs_open_local_stream(cid, range_header=request.headers.get("range"))
    except IPFSNotLocal:
        logger.warning("GET /content/%s: referenced by our state but not in the local blockstore", cid)
        raise HTTPException(status_code=404, detail="content not found")
    except Exception as exc:
        logger.error("GET /content/%s: local gateway read failed: %s", cid, exc)
        raise HTTPException(status_code=503, detail="content store unavailable")

    if upstream.status_code == 416:
        upstream.close()
        raise HTTPException(status_code=416, detail="requested range not satisfiable")

    headers = {"Accept-Ranges": "bytes"}
    for header in ("Content-Length", "Content-Range", "ETag"):
        value = upstream.headers.get(header)
        if value:
            headers[header] = value

    def stream():
        try:
            for chunk in upstream.iter_content(chunk_size=CONTENT_CHUNK_SIZE):
                if chunk:
                    yield chunk
        finally:
            upstream.close()

    return StreamingResponse(
        stream(),
        status_code=upstream.status_code,   # 200, or 206 for a Range request
        headers=headers,
        media_type="application/octet-stream",
    )


# ---------------------------------------------------------
# INBOX
# ---------------------------------------------------------
@app.post("/inbox")
async def inbox(request: Request, msg: InboxMessage):
    if msg.type != "follow_request":
        await require_delegate(request)

    ident = get_identity()
    result = process_inbox_message(ident.mlkem_sk, msg.model_dump())
    return {"status": "ok", "result": result}


# ---------------------------------------------------------
# REWRAP
# ---------------------------------------------------------
@app.post("/rewrap")
def rewrap_route(msg: RewrapMessage, delegate=Depends(require_owner)):
    if delegate["uid"] != msg.uid or delegate["device_uid"] != msg.device_uid:
        raise HTTPException(status_code=401, detail="header/body mismatch")

    ident = get_identity()
    result = handle_rewrap_request(ident.mlkem_sk, msg.model_dump())
    return {"status": "ok", "result": result}


# ---------------------------------------------------------
# NEW POST
# ---------------------------------------------------------
@app.post("/post")
def create_post(
    delegate=Depends(require_owner),
    file: UploadFile = File(...),
    metadata: str = Form(None),
    client: str = Form(None),
    audience_mode: str = Form("all"),
    audience_uids: str = Form(None),
    self_envelope: str = Form(None),
):
    # Non-public posts MUST arrive already encrypted: `file` is SecretBox
    # ciphertext, `metadata` (if any) is already-encrypted hex, and
    # self_envelope is that post's symmetric key ML-KEM-sealed to the
    # station's own public key. The station never receives plaintext content
    # or a key sent outside a post-quantum-wrapped channel — see posts.py.
    if audience_mode != "public" and not self_envelope:
        raise HTTPException(status_code=400, detail="self_envelope is required for non-public posts")

    file_bytes = file.file.read()

    metadata_obj = None
    if metadata:
        if audience_mode == "public":
            try:
                metadata_obj = json.loads(metadata)
            except Exception as e:
                logger.warning(f"Invalid metadata JSON: {e}")
        else:
            metadata_obj = metadata  # already-encrypted hex, stored as-is

    # Parse audience_uids from JSON string if provided
    parsed_audience_uids = None
    if audience_uids:
        try:
            parsed_audience_uids = json.loads(audience_uids)
        except Exception:
            parsed_audience_uids = [u.strip() for u in audience_uids.split(",") if u.strip()]

    try:
        return handle_new_post(
            file_bytes,
            metadata=metadata_obj,
            client=client,
            audience_mode=audience_mode,
            audience_uids=parsed_audience_uids,
            self_envelope=self_envelope,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


# ---------------------------------------------------------
# DELETE POST
# ---------------------------------------------------------
class DeletePostRequest(BaseModel):
    post_cid: str
    client: str | None = None


@app.post("/post/delete")
def delete_post(req: DeletePostRequest, delegate=Depends(require_owner)):
    result = remove_post_from_manifest(req.post_cid, client=req.client)
    if result["status"] == "not_found":
        raise HTTPException(status_code=404, detail=f"Post {req.post_cid} not found in manifest")
    return result


# ---------------------------------------------------------
# SHARE / RESHARE POST
# ---------------------------------------------------------
class SharePostRequest(BaseModel):
    post_cid: str
    audience_mode: str = "specific"
    audience_uids: list[str] | None = None
    client: str | None = None


@app.post("/post/share")
def share_post(req: SharePostRequest, delegate=Depends(require_owner)):
    try:
        result = handle_reshare_post(
            req.post_cid,
            audience_mode=req.audience_mode,
            audience_uids=req.audience_uids,
            client=req.client,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    if result.get("status") == "not_found":
        raise HTTPException(status_code=404, detail=f"Post {req.post_cid} not found")
    if result.get("status") == "error":
        raise HTTPException(status_code=500, detail=result.get("detail", "Unknown error"))

    return result


# ---------------------------------------------------------
# PUBLIC PROFILE
# ---------------------------------------------------------
@app.get("/profile")
def profile():
    return get_public_profile()


# ---------------------------------------------------------
# UPDATE PROFILE (owner-only)
# ---------------------------------------------------------
class ProfileUpdateRequest(BaseModel):
    display_name: str | None = None
    username: str | None = None
    bio: str | None = None
    link: str | None = None


@app.post("/profile/update")
def profile_update(req: ProfileUpdateRequest, owner=Depends(require_owner)):
    # Only update keys the client actually sent (omit unset fields, so a missing
    # key is "leave unchanged" while an explicit "" clears the field).
    provided = req.model_dump(exclude_unset=True)
    try:
        prof = update_profile_fields(**provided)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"status": "profile_updated", "profile": prof}


# ---------------------------------------------------------
# UPDATE AVATAR (owner-only)
# ---------------------------------------------------------
@app.post("/profile/avatar")
def profile_avatar(
    owner=Depends(require_owner),
    file: UploadFile = File(...),
):
    from cipher_station.ipfs_client import ipfs_add_bytes

    file_bytes = file.file.read()
    avatar_cid = ipfs_add_bytes(file_bytes)  # PLAINTEXT/public blob
    set_avatar_cid(avatar_cid)
    return {"status": "avatar_updated", "avatar_cid": avatar_cid}


# ---------------------------------------------------------
# LIST FOLLOWING (owner-only)
# ---------------------------------------------------------
@app.get("/following")
def api_list_following(owner=Depends(require_owner)):
    rows = list_following()
    following = [
        {
            "uid": r.get("uid"),
            "endpoint": r.get("endpoint"),
            "ipns_id": r.get("ipns_id"),
            "mlkem_public_key": r.get("mlkem_public_key"),
            "mldsa_public_key": r.get("mldsa_public_key"),
        }
        for r in rows
    ]
    return {"status": "ok", "following": following}


# ---------------------------------------------------------
# PRIVACY FLIP (owner-only)
# ---------------------------------------------------------
class PrivacyFlipRequest(BaseModel):
    mode: str
    audience_mode: str = "all"
    audience_uids: list[str] | None = None
    client: str = "cipherframe"


@app.post("/privacy/flip")
def privacy_flip(req: PrivacyFlipRequest, owner=Depends(require_owner)):
    if req.mode not in ("private", "public"):
        raise HTTPException(status_code=400, detail="mode must be 'private' or 'public'")
    return flip_account_privacy(
        req.mode,
        audience_mode=req.audience_mode,
        audience_uids=req.audience_uids,
        client=req.client,
    )


# ---------------------------------------------------------
# LIST FOLLOWERS (for share picker)
# ---------------------------------------------------------
@app.get("/followers")
def api_list_followers(delegate=Depends(require_owner)):
    """
    Returns user-level followers (deduplicated from devices),
    excluding the station's own UID.
    """
    self_uid = get_identity().uid

    raw = list_followers()

    # Deduplicate to user level, keep only Allowed, exclude self
    seen: dict[str, dict] = {}
    for f in raw:
        uid = f.get("uid")
        if not uid or uid == self_uid:
            continue
        if f.get("allowed") != "Allowed":
            continue
        if uid not in seen:
            seen[uid] = {
                "uid": uid,
                "alias": f.get("alias"),
                "endpoint": f.get("endpoint"),
                "ipns_id": f.get("ipns_id"),
            }

    return {
        "status": "ok",
        "followers": sorted(seen.values(), key=lambda f: f["uid"]),
    }


# ---------------------------------------------------------
# FOLLOWER APPROVAL (owner-only)
#
# Inbound follow requests land as "Pending" (unless dev auto-accept is on). The
# owner reviews pending requests and approves them here; approval is the only
# place a follower becomes "Allowed" and gets content + social-graph envelopes.
# ---------------------------------------------------------
@app.get("/followers/pending")
def api_list_pending_followers(owner=Depends(require_owner)):
    """Return follower devices awaiting the owner's approval."""
    self_uid = get_identity().uid
    pending = [p for p in list_pending_followers() if p.get("uid") != self_uid]
    return {"status": "ok", "pending": pending}


class ApproveFollowerRequest(BaseModel):
    uid: str
    device_uid: str | None = None  # omit to approve all devices for this uid


@app.post("/followers/approve")
def api_approve_follower(req: ApproveFollowerRequest, owner=Depends(require_owner)):
    self_uid = get_identity().uid
    if req.uid == self_uid:
        raise HTTPException(status_code=400, detail="cannot approve the station's own uid")

    updated = approve_follower(req.uid, req.device_uid)
    if updated == 0:
        raise HTTPException(status_code=404, detail="no matching follower to approve")

    # Now that the follower is Allowed, grant access: rewrap "all" post envelopes
    # and rebuild the encrypted social graph so they receive their envelopes.
    ident = get_identity()
    rewrap = None
    try:
        rewrap = rewrap_all_posts(ident.mlkem_sk)
    except Exception as e:
        rewrap = {"error": str(e)}
    cids = rebuild_graphs_and_envelopes()

    return {
        "status": "ok",
        "action": "approve_follower",
        "uid": req.uid,
        "device_uid": req.device_uid,
        "devices_approved": updated,
        "rewrap": rewrap,
        "updated_graph": cids,
    }


class RemoveFollowerRequest(BaseModel):
    uid: str
    device_uid: str | None = None  # omit to remove every device for this uid


@app.post("/followers/remove")
def api_remove_follower(req: RemoveFollowerRequest, owner=Depends(require_owner)):
    """
    Reject a pending follow request or revoke an existing follower (owner-only).

    Removing an Allowed follower re-wraps content envelopes and rebuilds the
    encrypted social graph so the published state no longer includes them.
    (Already-published content they previously had keys for cannot be recalled —
    IPFS has no delete — but they receive no new envelopes going forward.)
    """
    self_uid = get_identity().uid
    if req.uid == self_uid:
        raise HTTPException(status_code=400, detail="cannot remove the station's own identity")

    result = remove_follower(req.uid, req.device_uid)
    if result["removed"] == 0:
        raise HTTPException(status_code=404, detail="no matching follower to remove")

    rewrap = None
    cids = None
    if result["removed_allowed"]:
        ident = get_identity()
        try:
            rewrap = rewrap_all_posts(ident.mlkem_sk)
        except Exception as e:
            rewrap = {"error": str(e)}
        cids = rebuild_graphs_and_envelopes()

    return {
        "status": "ok",
        "action": "remove_follower",
        "uid": req.uid,
        "device_uid": req.device_uid,
        "removed": result["removed"],
        "removed_allowed": result["removed_allowed"],
        "rewrap": rewrap,
        "updated_graph": cids,
    }


class FollowRequest(BaseModel):
    uid: str
    endpoint: str
    mlkem_public_key: str               # ML-KEM-768 (content)
    mldsa_public_key: str | None = None  # ML-DSA-65 (auth), optional for read-only targets
    ipns_id: str | None = None          # IPNS peer ID for permanent discovery


# ---------------------------------------------------------
# FOLLOW / UNFOLLOW
# ---------------------------------------------------------
@app.post("/follow")
def api_follow(req: FollowRequest, auth_ctx=Depends(require_owner)):
    follow_user(
        req.uid,
        mlkem_public_key=req.mlkem_public_key,
        endpoint=req.endpoint,
        mldsa_public_key=req.mldsa_public_key,
        ipns_id=req.ipns_id,
    )

    cids = rebuild_graphs_and_envelopes()
    prof = get_public_profile()

    return {
        "status": "ok",
        "action": "follow",
        "target": {
            "uid": req.uid,
            "mlkem_public_key": req.mlkem_public_key,
            "mldsa_public_key": req.mldsa_public_key,
            "endpoint": req.endpoint,
            "ipns_id": req.ipns_id,
        },
        "updated_graph": cids,
        "updated_profile": prof
    }


class UnfollowRequest(BaseModel):
    uid: str


@app.post("/unfollow")
def api_unfollow(req: UnfollowRequest, auth_ctx=Depends(require_owner)):
    unfollow_user(req.uid)

    cids = rebuild_graphs_and_envelopes()
    prof = get_public_profile()

    return {
        "status": "ok",
        "action": "unfollow",
        "target": {"uid": req.uid},
        "updated_graph": cids,
        "updated_profile": prof
    }


@app.post("/delegate/start")
def delegate_start(req: DelegateStart):
    try:
        sess = create_pairing_session(req.device_uid, req.mlkem_public_key, req.mldsa_public_key)
    except PairingThrottled as e:
        raise HTTPException(status_code=429, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    logger.info(f"Pairing session created: pairing_id={sess.pairing_id}")
    logger.info(f">>> PAIRING PIN: {sess.pin} <<< (expires in 5 minutes)")
    return {"status": "ok", "pairing_id": sess.pairing_id, "expires_in_seconds": 5 * 60}


@app.post("/delegate/confirm")
def delegate_confirm(req: DelegateConfirm):
    try:
        device_uid, device_mlkem_pk, device_mldsa_pk = confirm_pairing_session(req.pairing_id, req.pin)
    except PairingThrottled as e:
        raise HTTPException(status_code=429, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    uid = get_identity().uid

    add_follower_device(
        uid,
        device_uid,
        mlkem_public_key=device_mlkem_pk,
        mldsa_public_key=device_mldsa_pk,
        alias=None,
        allowed="Allowed"
    )

    return {"status": "ok", "action": "delegate_added", "uid": uid, "device_uid": device_uid}
