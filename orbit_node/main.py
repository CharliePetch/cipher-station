from fastapi import FastAPI, UploadFile, File, Form, Depends, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from starlette.responses import JSONResponse
from pydantic import BaseModel
import json
import hashlib
import logging

from orbit_node.config import ensure_directories, MAX_UPLOAD_SIZE, CORS_ORIGINS
from orbit_node.inbox import process_inbox_message
from orbit_node.rewrap import handle_rewrap_request

from orbit_node.posts import handle_new_post, handle_reshare_post
from orbit_node.manifest import remove_post_from_manifest
from orbit_node.profile import get_public_profile
from orbit_node.following import follow_user, unfollow_user
from orbit_node.graph import rebuild_graphs_and_envelopes
from orbit_node.database import get_db
from orbit_node.identity import get_identity
from orbit_node.followers import (
    add_follower_device,
    list_followers,
    approve_follower,
    list_pending_followers,
    remove_follower,
)
from orbit_node.rewrap_envelopes import rewrap_all_posts
from orbit_node.pairing import create_pairing_session, confirm_pairing_session, PairingThrottled
from orbit_node.auth import require_delegate, require_owner
from orbit_node.tunnel import start_tunnel_monitor

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

app = FastAPI(title="Orbit Node", version="1.0.0")

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
        from orbit_node.ipfs_client import ipfs_add_bytes
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
    from orbit_node.ipfs_client import ipfs_repo_stat, ipfs_object_stat
    from orbit_node.manifest import load_manifest
    from orbit_node.config import BASE_DIR

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

    # Device disk stats (partition where orbit_data lives)
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
):
    file_bytes = file.file.read()

    metadata_obj = None
    if metadata:
        try:
            metadata_obj = json.loads(metadata)
        except Exception as e:
            logger.warning(f"Invalid metadata JSON: {e}")

    # Parse audience_uids from JSON string if provided
    parsed_audience_uids = None
    if audience_uids:
        try:
            parsed_audience_uids = json.loads(audience_uids)
        except Exception:
            parsed_audience_uids = [u.strip() for u in audience_uids.split(",") if u.strip()]

    return handle_new_post(
        file_bytes,
        metadata=metadata_obj,
        client=client,
        audience_mode=audience_mode,
        audience_uids=parsed_audience_uids,
    )


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
