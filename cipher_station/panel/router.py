# cipher_station/panel/router.py
"""
Admin panel routes, served ONLY by the dedicated loopback panel app
(cipher_station/panel/app.py) — never mounted on the main :8443 station app.

Two routers:

- ``panel_router``: the HTML shell + static assets. Localhost-guarded only —
  they contain no secrets, and the SPA needs to load before it can ask the
  operator for the token.
- ``panel_api``: every /admin/api route. Localhost guard PLUS the per-boot
  bearer token (guard.require_panel_token, constant-time compare).

None of them use the x-cipher-* signed-header auth: the trust boundary is the
dedicated 127.0.0.1 listener plus the panel token.
"""

import logging
from pathlib import Path

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from pydantic import BaseModel
from starlette.responses import FileResponse, Response

from cipher_station import config as cfg
from cipher_station.panel import drive, service
from cipher_station.panel.guard import require_localhost, require_panel_token

logger = logging.getLogger(__name__)

STATIC_DIR = Path(__file__).resolve().parent / "static"

panel_router = APIRouter(prefix="/admin", dependencies=[Depends(require_localhost)])
panel_api = APIRouter(
    prefix="/admin/api",
    dependencies=[Depends(require_localhost), Depends(require_panel_token)],
)


# ---------------------------------------------------------------------------
# Page + static assets (no token: no secrets, and the SPA must be able to
# render its token prompt)
# ---------------------------------------------------------------------------

@panel_router.get("", include_in_schema=False)
@panel_router.get("/", include_in_schema=False)
def panel_index():
    return FileResponse(STATIC_DIR / "index.html", media_type="text/html")


@panel_router.get("/static/{filename}", include_in_schema=False)
def panel_static(filename: str):
    # Flat static dir; refuse anything that is not a direct child of it.
    target = (STATIC_DIR / filename).resolve()
    if target.parent != STATIC_DIR or not target.is_file():
        raise HTTPException(status_code=404, detail="not found")
    return FileResponse(target)


# ---------------------------------------------------------------------------
# Status + configuration API
# ---------------------------------------------------------------------------

@panel_api.get("/status")
def api_status():
    return service.get_status()


@panel_api.get("/config")
def api_get_config():
    return service.get_config()


class ConfigUpdate(BaseModel):
    alias: str | None = None
    cloudflare_tunnel_enabled: bool | None = None
    permanent_url: str | None = None
    clear_permanent_url: bool = False


@panel_api.post("/config")
def api_update_config(req: ConfigUpdate):
    provided = req.model_dump(exclude_unset=True)
    result: dict = {"status": "ok", "restart_required": False}
    try:
        if "alias" in provided:
            result["alias"] = service.set_alias(provided["alias"])["alias"]
        env_result = service.update_env_settings(
            cloudflare_tunnel_enabled=provided.get("cloudflare_tunnel_enabled"),
            permanent_url=provided.get("permanent_url"),
            clear_permanent_url=req.clear_permanent_url,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    result["env_changed"] = env_result.get("changed", [])
    if env_result.get("restart_required"):
        result["restart_required"] = True
        result["restart_command"] = env_result["restart_command"]
    return result


class StorageMaxUpdate(BaseModel):
    storage_max: str


@panel_api.post("/config/storage-max")
def api_set_storage_max(req: StorageMaxUpdate):
    try:
        service.set_storage_max(req.storage_max)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"IPFS unreachable: {e}")
    return {
        "status": "ok",
        "storage_max": req.storage_max,
        # StorageMax applies at GC time; a daemon restart re-reads it now.
        "restart_required": True,
        "restart_command": "sudo systemctl restart ipfs",
    }


class ProfileUpdate(BaseModel):
    display_name: str | None = None
    username: str | None = None
    bio: str | None = None
    link: str | None = None


@panel_api.post("/profile")
def api_update_profile(req: ProfileUpdate):
    from cipher_station.profile import update_profile_fields
    provided = req.model_dump(exclude_unset=True)
    try:
        prof = update_profile_fields(**provided)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"status": "ok", "profile": prof}


# ---------------------------------------------------------------------------
# Drive API
# ---------------------------------------------------------------------------

# Decrypted private content: types that may render inline. Under the
# CSP "default-src 'none'; sandbox" + nosniff headers below they cannot run
# script; everything else ships as an application/octet-stream attachment.
_INLINE_MIME_PREFIXES = ("image/", "video/", "audio/")
_INLINE_MIME_EXACT = {"application/pdf", "text/plain"}


def _content_security_headers() -> dict:
    return {
        "X-Content-Type-Options": "nosniff",
        "Content-Security-Policy": "default-src 'none'; sandbox",
        # Keep decrypted content out of shared caches.
        "Cache-Control": "no-store",
    }


@panel_api.get("/drive/files")
def api_drive_files():
    try:
        return drive.list_files()
    except Exception as e:
        logger.error("Drive listing failed: %s", e)
        raise HTTPException(status_code=503, detail=f"drive unavailable: {e}")


@panel_api.get("/drive/file/{post_cid}")
def api_drive_file(post_cid: str, download: bool = False):
    try:
        plaintext, meta = drive.open_file(post_cid)
    except KeyError:
        raise HTTPException(status_code=404, detail="file not found")
    except drive.DriveError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except Exception as e:
        logger.error("Drive read failed for %s: %s", post_cid, e)
        raise HTTPException(status_code=503, detail=f"drive unavailable: {e}")

    filename = meta.get("filename") or post_cid
    mime = drive.guess_mime(meta)
    inline_ok = mime.startswith(_INLINE_MIME_PREFIXES) or mime in _INLINE_MIME_EXACT
    if not inline_ok:
        # Non-media types never render in the browser: opaque download only.
        mime = "application/octet-stream"
    disposition = "inline" if (inline_ok and not download) else "attachment"
    headers = _content_security_headers()
    headers["Content-Disposition"] = _content_disposition(disposition, str(filename))
    return Response(content=plaintext, media_type=mime, headers=headers)


def _content_disposition(disposition: str, filename: str) -> str:
    """
    RFC 6266 / RFC 5987 Content-Disposition. HTTP headers are Latin-1 on the
    wire (Starlette raises on anything else), and filenames come from
    device-written metadata — so a CJK or emoji name must not 500 the route.
    ASCII fallback in `filename=`, full UTF-8 name percent-encoded in
    `filename*=` for browsers that understand it (all current ones).
    """
    from urllib.parse import quote
    clean = filename.replace("\r", "").replace("\n", "").replace('"', "")
    ascii_name = clean.encode("ascii", "replace").decode("ascii").replace("?", "_") or "file"
    if ascii_name == clean:
        return f'{disposition}; filename="{ascii_name}"'
    return f"{disposition}; filename=\"{ascii_name}\"; filename*=UTF-8''{quote(clean, safe='')}"


_UPLOAD_CHUNK = 1024 * 1024


@panel_api.post("/drive/upload")
def api_drive_upload(
    file: UploadFile = File(...),
    folder: str = Form(None),
):
    # Stream from the (disk-spooled) upload and abort at the cap — never
    # buffer an unbounded body in memory. app.py also rejects oversized
    # Content-Length before the body is read at all.
    limit = cfg.MAX_UPLOAD_SIZE
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = file.file.read(_UPLOAD_CHUNK)
        if not chunk:
            break
        total += len(chunk)
        if total > limit:
            raise HTTPException(
                status_code=413,
                detail=f"upload too large (max {limit} bytes)",
            )
        chunks.append(chunk)
    file_bytes = b"".join(chunks)
    if not file_bytes:
        raise HTTPException(status_code=400, detail="empty file")
    try:
        return drive.upload_file(file_bytes, file.filename or "", folder)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error("Drive upload failed: %s", e)
        raise HTTPException(status_code=503, detail=f"upload failed: {e}")


class DriveDelete(BaseModel):
    post_cid: str


@panel_api.post("/drive/delete")
def api_drive_delete(req: DriveDelete):
    try:
        return drive.delete_file(req.post_cid)
    except KeyError:
        raise HTTPException(status_code=404, detail="file not found")
    except Exception as e:
        logger.error("Drive delete failed for %s: %s", req.post_cid, e)
        raise HTTPException(status_code=503, detail=f"delete failed: {e}")


# ---------------------------------------------------------------------------
# Federation API (peer pin replication) — consumer-side mirroring of other
# stations' already-published manifests. Never decrypts anything, never
# needs a peer's secret key; see cipher_station/federation.py.
# ---------------------------------------------------------------------------

@panel_api.get("/federation")
def api_federation_status():
    return service.federation_status()


class FederationPeerCreate(BaseModel):
    peer_id: str
    label: str | None = None
    quota_gb: float = 0.0


@panel_api.post("/federation/peers")
def api_federation_add_peer(req: FederationPeerCreate):
    try:
        return service.federation_add_peer(req.peer_id, req.label, req.quota_gb)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@panel_api.delete("/federation/peers/{peer_id}")
def api_federation_remove_peer(peer_id: str):
    return service.federation_remove_peer(peer_id)


@panel_api.post("/federation/sync")
def api_federation_sync_all():
    return service.federation_sync_all()


@panel_api.post("/federation/sync/{peer_id}")
def api_federation_sync_peer(peer_id: str):
    return service.federation_sync_peer(peer_id)
