# orbit_node/backup.py
"""
Backup & restore for an Orbit station.

A station's state spans two trees:
  * orbit_data/   — Orbit identity keys, the SQLite DB, the manifest, public.json
  * the IPFS repo — the post/envelope CONTENT bytes (pinned blocks) AND the IPFS
                    node identity key (= the permanent peer ID / IPNS address)

`create` bundles all of that into one portable archive on a USB drive; `restore`
(also invoked by install.sh) rebuilds a station from it byte-for-byte: same peer
ID, same keys, same posts.

Archive layout (orbit-backup-<peerid8>-<UTCstamp>.tar.gz[.enc]):

    backup.json            metadata + per-file sha256
    orbit_data/keys/*      mlkem.bin, mldsa.bin (as-is; ORBIT_PASSWORD-encrypted if set)
    orbit_data/public.json
    orbit_data/orbit.db    consistent snapshot (sqlite backup API, WAL-safe)
    orbit_data/manifests/manifest.json
    env                    the project .env
    ipfs_identity.json     {"PeerID","PrivKey"} from the IPFS repo config
    content/<cid>.car      one CAR per recursively-pinned root
    pinned_roots.txt       root CIDs to re-pin on restore

IPFS interaction is isolated behind the _ipfs_* helpers below (shelling out to the
`ipfs` CLI, which works offline against the repo). Tests stub these helpers.
"""

import argparse
import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from orbit_node import config as cfg
from orbit_node.crypto import encrypt_private_keys, decrypt_private_keys

SCHEMA_VERSION = 1
ARCHIVE_PREFIX = "orbit-backup-"


# ---------------------------------------------------------------------------
# Path helpers (read cfg dynamically so tests can repoint the data dir)
# ---------------------------------------------------------------------------

def _env_path() -> Path:
    return cfg.PROJECT_ROOT / ".env"


def ipfs_repo_path() -> Path:
    return Path(os.getenv("IPFS_PATH", str(Path.home() / ".ipfs")))


# ---------------------------------------------------------------------------
# IPFS helpers (shell out to the `ipfs` CLI; offline-capable). Stubbed in tests.
# ---------------------------------------------------------------------------

def _run_ipfs(args, repo: Path, stdout=None, check=True):
    env = dict(os.environ, IPFS_PATH=str(repo))
    return subprocess.run(["ipfs", *args], env=env, stdout=stdout,
                          stderr=subprocess.PIPE, check=check)


def ipfs_read_identity(repo: Path) -> dict | None:
    """Read {'PeerID','PrivKey'} from <repo>/config without needing a daemon."""
    cfg_file = repo / "config"
    if not cfg_file.exists():
        return None
    try:
        obj = json.loads(cfg_file.read_text())
        ident = obj.get("Identity") or {}
        if ident.get("PeerID") and ident.get("PrivKey"):
            return {"PeerID": ident["PeerID"], "PrivKey": ident["PrivKey"]}
    except Exception:
        pass
    return None


def ipfs_list_pinned_roots(repo: Path) -> list[str]:
    out = _run_ipfs(["pin", "ls", "--type=recursive", "-q"], repo,
                    stdout=subprocess.PIPE).stdout.decode()
    return [line.strip() for line in out.splitlines() if line.strip()]


def ipfs_export_car(repo: Path, cid: str, dest: Path) -> None:
    with open(dest, "wb") as f:
        _run_ipfs(["dag", "export", cid], repo, stdout=f)


def ipfs_init_if_needed(repo: Path) -> None:
    if not (repo / "config").exists():
        _run_ipfs(["init", "--profile=lowpower"], repo)


def ipfs_set_identity(repo: Path, peer_id: str, priv_key: str) -> None:
    _run_ipfs(["config", "Identity.PeerID", peer_id], repo)
    _run_ipfs(["config", "Identity.PrivKey", priv_key], repo)


def ipfs_import_cars(repo: Path, car_paths: list[Path]) -> None:
    if car_paths:
        _run_ipfs(["dag", "import", *[str(p) for p in car_paths]], repo)


def ipfs_pin_add(repo: Path, cid: str) -> None:
    _run_ipfs(["pin", "add", cid], repo, check=False)


# ---------------------------------------------------------------------------
# Small utilities
# ---------------------------------------------------------------------------

def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _copy_consistent_db(src: Path, dst: Path) -> None:
    """WAL-safe consistent snapshot of the SQLite DB via the backup API."""
    src_conn = sqlite3.connect(str(src))
    try:
        dst_conn = sqlite3.connect(str(dst))
        try:
            src_conn.backup(dst_conn)
        finally:
            dst_conn.close()
    finally:
        src_conn.close()


def _auto_detect_usb() -> Path | None:
    """Return a single removable mount under /media/<user> or /mnt, else None."""
    user = os.getenv("SUDO_USER") or os.getenv("USER") or ""
    candidates: list[Path] = []
    for base in (Path("/media") / user, Path("/media"), Path("/mnt")):
        if base.is_dir():
            for child in sorted(base.iterdir()):
                if child.is_dir() and os.path.ismount(child):
                    candidates.append(child)
    # de-dupe while preserving order
    seen, uniq = set(), []
    for c in candidates:
        if c not in seen:
            seen.add(c)
            uniq.append(c)
    return uniq[0] if len(uniq) == 1 else (uniq[0] if uniq else None)


def _resolve_dest(dest: str | None) -> Path | None:
    if dest:
        return Path(dest).expanduser()
    env_dest = os.getenv("ORBIT_BACKUP_DEST", "").strip()
    if env_dest:
        return Path(env_dest).expanduser()
    return _auto_detect_usb()


# ---------------------------------------------------------------------------
# create
# ---------------------------------------------------------------------------

def create_backup(dest: str | None = None, passphrase: str | None = None,
                  if_present: bool = False, now: datetime | None = None) -> dict:
    """
    Build a self-contained station backup archive in `dest`.

    Returns a result dict. With if_present=True, a missing destination is a
    no-op (status="skipped") rather than an error — used by the scheduled timer.
    """
    dest_dir = _resolve_dest(dest)
    if dest_dir is None or not dest_dir.is_dir():
        msg = f"backup destination not available: {dest_dir or '(none detected)'}"
        if if_present:
            return {"status": "skipped", "reason": msg}
        raise FileNotFoundError(msg)

    now = now or datetime.now(timezone.utc)
    repo = ipfs_repo_path()
    stage = Path(tempfile.mkdtemp(prefix="orbit-backup-"))
    try:
        contents: list[str] = []
        sha: dict[str, str] = {}

        def _record(rel: str):
            contents.append(rel)
            sha[rel] = _sha256_file(stage / rel)

        # --- orbit_data ---
        if cfg.KEYS_DIR.is_dir():
            (stage / "orbit_data" / "keys").mkdir(parents=True, exist_ok=True)
            for kf in sorted(cfg.KEYS_DIR.glob("*.bin")):
                shutil.copy2(kf, stage / "orbit_data" / "keys" / kf.name)
                _record(f"orbit_data/keys/{kf.name}")

        if cfg.PUBLIC_JSON_PATH.exists():
            (stage / "orbit_data").mkdir(parents=True, exist_ok=True)
            shutil.copy2(cfg.PUBLIC_JSON_PATH, stage / "orbit_data" / "public.json")
            _record("orbit_data/public.json")

        if Path(cfg.DB_PATH).exists():
            (stage / "orbit_data").mkdir(parents=True, exist_ok=True)
            _copy_consistent_db(Path(cfg.DB_PATH), stage / "orbit_data" / "orbit.db")
            _record("orbit_data/orbit.db")

        manifest_src = cfg.MANIFEST_DIR / "manifest.json"
        if manifest_src.exists():
            (stage / "orbit_data" / "manifests").mkdir(parents=True, exist_ok=True)
            shutil.copy2(manifest_src, stage / "orbit_data" / "manifests" / "manifest.json")
            _record("orbit_data/manifests/manifest.json")

        # --- .env ---
        if _env_path().exists():
            shutil.copy2(_env_path(), stage / "env")
            _record("env")

        # --- IPFS identity ---
        peer_id = None
        identity = ipfs_read_identity(repo)
        if identity:
            peer_id = identity.get("PeerID")
            (stage / "ipfs_identity.json").write_text(json.dumps(identity, indent=2))
            _record("ipfs_identity.json")

        # --- IPFS pinned content (best-effort per root) ---
        roots, exported = [], []
        try:
            roots = ipfs_list_pinned_roots(repo)
        except Exception as e:
            print(f"[orbit-backup] WARNING: could not list pins: {e}", file=sys.stderr)
        if roots:
            (stage / "content").mkdir(parents=True, exist_ok=True)
            for cid in roots:
                try:
                    ipfs_export_car(repo, cid, stage / "content" / f"{cid}.car")
                    _record(f"content/{cid}.car")
                    exported.append(cid)
                except Exception as e:
                    print(f"[orbit-backup] WARNING: export {cid} failed: {e}", file=sys.stderr)
            (stage / "pinned_roots.txt").write_text("\n".join(exported) + ("\n" if exported else ""))
            _record("pinned_roots.txt")

        # --- uid (for metadata) ---
        uid = None
        try:
            if cfg.PUBLIC_JSON_PATH.exists():
                uid = json.loads(cfg.PUBLIC_JSON_PATH.read_text()).get("uid")
        except Exception:
            pass

        # --- backup.json ---
        meta = {
            "schema_version": SCHEMA_VERSION,
            "tool": "orbit-backup",
            "created_at": now.isoformat(),
            "peer_id": peer_id,
            "uid": uid,
            "encrypted": bool(passphrase),
            "pinned_root_count": len(exported),
            "contents": contents,
            "sha256": sha,
        }
        (stage / "backup.json").write_text(json.dumps(meta, indent=2))

        # --- pack ---
        peer8 = (peer_id or "noipfs")[:8]
        stamp = now.strftime("%Y%m%dT%H%M%SZ")
        base_name = f"{ARCHIVE_PREFIX}{peer8}-{stamp}.tar.gz"
        tmp_tar = stage.parent / (base_name + ".tmp")
        with tarfile.open(tmp_tar, "w:gz") as tar:
            tar.add(stage, arcname=".")

        final_name = base_name + (".enc" if passphrase else "")
        final_path = dest_dir / final_name
        tmp_out = dest_dir / (final_name + ".partial")
        if passphrase:
            tmp_out.write_bytes(encrypt_private_keys(tmp_tar.read_bytes(), passphrase))
        else:
            shutil.move(str(tmp_tar), str(tmp_out))
            print("[orbit-backup] WARNING: this archive is UNENCRYPTED and contains "
                  "private keys. Keep the drive physically secure, or use --passphrase.",
                  file=sys.stderr)
        os.replace(tmp_out, final_path)  # atomic
        if tmp_tar.exists():
            tmp_tar.unlink()

        return {"status": "ok", "archive": str(final_path),
                "size_bytes": final_path.stat().st_size, "pinned_roots": len(exported),
                "encrypted": bool(passphrase), "peer_id": peer_id}
    finally:
        shutil.rmtree(stage, ignore_errors=True)


# ---------------------------------------------------------------------------
# restore
# ---------------------------------------------------------------------------

def restore_backup(archive: str, passphrase: str | None = None,
                   force: bool = False) -> dict:
    arc = Path(archive).expanduser()
    if not arc.exists():
        raise FileNotFoundError(f"archive not found: {arc}")

    is_enc = arc.name.endswith(".enc")
    if is_enc and not passphrase:
        raise ValueError("archive is encrypted; --passphrase is required")

    stage = Path(tempfile.mkdtemp(prefix="orbit-restore-"))
    try:
        if is_enc:
            tar_bytes = decrypt_private_keys(arc.read_bytes(), passphrase)
            tar_tmp = stage / "_archive.tar.gz"
            tar_tmp.write_bytes(tar_bytes)
            tar_src = tar_tmp
        else:
            tar_src = arc

        with tarfile.open(tar_src, "r:gz") as tar:
            tar.extractall(stage, filter="data")  # 'data' filter rejects unsafe members

        meta_path = stage / "backup.json"
        if not meta_path.exists():
            raise ValueError("invalid backup: backup.json missing")
        meta = json.loads(meta_path.read_text())
        if meta.get("schema_version") != SCHEMA_VERSION:
            raise ValueError(f"unsupported backup schema_version: {meta.get('schema_version')}")

        # Guard against clobbering a live station
        if Path(cfg.DB_PATH).exists() or cfg.KEYS_DIR.is_dir() and any(cfg.KEYS_DIR.glob("*.bin")):
            if not force:
                raise FileExistsError(
                    "target orbit_data already has keys/db; pass force=True to overwrite")

        # --- lay down orbit_data + .env ---
        src_data = stage / "orbit_data"
        if src_data.is_dir():
            cfg.BASE_DIR.mkdir(parents=True, exist_ok=True)
            for item in src_data.rglob("*"):
                if item.is_file():
                    rel = item.relative_to(src_data)
                    target = cfg.BASE_DIR / rel
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(item, target)

        if (stage / "env").exists():
            _env_path().parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(stage / "env", _env_path())

        # --- IPFS: identity + content ---
        repo = ipfs_repo_path()
        ipfs_restored = {"identity": False, "cars": 0, "pins": 0}
        ident_file = stage / "ipfs_identity.json"
        if ident_file.exists():
            ipfs_init_if_needed(repo)
            ident = json.loads(ident_file.read_text())
            ipfs_set_identity(repo, ident["PeerID"], ident["PrivKey"])
            ipfs_restored["identity"] = True

        content_dir = stage / "content"
        if content_dir.is_dir():
            cars = sorted(content_dir.glob("*.car"))
            ipfs_import_cars(repo, cars)
            ipfs_restored["cars"] = len(cars)
            roots_file = stage / "pinned_roots.txt"
            if roots_file.exists():
                for cid in [l.strip() for l in roots_file.read_text().splitlines() if l.strip()]:
                    ipfs_pin_add(repo, cid)
                    ipfs_restored["pins"] += 1

        return {"status": "ok", "uid": meta.get("uid"), "peer_id": meta.get("peer_id"),
                "ipfs": ipfs_restored}
    finally:
        shutil.rmtree(stage, ignore_errors=True)


# ---------------------------------------------------------------------------
# list
# ---------------------------------------------------------------------------

def list_backups(dest: str | None = None) -> list[dict]:
    dest_dir = _resolve_dest(dest)
    if dest_dir is None or not dest_dir.is_dir():
        return []
    out = []
    for p in sorted(dest_dir.glob(f"{ARCHIVE_PREFIX}*.tar.gz*")):
        out.append({"archive": str(p), "size_bytes": p.stat().st_size,
                    "encrypted": p.name.endswith(".enc")})
    return out


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="orbit-backup",
                                     description="Backup & restore an Orbit station.")
    sub = parser.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("create", help="Create a backup archive")
    c.add_argument("--dest", help="Destination dir (default: $ORBIT_BACKUP_DEST or auto-detected USB)")
    c.add_argument("--passphrase", help="Encrypt the archive with this passphrase")
    c.add_argument("--if-present", action="store_true",
                   help="No-op (exit 0) if the destination is not mounted (for timers)")

    r = sub.add_parser("restore", help="Restore a station from a backup archive")
    r.add_argument("--archive", required=True, help="Path to the backup archive")
    r.add_argument("--passphrase", help="Passphrase for an encrypted archive")
    r.add_argument("--force", action="store_true", help="Overwrite an existing orbit_data")

    l = sub.add_parser("list", help="List backups in a destination")
    l.add_argument("--dest", help="Destination dir (default: $ORBIT_BACKUP_DEST or auto-detected USB)")

    args = parser.parse_args(argv)

    if args.cmd == "create":
        res = create_backup(dest=args.dest, passphrase=args.passphrase, if_present=args.if_present)
        print(json.dumps(res, indent=2))
        return 0
    if args.cmd == "restore":
        res = restore_backup(archive=args.archive, passphrase=args.passphrase, force=args.force)
        print(json.dumps(res, indent=2))
        return 0
    if args.cmd == "list":
        for b in list_backups(dest=args.dest):
            print(json.dumps(b))
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
