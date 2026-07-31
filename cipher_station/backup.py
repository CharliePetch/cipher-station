# cipher_station/backup.py
"""
Backup & restore for an Cipher Station station.

A station's state spans two trees:
  * cipher_station_data/   — Cipher Station identity keys, the SQLite DB, the manifest, public.json
  * the IPFS repo — the post/envelope CONTENT bytes (pinned blocks) AND the IPFS
                    node identity key (= the permanent peer ID / IPNS address)

`create` bundles all of that into one portable archive on a USB drive; `restore`
(also invoked by install.sh) rebuilds a station from it byte-for-byte: same peer
ID, same keys, same posts.

Archive layout (cipherstation-backup-<peerid8>-<UTCstamp>.tar.gz[.enc]):

    backup.json            metadata + per-file sha256
    cipher_station_data/keys/*      mlkem.bin, mldsa.bin (as-is; CIPHER_PASSWORD-encrypted if set)
    cipher_station_data/public.json
    cipher_station_data/cipherstation.db    consistent snapshot (sqlite backup API, WAL-safe)
    cipher_station_data/manifests/manifest.json
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

from cipher_station import config as cfg
from cipher_station.crypto import encrypt_private_keys, decrypt_private_keys

SCHEMA_VERSION = 1
ARCHIVE_PREFIX = "cipherstation-backup-"


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


def _open_private(path: Path):
    """
    Open `path` for writing, owner-only (0600) from before the first byte lands.

    Creating the file with mode 0600 (rather than writing it and chmod'ing after)
    is what closes the window: the archive holds mlkem.bin, mldsa.bin, the .env
    and the IPFS PrivKey in the clear, and the default umask makes that 0644 —
    world-readable for however long the write takes. os.open() applies the mode
    at creation; the fchmod() covers the case where the file already existed with
    a laxer mode (O_TRUNC has already emptied it, so nothing leaks in between).

    chmod is a no-op on vfat/exfat, which is what most USB sticks are formatted
    as — the mode there comes from the mount options and there is nothing we can
    do about it, so a failure must not abort the backup.
    """
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.fchmod(fd, 0o600)
    except OSError:
        pass
    return os.fdopen(fd, "wb")


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


def _data_root() -> Path | None:
    """
    CIPHER_DATA_ROOT resolved, or None when it is not set.

    That variable is the installers' "keep all station state on this volume"
    switch: install.sh / install-macos.command put the station data dir at
    $CIPHER_DATA_ROOT/station and the IPFS repo at $CIPHER_DATA_ROOT/ipfs. The
    root itself is therefore station territory even though it is neither of
    those two directories, and reading it here is what closes the
    <data-root>/backups hole — that path is a SIBLING of both live dirs, so a
    check that only knows BASE_DIR and the IPFS repo waves it straight through.
    """
    raw = os.getenv("CIPHER_DATA_ROOT", "").strip()
    if not raw:
        return None
    try:
        return Path(raw).expanduser().resolve()
    except Exception:  # unresolvable path: nothing to compare against
        return None


def _protected_roots() -> list[Path]:
    """
    Resolved directories that make up this station's data territory: the
    configured data root (when set), the station data dir, and the IPFS repo.

    Every path is resolve()d, so symlinks, ".." segments and relative forms all
    collapse to one canonical spelling — a destination cannot name protected
    territory in a way the containment test fails to recognise.

    resolve() is non-strict, so a configured-but-absent directory still yields a
    usable canonical path. That is deliberate; see _protected_root_collision.
    """
    roots: list[Path] = []
    for p in (_data_root(), cfg.BASE_DIR, ipfs_repo_path()):
        if p is None:
            continue
        try:
            r = Path(p).expanduser().resolve()
        except Exception:  # unresolvable path: nothing to compare against
            continue
        if r not in roots:
            roots.append(r)
    return roots


def _fs_device(path: Path):
    """
    Identity of the filesystem `path` lives on: st_dev of `path`, or of its
    nearest existing ancestor when `path` itself does not exist yet.

    Returns None only if nothing along the chain can be stat()ed.
    """
    p = path
    while True:
        try:
            return os.stat(p).st_dev
        except OSError:
            parent = p.parent
            if parent == p:
                return None
            p = parent


def _mount_point(path: Path) -> Path | None:
    """
    Nearest ancestor of `path` that is a mount point. Diagnostics only: it names
    the volume in the same-disk warning. Nothing is refused on its answer.
    """
    p = path
    while True:
        try:
            if os.path.ismount(p):
                return p
        except OSError:
            pass
        parent = p.parent
        if parent == p:
            return None
        p = parent


def _protected_root_collision(path: Path) -> Path | None:
    """
    Return the protected root that makes `path` an unacceptable backup
    destination, or None when the destination is outside all of them.

    The rule is CONTAINMENT, in both directions: `path` IS a protected root,
    sits inside one, or contains one. Both sides come from resolve() (see
    _protected_roots), so symlinks and ".." cannot walk around the comparison.

    Including CIPHER_DATA_ROOT is the whole point. On a hosted station with
    CIPHER_DATA_ROOT=/mnt/cipher-data holding station/ and ipfs/, the directory
    /mnt/cipher-data/backups is inside neither live dir and contains neither —
    it is a sibling — so a BASE_DIR-and-repo-only check calls it safe and drops
    a plaintext copy of the keys back onto the volume they already live on.

    An absent root still counts. A configured directory that does not exist yet
    is not thereby a safe place to write backups: install.sh creates
    $CIPHER_DATA_ROOT/station on first run, and a check that skipped absent
    roots would bless <data-root>/backups right up until the moment the station
    booted. resolve() is non-strict and containment is pure path arithmetic, so
    no stat() is needed and existence never enters into it.

    This deliberately does NOT refuse "same physical disk". That rule was tried
    and is far too blunt: on a single-disk Pi, a dev laptop or a pytest tmpdir
    every path shares one mount, so it banned unencrypted backups outright and
    broke the USB workflow the feature exists for. Same-disk-but-outside is a
    warning instead (see _same_disk_live_dir).
    """
    try:
        target = path.expanduser().resolve()
    except Exception:
        return None
    for root in _protected_roots():
        if target.is_relative_to(root) or root.is_relative_to(target):
            return root
    return None


def _same_disk_live_dir(path: Path) -> Path | None:
    """
    Return a protected root that shares a filesystem with `path`, else None.

    ADVISORY ONLY — this drives a warning, never a refusal. A backup on the same
    disk as the original does not survive that disk failing, which the operator
    should hear, but writing one is a legitimate step (stage it in $HOME, then
    scp it off the box) and refusing it would ban backups entirely on any
    machine with one disk.

    st_dev rather than comparing os.path.ismount() paths: a bind mount or an
    aliased mount point yields two different mount-point paths for one physical
    filesystem, and path comparison would call those "different disks" — the
    exact case worth warning about. st_dev is also a single stat() and degrades
    gracefully when the leaf does not exist yet. It is not perfect either (btrfs
    subvolumes on one disk report distinct st_dev values), which is another
    reason it only ever produces advice.

    Only roots that actually EXIST take part: _fs_device() charges an absent
    path to its nearest existing ancestor — usually $HOME or / — so an absent
    root (commonly ~/.ipfs on a station using a remote IPFS API) would make this
    fire on practically every destination. Absent roots lose nothing by being
    skipped here; _protected_root_collision covers them without needing stat().
    """
    try:
        target = path.expanduser().resolve()
    except Exception:
        return None
    target_dev = _fs_device(target)
    if target_dev is None:
        return None
    for root in _protected_roots():
        try:
            if not root.exists():
                continue
        except OSError:
            continue
        if _fs_device(root) == target_dev:
            return root
    return None


def _candidate_mounts() -> list[Path]:
    """
    Every mount point under /media/<user>, /media and /mnt, de-duped, in order.

    Split out from _auto_detect_usb so the selection policy below can be tested
    without a real removable drive — this function is the only part of detection
    that touches the machine's actual mount table.
    """
    user = os.getenv("SUDO_USER") or os.getenv("USER") or ""
    candidates: list[Path] = []
    for base in (Path("/media") / user, Path("/media"), Path("/mnt")):
        if base.is_dir():
            for child in sorted(base.iterdir()):
                if child.is_dir() and os.path.ismount(child):
                    candidates.append(child)
    seen, uniq = set(), []
    for c in candidates:
        if c not in seen:
            seen.add(c)
            uniq.append(c)
    return uniq


def _auto_detect_usb() -> tuple[Path | None, str | None]:
    """
    Find the single removable mount under /media/<user> or /mnt.

    Returns (mount, None) on success and (None, reason) otherwise. Every failure
    carries a reason, which is both printed and handed back to the caller — a
    detection that declines to pick a drive must never look like "nothing
    happened, all good" to a scheduled run reading only the result dict.
    """
    uniq = _candidate_mounts()

    # Never offer a mount that holds this station's own state. A hosted station
    # mounts its data volume at /mnt/cipher-data, which used to be picked up
    # here as "the USB drive" and handed a plaintext copy of the very keys
    # sitting on it. Detection is stricter than the write policy on purpose: a
    # mount inside the data root is disqualified, and so is one that merely
    # shares a filesystem with live data, because genuinely removable media
    # never does.
    safe: list[Path] = []
    for c in uniq:
        root = _protected_root_collision(c)
        if root is not None:
            print(f"[cipherstation-backup] ignoring mount {c}: it is (or is inside) this "
                  f"station's data directory ({root}), not removable media", file=sys.stderr)
            continue
        same = _same_disk_live_dir(c)
        if same is not None:
            print(f"[cipherstation-backup] ignoring mount {c}: it is on the same filesystem "
                  f"as this station's live data ({same}), not removable media", file=sys.stderr)
            continue
        safe.append(c)

    if not safe:
        if uniq:
            reason = ("no usable backup drive: every candidate mount ("
                      f"{', '.join(str(p) for p in uniq)}) is this station's own storage, "
                      "not removable media — attach a drive, or set CIPHER_BACKUP_DEST / "
                      "pass --dest")
            print(f"[cipherstation-backup] WARNING: {reason}", file=sys.stderr)
            return None, reason
        return None, ("no backup destination: no removable drive detected under /media or "
                      "/mnt — set CIPHER_BACKUP_DEST or pass --dest")
    if len(safe) > 1:
        # Auto-detection fires only when the answer is unambiguous. The old
        # return line
        #     uniq[0] if len(uniq) == 1 else (uniq[0] if uniq else None)
        # had two identical branches, so with several mounts it silently picked
        # whichever sorted first — a network share or a second data volume just
        # as easily as the operator's USB stick. The payload is a plaintext copy
        # of the station's private keys, so guessing wrong is a key disclosure.
        #
        # Refusing costs one skipped run, but it must not cost it QUIETLY: the
        # reason goes to stderr for a human at a terminal AND back to the caller,
        # so `create --if-present` reports it in the result JSON (the systemd
        # timer's journal) instead of an unexplained "destination not available".
        reason = ("refusing to guess the backup drive: multiple candidate mounts ("
                  f"{', '.join(str(p) for p in safe)}) — set CIPHER_BACKUP_DEST or pass "
                  "--dest to name the right one")
        print(f"[cipherstation-backup] WARNING: {reason}", file=sys.stderr)
        return None, reason
    return safe[0], None


def _resolve_dest(dest: str | None) -> tuple[Path | None, str | None]:
    """(destination, reason_there_is_none) — exactly one of the two is set."""
    if dest:
        return Path(dest).expanduser(), None
    env_dest = os.getenv("CIPHER_BACKUP_DEST", "").strip()
    if env_dest:
        return Path(env_dest).expanduser(), None
    return _auto_detect_usb()


def _warn_unencrypted(dest_dir: Path) -> None:
    """Shout about a plaintext key archive before a single byte of it is written."""
    bar = "!" * 74
    print(f"\n{bar}\n"
          "[cipherstation-backup] WARNING: THIS ARCHIVE WILL BE UNENCRYPTED.\n"
          "  It contains your station's PRIVATE KEYS (mlkem.bin, mldsa.bin), the\n"
          "  SQLite database, the .env, and the IPFS node private key. Anyone who\n"
          "  reads it can impersonate this station and decrypt its envelopes.\n"
          f"  destination: {dest_dir}\n"
          "  Re-run with --passphrase to encrypt it. Write it to removable media you\n"
          "  keep physically secure — not a shared, networked, or cloud-synced disk.\n"
          f"{bar}\n", file=sys.stderr)


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
    dest_dir, unavailable = _resolve_dest(dest)
    if dest_dir is None or not dest_dir.is_dir():
        msg = unavailable or f"backup destination not available: {dest_dir or '(none detected)'}"
        if if_present:
            return {"status": "skipped", "reason": msg}
        raise FileNotFoundError(msg)

    # Defense in depth, independent of how the destination was chosen (--dest,
    # CIPHER_BACKUP_DEST, or auto-detect): the destination must not land inside
    # this station's data territory — cfg.BASE_DIR, the IPFS repo, or
    # CIPHER_DATA_ROOT when the installers set it. The data root is the one that
    # closes the hosted leak: on a droplet with CIPHER_DATA_ROOT=/mnt/cipher-data
    # the sibling directory /mnt/cipher-data/backups is inside neither live dir,
    # so a BASE_DIR-and-repo-only check passes it and an unencrypted archive puts
    # mlkem.bin, mldsa.bin, the .env and the IPFS private key straight back onto
    # the volume they already live on.
    #
    # The refusal stands even WITH a passphrase. Encryption answers the plaintext
    # leak but not the rest: a destination under BASE_DIR gets swept into later
    # archives and overwritten by a restore, and any copy inside the tree it
    # backs up dies with that tree. Naming another directory is the fix, and it
    # is always available.
    #
    # It also raises under if_present — that flag means "the drive isn't plugged
    # in today", not "the destination is unsafe", so a misconfiguration is loud
    # rather than a silent exit 0.
    protected = _protected_root_collision(dest_dir)
    if protected is not None:
        raise ValueError(
            f"refusing to write a backup to {dest_dir}: it is inside (or contains) this "
            f"station's data directory {protected}. A copy stored in the tree it backs "
            "up dies with that tree, and unencrypted it puts mlkem.bin, mldsa.bin, the "
            ".env and the IPFS private key in the clear right beside the originals. "
            "Point --dest / CIPHER_BACKUP_DEST at removable media or another drive.")

    # Outside the data root but on the same disk is ALLOWED, and only warned
    # about. Staging a backup in $HOME to scp off the box is a real workflow, and
    # on a one-disk Pi or laptop every writable path is the same disk — refusing
    # here would ban backups outright rather than make them safer.
    same_disk = _same_disk_live_dir(dest_dir)
    if same_disk is not None:
        mount = _mount_point(dest_dir.expanduser().resolve())
        print(f"[cipherstation-backup] WARNING: {dest_dir} is on the same physical disk"
              f"{f' ({mount})' if mount else ''} as your live station data ({same_disk}). "
              "This backup will NOT survive that disk failing — copy it to removable "
              "media or another machine.", file=sys.stderr)
    if not passphrase:
        _warn_unencrypted(dest_dir)

    now = now or datetime.now(timezone.utc)
    repo = ipfs_repo_path()
    # One working tree holds everything temporary, so the single rmtree in the
    # finally below is guaranteed to clean up on every exit path. `stage` is the
    # directory that gets tarred; the tarball is written to a SIBLING inside
    # `work` so it is not swept into its own archive.
    #
    # The tar used to live in the shared system temp dir and was unlinked only on
    # the success path, so any exception after staging (a failed encrypt, a full
    # USB stick, SIGINT) left a plaintext archive of mlkem.bin, mldsa.bin, the
    # .env and the IPFS private key behind indefinitely.
    work = Path(tempfile.mkdtemp(prefix="cipherstation-backup-"))
    stage = work / "stage"
    stage.mkdir()
    try:
        contents: list[str] = []
        sha: dict[str, str] = {}

        def _record(rel: str):
            contents.append(rel)
            sha[rel] = _sha256_file(stage / rel)

        # --- cipher_station_data ---
        if cfg.KEYS_DIR.is_dir():
            (stage / "cipher_station_data" / "keys").mkdir(parents=True, exist_ok=True)
            for kf in sorted(cfg.KEYS_DIR.glob("*.bin")):
                shutil.copy2(kf, stage / "cipher_station_data" / "keys" / kf.name)
                _record(f"cipher_station_data/keys/{kf.name}")

        if cfg.PUBLIC_JSON_PATH.exists():
            (stage / "cipher_station_data").mkdir(parents=True, exist_ok=True)
            shutil.copy2(cfg.PUBLIC_JSON_PATH, stage / "cipher_station_data" / "public.json")
            _record("cipher_station_data/public.json")

        if Path(cfg.DB_PATH).exists():
            (stage / "cipher_station_data").mkdir(parents=True, exist_ok=True)
            _copy_consistent_db(Path(cfg.DB_PATH), stage / "cipher_station_data" / "cipherstation.db")
            _record("cipher_station_data/cipherstation.db")

        manifest_src = cfg.MANIFEST_DIR / "manifest.json"
        if manifest_src.exists():
            (stage / "cipher_station_data" / "manifests").mkdir(parents=True, exist_ok=True)
            shutil.copy2(manifest_src, stage / "cipher_station_data" / "manifests" / "manifest.json")
            _record("cipher_station_data/manifests/manifest.json")

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
            print(f"[cipherstation-backup] WARNING: could not list pins: {e}", file=sys.stderr)
        if roots:
            (stage / "content").mkdir(parents=True, exist_ok=True)
            for cid in roots:
                try:
                    ipfs_export_car(repo, cid, stage / "content" / f"{cid}.car")
                    _record(f"content/{cid}.car")
                    exported.append(cid)
                except Exception as e:
                    print(f"[cipherstation-backup] WARNING: export {cid} failed: {e}", file=sys.stderr)
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
            "tool": "cipherstation-backup",
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
        # The staging tar sits in the shared system temp dir, so it needs the
        # same 0600 treatment as the final archive — it is the identical payload.
        tmp_tar = work / (base_name + ".tmp")
        with _open_private(tmp_tar) as raw:
            with tarfile.open(fileobj=raw, mode="w:gz") as tar:
                tar.add(stage, arcname=".")

        final_name = base_name + (".enc" if passphrase else "")
        final_path = dest_dir / final_name
        tmp_out = dest_dir / (final_name + ".partial")
        # Everything below writes/moves at 0600, so the archive is never visible
        # to other users — not as .partial, and not after the rename. os.replace
        # swaps inodes, so final_path inherits the 0600 of tmp_out atomically
        # rather than being chmod'ed into place afterwards.
        #
        # tmp_out is in the DESTINATION, outside `work`, so the rmtree below does
        # not reach it: a failure mid-write would otherwise strand a partial copy
        # of the same secrets on the drive. Hence the explicit unlink on the way
        # out; BaseException so SIGINT is covered too.
        try:
            if passphrase:
                with _open_private(tmp_out) as out:
                    out.write(encrypt_private_keys(tmp_tar.read_bytes(), passphrase))
            else:
                try:
                    os.replace(tmp_tar, tmp_out)  # same fs: keeps the 0600 inode
                except OSError:
                    # Cross-device (the usual case: temp dir -> USB stick). Stream
                    # it through a 0600 fd instead of shutil.move, whose copy2
                    # fallback creates the destination at the umask default and
                    # only fixes the mode after the bytes are already on disk.
                    with open(tmp_tar, "rb") as src, _open_private(tmp_out) as out:
                        shutil.copyfileobj(src, out)
            os.replace(tmp_out, final_path)  # atomic
        except BaseException:
            try:
                tmp_out.unlink(missing_ok=True)
            except OSError:
                pass
            raise
        if not passphrase:
            print("[cipherstation-backup] WARNING: UNENCRYPTED archive containing private "
                  f"keys written to {final_path}", file=sys.stderr)

        return {"status": "ok", "archive": str(final_path),
                "size_bytes": final_path.stat().st_size, "pinned_roots": len(exported),
                "encrypted": bool(passphrase), "peer_id": peer_id}
    finally:
        # Removes the staging tree AND the plaintext tarball beside it.
        shutil.rmtree(work, ignore_errors=True)


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

    stage = Path(tempfile.mkdtemp(prefix="cipherstation-restore-"))
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
                    "target cipher_station_data already has keys/db; pass force=True to overwrite")

        # --- lay down cipher_station_data + .env ---
        src_data = stage / "cipher_station_data"
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
    dest_dir, _unavailable = _resolve_dest(dest)
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
    parser = argparse.ArgumentParser(prog="cipherstation-backup",
                                     description="Backup & restore an Cipher Station station.")
    sub = parser.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("create", help="Create a backup archive")
    c.add_argument("--dest", help="Destination dir (default: $CIPHER_BACKUP_DEST, else an "
                                  "auto-detected USB drive when exactly one removable mount "
                                  "is present)")
    c.add_argument("--passphrase", help="Encrypt the archive with this passphrase")
    c.add_argument("--if-present", action="store_true",
                   help="No-op (exit 0) if the destination is not mounted (for timers)")

    r = sub.add_parser("restore", help="Restore a station from a backup archive")
    r.add_argument("--archive", required=True, help="Path to the backup archive")
    r.add_argument("--passphrase", help="Passphrase for an encrypted archive")
    r.add_argument("--force", action="store_true", help="Overwrite an existing cipher_station_data")

    l = sub.add_parser("list", help="List backups in a destination")
    l.add_argument("--dest", help="Destination dir (default: $CIPHER_BACKUP_DEST, else an "
                                  "auto-detected USB drive when exactly one removable mount "
                                  "is present)")

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
