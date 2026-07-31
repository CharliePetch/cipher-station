# tests/test_backup.py

import json
import os
import shutil
import sqlite3
import tarfile
import tempfile
from datetime import datetime, timezone

import pytest

from cipher_station import backup, config as cfg


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _seed_station(tmp_path, monkeypatch):
    """Create a minimal station state in the temp data dir, and stub IPFS.

    We write the key files / public.json directly (rather than via get_identity)
    because identity.py binds its key paths at import time and wouldn't honor the
    conftest path monkeypatch — backup.py itself reads cfg.* dynamically, which is
    what we're exercising here.
    """
    # .env lives next to the project root; point that at the temp dir so we never
    # touch the real repo .env.
    monkeypatch.setattr(cfg, "PROJECT_ROOT", tmp_path)

    uid = "test-uid-0001"
    cfg.KEYS_DIR.mkdir(parents=True, exist_ok=True)
    (cfg.KEYS_DIR / "mlkem.bin").write_bytes(b"MLKEM-PUB||MLKEM-SECRET-bytes")
    (cfg.KEYS_DIR / "mldsa.bin").write_bytes(b"MLDSA-PUB||MLDSA-SECRET-bytes")
    cfg.PUBLIC_JSON_PATH.write_text(json.dumps({
        "uid": uid, "mlkem_public_key": "aa" * 1184, "mldsa_public_key": "bb" * 1952,
    }, indent=2))

    # A populated DB (left OPEN to mimic the running service during backup).
    from cipher_station.database import get_db
    from cipher_station.followers import add_follower_device
    get_db()
    add_follower_device("alice", "alice",
                        mlkem_public_key="aa" * 1184, mldsa_public_key="bb" * 1952,
                        allowed="Allowed")

    # A manifest.
    (cfg.MANIFEST_DIR).mkdir(parents=True, exist_ok=True)
    (cfg.MANIFEST_DIR / "manifest.json").write_text(json.dumps(
        {"clients": {"cipherframe": {"posts": [
            {"post_cid": "Qmaaa", "audience_mode": "all", "envelopes_cid": "Qmbbb"}]}}}))

    # A .env.
    (tmp_path / ".env").write_text("CIPHER_PASSWORD=\nCIPHER_PORT=8443\n")

    # Stub all IPFS interaction.
    calls = {"init": 0, "set_identity": [], "import_cars": [], "pin_add": []}
    monkeypatch.setattr(backup, "ipfs_read_identity",
                        lambda repo: {"PeerID": "QmPEERtest12345", "PrivKey": "CAEScPRIVKEYb64"})
    monkeypatch.setattr(backup, "ipfs_list_pinned_roots", lambda repo: ["Qmaaa", "Qmbbb"])
    monkeypatch.setattr(backup, "ipfs_export_car",
                        lambda repo, cid, dest: dest.write_bytes(b"CARDATA:" + cid.encode()))
    monkeypatch.setattr(backup, "ipfs_init_if_needed",
                        lambda repo: calls.__setitem__("init", calls["init"] + 1))
    monkeypatch.setattr(backup, "ipfs_set_identity",
                        lambda repo, pid, pk: calls["set_identity"].append((pid, pk)))
    monkeypatch.setattr(backup, "ipfs_import_cars",
                        lambda repo, cars: calls["import_cars"].append(list(cars)))
    monkeypatch.setattr(backup, "ipfs_pin_add",
                        lambda repo, cid: calls["pin_add"].append(cid))
    return uid, calls


def _wipe_data(tmp_path):
    """Remove the data dir + .env to simulate a fresh box."""
    import cipher_station.database as db_mod
    db_mod.reset_connection()
    shutil.rmtree(cfg.BASE_DIR, ignore_errors=True)
    (tmp_path / ".env").unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestCreate:
    def test_archive_contents(self, tmp_path, monkeypatch):
        uid, _ = _seed_station(tmp_path, monkeypatch)
        usb = tmp_path / "usb"; usb.mkdir()

        res = backup.create_backup(dest=str(usb), now=datetime(2026, 6, 4, tzinfo=timezone.utc))
        assert res["status"] == "ok"
        assert res["peer_id"] == "QmPEERtest12345"
        assert res["pinned_roots"] == 2

        arc = list(usb.glob("cipherstation-backup-*.tar.gz"))
        assert len(arc) == 1
        assert arc[0].name == "cipherstation-backup-QmPEERte-20260604T000000Z.tar.gz"

        with tarfile.open(arc[0], "r:gz") as tar:
            names = set(tar.getnames())
            meta = json.loads(tar.extractfile("./backup.json").read())

        for need in ("./cipher_station_data/keys/mlkem.bin", "./cipher_station_data/keys/mldsa.bin",
                     "./cipher_station_data/public.json", "./cipher_station_data/cipherstation.db",
                     "./cipher_station_data/manifests/manifest.json", "./env",
                     "./ipfs_identity.json", "./content/Qmaaa.car",
                     "./content/Qmbbb.car", "./pinned_roots.txt"):
            assert need in names, need
        assert meta["schema_version"] == backup.SCHEMA_VERSION
        assert meta["uid"] == uid
        assert meta["encrypted"] is False
        assert "cipher_station_data/keys/mlkem.bin" in meta["sha256"]

    def test_if_present_skips_when_dest_missing(self, tmp_path, monkeypatch):
        _seed_station(tmp_path, monkeypatch)
        res = backup.create_backup(dest=str(tmp_path / "no-such-usb"), if_present=True)
        assert res["status"] == "skipped"
        assert not list(tmp_path.glob("**/cipherstation-backup-*"))


class TestDestinationPolicy:
    """
    The destination rule is CONTAINMENT in the station's data territory, not
    "same disk". A one-disk Pi, a laptop and this tmpdir are all a single mount,
    so a same-mount refusal would ban backups outright (see
    test_same_disk_outside_data_root_is_allowed_with_a_warning) while still
    missing the sibling directory that actually leaked keys.
    """

    def test_refuses_dest_inside_cipher_data_root(self, tmp_path, monkeypatch):
        """The hosted leak: <data-root>/backups is a SIBLING of both live dirs.

        With CIPHER_DATA_ROOT=/mnt/cipher-data the installers put the station at
        <root>/station and the IPFS repo at <root>/ipfs, so <root>/backups is
        inside neither and contains neither — a check that knows only BASE_DIR
        and the repo waves it through and drops the keys back on that volume.
        """
        _seed_station(tmp_path, monkeypatch)
        vol = tmp_path / "cipher-data"
        (vol / "station").mkdir(parents=True)
        backups = vol / "backups"; backups.mkdir()
        monkeypatch.setenv("CIPHER_DATA_ROOT", str(vol))

        with pytest.raises(ValueError, match="refusing to write a backup"):
            backup.create_backup(dest=str(backups))
        assert not list(backups.iterdir())

    def test_refuses_dest_inside_data_root_even_with_passphrase(self, tmp_path, monkeypatch):
        """Encryption answers the plaintext leak, not "it dies with the volume"."""
        _seed_station(tmp_path, monkeypatch)
        vol = tmp_path / "cipher-data"
        backups = vol / "backups"; backups.mkdir(parents=True)
        monkeypatch.setenv("CIPHER_DATA_ROOT", str(vol))

        with pytest.raises(ValueError, match="refusing to write a backup"):
            backup.create_backup(dest=str(backups), passphrase="correct horse")
        assert not list(backups.iterdir())

    def test_refuses_dest_inside_base_dir(self, tmp_path, monkeypatch):
        _seed_station(tmp_path, monkeypatch)
        inside = cfg.BASE_DIR / "backups"; inside.mkdir(parents=True)
        with pytest.raises(ValueError, match="refusing to write a backup"):
            backup.create_backup(dest=str(inside))

    def test_refuses_dest_that_contains_the_data_dir(self, tmp_path, monkeypatch):
        """Backing up into an ancestor of the live data is the same collision."""
        _seed_station(tmp_path, monkeypatch)
        with pytest.raises(ValueError, match="refusing to write a backup"):
            backup.create_backup(dest=str(tmp_path))

    def test_absent_data_root_is_still_protected(self, tmp_path, monkeypatch):
        """A configured root that does not exist YET is not thereby fair game.

        install.sh creates <root>/station on first run; a guard that skipped
        absent roots would bless <root>/backups right up until the station
        booted, which is exactly when the keys land there.
        """
        vol = tmp_path / "not-yet"
        monkeypatch.setenv("CIPHER_DATA_ROOT", str(vol / "data"))
        assert not (vol / "data").exists()
        vol.mkdir()
        # `vol` contains the (absent) configured root -> collision.
        assert backup._protected_root_collision(vol) is not None
        # A sibling of it is outside the root and stays usable.
        assert backup._protected_root_collision(tmp_path / "elsewhere") is None

    def test_symlinked_dest_cannot_dodge_the_check(self, tmp_path, monkeypatch):
        vol = tmp_path / "cipher-data"
        (vol / "backups").mkdir(parents=True)
        monkeypatch.setenv("CIPHER_DATA_ROOT", str(vol))
        link = tmp_path / "sneaky"
        link.symlink_to(vol / "backups")
        assert backup._protected_root_collision(link) is not None
        assert backup._protected_root_collision(vol / "backups" / ".." / "backups") is not None

    def test_same_disk_outside_data_root_is_allowed_with_a_warning(
            self, tmp_path, monkeypatch, capsys):
        """The Pi/USB and "stage it in $HOME then scp it off" workflows.

        `usb` is on the same filesystem as the live data here (one tmpdir), which
        must not be a refusal — only a warning that the copy dies with the disk.
        """
        _seed_station(tmp_path, monkeypatch)
        usb = tmp_path / "usb"; usb.mkdir()
        monkeypatch.setenv("CIPHER_DATA_ROOT", str(tmp_path / "some-other-volume"))

        res = backup.create_backup(dest=str(usb))
        assert res["status"] == "ok"
        assert len(list(usb.glob("cipherstation-backup-*.tar.gz"))) == 1
        assert "same physical disk" in capsys.readouterr().err

    def test_ambiguous_auto_detect_is_loud_and_reported(self, tmp_path, monkeypatch, capsys):
        """Refusing to guess between mounts must not look like "nothing to do".

        The payload is a plaintext copy of the private keys, so picking the wrong
        mount is a key disclosure — but a silent skip hides a broken backup
        schedule for months, so the reason is printed AND returned.
        """
        _seed_station(tmp_path, monkeypatch)
        monkeypatch.delenv("CIPHER_BACKUP_DEST", raising=False)
        one = tmp_path / "mnt-a"; one.mkdir()
        two = tmp_path / "mnt-b"; two.mkdir()
        monkeypatch.setattr(backup, "_candidate_mounts", lambda: [one, two])
        # Real removable media is a different device; two dirs in one tmpdir are
        # not, and the same-filesystem filter (covered separately below) would
        # otherwise disqualify both before the ambiguity policy is reached.
        monkeypatch.setattr(backup, "_same_disk_live_dir", lambda p: None)

        chosen, reason = backup._auto_detect_usb()
        assert chosen is None
        assert "refusing to guess" in reason
        assert str(one) in reason and str(two) in reason
        assert "refusing to guess" in capsys.readouterr().err

        res = backup.create_backup(if_present=True)
        assert res["status"] == "skipped"
        assert res["reason"] == reason

    def test_auto_detect_skips_the_stations_own_data_volume(self, tmp_path, monkeypatch):
        _seed_station(tmp_path, monkeypatch)
        vol = tmp_path / "cipher-data"; vol.mkdir()
        monkeypatch.setenv("CIPHER_DATA_ROOT", str(vol))
        monkeypatch.setattr(backup, "_candidate_mounts", lambda: [vol])

        chosen, reason = backup._auto_detect_usb()
        assert chosen is None
        assert "this station's own storage" in reason


class TestFailureCleanup:
    """
    A half-finished backup must not leave the payload lying around. The archive
    holds mlkem.bin, mldsa.bin, the .env and the IPFS private key, so an orphan
    is a key disclosure that outlives the failed run.
    """

    def test_no_plaintext_tar_survives_a_failed_encrypt(self, tmp_path, monkeypatch):
        _seed_station(tmp_path, monkeypatch)
        usb = tmp_path / "usb"; usb.mkdir()
        scratch = tmp_path / "systemp"; scratch.mkdir()
        monkeypatch.setattr(tempfile, "tempdir", str(scratch))

        def boom(data, passphrase):
            raise RuntimeError("key wrap failed")
        monkeypatch.setattr(backup, "encrypt_private_keys", boom)

        with pytest.raises(RuntimeError, match="key wrap failed"):
            backup.create_backup(dest=str(usb), passphrase="correct horse")

        # The tar is built BEFORE encryption, in the clear. Nothing may outlive
        # the exception — neither the staging tree nor the tarball beside it.
        assert list(scratch.iterdir()) == []
        assert list(usb.iterdir()) == []

    def test_no_partial_archive_survives_a_failed_move(self, tmp_path, monkeypatch):
        _seed_station(tmp_path, monkeypatch)
        usb = tmp_path / "usb"; usb.mkdir()
        scratch = tmp_path / "systemp"; scratch.mkdir()
        monkeypatch.setattr(tempfile, "tempdir", str(scratch))

        def yanked(src, dst):
            raise OSError("drive went away")
        monkeypatch.setattr(backup.os, "replace", yanked)

        with pytest.raises(OSError, match="drive went away"):
            backup.create_backup(dest=str(usb))

        assert list(scratch.iterdir()) == []
        assert list(usb.iterdir()) == []  # no orphaned .partial on the drive


class TestRoundTrip:
    def test_create_then_restore(self, tmp_path, monkeypatch):
        _uid, calls = _seed_station(tmp_path, monkeypatch)
        usb = tmp_path / "usb"; usb.mkdir()

        mlkem_before = (cfg.KEYS_DIR / "mlkem.bin").read_bytes()
        res = backup.create_backup(dest=str(usb))
        archive = res["archive"]

        _wipe_data(tmp_path)
        assert not cfg.PUBLIC_JSON_PATH.exists()

        rres = backup.restore_backup(archive=archive)
        assert rres["status"] == "ok"
        assert rres["peer_id"] == "QmPEERtest12345"

        # Files came back, key bytes identical.
        assert (cfg.KEYS_DIR / "mlkem.bin").read_bytes() == mlkem_before
        assert cfg.PUBLIC_JSON_PATH.exists()
        assert (cfg.MANIFEST_DIR / "manifest.json").exists()
        assert (tmp_path / ".env").read_text().startswith("CIPHER_PASSWORD=")

        # DB row survived (verify via a fresh connection).
        conn = sqlite3.connect(str(cfg.DB_PATH))
        try:
            row = conn.execute(
                "SELECT mlkem_public_key FROM followers WHERE uid='alice'").fetchone()
        finally:
            conn.close()
        assert row is not None and row[0] == "aa" * 1184

        # IPFS restore steps were invoked.
        assert calls["init"] == 1
        assert calls["set_identity"] == [("QmPEERtest12345", "CAEScPRIVKEYb64")]
        assert len(calls["import_cars"][0]) == 2
        assert sorted(calls["pin_add"]) == ["Qmaaa", "Qmbbb"]

    def test_restore_refuses_to_clobber_without_force(self, tmp_path, monkeypatch):
        _seed_station(tmp_path, monkeypatch)
        usb = tmp_path / "usb"; usb.mkdir()
        res = backup.create_backup(dest=str(usb))
        # data still in place -> restore must refuse
        with pytest.raises(FileExistsError):
            backup.restore_backup(archive=res["archive"])
        # ...but force overwrites
        rres = backup.restore_backup(archive=res["archive"], force=True)
        assert rres["status"] == "ok"


class TestEncrypted:
    def test_passphrase_round_trip(self, tmp_path, monkeypatch):
        _seed_station(tmp_path, monkeypatch)
        usb = tmp_path / "usb"; usb.mkdir()

        res = backup.create_backup(dest=str(usb), passphrase="correct horse")
        assert res["encrypted"] is True
        assert res["archive"].endswith(".tar.gz.enc")

        _wipe_data(tmp_path)

        with pytest.raises(Exception):
            backup.restore_backup(archive=res["archive"], passphrase="wrong")

        with pytest.raises(ValueError, match="passphrase is required"):
            backup.restore_backup(archive=res["archive"])

        rres = backup.restore_backup(archive=res["archive"], passphrase="correct horse")
        assert rres["status"] == "ok"
        assert cfg.PUBLIC_JSON_PATH.exists()
