# cipher_station/storage.py

import json
import logging
import os
import tempfile
import threading
from pathlib import Path

from cipher_station.config import BASE_DIR, KEYS_DIR, PUBLIC_JSON_PATH

logger = logging.getLogger(__name__)

# One process-wide lock for every read-modify-write of the station's shared
# JSON state (manifest.json, public.json, graph files). Requests are served on
# a thread pool, so two concurrent /post calls otherwise interleave their
# load → append → save cycles and the second silently erases the first's entry.
# RLock so a locked caller can call locked helpers (e.g. the manifest pointer
# update inside a locked append).
STATE_LOCK = threading.RLock()


def write_file(path: Path, data: bytes):
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "wb") as f:
            f.write(data)
    except OSError as exc:
        logger.error("Failed to write file %s: %s", path, exc)
        raise


def read_file(path: Path) -> bytes:
    try:
        with open(path, "rb") as f:
            return f.read()
    except FileNotFoundError:
        logger.error("File not found: %s", path)
        raise
    except OSError as exc:
        logger.error("Failed to read file %s: %s", path, exc)
        raise


def write_json(path: Path, obj: dict):
    """Write JSON atomically (temp file + os.replace) so a crash mid-write can't
    truncate the destination. The temp name is unique per call: a fixed name
    like `manifest.json.tmp` would let two concurrent writers interleave into
    one garbage temp file and os.replace it over the real state."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(
            prefix=path.name + ".", suffix=".tmp", dir=path.parent
        )
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(obj, f, indent=4)
            os.replace(tmp_name, path)
        except BaseException:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
            raise
    except (OSError, TypeError) as exc:
        logger.error("Failed to write JSON %s: %s", path, exc)
        raise


def read_json(path: Path):
    try:
        with open(path, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        logger.error("JSON file not found: %s", path)
        raise
    except json.JSONDecodeError as exc:
        logger.error("Invalid JSON in %s: %s", path, exc)
        raise
    except OSError as exc:
        logger.error("Failed to read JSON %s: %s", path, exc)
        raise
