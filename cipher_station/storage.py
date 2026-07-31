# cipher_station/storage.py

import json
import logging
import os
from pathlib import Path

from cipher_station.config import BASE_DIR, KEYS_DIR, PUBLIC_JSON_PATH

logger = logging.getLogger(__name__)


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
    truncate the destination."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + ".tmp")
        with open(tmp, "w") as f:
            json.dump(obj, f, indent=4)
        os.replace(tmp, path)
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
