# cipher_station/database.py

import logging
import sqlite3
import threading

from cipher_station.config import DB_PATH, ensure_directories

logger = logging.getLogger(__name__)

# One SQLite connection PER THREAD. A single shared connection is NOT safe across
# FastAPI's worker threads: check_same_thread=False only silences the guard, it
# does not serialize cursor use, so concurrent authenticated requests could
# interleave on one connection and return corrupted/empty reads (seen as
# intermittent "device not authorized" 403s under parallel /rewrap). WAL mode
# lets per-thread connections read+write the same DB file concurrently and
# safely; busy_timeout makes a contended writer wait rather than error.
_local = threading.local()


def _init_schema(conn: sqlite3.Connection) -> None:
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA busy_timeout=5000")  # wait up to 5s for a write lock

    # -----------------------------------------------------
    #  FOLLOWERS TABLE (inbound) — ML-KEM (content) + ML-DSA (auth) public keys
    # -----------------------------------------------------
    conn.execute("""
        CREATE TABLE IF NOT EXISTS followers (
            uid TEXT NOT NULL,
            device_uid TEXT NOT NULL,
            mlkem_public_key TEXT NOT NULL,
            mldsa_public_key TEXT NULL,
            alias TEXT NULL,
            allowed TEXT NOT NULL DEFAULT 'Allowed',
            endpoint TEXT NULL,
            ipns_id TEXT NULL,
            PRIMARY KEY(uid, device_uid)
        );
    """)

    # -----------------------------------------------------
    #  FOLLOWING TABLE (outbound)
    # -----------------------------------------------------
    conn.execute("""
        CREATE TABLE IF NOT EXISTS following (
            uid TEXT NOT NULL,
            mlkem_public_key TEXT NOT NULL,
            mldsa_public_key TEXT NULL,
            endpoint TEXT NOT NULL,
            alias TEXT NULL,
            ipns_id TEXT NULL,
            PRIMARY KEY(uid)
        );
    """)

    # -----------------------------------------------------
    #  AUTH NONCES TABLE (replay protection)
    # -----------------------------------------------------
    conn.execute("""
        CREATE TABLE IF NOT EXISTS auth_nonces (
            uid TEXT NOT NULL,
            device_uid TEXT NOT NULL,
            nonce TEXT NOT NULL,
            ts INTEGER NOT NULL,
            PRIMARY KEY (uid, device_uid, nonce)
        );
    """)

    # ---- Indexes for common queries ----
    conn.execute("CREATE INDEX IF NOT EXISTS idx_followers_uid ON followers(uid)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_auth_nonces_ts ON auth_nonces(ts)")

    # ---- Migrations for existing databases ----
    # Add ipns_id column if upgrading from a pre-IPNS schema. SQLite raises
    # OperationalError if the column already exists — safe to ignore.
    for table in ("followers", "following"):
        try:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN ipns_id TEXT NULL")
            logger.info("Migration: added ipns_id column to %s", table)
        except sqlite3.OperationalError:
            pass  # column already exists

    conn.commit()


def get_db() -> sqlite3.Connection:
    """
    Return this thread's SQLite connection, creating + initializing it on first
    use (one connection per thread — see the _local note above).
    """
    conn = getattr(_local, "conn", None)
    if conn is None:
        ensure_directories()
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        _init_schema(conn)
        _local.conn = conn
        logger.info("Database connection initialized (WAL, per-thread)")
    return conn


def reset_connection() -> None:
    """Close + drop this thread's connection (used by tests between runs)."""
    conn = getattr(_local, "conn", None)
    if conn is not None:
        try:
            conn.close()
        except Exception:
            pass
        _local.conn = None
