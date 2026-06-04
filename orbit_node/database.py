# orbit_node/database.py

import logging
import sqlite3

from orbit_node.config import DB_PATH, ensure_directories

logger = logging.getLogger(__name__)

_conn = None


def get_db():
    """
    Returns a global SQLite connection and initializes the DB schema if needed.
    The connection is created with check_same_thread=False so FastAPI worker
    threads can safely execute queries using the same connection.
    """
    global _conn
    if _conn is None:
        ensure_directories()

        _conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        _conn.row_factory = sqlite3.Row

        # ---- Performance pragmas ----
        _conn.execute("PRAGMA journal_mode=WAL")
        _conn.execute("PRAGMA synchronous=NORMAL")

        # -----------------------------------------------------
        #  FOLLOWERS TABLE (inbound)
        #  Post-quantum: each principal carries an ML-KEM public key
        #  (content envelopes) and an ML-DSA public key (auth signatures).
        # -----------------------------------------------------
        _conn.execute("""
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
        _conn.execute("""
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
        _conn.execute("""
            CREATE TABLE IF NOT EXISTS auth_nonces (
                uid TEXT NOT NULL,
                device_uid TEXT NOT NULL,
                nonce TEXT NOT NULL,
                ts INTEGER NOT NULL,
                PRIMARY KEY (uid, device_uid, nonce)
            );
        """)

        # ---- Indexes for common queries ----
        _conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_followers_uid ON followers(uid)"
        )
        _conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_auth_nonces_ts ON auth_nonces(ts)"
        )

        # ---- Migrations for existing databases ----
        # Add ipns_id column if upgrading from a pre-IPNS schema.
        # SQLite raises OperationalError if column already exists — safe to ignore.
        for table in ("followers", "following"):
            try:
                _conn.execute(f"ALTER TABLE {table} ADD COLUMN ipns_id TEXT NULL")
                logger.info("Migration: added ipns_id column to %s", table)
            except sqlite3.OperationalError:
                pass  # column already exists

        _conn.commit()
        logger.info("Database initialized (WAL mode, indexes created)")

    return _conn
