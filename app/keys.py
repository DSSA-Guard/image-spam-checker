"""API keys issued from the admin page.

Only the SHA-256 of each key is stored; the raw key is shown once when it
is issued. Keys are 256-bit random tokens, so a plain hash (no salt or
KDF) is enough. Active key hashes are cached in memory so the per-request
check never touches SQLite; the service runs as one worker, and
``create_key``/``revoke_key`` keep that cache current.
"""

from __future__ import annotations

import hashlib
import secrets
import sqlite3
import threading
import time

from app import engine

_DB_FILE = engine._DB_DIR / "api_keys.sqlite3"
PREFIX = "isc_"
# last_used_at is informational; writing it on every request would turn
# each API call into a disk write.
_TOUCH_INTERVAL = 60

_lock = threading.Lock()
_active: dict[str, int] | None = None  # key hash -> id
_touched: dict[int, float] = {}


def _connect() -> sqlite3.Connection:
    engine._DB_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(_DB_FILE, check_same_thread=False, timeout=5.0)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS api_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            prefix TEXT NOT NULL,
            key_hash TEXT NOT NULL UNIQUE,
            created_at INTEGER NOT NULL,
            last_used_at INTEGER,
            revoked_at INTEGER
        )
        """
    )
    return conn


def _hash(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def _load() -> dict[str, int]:
    global _active
    with _lock:
        if _active is None:
            conn = _connect()
            try:
                rows = conn.execute(
                    "SELECT key_hash, id FROM api_keys WHERE revoked_at IS NULL"
                ).fetchall()
            finally:
                conn.close()
            _active = dict(rows)
        return _active


def create_key(name: str) -> str:
    """Issue a key and return it. This is the only time the raw key exists."""
    raw = PREFIX + secrets.token_urlsafe(32)
    h = _hash(raw)
    conn = _connect()
    try:
        cur = conn.execute(
            "INSERT INTO api_keys (name, prefix, key_hash, created_at) VALUES (?, ?, ?, ?)",
            (name, raw[: len(PREFIX) + 6], h, int(time.time())),
        )
        conn.commit()
        key_id = cur.lastrowid
    finally:
        conn.close()
    _load()[h] = key_id
    return raw


def revoke_key(key_id: int) -> bool:
    conn = _connect()
    try:
        cur = conn.execute(
            "UPDATE api_keys SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL",
            (int(time.time()), key_id),
        )
        conn.commit()
        revoked = cur.rowcount > 0
    finally:
        conn.close()
    active = _load()
    for h, i in list(active.items()):
        if i == key_id:
            del active[h]
    return revoked


def verify(raw: str) -> bool:
    key_id = _load().get(_hash(raw))
    if key_id is None:
        return False
    now = time.time()
    if now - _touched.get(key_id, 0) >= _TOUCH_INTERVAL:
        _touched[key_id] = now
        conn = _connect()
        try:
            conn.execute("UPDATE api_keys SET last_used_at = ? WHERE id = ?", (int(now), key_id))
            conn.commit()
        finally:
            conn.close()
    return True


def list_keys() -> list[dict]:
    """Every key, newest first. Never includes the hash."""
    conn = _connect()
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            "SELECT id, name, prefix, created_at, last_used_at, revoked_at "
            "FROM api_keys ORDER BY id DESC"
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()
