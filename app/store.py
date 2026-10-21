"""Durable storage: SQLite with a simple namespaced key/value API plus a
content-addressed decision cache. Writes are committed before the handler
responds (contract: 'store state before responding'). A process-wide lock
serializes writes so concurrent equivalent requests cannot double-apply.
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
from typing import Any, Optional

_DB_PATH = os.environ.get("DB_PATH", "state.db")
_lock = threading.RLock()
_conn: Optional[sqlite3.Connection] = None


def _db() -> sqlite3.Connection:
    global _conn
    if _conn is None:
        _conn = sqlite3.connect(_DB_PATH, check_same_thread=False)
        _conn.execute("PRAGMA journal_mode=WAL;")
        _conn.execute("PRAGMA synchronous=NORMAL;")
        _conn.execute(
            "CREATE TABLE IF NOT EXISTS kv ("
            "ns TEXT NOT NULL, k TEXT NOT NULL, v TEXT NOT NULL, "
            "PRIMARY KEY (ns, k))"
        )
        _conn.execute(
            "CREATE TABLE IF NOT EXISTS cache ("
            "ns TEXT NOT NULL, fingerprint TEXT NOT NULL, v TEXT NOT NULL, "
            "PRIMARY KEY (ns, fingerprint))"
        )
        _conn.commit()
    return _conn


def get(ns: str, key: str) -> Optional[Any]:
    with _lock:
        cur = _db().execute("SELECT v FROM kv WHERE ns=? AND k=?", (ns, key))
        row = cur.fetchone()
    return json.loads(row[0]) if row else None


def put(ns: str, key: str, value: Any) -> None:
    with _lock:
        _db().execute(
            "INSERT OR REPLACE INTO kv (ns,k,v) VALUES (?,?,?)",
            (ns, key, json.dumps(value)),
        )
        _db().commit()


def put_if_absent(ns: str, key: str, value: Any) -> bool:
    """Atomic create. Returns True if inserted, False if key already existed."""
    with _lock:
        try:
            _db().execute(
                "INSERT INTO kv (ns,k,v) VALUES (?,?,?)",
                (ns, key, json.dumps(value)),
            )
            _db().commit()
            return True
        except sqlite3.IntegrityError:
            return False


def delete(ns: str, key: str) -> None:
    with _lock:
        _db().execute("DELETE FROM kv WHERE ns=? AND k=?", (ns, key))
        _db().commit()


def list_ns(ns: str) -> list[Any]:
    with _lock:
        cur = _db().execute("SELECT v FROM kv WHERE ns=?", (ns,))
        rows = cur.fetchall()
    return [json.loads(r[0]) for r in rows]


# ---- content-addressed decision cache (per-agent namespace) ----
def cache_get(ns: str, fingerprint: str) -> Optional[Any]:
    with _lock:
        cur = _db().execute(
            "SELECT v FROM cache WHERE ns=? AND fingerprint=?", (ns, fingerprint)
        )
        row = cur.fetchone()
    return json.loads(row[0]) if row else None


def cache_put(ns: str, fingerprint: str, value: Any) -> None:
    with _lock:
        _db().execute(
            "INSERT OR REPLACE INTO cache (ns,fingerprint,v) VALUES (?,?,?)",
            (ns, fingerprint, json.dumps(value)),
        )
        _db().commit()


def transaction():
    """Return the process lock for multi-step atomic sections."""
    return _lock
