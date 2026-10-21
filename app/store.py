"""Durable storage: SQLite key/value + content-addressed decision cache.

* Writes commit before handlers respond ("store state before responding").
* `_db_lock` only guards short SQLite operations.
* `key_lock(name)` gives a per-entity lock (task, evaluation, run) so slow model
  calls for one entity never block unrelated requests, while concurrent
  equivalent requests for the same entity are serialized (no double work).
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from typing import Any, Optional

_DB_PATH = os.environ.get("DB_PATH", "state.db")
_db_lock = threading.RLock()
_conn: Optional[sqlite3.Connection] = None

_key_locks: dict[str, threading.Lock] = {}
_key_locks_guard = threading.Lock()


def _db() -> sqlite3.Connection:
    global _conn
    if _conn is None:
        _conn = sqlite3.connect(_DB_PATH, check_same_thread=False)
        _conn.execute("PRAGMA journal_mode=WAL;")
        _conn.execute("PRAGMA synchronous=NORMAL;")
        _conn.execute("CREATE TABLE IF NOT EXISTS kv (ns TEXT NOT NULL, k TEXT NOT NULL, "
                      "v TEXT NOT NULL, PRIMARY KEY (ns, k))")
        _conn.execute("CREATE TABLE IF NOT EXISTS cache (ns TEXT NOT NULL, fingerprint TEXT NOT NULL, "
                      "v TEXT NOT NULL, PRIMARY KEY (ns, fingerprint))")
        _conn.execute("CREATE TABLE IF NOT EXISTS capture (id INTEGER PRIMARY KEY AUTOINCREMENT, "
                      "ts REAL, v TEXT NOT NULL)")
        _conn.commit()
    return _conn


def key_lock(name: str) -> threading.Lock:
    with _key_locks_guard:
        lk = _key_locks.get(name)
        if lk is None:
            lk = _key_locks[name] = threading.Lock()
        return lk


def get(ns: str, key: str) -> Optional[Any]:
    with _db_lock:
        row = _db().execute("SELECT v FROM kv WHERE ns=? AND k=?", (ns, key)).fetchone()
    return json.loads(row[0]) if row else None


def put(ns: str, key: str, value: Any) -> None:
    with _db_lock:
        _db().execute("INSERT OR REPLACE INTO kv (ns,k,v) VALUES (?,?,?)", (ns, key, json.dumps(value)))
        _db().commit()


def list_ns(ns: str) -> list[Any]:
    with _db_lock:
        rows = _db().execute("SELECT v FROM kv WHERE ns=?", (ns,)).fetchall()
    return [json.loads(r[0]) for r in rows]


def cache_get(ns: str, fingerprint: str) -> Optional[Any]:
    with _db_lock:
        row = _db().execute("SELECT v FROM cache WHERE ns=? AND fingerprint=?", (ns, fingerprint)).fetchone()
    return json.loads(row[0]) if row else None


def cache_put(ns: str, fingerprint: str, value: Any) -> None:
    with _db_lock:
        _db().execute("INSERT OR REPLACE INTO cache (ns,fingerprint,v) VALUES (?,?,?)",
                      (ns, fingerprint, json.dumps(value)))
        _db().commit()


# ---- debug capture (only used when DEBUG_TOKEN is configured) ----
def capture_add(entry: dict, keep: int = 40) -> None:
    with _db_lock:
        _db().execute("INSERT INTO capture (ts, v) VALUES (?, ?)", (time.time(), json.dumps(entry)))
        _db().execute("DELETE FROM capture WHERE id NOT IN (SELECT id FROM capture ORDER BY id DESC LIMIT ?)", (keep,))
        _db().commit()


def capture_list() -> list[dict]:
    with _db_lock:
        rows = _db().execute("SELECT id, ts, v FROM capture ORDER BY id").fetchall()
    return [{"id": r[0], "ts": r[1], **json.loads(r[2])} for r in rows]
