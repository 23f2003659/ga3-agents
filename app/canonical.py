"""Canonical JSON + hashing helpers shared by all three agents.

Canonical form = recursively key-sorted, compact (no whitespace) JSON encoded
as UTF-8. This is the deterministic basis for idempotency keys, content
fingerprints, and SHA-256 argument digests required by the contracts.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any


def canonical_bytes(obj: Any) -> bytes:
    """Recursively key-sorted, compact JSON as UTF-8 bytes."""
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def canonical_str(obj: Any) -> str:
    return canonical_bytes(obj).decode("utf-8")


def sha256_hex(obj: Any) -> str:
    """Lowercase SHA-256 hex over the canonical JSON of obj."""
    return hashlib.sha256(canonical_bytes(obj)).hexdigest()


def sha256_hex_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
