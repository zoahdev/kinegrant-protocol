from __future__ import annotations

import hashlib
import json
from typing import Any


def canonical_json(value: Any) -> bytes:
    """Return a deterministic UTF-8 JSON encoding used for signatures and hashes."""
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value)).hexdigest()


def content_id(prefix: str, value: Any) -> str:
    return f"{prefix}:{hashlib.sha256(canonical_json(value)).hexdigest()}"
