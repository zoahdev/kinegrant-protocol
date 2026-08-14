from __future__ import annotations

import hashlib
import json
import math
import re
from decimal import Decimal
from typing import Any

_MAX_SAFE_INTEGER = 2**53 - 1

_ESCAPE_RE = re.compile(r'["\\\x00-\x1f\u2028\u2029]')
_ESCAPE_MAP = {
    '"': '\\"',
    "\\": "\\\\",
    "\b": "\\b",
    "\f": "\\f",
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\t",
    "\u2028": "\\u2028",
    "\u2029": "\\u2029",
}
_EXPONENT_RE = re.compile(r"e([+-])0+(\d+)$")


def _escape(match: re.Match[str]) -> str:
    char = match.group(0)
    return _ESCAPE_MAP.get(char, "\\u%04x" % ord(char))


def _number(value: int | float) -> str:
    """Serialize a number using ECMAScript JSON.stringify semantics (RFC 8785)."""
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("non-finite numbers are not allowed in canonical JSON")
        if value == 0.0:
            # ECMAScript serializes both +0 and -0 as 0.
            return "0"
        absolute = abs(value)
        if absolute >= 1e21 or absolute < 1e-6:
            text = repr(value)
            return _EXPONENT_RE.sub(r"e\1\2", text)
        if value.is_integer():
            return str(int(value))
        # repr() yields the shortest decimal that round-trips; Decimal formatting
        # expands it to the fixed notation required by Number::toString in this range.
        return format(Decimal(repr(value)), "f")
    # Python bool is an int subclass; JSON booleans must not reach this branch.
    if isinstance(value, bool):
        raise TypeError("booleans must be serialized as true/false")
    if not -_MAX_SAFE_INTEGER <= value <= _MAX_SAFE_INTEGER:
        raise ValueError(
            f"integer {value} is outside the RFC 8785 safe range "
            f"({-_MAX_SAFE_INTEGER}..{_MAX_SAFE_INTEGER})"
        )
    return str(value)


def _string(value: str) -> str:
    return '"' + _ESCAPE_RE.sub(_escape, value) + '"'


def _jcs(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return _string(value)
    if isinstance(value, (int, float)):
        return _number(value)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_jcs(item) for item in value) + "]"
    if isinstance(value, dict):
        for key in value:
            if not isinstance(key, str):
                raise ValueError("canonical JSON object member names must be strings")
        body = ",".join(
            _string(key) + ":" + _jcs(value[key])
            for key in sorted(value, key=lambda item: item.encode("utf-16-be"))
        )
        return "{" + body + "}"
    raise TypeError(f"cannot canonicalize {type(value).__name__}")


def canonical_json(value: Any) -> bytes:
    """Return the RFC 8785 JCS encoding used for signatures and hashes.

    The encoding is deterministic across implementations: object members are
    sorted by UTF-16 code unit order, strings follow ECMAScript escaping rules,
    and numbers use the shortest round-trippable ECMAScript representation.
    """
    return _jcs(value).encode("utf-8")


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value)).hexdigest()


def content_id(prefix: str, value: Any) -> str:
    return f"{prefix}:{hashlib.sha256(canonical_json(value)).hexdigest()}"
