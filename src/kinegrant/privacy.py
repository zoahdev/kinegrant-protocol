"""Privacy groundwork (v0.5): rotating identifiers and selective disclosure.

Rotating identifiers keep long-lived identity strings out of receipts and
logs: a static id is mapped to a short-lived ephemeral id that the registry
can resolve only within its lifetime. Selective disclosure lets a party show
only the fields it wants while committing to the full document digest.

These are drafts, not zero-knowledge proofs; the reference implementation
documents exactly what each mechanism proves.
"""

from __future__ import annotations

import re
import secrets
from datetime import datetime, timedelta
from typing import Any, Iterable, Mapping

from .canonical import digest
from .models import utc_now

_EPHEMERAL_RE = re.compile(r"^urn:kinegrant:ephemeral:[a-z0-9.-]{1,63}:[0-9a-f]{24}$")


class RotatingIdentifierRegistry:
    """Maps static identifiers to short-lived ephemeral identifiers."""

    def __init__(self, *, lifetime_seconds: int = 300) -> None:
        if (
            not isinstance(lifetime_seconds, int)
            or isinstance(lifetime_seconds, bool)
            or lifetime_seconds < 1
        ):
            raise ValueError("lifetime_seconds must be a positive integer")
        self.lifetime = timedelta(seconds=lifetime_seconds)
        self._active: dict[str, tuple[str, str, datetime]] = {}

    def issue(self, namespace: str, static_id: str, *, now: datetime | None = None) -> str:
        if not isinstance(namespace, str) or not re.fullmatch(r"[a-z0-9.-]{1,63}", namespace):
            raise ValueError("namespace must match the KineGrant namespace grammar")
        if not isinstance(static_id, str) or not static_id:
            raise ValueError("static_id must be a non-empty string")
        ephemeral = (
            f"urn:kinegrant:ephemeral:{namespace}:{secrets.token_hex(12)}"
        )
        self._active[ephemeral] = (namespace, static_id, now or utc_now())
        return ephemeral

    def resolve(
        self,
        ephemeral: str,
        *,
        now: datetime | None = None,
    ) -> str:
        if _EPHEMERAL_RE.fullmatch(ephemeral) is None:
            raise ValueError(f"{ephemeral!r} is not a valid ephemeral identifier")
        record = self._active.get(ephemeral)
        if record is None:
            raise ValueError(f"ephemeral identifier {ephemeral!r} is not active")
        namespace, static_id, created = record
        current = now or utc_now()
        if current - created > self.lifetime:
            del self._active[ephemeral]
            raise ValueError(f"ephemeral identifier {ephemeral!r} has expired")
        return static_id

    def rotate(
        self,
        namespace: str,
        static_id: str,
        *,
        now: datetime | None = None,
    ) -> str:
        """Revoke the previous ephemeral for *static_id* and issue a new one."""
        stale = [
            ephemeral
            for ephemeral, (ns, sid, _) in self._active.items()
            if ns == namespace and sid == static_id
        ]
        for ephemeral in stale:
            del self._active[ephemeral]
        return self.issue(namespace, static_id, now=now)

    def revoke(self, ephemeral: str) -> None:
        if ephemeral not in self._active:
            raise ValueError(f"ephemeral identifier {ephemeral!r} is not active")
        del self._active[ephemeral]

    @property
    def active_count(self) -> int:
        return len(self._active)


def redact(
    document: Mapping[str, Any],
    *,
    visible: Iterable[str] | None = None,
    hidden: Iterable[str] | None = None,
) -> dict[str, Any]:
    """Build a selective-disclosure envelope over *document*."""
    keys = set(document)
    if visible is not None and hidden is not None:
        raise ValueError("provide visible or hidden, not both")
    if visible is not None:
        keep = set(visible) & keys
    elif hidden is not None:
        keep = keys - set(hidden)
    else:
        keep = keys
    redacted = {key: (value if key in keep else None) for key, value in document.items()}
    return {
        "type": "kinegrant:Redaction",
        "schema_version": "0.1",
        "visible_fields": sorted(keep),
        "hidden_fields": sorted(keys - keep),
        "full_digest": digest(dict(document)),
        "redacted": redacted,
    }


def verify_redaction(redaction: Mapping[str, Any], full: Mapping[str, Any]) -> bool:
    """Return True when *redaction* commits to *full* and reveals it exactly."""
    try:
        if redaction.get("type") != "kinegrant:Redaction":
            return False
        if redaction.get("schema_version") != "0.1":
            return False
        if redaction.get("full_digest") != digest(dict(full)):
            return False
        redacted = redaction.get("redacted")
        if not isinstance(redacted, Mapping) or set(redacted) != set(full):
            return False
        visible_fields = redaction.get("visible_fields", [])
        hidden_fields = redaction.get("hidden_fields", [])
        if not isinstance(visible_fields, list) or not isinstance(hidden_fields, list):
            return False
        if set(visible_fields).union(hidden_fields) != set(full):
            return False
        if set(visible_fields).intersection(hidden_fields):
            return False
        for field in visible_fields:
            if redacted.get(field) != full.get(field):
                return False
        for field in hidden_fields:
            if redacted.get(field) is not None:
                return False
        return True
    except (TypeError, ValueError):
        return False
