"""Offline revocation list for capabilities and delegation chains.

A capability is revoked by its ``capability_id``. Because every v0.2
capability also carries the ``root_capability_id`` of its delegation chain,
revoking the root revokes every descendant even when the gate never sees the
intermediate children.

The list is deliberately independent of ledgers and can be distributed as a
checksummed bundle; deployments choose their own authenticated distribution
channel (signed file, device update, registry). This module does not assume
one.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Iterable

from .canonical import canonical_json
from .models import isoformat, parse_time, utc_now


@dataclass(frozen=True)
class RevocationEntry:
    capability_id: str
    reason: str | None = None
    at: datetime = utc_now()

    def __post_init__(self) -> None:
        if not isinstance(self.capability_id, str) or not self.capability_id:
            raise ValueError("capability_id must be a non-empty string")
        if self.reason is not None and (
            not isinstance(self.reason, str) or not self.reason
        ):
            raise ValueError("reason must be a non-empty string or None")
        if self.at.tzinfo is None:
            raise ValueError("revocation timestamps must include a timezone")

    def to_dict(self) -> dict[str, Any]:
        return {
            "capability_id": self.capability_id,
            "reason": self.reason,
            "at": isoformat(self.at),
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "RevocationEntry":
        return cls(
            capability_id=value["capability_id"],
            reason=value.get("reason"),
            at=parse_time(value["at"]),
        )


class RevocationList:
    """Set of revoked capability ids with optional reasons and timestamps."""

    def __init__(self, entries: Iterable[RevocationEntry] = ()) -> None:
        self._entries: dict[str, RevocationEntry] = {}
        for entry in entries:
            self._entries[entry.capability_id] = entry

    @property
    def entries(self) -> tuple[RevocationEntry, ...]:
        return tuple(self._entries.values())

    def revoke(
        self,
        capability_id: str,
        *,
        reason: str | None = None,
        at: datetime | None = None,
    ) -> RevocationEntry:
        entry = RevocationEntry(capability_id, reason, at or utc_now())
        self._entries[entry.capability_id] = entry
        return entry

    def is_revoked(self, capability_id: str | None) -> bool:
        return capability_id is not None and capability_id in self._entries

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "kinegrant:RevocationList",
            "schema_version": "0.1",
            "entries": [entry.to_dict() for entry in self.entries],
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "RevocationList":
        if value.get("type") != "kinegrant:RevocationList":
            raise ValueError("wrong revocation list type")
        if value.get("schema_version") != "0.1":
            raise ValueError("unsupported revocation list version")
        entries = value.get("entries", [])
        if not isinstance(entries, list):
            raise ValueError("revocation entries must be an array")
        return cls(RevocationEntry.from_dict(entry) for entry in entries)

    def digest(self) -> str:
        return "sha256:" + hashlib.sha256(canonical_json(self.to_dict())).hexdigest()
