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
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Iterable, Mapping

from .canonical import canonical_json, content_id
from .crypto import verify_envelope
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


_BUNDLE_TYPE = "kinegrant:RevocationBundle"
_BUNDLE_VERSION = "0.1"
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def build_revocation_bundle(
    revocation_list: RevocationList,
    *,
    issuer: str,
    version: int = 1,
    previous_bundle_digest: str | None = None,
    issued_at: datetime | None = None,
) -> dict[str, Any]:
    """Build an unsigned revocation bundle body with a content-addressed id."""
    if not isinstance(version, int) or isinstance(version, bool) or version < 1:
        raise ValueError("bundle version must be a positive integer")
    if previous_bundle_digest is not None and _SHA256_RE.fullmatch(
        previous_bundle_digest
    ) is None:
        raise ValueError("previous_bundle_digest must be a sha256 digest or None")
    if not isinstance(issuer, str) or not issuer:
        raise ValueError("issuer must be a non-empty string")
    body = {
        "type": _BUNDLE_TYPE,
        "schema_version": _BUNDLE_VERSION,
        "issuer": issuer,
        "version": version,
        "previous_bundle_digest": previous_bundle_digest,
        "issued_at": isoformat(issued_at or utc_now()),
        "revocations": [entry.to_dict() for entry in revocation_list.entries],
    }
    body["bundle_id"] = content_id(
        "kinegrant:revocation-bundle",
        {key: value for key, value in body.items() if key != "bundle_id"},
    )
    return body


def bundle_digest(bundle: Mapping[str, Any]) -> str:
    """Content digest of a complete (unsigned) bundle body."""
    return "sha256:" + hashlib.sha256(canonical_json(dict(bundle))).hexdigest()


def sign_revocation_bundle(
    bundle: dict[str, Any],
    key_pair: Any,
) -> dict[str, Any]:
    """Sign a bundle with any KineGrant envelope key pair (Ed25519/ML-DSA)."""
    return key_pair.sign_envelope(bundle)


def verify_revocation_bundle(
    envelope: Mapping[str, Any],
    *,
    trusted_authorities: set[str] | None = None,
    expected_previous_digest: str | None = None,
) -> RevocationList:
    """Verify a signed revocation bundle and return its revocation list."""
    payload = verify_envelope(envelope)
    if payload.get("type") != _BUNDLE_TYPE:
        raise ValueError("wrong revocation bundle type")
    if payload.get("schema_version") != _BUNDLE_VERSION:
        raise ValueError("unsupported revocation bundle version")
    if trusted_authorities is not None and payload.get("issuer") not in trusted_authorities:
        raise ValueError("untrusted revocation authority")
    if payload.get("issuer") != envelope.get("kid"):
        raise ValueError("revocation bundle issuer does not match signing key")
    version = payload.get("version")
    if not isinstance(version, int) or isinstance(version, bool) or version < 1:
        raise ValueError("bundle version must be a positive integer")
    previous = payload.get("previous_bundle_digest")
    if previous is not None and _SHA256_RE.fullmatch(previous) is None:
        raise ValueError("previous_bundle_digest must be a sha256 digest or None")
    if expected_previous_digest is not None and previous != expected_previous_digest:
        raise ValueError("previous bundle digest does not match the expected chain")
    bundle_id = payload.get("bundle_id")
    expected_id = content_id(
        "kinegrant:revocation-bundle",
        {key: value for key, value in payload.items() if key != "bundle_id"},
    )
    if bundle_id != expected_id:
        raise ValueError("revocation bundle identifier is inconsistent")
    revocations = payload.get("revocations")
    if not isinstance(revocations, list):
        raise ValueError("revocations must be an array")
    return RevocationList.from_dict(
        {
            "type": "kinegrant:RevocationList",
            "schema_version": "0.1",
            "entries": revocations,
        }
    )
