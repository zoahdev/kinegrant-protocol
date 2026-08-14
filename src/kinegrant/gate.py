from __future__ import annotations

from collections.abc import Iterator, Mapping as MappingABC
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timedelta
from fnmatch import fnmatchcase
from pathlib import Path
import sqlite3
import re
from threading import Lock
from typing import Any, Mapping, Protocol

from .canonical import content_id
from .crypto import verify_envelope
from .models import ActionRequest, parse_time, utc_now
from .obligations import KNOWN_OBLIGATIONS
from .revocation import RevocationList


class ReplayStore(Protocol):
    def consume_once(self, capability_id: str, expires_at: datetime) -> bool: ...


class InMemoryReplayStore:
    """Process-local replay protection for tests and simulators only."""

    def __init__(self) -> None:
        self._entries: dict[str, datetime] = {}
        self._lock = Lock()

    def consume_once(self, capability_id: str, expires_at: datetime) -> bool:
        with self._lock:
            expired = [key for key, expiry in self._entries.items() if expiry < utc_now()]
            for key in expired:
                del self._entries[key]
            if capability_id in self._entries:
                return False
            self._entries[capability_id] = expires_at
            return True


class SQLiteReplayStore:
    """Crash-persistent replay store using an atomic SQLite primary-key insert."""

    def __init__(self, path: str | Path) -> None:
        self.path = str(path)
        if self.path == ":memory:":
            raise ValueError("SQLiteReplayStore requires a filesystem path")
        with closing(sqlite3.connect(self.path)) as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute(
                "CREATE TABLE IF NOT EXISTS consumed_capabilities ("
                "capability_id TEXT PRIMARY KEY, expires_at REAL NOT NULL)"
            )
            connection.commit()

    def consume_once(self, capability_id: str, expires_at: datetime) -> bool:
        with closing(
            sqlite3.connect(self.path, isolation_level=None, timeout=5)
        ) as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(
                    "DELETE FROM consumed_capabilities WHERE expires_at < ?",
                    (utc_now().timestamp(),),
                )
                cursor = connection.execute(
                    "INSERT OR IGNORE INTO consumed_capabilities(capability_id, expires_at) "
                    "VALUES (?, ?)",
                    (capability_id, expires_at.timestamp()),
                )
                connection.execute("COMMIT")
                return cursor.rowcount == 1
            except Exception:
                if connection.in_transaction:
                    connection.rollback()
                raise


@dataclass(frozen=True)
class VerifiedCapability(MappingABC[str, Any]):
    """Claims returned only after a gate has verified and consumed a capability."""

    claims: dict[str, Any]
    authorized_at: datetime

    def __getitem__(self, key: str) -> Any:
        return self.claims[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self.claims)

    def __len__(self) -> int:
        return len(self.claims)


CAPABILITY_FIELDS = {
    "type", "version", "issuer", "agent", "target", "action", "purpose",
    "request_digest", "policy_digest", "matched_policy_ids", "obligations",
    "issued_at", "not_before", "expires_at", "nonce", "capability_id",
}
CAPABILITY_FIELDS_V2 = (
    CAPABILITY_FIELDS - {"action", "purpose"}
) | {
    "actions", "purposes", "parent_capability_id", "constraints", "approval_tier",
    "delegation_allowed", "max_delegation_depth", "delegate_agent", "delegation_depth",
    "root_capability_id", "delegate_allowlist",
}
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class ActionGate:
    """Fail-closed verifier intended to sit immediately before an actuator call."""

    def __init__(
        self,
        *,
        trusted_issuers: set[str] | None = None,
        replay_store: ReplayStore | None = None,
        revocation_list: RevocationList | None = None,
    ) -> None:
        # An omitted trust store means trust nobody, not trust everybody.
        self.trusted_issuers = set(trusted_issuers or ())
        self.replay_store = replay_store or InMemoryReplayStore()
        self.revocation_list = revocation_list

    def authorize(
        self,
        capability: Mapping[str, Any],
        request: ActionRequest,
        *,
        now: datetime | None = None,
        parent_capability: Mapping[str, Any] | None = None,
    ) -> VerifiedCapability:
        payload = verify_envelope(capability)
        version = payload.get("version")
        if version == "0.1":
            if set(payload) != CAPABILITY_FIELDS:
                raise PermissionError("capability fields do not match the v0.1 schema")
        elif version in ("0.2", "1.0"):
            if set(payload) != CAPABILITY_FIELDS_V2:
                raise PermissionError("capability fields do not match the v0.2 schema")
            self._validate_v2_fields(payload)
        else:
            raise PermissionError("unsupported capability version")
        if payload.get("type") != "kinegrant:PhysicalActionCapability":
            raise PermissionError("wrong capability type")
        if payload.get("issuer") != capability.get("kid"):
            raise PermissionError("capability issuer does not match signing key")
        if payload.get("issuer") not in self.trusted_issuers:
            raise PermissionError("untrusted capability issuer")
        if payload.get("request_digest") != request.digest:
            raise PermissionError("capability does not authorize this request")

        if version == "0.1":
            if payload.get("agent") != request.agent:
                raise PermissionError("capability agent mismatch")
            if payload.get("target") != request.target:
                raise PermissionError("capability target mismatch")
            if payload.get("action") != request.action:
                raise PermissionError("capability action mismatch")
            if payload.get("purpose") != request.purpose:
                raise PermissionError("capability purpose mismatch")
        else:
            delegate_agent = payload.get("delegate_agent")
            if delegate_agent is None:
                if payload.get("agent") != request.agent:
                    raise PermissionError("capability agent mismatch")
            elif request.agent != delegate_agent:
                raise PermissionError("capability delegate agent mismatch")
            if not fnmatchcase(request.target, payload.get("target", "")):
                raise PermissionError("capability target scope mismatch")
            if request.action not in payload.get("actions", []):
                raise PermissionError("capability action scope mismatch")
            if request.purpose not in payload.get("purposes", []):
                raise PermissionError("capability purpose scope mismatch")

        if parent_capability is not None:
            if version != "0.2":
                raise PermissionError("only v0.2 capabilities can present a parent")
            from .attenuation import verify_attenuation

            try:
                parent_payload = verify_envelope(parent_capability)
            except (TypeError, ValueError) as exc:
                raise PermissionError("parent capability is not a valid signed envelope") from exc
            if not verify_attenuation(payload, parent_payload):
                raise PermissionError("capability is not a valid attenuation of its parent")

        current = now or utc_now()
        if current.tzinfo is None:
            raise PermissionError("verification time must include a timezone")
        try:
            issued_at = parse_time(payload["issued_at"])
            not_before = parse_time(payload["not_before"])
            expires_at = parse_time(payload["expires_at"])
        except (KeyError, TypeError, ValueError) as exc:
            raise PermissionError("invalid capability time window") from exc
        if not_before < issued_at or expires_at <= not_before:
            raise PermissionError("invalid capability time window")
        if expires_at - not_before > timedelta(seconds=300):
            raise PermissionError("capability lifetime exceeds protocol maximum")
        if current < not_before:
            raise PermissionError("capability is not active yet")
        if current >= expires_at:
            raise PermissionError("capability has expired")

        nonce = payload.get("nonce")
        if not isinstance(nonce, str) or len(nonce) < 20:
            raise PermissionError("capability nonce is invalid")
        if not isinstance(payload.get("matched_policy_ids"), list) or not payload["matched_policy_ids"]:
            raise PermissionError("capability has no matching policy")
        if any(not isinstance(item, str) or not item for item in payload["matched_policy_ids"]):
            raise PermissionError("capability matching policies are invalid")
        if not isinstance(payload.get("obligations"), list) or any(
            item not in KNOWN_OBLIGATIONS for item in payload.get("obligations", [])
        ):
            raise PermissionError("capability obligations are invalid")
        if _DIGEST_RE.fullmatch(str(payload.get("policy_digest", ""))) is None:
            raise PermissionError("capability policy digest is invalid")

        capability_id = payload.get("capability_id")
        if not isinstance(capability_id, str):
            raise PermissionError("capability has no identifier")
        if self.revocation_list is not None and (
            self.revocation_list.is_revoked(capability_id)
            or self.revocation_list.is_revoked(payload.get("root_capability_id"))
        ):
            raise PermissionError("capability revoked")
        unsigned_id_body = dict(payload)
        del unsigned_id_body["capability_id"]
        unsigned_id_body.pop("root_capability_id", None)
        if capability_id != content_id("kinegrant:cap", unsigned_id_body):
            raise PermissionError("capability identifier is inconsistent")
        if not self.replay_store.consume_once(capability_id, expires_at):
            raise PermissionError("capability replay detected")
        return VerifiedCapability(dict(payload), current)

    @staticmethod
    def _validate_v2_fields(payload: dict[str, Any]) -> None:
        parent_id = payload.get("parent_capability_id")
        if parent_id is not None and (not isinstance(parent_id, str) or not parent_id):
            raise PermissionError("v0.2 capability parent id must be a string or null")
        constraints = payload.get("constraints")
        if not isinstance(constraints, dict):
            raise PermissionError("v0.2 capability constraints must be an object")
        unknown = set(constraints) - {"max_force_newtons", "max_velocity_mps", "allowed_zones"}
        if unknown:
            raise PermissionError(f"unknown capability constraints: {', '.join(sorted(unknown))}")
        for name in ("max_force_newtons", "max_velocity_mps"):
            value = constraints.get(name)
            if value is not None and (
                not isinstance(value, (int, float))
                or isinstance(value, bool)
                or value < 0
            ):
                raise PermissionError(f"capability {name} must be a non-negative number")
        zones = constraints.get("allowed_zones")
        if zones is not None and (
            not isinstance(zones, list)
            or not zones
            or any(not isinstance(zone, str) or not zone for zone in zones)
        ):
            raise PermissionError("capability allowed_zones must be a non-empty list")
        tier = payload.get("approval_tier")
        if not isinstance(tier, int) or isinstance(tier, bool) or not 0 <= tier <= 2:
            raise PermissionError("capability approval_tier must be an integer between 0 and 2")
        delegation_allowed = payload.get("delegation_allowed")
        if not isinstance(delegation_allowed, bool):
            raise PermissionError("capability delegation_allowed must be a boolean")
        max_depth = payload.get("max_delegation_depth")
        if not isinstance(max_depth, int) or isinstance(max_depth, bool) or not 0 <= max_depth <= 3:
            raise PermissionError("capability max_delegation_depth must be an integer between 0 and 3")
        depth = payload.get("delegation_depth")
        if not isinstance(depth, int) or isinstance(depth, bool) or not 0 <= depth <= 3:
            raise PermissionError("capability delegation_depth must be an integer between 0 and 3")
        if delegation_allowed and depth > max_depth:
            raise PermissionError("capability delegation depth exceeds its limit")
        delegate_agent = payload.get("delegate_agent")
        if delegate_agent is not None and (
            not isinstance(delegate_agent, str) or not delegate_agent
        ):
            raise PermissionError("capability delegate_agent must be a non-empty string or null")
        root_id = payload.get("root_capability_id")
        if not isinstance(root_id, str) or not root_id:
            raise PermissionError("capability root_capability_id must be a non-empty string")
        allowlist = payload.get("delegate_allowlist")
        if allowlist is not None and (
            not isinstance(allowlist, list)
            or any(not isinstance(item, str) or not item for item in allowlist)
        ):
            raise PermissionError("capability delegate_allowlist must be a list or null")
        actions = payload.get("actions")
        purposes = payload.get("purposes")
        if not isinstance(actions, list) or not actions or any(
            not isinstance(action, str) or not action for action in actions
        ):
            raise PermissionError("v0.2 capability actions must be a non-empty list")
        if not isinstance(purposes, list) or not purposes or any(
            not isinstance(purpose, str) or not purpose for purpose in purposes
        ):
            raise PermissionError("v0.2 capability purposes must be a non-empty list")
