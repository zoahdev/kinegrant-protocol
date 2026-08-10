from __future__ import annotations

from collections.abc import Iterator, Mapping as MappingABC
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
import sqlite3
import re
from threading import Lock
from typing import Any, Mapping, Protocol

from .canonical import content_id
from .crypto import verify_envelope
from .models import ActionRequest, parse_time, utc_now


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
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class ActionGate:
    """Fail-closed verifier intended to sit immediately before an actuator call."""

    def __init__(
        self,
        *,
        trusted_issuers: set[str] | None = None,
        replay_store: ReplayStore | None = None,
    ) -> None:
        # An omitted trust store means trust nobody, not trust everybody.
        self.trusted_issuers = set(trusted_issuers or ())
        self.replay_store = replay_store or InMemoryReplayStore()

    def authorize(
        self,
        capability: Mapping[str, Any],
        request: ActionRequest,
        *,
        now: datetime | None = None,
    ) -> VerifiedCapability:
        payload = verify_envelope(capability)
        if set(payload) != CAPABILITY_FIELDS:
            raise PermissionError("capability fields do not match the v0.1 schema")
        if payload.get("type") != "kinegrant:PhysicalActionCapability":
            raise PermissionError("wrong capability type")
        if payload.get("version") != "0.1":
            raise PermissionError("unsupported capability version")
        if payload.get("issuer") != capability.get("kid"):
            raise PermissionError("capability issuer does not match signing key")
        if payload.get("issuer") not in self.trusted_issuers:
            raise PermissionError("untrusted capability issuer")
        if payload.get("request_digest") != request.digest:
            raise PermissionError("capability does not authorize this request")

        for field in ("agent", "target", "action", "purpose"):
            if payload.get(field) != getattr(request, field):
                raise PermissionError(f"capability {field} mismatch")

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
            item not in {"emitActionReceipt"} for item in payload.get("obligations", [])
        ):
            raise PermissionError("capability obligations are invalid")
        if _DIGEST_RE.fullmatch(str(payload.get("policy_digest", ""))) is None:
            raise PermissionError("capability policy digest is invalid")

        capability_id = payload.get("capability_id")
        if not isinstance(capability_id, str):
            raise PermissionError("capability has no identifier")
        unsigned_id_body = dict(payload)
        del unsigned_id_body["capability_id"]
        if capability_id != content_id("kinegrant:cap", unsigned_id_body):
            raise PermissionError("capability identifier is inconsistent")
        if not self.replay_store.consume_once(capability_id, expires_at):
            raise PermissionError("capability replay detected")
        return VerifiedCapability(dict(payload), current)
