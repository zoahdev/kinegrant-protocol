from __future__ import annotations

from collections.abc import Mapping
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime
import re
import secrets
import sqlite3
from pathlib import Path
from threading import Lock
import time
from typing import Any, Callable, Protocol

from ..canonical import content_id
from ..crypto import Ed25519KeyPair, verify_envelope
from ..gate import InMemoryReplayStore, ReplayStore, VerifiedCapability
from ..models import ActionRequest, parse_time, utc_now


PROFILE = "kgp-esp32c3-paper-barrier/0.1"
CHALLENGE_TYPE = "kinegrant:ExperimentalDeviceChallenge"
COMMAND_TYPE = "kinegrant:ExperimentalDeviceCommand"
ACK_TYPE = "kinegrant:ExperimentalDeviceAck"
MAX_CHALLENGE_AGE_MS = 10_000

_B64URL_RE = re.compile(r"^[A-Za-z0-9_-]{20,}$")
_CAPABILITY_ID_RE = re.compile(r"^kinegrant:cap:[0-9a-f]{64}$")
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_COMMAND_ID_RE = re.compile(r"^kinegrant:device-command:[0-9a-f]{64}$")

CHALLENGE_FIELDS = {
    "type",
    "profile",
    "device_id",
    "boot_counter",
    "challenge_nonce",
    "next_sequence",
    "max_age_ms",
}

COMMAND_FIELDS = {
    "type",
    "profile",
    "executor",
    "device_id",
    "capability_id",
    "request_digest",
    "action",
    "parameters",
    "boot_counter",
    "challenge_nonce",
    "sequence",
    "command_id",
}

ACK_FIELDS = {
    "type",
    "profile",
    "device",
    "device_id",
    "command_id",
    "capability_id",
    "boot_counter",
    "sequence",
    "result",
    "actuator_count",
    "ack_id",
}

ENVELOPE_FIELDS = {"alg", "kid", "payload", "signature"}


@dataclass(frozen=True)
class DeviceChallenge:
    device_id: str
    boot_counter: int
    challenge_nonce: str
    next_sequence: int
    max_age_ms: int = MAX_CHALLENGE_AGE_MS

    def __post_init__(self) -> None:
        if not isinstance(self.device_id, str) or not self.device_id.strip():
            raise ValueError("device_id must be a non-empty string")
        if not isinstance(self.boot_counter, int) or isinstance(self.boot_counter, bool) or self.boot_counter < 1:
            raise ValueError("boot_counter must be a positive integer")
        if not isinstance(self.challenge_nonce, str) or _B64URL_RE.fullmatch(self.challenge_nonce) is None:
            raise ValueError("challenge_nonce must be canonical base64url with at least 20 characters")
        if not isinstance(self.next_sequence, int) or isinstance(self.next_sequence, bool) or self.next_sequence < 1:
            raise ValueError("next_sequence must be a positive integer")
        if self.max_age_ms != MAX_CHALLENGE_AGE_MS:
            raise ValueError("unsupported challenge lifetime")

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": CHALLENGE_TYPE,
            "profile": PROFILE,
            "device_id": self.device_id,
            "boot_counter": self.boot_counter,
            "challenge_nonce": self.challenge_nonce,
            "next_sequence": self.next_sequence,
            "max_age_ms": self.max_age_ms,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "DeviceChallenge":
        if not isinstance(value, Mapping) or set(value) != CHALLENGE_FIELDS:
            raise ValueError("device challenge fields do not match the proof profile")
        if value.get("type") != CHALLENGE_TYPE or value.get("profile") != PROFILE:
            raise ValueError("unsupported device challenge profile")
        return cls(
            device_id=value["device_id"],
            boot_counter=value["boot_counter"],
            challenge_nonce=value["challenge_nonce"],
            next_sequence=value["next_sequence"],
            max_age_ms=value["max_age_ms"],
        )


class DeviceStateStore(Protocol):
    def begin_boot(self, device_id: str) -> int: ...

    def next_sequence(self, device_id: str, boot_counter: int) -> int: ...

    def actuator_count(self, device_id: str) -> int: ...

    def consume_command(
        self,
        device_id: str,
        boot_counter: int,
        sequence: int,
        command_id: str,
    ) -> int | None: ...


class InMemoryDeviceStateStore:
    """Process-local proof state. Use SQLite to test restart persistence."""

    def __init__(self) -> None:
        self._state: dict[str, tuple[int, int, int]] = {}
        self._consumed: set[tuple[str, str]] = set()
        self._lock = Lock()

    def begin_boot(self, device_id: str) -> int:
        with self._lock:
            old_boot, _, count = self._state.get(device_id, (0, 0, 0))
            boot_counter = old_boot + 1
            self._state[device_id] = (boot_counter, 0, count)
            return boot_counter

    def next_sequence(self, device_id: str, boot_counter: int) -> int:
        with self._lock:
            current_boot, last_sequence, _ = self._state[device_id]
            if current_boot != boot_counter:
                raise RuntimeError("device boot state changed")
            return last_sequence + 1

    def actuator_count(self, device_id: str) -> int:
        with self._lock:
            return self._state[device_id][2]

    def consume_command(
        self,
        device_id: str,
        boot_counter: int,
        sequence: int,
        command_id: str,
    ) -> int | None:
        with self._lock:
            current_boot, last_sequence, count = self._state[device_id]
            key = (device_id, command_id)
            if current_boot != boot_counter or sequence != last_sequence + 1 or key in self._consumed:
                return None
            count += 1
            self._consumed.add(key)
            self._state[device_id] = (current_boot, sequence, count)
            return count


class SQLiteDeviceStateStore:
    """Crash-persistent proof state with an atomic consume-before-actuate update."""

    def __init__(self, path: str | Path) -> None:
        self.path = str(path)
        if self.path == ":memory:":
            raise ValueError("SQLiteDeviceStateStore requires a filesystem path")
        with closing(sqlite3.connect(self.path)) as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute(
                "CREATE TABLE IF NOT EXISTS device_state ("
                "device_id TEXT PRIMARY KEY, boot_counter INTEGER NOT NULL, "
                "last_sequence INTEGER NOT NULL, actuator_count INTEGER NOT NULL)"
            )
            connection.execute(
                "CREATE TABLE IF NOT EXISTS consumed_device_commands ("
                "device_id TEXT NOT NULL, command_id TEXT NOT NULL, "
                "PRIMARY KEY(device_id, command_id))"
            )
            connection.commit()

    def begin_boot(self, device_id: str) -> int:
        with closing(sqlite3.connect(self.path, isolation_level=None, timeout=5)) as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    "SELECT boot_counter, actuator_count FROM device_state WHERE device_id = ?",
                    (device_id,),
                ).fetchone()
                boot_counter = (row[0] if row else 0) + 1
                actuator_count = row[1] if row else 0
                connection.execute(
                    "INSERT INTO device_state(device_id, boot_counter, last_sequence, actuator_count) "
                    "VALUES (?, ?, 0, ?) ON CONFLICT(device_id) DO UPDATE SET "
                    "boot_counter=excluded.boot_counter, last_sequence=0",
                    (device_id, boot_counter, actuator_count),
                )
                connection.execute("COMMIT")
                return boot_counter
            except Exception:
                if connection.in_transaction:
                    connection.rollback()
                raise

    def next_sequence(self, device_id: str, boot_counter: int) -> int:
        with closing(sqlite3.connect(self.path, timeout=5)) as connection:
            row = connection.execute(
                "SELECT boot_counter, last_sequence FROM device_state WHERE device_id = ?",
                (device_id,),
            ).fetchone()
        if row is None or row[0] != boot_counter:
            raise RuntimeError("device boot state changed")
        return row[1] + 1

    def actuator_count(self, device_id: str) -> int:
        with closing(sqlite3.connect(self.path, timeout=5)) as connection:
            row = connection.execute(
                "SELECT actuator_count FROM device_state WHERE device_id = ?",
                (device_id,),
            ).fetchone()
        if row is None:
            raise RuntimeError("device state is not initialized")
        return row[0]

    def consume_command(
        self,
        device_id: str,
        boot_counter: int,
        sequence: int,
        command_id: str,
    ) -> int | None:
        with closing(sqlite3.connect(self.path, isolation_level=None, timeout=5)) as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    "SELECT boot_counter, last_sequence, actuator_count FROM device_state "
                    "WHERE device_id = ?",
                    (device_id,),
                ).fetchone()
                if row is None or row[0] != boot_counter or sequence != row[1] + 1:
                    connection.execute("ROLLBACK")
                    return None
                cursor = connection.execute(
                    "INSERT OR IGNORE INTO consumed_device_commands(device_id, command_id) VALUES (?, ?)",
                    (device_id, command_id),
                )
                if cursor.rowcount != 1:
                    connection.execute("ROLLBACK")
                    return None
                count = row[2] + 1
                connection.execute(
                    "UPDATE device_state SET last_sequence = ?, actuator_count = ? WHERE device_id = ?",
                    (sequence, count, device_id),
                )
                connection.execute("COMMIT")
                return count
            except Exception:
                if connection.in_transaction:
                    connection.rollback()
                raise


class DeviceCommandIssuer:
    """Bind a gate-consumed KGP request to one live device challenge."""

    def __init__(
        self,
        executor_key: Ed25519KeyPair,
        *,
        issuance_store: ReplayStore | None = None,
        now: Callable[[], datetime] = utc_now,
    ) -> None:
        self.executor_key = executor_key
        self.issuance_store = issuance_store or InMemoryReplayStore()
        self.now = now

    def issue(
        self,
        capability: VerifiedCapability,
        request: ActionRequest,
        challenge: DeviceChallenge,
    ) -> dict[str, Any]:
        if not isinstance(capability, VerifiedCapability):
            raise TypeError("device commands require a capability consumed by ActionGate")
        if not isinstance(challenge, DeviceChallenge):
            raise TypeError("device command requires a validated DeviceChallenge")
        if capability["request_digest"] != request.digest:
            raise PermissionError("verified capability does not bind this request")
        for field in ("agent", "target", "action", "purpose"):
            if capability[field] != getattr(request, field):
                raise PermissionError(f"verified capability {field} mismatch")
        if request.target != challenge.device_id:
            raise PermissionError("request target does not match challenged device")
        parameters = request.context.get("device_parameters")
        if not isinstance(parameters, dict):
            raise PermissionError("request context must contain device_parameters")

        current = self.now()
        if current.tzinfo is None:
            raise PermissionError("device-command issuance time must include a timezone")
        try:
            expires_at = parse_time(capability["expires_at"])
        except (KeyError, TypeError, ValueError) as exc:
            raise PermissionError("verified capability has an invalid expiry") from exc
        if current >= expires_at:
            raise PermissionError("verified capability expired before device-command issuance")
        capability_id = capability["capability_id"]
        if not self.issuance_store.consume_once(capability_id, expires_at):
            raise PermissionError("verified capability already produced a device command")

        body: dict[str, Any] = {
            "type": COMMAND_TYPE,
            "profile": PROFILE,
            "executor": self.executor_key.kid,
            "device_id": challenge.device_id,
            "capability_id": capability_id,
            "request_digest": request.digest,
            "action": request.action,
            "parameters": dict(parameters),
            "boot_counter": challenge.boot_counter,
            "challenge_nonce": challenge.challenge_nonce,
            "sequence": challenge.next_sequence,
        }
        body["command_id"] = content_id("kinegrant:device-command", body)
        return self.executor_key.sign_envelope(body)


class SimulatedPaperBarrierDevice:
    """Fail-closed model of the firmware boundary; it never controls real hardware."""

    def __init__(
        self,
        *,
        device_id: str,
        device_key: Ed25519KeyPair,
        trusted_executors: set[str],
        state_store: DeviceStateStore | None = None,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        if not isinstance(device_id, str) or not device_id.strip():
            raise ValueError("device_id must be a non-empty string")
        self.device_id = device_id
        self.device_key = device_key
        self.trusted_executors = set(trusted_executors)
        self.state_store = state_store or InMemoryDeviceStateStore()
        self.monotonic = monotonic
        self.boot_counter = self.state_store.begin_boot(device_id)
        self._active_challenge: tuple[DeviceChallenge, float] | None = None
        self._lock = Lock()

    @property
    def actuator_count(self) -> int:
        return self.state_store.actuator_count(self.device_id)

    def challenge(self) -> DeviceChallenge:
        with self._lock:
            challenge = DeviceChallenge(
                device_id=self.device_id,
                boot_counter=self.boot_counter,
                challenge_nonce=secrets.token_urlsafe(18),
                next_sequence=self.state_store.next_sequence(self.device_id, self.boot_counter),
            )
            self._active_challenge = (challenge, self.monotonic())
            return challenge

    def execute(self, command: Mapping[str, Any]) -> dict[str, Any]:
        if not isinstance(command, Mapping) or set(command) != ENVELOPE_FIELDS:
            raise PermissionError("device command envelope fields do not match the proof profile")
        try:
            payload = verify_envelope(command)
        except (TypeError, ValueError) as exc:
            raise PermissionError("invalid device command signature") from exc
        if set(payload) != COMMAND_FIELDS:
            raise PermissionError("device command fields do not match the proof profile")
        if payload.get("type") != COMMAND_TYPE or payload.get("profile") != PROFILE:
            raise PermissionError("unsupported device command profile")
        if payload.get("executor") != command.get("kid"):
            raise PermissionError("device command executor does not match signing key")
        if payload.get("executor") not in self.trusted_executors:
            raise PermissionError("untrusted device command executor")
        if payload.get("device_id") != self.device_id:
            raise PermissionError("device command target mismatch")
        if _CAPABILITY_ID_RE.fullmatch(str(payload.get("capability_id", ""))) is None:
            raise PermissionError("invalid capability identifier")
        if _DIGEST_RE.fullmatch(str(payload.get("request_digest", ""))) is None:
            raise PermissionError("invalid request digest")
        if payload.get("action") != "move_paper_barrier":
            raise PermissionError("unsupported physical proof action")
        for name in ("boot_counter", "sequence"):
            value = payload.get(name)
            if not isinstance(value, int) or isinstance(value, bool) or value < 1:
                raise PermissionError(f"device command {name} must be a positive integer")
        parameters = payload.get("parameters")
        if not isinstance(parameters, dict) or set(parameters) != {"position"}:
            raise PermissionError("unsupported physical proof parameters")
        if parameters["position"] not in {"open", "closed"}:
            raise PermissionError("paper barrier position must be open or closed")

        command_id = payload.get("command_id")
        if _COMMAND_ID_RE.fullmatch(str(command_id or "")) is None:
            raise PermissionError("invalid device command identifier")
        unsigned_id_body = dict(payload)
        del unsigned_id_body["command_id"]
        if command_id != content_id("kinegrant:device-command", unsigned_id_body):
            raise PermissionError("device command identifier is inconsistent")

        with self._lock:
            if self._active_challenge is None:
                raise PermissionError("no active device challenge")
            challenge, issued_at = self._active_challenge
            self._active_challenge = None
            elapsed = self.monotonic() - issued_at
            if elapsed < 0 or elapsed * 1000 >= challenge.max_age_ms:
                raise PermissionError("device challenge expired")
            expected = {
                "device_id": challenge.device_id,
                "boot_counter": challenge.boot_counter,
                "challenge_nonce": challenge.challenge_nonce,
                "sequence": challenge.next_sequence,
            }
            if any(payload.get(name) != value for name, value in expected.items()):
                raise PermissionError("device command does not match the active challenge")
            actuator_count = self.state_store.consume_command(
                self.device_id,
                self.boot_counter,
                challenge.next_sequence,
                command_id,
            )
            if actuator_count is None:
                raise PermissionError("device command replay or sequence conflict")

        ack_body: dict[str, Any] = {
            "type": ACK_TYPE,
            "profile": PROFILE,
            "device": self.device_key.kid,
            "device_id": self.device_id,
            "command_id": command_id,
            "capability_id": payload["capability_id"],
            "boot_counter": self.boot_counter,
            "sequence": payload["sequence"],
            "result": "succeeded",
            "actuator_count": actuator_count,
        }
        ack_body["ack_id"] = content_id("kinegrant:device-ack", ack_body)
        return self.device_key.sign_envelope(ack_body)


def verify_device_ack(
    ack: Mapping[str, Any],
    *,
    trusted_devices: set[str],
    expected_command_ids: set[str] | None = None,
    expected_device_ids: set[str] | None = None,
    expected_capability_ids: set[str] | None = None,
) -> bool:
    if not isinstance(ack, Mapping) or set(ack) != ENVELOPE_FIELDS:
        return False
    try:
        payload = verify_envelope(ack)
    except (TypeError, ValueError):
        return False
    if set(payload) != ACK_FIELDS:
        return False
    if payload.get("type") != ACK_TYPE or payload.get("profile") != PROFILE:
        return False
    if payload.get("device") != ack.get("kid") or payload.get("device") not in trusted_devices:
        return False
    if not isinstance(payload.get("device_id"), str) or not payload["device_id"].strip():
        return False
    if expected_device_ids is not None and payload["device_id"] not in expected_device_ids:
        return False
    command_id = payload.get("command_id")
    if _COMMAND_ID_RE.fullmatch(str(command_id or "")) is None:
        return False
    if expected_command_ids is not None and command_id not in expected_command_ids:
        return False
    capability_id = payload.get("capability_id")
    if _CAPABILITY_ID_RE.fullmatch(str(capability_id or "")) is None:
        return False
    if expected_capability_ids is not None and capability_id not in expected_capability_ids:
        return False
    if payload.get("result") not in {"succeeded", "failed"}:
        return False
    for name in ("boot_counter", "sequence", "actuator_count"):
        value = payload.get(name)
        if not isinstance(value, int) or isinstance(value, bool) or value < 1:
            return False
    ack_id = payload.get("ack_id")
    unsigned_id_body = dict(payload)
    del unsigned_id_body["ack_id"]
    return ack_id == content_id("kinegrant:device-ack", unsigned_id_body)
