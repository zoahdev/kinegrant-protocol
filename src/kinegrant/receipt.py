from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Iterable, Mapping

from .canonical import content_id, digest
from .crypto import Ed25519KeyPair, verify_envelope
from .gate import VerifiedCapability
from .models import isoformat, parse_time, utc_now

_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class ReceiptLog:
    def __init__(self, executor_key: Ed25519KeyPair) -> None:
        self.executor_key = executor_key
        self._entries: list[dict[str, Any]] = []

    @property
    def entries(self) -> tuple[dict[str, Any], ...]:
        return tuple(self._entries)

    def append(
        self,
        capability_payload: VerifiedCapability,
        *,
        result: str,
        evidence_hash: str | None = None,
        started_at: datetime | None = None,
        finished_at: datetime | None = None,
    ) -> dict[str, Any]:
        if not isinstance(capability_payload, VerifiedCapability):
            raise TypeError("receipt input must be a capability consumed by ActionGate")
        if result not in {"succeeded", "failed", "aborted"}:
            raise ValueError("invalid action result")
        capability_id = capability_payload["capability_id"]
        if any(entry["payload"].get("capability_id") == capability_id for entry in self._entries):
            raise ValueError("a terminal receipt already exists for this capability")
        if evidence_hash is not None and _SHA256_RE.fullmatch(evidence_hash) is None:
            raise ValueError("evidence_hash must be sha256 followed by 64 lowercase hex characters")
        started = started_at or utc_now()
        finished = finished_at or utc_now()
        if finished < started:
            raise ValueError("finished_at cannot precede started_at")
        not_before = parse_time(capability_payload["not_before"])
        expires_at = parse_time(capability_payload["expires_at"])
        if started < not_before or started >= expires_at:
            raise ValueError("action must start while the capability is active")

        previous_hash = digest(self._entries[-1]) if self._entries else None
        body = {
            "type": "kinegrant:PhysicalActionReceipt",
            "version": "0.1",
            "executor": self.executor_key.kid,
            "capability_id": capability_id,
            "request_digest": capability_payload["request_digest"],
            "agent": capability_payload["agent"],
            "target": capability_payload["target"],
            "action": capability_payload["action"],
            "purpose": capability_payload["purpose"],
            "result": result,
            "started_at": isoformat(started),
            "finished_at": isoformat(finished),
            "evidence_hash": evidence_hash,
            "previous_receipt_hash": previous_hash,
        }
        body["receipt_id"] = content_id("kinegrant:receipt", body)
        envelope = self.executor_key.sign_envelope(body)
        self._entries.append(envelope)
        return envelope


def verify_receipt_chain(
    entries: Iterable[Mapping[str, Any]],
    *,
    trusted_executors: set[str] | None = None,
    expected_capability_ids: set[str] | None = None,
) -> bool:
    """Verify receipt integrity and ordering.

    Passing ``trusted_executors`` additionally authenticates each executor against
    a caller-controlled trust store. Without it, this function proves only that the
    embedded signing keys produced an internally consistent chain.
    """
    previous: Mapping[str, Any] | None = None
    seen_capabilities: set[str] = set()
    for envelope in entries:
        try:
            payload = verify_envelope(envelope)
        except (TypeError, ValueError):
            return False
        if payload.get("type") != "kinegrant:PhysicalActionReceipt":
            return False
        if payload.get("version") != "0.1":
            return False
        if payload.get("executor") != envelope.get("kid"):
            return False
        if trusted_executors is not None and payload.get("executor") not in trusted_executors:
            return False
        capability_id = payload.get("capability_id")
        if not isinstance(capability_id, str) or capability_id in seen_capabilities:
            return False
        if expected_capability_ids is not None and capability_id not in expected_capability_ids:
            return False
        seen_capabilities.add(capability_id)
        receipt_id = payload.get("receipt_id")
        if not isinstance(receipt_id, str):
            return False
        unsigned_id_body = dict(payload)
        del unsigned_id_body["receipt_id"]
        if receipt_id != content_id("kinegrant:receipt", unsigned_id_body):
            return False
        expected = digest(previous) if previous is not None else None
        if payload.get("previous_receipt_hash") != expected:
            return False
        previous = envelope
    return True
