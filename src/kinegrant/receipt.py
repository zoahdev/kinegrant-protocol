from __future__ import annotations

from datetime import datetime
from typing import Any, Iterable, Mapping

from .canonical import content_id, digest
from .crypto import Ed25519KeyPair, verify_envelope
from .models import isoformat, utc_now


class ReceiptLog:
    def __init__(self, executor_key: Ed25519KeyPair) -> None:
        self.executor_key = executor_key
        self._entries: list[dict[str, Any]] = []

    @property
    def entries(self) -> tuple[dict[str, Any], ...]:
        return tuple(self._entries)

    def append(
        self,
        capability_payload: Mapping[str, Any],
        *,
        result: str,
        evidence_hash: str | None = None,
        started_at: datetime | None = None,
        finished_at: datetime | None = None,
    ) -> dict[str, Any]:
        if result not in {"succeeded", "failed", "aborted"}:
            raise ValueError("invalid action result")
        started = started_at or utc_now()
        finished = finished_at or utc_now()
        if finished < started:
            raise ValueError("finished_at cannot precede started_at")

        previous_hash = digest(self._entries[-1]) if self._entries else None
        body = {
            "type": "kinegrant:PhysicalActionReceipt",
            "version": "0.1",
            "executor": self.executor_key.kid,
            "capability_id": capability_payload["capability_id"],
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


def verify_receipt_chain(entries: Iterable[Mapping[str, Any]]) -> bool:
    previous: Mapping[str, Any] | None = None
    for envelope in entries:
        payload = verify_envelope(envelope)
        if payload.get("type") != "kinegrant:PhysicalActionReceipt":
            return False
        if payload.get("executor") != envelope.get("kid"):
            return False
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
