from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Iterable, Mapping

from .canonical import content_id, digest
from .crypto import Ed25519KeyPair, verify_envelope
from .gate import VerifiedCapability
from .models import ActionRequest, isoformat, parse_time, utc_now

_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_KNOWN_OBLIGATIONS = {"emitActionReceipt"}
_OBLIGATION_STATUSES = {"satisfied", "pending", "failed"}
_RECEIPT_VERSIONS = {"0.1", "1.0"}


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
        request: ActionRequest | None = None,
        obligation_results: list[dict[str, Any]] | None = None,
        failure_reason: str | None = None,
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
        obligation_results = _validate_obligation_results(obligation_results)
        if failure_reason is not None and (
            not isinstance(failure_reason, str) or not failure_reason.strip()
        ):
            raise ValueError("failure_reason must be a non-empty string when provided")
        extended = obligation_results is not None or failure_reason is not None
        started = started_at or utc_now()
        finished = finished_at or utc_now()
        if finished < started:
            raise ValueError("finished_at cannot precede started_at")
        not_before = parse_time(capability_payload["not_before"])
        expires_at = parse_time(capability_payload["expires_at"])
        if started < not_before or started >= expires_at:
            raise ValueError("action must start while the capability is active")

        action = capability_payload.get("action")
        purpose = capability_payload.get("purpose")
        if action is None or purpose is None:
            # v0.2 capabilities carry scope lists; the exact executed values
            # must come from the verified request.
            if request is None:
                raise ValueError("v0.2 capabilities require the ActionRequest for a receipt")
            action = request.action
            purpose = request.purpose

        previous_hash = digest(self._entries[-1]) if self._entries else None
        body = {
            "type": "kinegrant:PhysicalActionReceipt",
            "version": "1.0" if extended else "0.1",
            "executor": self.executor_key.kid,
            "capability_id": capability_id,
            "request_digest": capability_payload["request_digest"],
            "agent": capability_payload["agent"],
            "target": capability_payload["target"],
            "action": action,
            "purpose": purpose,
            "result": result,
            "started_at": isoformat(started),
            "finished_at": isoformat(finished),
            "evidence_hash": evidence_hash,
            "previous_receipt_hash": previous_hash,
        }
        # v0.2 capabilities carry authorization context that must survive into
        # the receipt so an auditor can see the exact constraints and approval
        # tier under which the action was authorized. v0.1 receipts stay
        # byte-identical to earlier releases.
        for field in ("approval_tier", "constraints", "parent_capability_id"):
            if field in capability_payload:
                body[field] = capability_payload[field]
        if obligation_results is not None:
            body["obligation_results"] = obligation_results
        if failure_reason is not None:
            body["failure_reason"] = failure_reason
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
        if payload.get("version") not in _RECEIPT_VERSIONS:
            return False
        if payload.get("version") == "1.0" and not _validate_v10_receipt(payload):
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


def _validate_obligation_results(
    obligation_results: list[dict[str, Any]] | None,
) -> list[dict[str, Any]] | None:
    """Validate optional obligation execution results; return None when absent."""
    if obligation_results is None:
        return None
    if not isinstance(obligation_results, list) or not obligation_results:
        raise ValueError("obligation_results must be a non-empty list when provided")
    for item in obligation_results:
        if not isinstance(item, dict):
            raise ValueError("obligation_results entries must be objects")
        unknown = set(item) - {"obligation", "status", "failure_reason"}
        if unknown:
            raise ValueError(
                f"unsupported obligation result fields: {', '.join(sorted(unknown))}"
            )
        obligation = item.get("obligation")
        if obligation not in _KNOWN_OBLIGATIONS:
            raise ValueError(f"unknown obligation in result: {obligation!r}")
        status = item.get("status")
        if status not in _OBLIGATION_STATUSES:
            raise ValueError(f"invalid obligation status: {status!r}")
        failure_reason = item.get("failure_reason")
        if failure_reason is not None and (
            not isinstance(failure_reason, str) or not failure_reason.strip()
        ):
            raise ValueError("obligation failure_reason must be a non-empty string or null")
        if status == "failed" and (
            not isinstance(failure_reason, str) or not failure_reason.strip()
        ):
            raise ValueError("a failed obligation requires a non-empty failure_reason")
    return obligation_results


def _validate_v10_receipt(payload: Mapping[str, Any]) -> bool:
    """Validate additive receipt 1.0 fields; return False on any violation."""
    has_obligations = "obligation_results" in payload
    has_failure_reason = "failure_reason" in payload
    if not (has_obligations or has_failure_reason):
        return False
    if has_failure_reason:
        reason = payload["failure_reason"]
        if not isinstance(reason, str) or not reason.strip():
            return False
    if has_obligations:
        try:
            _validate_obligation_results(payload["obligation_results"])
        except ValueError:
            return False
    return True
