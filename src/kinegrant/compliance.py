"""Obligation compliance checking (v0.6 draft).

A capability can carry obligations (e.g. ``emitActionReceipt``). This module
checks, after execution, that every obligation was actually fulfilled in a
way an auditor can verify: for ``emitActionReceipt`` the executor must provide
a signed receipt for the exact capability, and a receipt 1.0 must report the
obligation as ``satisfied``.

The check is fail-closed: an unknown obligation, an invalid receipt chain, a
missing receipt, a receipt for a different capability, or an executor outside
the caller-supplied trust set all fail compliance.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from .crypto import verify_envelope
from .receipt import KNOWN_OBLIGATIONS, verify_receipt_chain

_SATISFIED = "satisfied"
_FAILED = "failed"


@dataclass(frozen=True)
class ObligationResult:
    obligation: str
    status: str
    failure_reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "obligation": self.obligation,
            "status": self.status,
            "failure_reason": self.failure_reason,
        }


@dataclass(frozen=True)
class ObligationComplianceVerdict:
    compliant: bool
    results: tuple[ObligationResult, ...] = ()
    reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "compliant": self.compliant,
            "reason": self.reason,
            "results": [result.to_dict() for result in self.results],
        }


class ObligationCompliance:
    """Fail-closed checker that a capability's obligations were fulfilled."""

    def evaluate(
        self,
        capability: Mapping[str, Any],
        receipts: Iterable[Mapping[str, Any]],
        *,
        trusted_executors: set[str] | None = None,
    ) -> ObligationComplianceVerdict:
        if trusted_executors is None:
            raise ValueError("trusted_executors is required for obligation compliance")
        if not trusted_executors:
            raise ValueError("trusted_executors must not be empty")
        try:
            payload = verify_envelope(capability)
        except (TypeError, ValueError) as exc:
            return ObligationComplianceVerdict(
                False,
                reason=f"invalid capability envelope: {exc}",
            )
        obligations = payload.get("obligations")
        if not isinstance(obligations, list) or not obligations:
            return ObligationComplianceVerdict(True)

        entry_list = list(receipts)
        if not verify_receipt_chain(entry_list, trusted_executors=trusted_executors):
            results = tuple(
                ObligationResult(obligation, _FAILED, "receipt chain is invalid")
                for obligation in obligations
            )
            return ObligationComplianceVerdict(False, results, "receipt chain is invalid")

        capability_id = payload.get("capability_id")
        receipt_payload: Mapping[str, Any] | None = None
        for envelope in entry_list:
            try:
                candidate = verify_envelope(envelope)
            except (TypeError, ValueError):
                continue
            if candidate.get("capability_id") == capability_id:
                receipt_payload = candidate
                break

        results: list[ObligationResult] = []
        for obligation in obligations:
            if not isinstance(obligation, str) or obligation not in KNOWN_OBLIGATIONS:
                results.append(
                    ObligationResult(str(obligation), _FAILED, "unknown obligation")
                )
                continue
            if receipt_payload is None:
                results.append(
                    ObligationResult(
                        obligation,
                        _FAILED,
                        "missing receipt for capability",
                    )
                )
                continue
            obligation_results = receipt_payload.get("obligation_results")
            if obligation_results is None:
                # A 0.1 receipt is itself the fulfillment of emitActionReceipt.
                results.append(ObligationResult(obligation, _SATISFIED))
                continue
            matched: Mapping[str, Any] | None = None
            if isinstance(obligation_results, list):
                for item in obligation_results:
                    if isinstance(item, Mapping) and item.get("obligation") == obligation:
                        matched = item
                        break
            if matched is None:
                results.append(
                    ObligationResult(
                        obligation,
                        _FAILED,
                        "obligation result missing from receipt",
                    )
                )
            elif matched.get("status") == _SATISFIED:
                results.append(ObligationResult(obligation, _SATISFIED))
            elif matched.get("status") == "pending":
                results.append(
                    ObligationResult(
                        obligation,
                        _FAILED,
                        matched.get("failure_reason") or "obligation pending",
                    )
                )
            else:
                results.append(
                    ObligationResult(
                        obligation,
                        _FAILED,
                        matched.get("failure_reason") or "obligation failed",
                    )
                )
        result_tuple = tuple(results)
        compliant = all(result.status == _SATISFIED for result in result_tuple)
        reason = None if compliant else next(
            (result.failure_reason for result in result_tuple if result.status != _SATISFIED),
            "obligation not satisfied",
        )
        return ObligationComplianceVerdict(compliant, result_tuple, reason)
