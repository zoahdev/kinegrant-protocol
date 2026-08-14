"""Gatekeeper: one-call composition of the full action boundary (v0.6 draft).

Deployments compose the same steps in the same order:

1. sequence check (forbidden combinations against the action journal);
2. gate verification and atomic one-time consumption;
3. actuator execution;
4. signed receipt append (with optional obligation results);
5. obligation compliance check against the full receipt chain;
6. action-journal record on success.

:class:`Gatekeeper` runs this whole boundary in one call and returns a
machine-readable outcome. Every step is fail-closed: a sequence violation,
gate denial, actuator failure, receipt failure, or compliance failure denies
the outcome and explains why. The actuator runs only after the gate consumes
the capability.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping

from .compliance import ObligationCompliance, ObligationComplianceVerdict
from .gate import ActionGate, VerifiedCapability
from .models import ActionRequest, utc_now
from .receipt import ReceiptLog
from .sequence import ActionJournal, JournalEntry, SequencePolicy


@dataclass(frozen=True)
class GatekeeperOutcome:
    allowed: bool
    stage: str
    reason: str | None = None
    capability_id: str | None = None
    receipt_id: str | None = None
    obligation_compliant: bool | None = None
    journal_recorded: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "stage": self.stage,
            "reason": self.reason,
            "capability_id": self.capability_id,
            "receipt_id": self.receipt_id,
            "obligation_compliant": self.obligation_compliant,
            "journal_recorded": self.journal_recorded,
        }


class Gatekeeper:
    """Compose sequence policy, action gate, receipts, and compliance."""

    def __init__(
        self,
        *,
        gate: ActionGate,
        sequence: SequencePolicy,
        journal: ActionJournal,
        receipt_log: ReceiptLog,
        compliance: ObligationCompliance | None = None,
        trusted_executors: set[str] | None = None,
    ) -> None:
        self.gate = gate
        self.sequence = sequence
        self.journal = journal
        self.receipt_log = receipt_log
        self.compliance = compliance or ObligationCompliance()
        self.trusted_executors = set(trusted_executors or ())
        if not self.trusted_executors:
            self.trusted_executors = {receipt_log.executor_key.kid}
        if not self.trusted_executors:
            raise ValueError("trusted_executors must not be empty")

    def execute(
        self,
        capability: Mapping[str, Any],
        request: ActionRequest,
        actuator: Callable[[VerifiedCapability], Any],
        *,
        now: Any = None,
        parent_capability: Mapping[str, Any] | None = None,
        result: str = "succeeded",
        evidence_hash: str | None = None,
        obligation_results: list[dict[str, Any]] | None = None,
        failure_reason: str | None = None,
    ) -> GatekeeperOutcome:
        current = now if now is not None else utc_now()

        sequence_verdict = self.sequence.evaluate(request, self.journal, now=current)
        if not sequence_verdict.allowed:
            return GatekeeperOutcome(
                False,
                "sequence",
                f"forbidden_combination:{sequence_verdict.reason}",
            )

        try:
            verified = self.gate.authorize(
                capability,
                request,
                now=current,
                parent_capability=parent_capability,
            )
        except (PermissionError, ValueError) as exc:
            return GatekeeperOutcome(False, "gate", f"{type(exc).__name__}: {exc}")

        try:
            actuator(verified)
            actuator_ok = True
        except Exception as exc:  # actuator failure becomes a failed receipt
            actuator_ok = False
            failure_reason = failure_reason or f"actuator failure: {type(exc).__name__}: {exc}"

        try:
            receipt = self.receipt_log.append(
                verified,
                result=result if actuator_ok else "failed",
                evidence_hash=evidence_hash,
                request=request,
                obligation_results=obligation_results if actuator_ok else None,
                failure_reason=None if actuator_ok else failure_reason,
            )
        except (TypeError, ValueError) as exc:
            return GatekeeperOutcome(
                False,
                "receipt",
                f"{type(exc).__name__}: {exc}",
                capability_id=verified.get("capability_id"),
            )

        verdict = self.compliance.evaluate(
            capability,
            self.receipt_log.entries,
            trusted_executors=self.trusted_executors,
        )
        compliant = verdict.compliant and actuator_ok
        reason = None
        if not actuator_ok:
            stage = "actuator"
            reason = failure_reason
        elif not verdict.compliant:
            stage = "obligation"
            reason = verdict.reason or "obligation not satisfied"
        else:
            stage = "complete"

        journal_recorded = False
        if compliant:
            self.journal.record(request.action, request.target, at=current)
            journal_recorded = True

        return GatekeeperOutcome(
            allowed=compliant,
            stage=stage,
            reason=reason,
            capability_id=verified.get("capability_id"),
            receipt_id=receipt["payload"].get("receipt_id"),
            obligation_compliant=bool(verdict.compliant),
            journal_recorded=journal_recorded,
        )
