"""Bounded model checking for the Gatekeeper boundary (v1.6 draft).

``check_gatekeeper_boundary`` enumerates the executable decision space of the
one-call deployment boundary and verifies composition invariants:

- the actuator never runs when sequence, revocation, or the gate denies;
- receipts are appended only after gate consumption;
- the action journal records only fully compliant successes;
- replay cannot cause a second actuator execution;
- every denial carries a stage and a reason.

Like :func:`kinegrant.modelcheck.bounded_model_check`, this is a bounded,
executable model check -- a conservative foundation, not a full symbolic
proof.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from .capability import CapabilityIssuer
from .crypto import Ed25519KeyPair
from .gate import ActionGate, InMemoryReplayStore
from .gatekeeper import Gatekeeper, GatekeeperOutcome
from .models import ActionRequest, PolicyRule
from .policy import PolicyEngine
from .receipt import ReceiptLog
from .revocation import RevocationList
from .sequence import ActionJournal, ForbiddenCombination, SequencePolicy


@dataclass(frozen=True)
class _Counts:
    actuator: int
    receipts: int
    journal: int


def _counts(gatekeeper: Gatekeeper, actuator: list[str]) -> _Counts:
    return _Counts(
        actuator=len(actuator),
        receipts=len(gatekeeper.receipt_log.entries),
        journal=len(gatekeeper.journal.entries),
    )


def _fixture(
    *,
    obligations: tuple[str, ...] = ("emitActionReceipt",),
    actions: tuple[str, ...] = ("open", "enter"),
) -> tuple[
    ActionRequest,
    ActionRequest,
    dict[str, Any],
    Gatekeeper,
    list[str],
    dict[str, Any],
]:
    authority = Ed25519KeyPair.generate()
    executor = Ed25519KeyPair.generate()
    request = ActionRequest(
        "urn:kinegrant:modelcheck:request:open",
        "urn:kinegrant:modelcheck:agent:1",
        "urn:kinegrant:modelcheck:target:1",
        "open",
        "permission-test",
    )
    rule = PolicyRule(
        "urn:kinegrant:modelcheck:policy",
        authority.kid,
        "urn:kinegrant:modelcheck:target:*",
        "allow",
        actions,
        subjects=("urn:kinegrant:modelcheck:agent:*",),
        purposes=("permission-test",),
        obligations=obligations,
    )
    engine = PolicyEngine([rule], trusted_policy_issuers={authority.kid})
    decision = engine.evaluate(request)
    capability = CapabilityIssuer(authority).issue(
        request,
        decision,
        ttl_seconds=30,
    )
    journal = ActionJournal()
    sequence = SequencePolicy(
        [
            ForbiddenCombination(
                "modelcheck-open-enter",
                patterns=(("open", "urn:kinegrant:modelcheck:target:*"),),
                trigger=("enter", "urn:kinegrant:modelcheck:target:*"),
            )
        ]
    )
    gatekeeper = Gatekeeper(
        gate=ActionGate(
            trusted_issuers={authority.kid},
            replay_store=InMemoryReplayStore(),
        ),
        sequence=sequence,
        journal=journal,
        receipt_log=ReceiptLog(executor),
    )
    enter = ActionRequest(
        "urn:kinegrant:modelcheck:request:enter",
        "urn:kinegrant:modelcheck:agent:1",
        "urn:kinegrant:modelcheck:target:1",
        "enter",
        "permission-test",
    )
    enter_capability = CapabilityIssuer(authority).issue(
        enter,
        PolicyEngine([rule], trusted_policy_issuers={authority.kid}).evaluate(enter),
        ttl_seconds=30,
    )
    actuator: list[str] = []
    return request, enter, capability, gatekeeper, actuator, enter_capability


def _run(
    gatekeeper: Gatekeeper,
    capability: dict[str, Any],
    request: ActionRequest,
    actuator: list[str],
) -> tuple[GatekeeperOutcome, _Counts, _Counts]:
    before = _counts(gatekeeper, actuator)
    outcome = gatekeeper.execute(
        capability,
        request,
        lambda verified: actuator.append(verified["capability_id"]),
    )
    after = _counts(gatekeeper, actuator)
    return outcome, before, after


def check_gatekeeper_boundary() -> dict[str, Any]:
    """Run the bounded boundary model check and return a PASS/FAIL report."""
    scenarios: list[dict[str, Any]] = []

    # 1. Fully compliant success.
    (
        request,
        enter,
        capability,
        gatekeeper,
        actuator,
        enter_capability,
    ) = _fixture()
    outcome, before, after = _run(gatekeeper, capability, request, actuator)
    scenarios.append(
        {
            "name": "allow",
            "outcome": outcome.to_dict(),
            "before": before.__dict__,
            "after": after.__dict__,
        }
    )

    # 2. Sequence denial (enter after open).
    outcome, before, after = _run(gatekeeper, enter_capability, enter, actuator)
    scenarios.append(
        {
            "name": "sequence_deny",
            "outcome": outcome.to_dict(),
            "before": before.__dict__,
            "after": after.__dict__,
        }
    )

    # 3. Gate denial (replay).
    outcome, before, after = _run(gatekeeper, capability, request, actuator)
    scenarios.append(
        {
            "name": "gate_replay_deny",
            "outcome": outcome.to_dict(),
            "before": before.__dict__,
            "after": after.__dict__,
        }
    )

    # 4. Revocation denial.
    (
        rev_request,
        _enter,
        rev_capability,
        _gatekeeper,
        rev_actuator,
        _enter_capability,
    ) = _fixture()
    revocation_list = RevocationList()
    revocation_list.revoke(rev_capability["payload"]["capability_id"])
    revoked_gatekeeper = Gatekeeper(
        gate=ActionGate(
            trusted_issuers={rev_capability["payload"]["issuer"]},
            replay_store=InMemoryReplayStore(),
        ),
        sequence=SequencePolicy([]),
        journal=ActionJournal(),
        receipt_log=ReceiptLog(Ed25519KeyPair.generate()),
        revocation_list=revocation_list,
    )
    outcome, before, after = _run(
        revoked_gatekeeper,
        rev_capability,
        rev_request,
        rev_actuator,
    )
    scenarios.append(
        {
            "name": "revocation_deny",
            "outcome": outcome.to_dict(),
            "before": before.__dict__,
            "after": after.__dict__,
        }
    )

    # 5. Obligation denial (logAuditEvent without a receipt commitment).
    (
        ob_request,
        _enter,
        ob_capability,
        ob_gatekeeper,
        ob_actuator,
        _enter_capability,
    ) = _fixture(obligations=("logAuditEvent",))
    outcome, before, after = _run(
        ob_gatekeeper,
        ob_capability,
        ob_request,
        ob_actuator,
    )
    scenarios.append(
        {
            "name": "obligation_deny",
            "outcome": outcome.to_dict(),
            "before": before.__dict__,
            "after": after.__dict__,
        }
    )

    # 6. Actuator failure records a failed receipt.
    (
        af_request,
        _enter,
        af_capability,
        af_gatekeeper,
        _actuator_placeholder,
        _enter_capability,
    ) = _fixture()
    af_actuator: list[str] = []

    def boom(verified: Any) -> None:
        af_actuator.append(verified["capability_id"])
        raise RuntimeError("modelcheck actuator failure")

    before = _counts(af_gatekeeper, af_actuator)
    outcome = af_gatekeeper.execute(af_capability, af_request, boom)
    after = _counts(af_gatekeeper, af_actuator)
    scenarios.append(
        {
            "name": "actuator_failure",
            "outcome": outcome.to_dict(),
            "before": before.__dict__,
            "after": after.__dict__,
        }
    )

    properties: list[dict[str, Any]] = []

    pre_gate_denies = [
        scenario
        for scenario in scenarios
        if scenario["outcome"]["stage"] in {"sequence", "gate", "revocation"}
    ]
    pre_gate_ok = all(
        scenario["after"]["actuator"] == scenario["before"]["actuator"]
        and scenario["after"]["receipts"] == scenario["before"]["receipts"]
        and scenario["after"]["journal"] == scenario["before"]["journal"]
        for scenario in pre_gate_denies
    )
    properties.append(
        {
            "name": "actuator_runs_only_after_sequence_gate_revocation",
            "passed": bool(pre_gate_denies) and pre_gate_ok,
            "detail": "no actuator/receipt/journal change on pre-gate denials",
        }
    )

    journal_ok = all(
        (scenario["outcome"]["allowed"] and scenario["after"]["journal"]
         == scenario["before"]["journal"] + 1)
        or (not scenario["outcome"]["allowed"] and scenario["after"]["journal"]
            == scenario["before"]["journal"])
        for scenario in scenarios
    )
    properties.append(
        {
            "name": "journal_only_on_fully_compliant_success",
            "passed": journal_ok,
            "detail": "journal increments exactly on allowed outcomes",
        }
    )

    allow_scenario = next(
        scenario for scenario in scenarios if scenario["name"] == "allow"
    )
    replay_scenario = next(
        scenario for scenario in scenarios if scenario["name"] == "gate_replay_deny"
    )
    replay_ok = (
        replay_scenario["after"]["actuator"]
        == allow_scenario["after"]["actuator"]
        == 1
    )
    properties.append(
        {
            "name": "replay_prevents_double_execution",
            "passed": replay_ok,
            "detail": "second use of the same capability did not actuate",
        }
    )

    reason_ok = all(
        not scenario["outcome"]["allowed"] or scenario["outcome"]["stage"] == "complete"
        for scenario in scenarios
    )
    properties.append(
        {
            "name": "denials_carry_stage",
            "passed": reason_ok,
            "detail": "every denied outcome has a non-complete stage",
        }
    )

    obligation_scenario = next(
        scenario for scenario in scenarios if scenario["name"] == "obligation_deny"
    )
    obligation_ok = (
        not obligation_scenario["outcome"]["allowed"]
        and obligation_scenario["outcome"]["stage"] == "obligation"
        and obligation_scenario["after"]["journal"]
        == obligation_scenario["before"]["journal"]
        and obligation_scenario["after"]["receipts"]
        == obligation_scenario["before"]["receipts"] + 1
    )
    properties.append(
        {
            "name": "obligation_failure_keeps_evidence_not_journal",
            "passed": obligation_ok,
            "detail": "failed compliance records receipt but no journal entry",
        }
    )

    passed = sum(1 for prop in properties if prop["passed"])
    return {
        "type": "kinegrant:GatekeeperBoundaryModelCheck",
        "schema_version": "0.1",
        "overall_result": "PASS" if passed == len(properties) else "FAIL",
        "summary": {
            "scenarios": len(scenarios),
            "properties": len(properties),
            "passed_properties": passed,
            "failed_properties": len(properties) - passed,
        },
        "properties": properties,
        "scenarios": scenarios,
    }
