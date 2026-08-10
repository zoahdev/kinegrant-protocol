from __future__ import annotations

import argparse
import copy
import json
import tempfile
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from typing import Any, Callable
from uuid import uuid4

from . import __version__
from .capability import CapabilityIssuer
from .crypto import Ed25519KeyPair
from .gate import ActionGate, SQLiteReplayStore, VerifiedCapability
from .models import ActionRequest, PolicyRule, parse_time
from .policy import PolicyEngine
from .receipt import ReceiptLog, verify_receipt_chain

CaseResult = dict[str, Any]


class _SandboxActuator:
    """Count calls that cross the verified-capability boundary."""

    def __init__(self) -> None:
        self._calls = 0
        self._lock = Lock()

    @property
    def calls(self) -> int:
        with self._lock:
            return self._calls

    def execute(self, capability: VerifiedCapability) -> None:
        if not isinstance(capability, VerifiedCapability):
            raise TypeError("actuator requires a gate-verified capability")
        with self._lock:
            self._calls += 1


def _authorize_and_act(
    gate: ActionGate,
    capability: dict[str, Any],
    request: ActionRequest,
    actuator: _SandboxActuator,
    *,
    now: datetime | None = None,
) -> None:
    actuator.execute(gate.authorize(capability, request, now=now))


def _fixture(label: str) -> tuple[ActionRequest, Ed25519KeyPair, dict[str, Any]]:
    request = ActionRequest(
        f"urn:kinegrant:mpt:request:{label}",
        "urn:kinegrant:mpt:agent:1",
        "urn:kinegrant:mpt:target:1",
        "open",
        "permission-test",
    )
    rule = PolicyRule(
        f"urn:kinegrant:mpt:policy:{label}",
        "urn:kinegrant:mpt:policy-issuer:trusted",
        request.target,
        "allow",
        (request.action,),
        subjects=(request.agent,),
        purposes=(request.purpose,),
        obligations=("emitActionReceipt",),
    )
    decision = PolicyEngine(
        [rule], trusted_policy_issuers={rule.issuer}
    ).evaluate(request)
    authority = Ed25519KeyPair.generate()
    capability = CapabilityIssuer(authority).issue(request, decision, ttl_seconds=10)
    return request, authority, capability


def _rejected(operation: Callable[[], object]) -> tuple[bool, str]:
    try:
        operation()
    except (PermissionError, TypeError, ValueError) as exc:
        return True, f"{type(exc).__name__}: {exc}"
    return False, "accepted"


def _result(
    case_id: str,
    name: str,
    expected: str,
    observed: str,
    passed: bool,
    evidence: dict[str, Any],
) -> CaseResult:
    return {
        "id": case_id,
        "name": name,
        "expected": expected,
        "observed": observed,
        "passed": passed,
        "evidence": evidence,
    }


def _no_grant() -> CaseResult:
    request, authority, _ = _fixture("no-grant")
    actuator = _SandboxActuator()
    rejected, error = _rejected(
        lambda: _authorize_and_act(
            ActionGate(trusted_issuers={authority.kid}), {}, request, actuator
        )
    )
    actions = actuator.calls
    return _result(
        "MPT-001",
        "No capability means no action",
        "DENY with zero actuator calls",
        f"{'DENY' if rejected else 'ALLOW'} with {actions} actuator calls",
        rejected and actions == 0,
        {"rejection": error, "actuator_calls": actions},
    )


def _valid_once() -> CaseResult:
    request, authority, capability = _fixture("valid-once")
    actuator = _SandboxActuator()
    gate = ActionGate(trusted_issuers={authority.kid})
    verified = gate.authorize(capability, request)
    actuator.execute(verified)
    actions = actuator.calls
    passed = verified["request_digest"] == request.digest and actions == 1
    return _result(
        "MPT-002",
        "Valid capability executes exactly once",
        "ALLOW with one actuator call",
        f"{'ALLOW' if passed else 'ERROR'} with {actions} actuator call",
        passed,
        {"capability_id": verified["capability_id"], "actuator_calls": actions},
    )


def _replay() -> CaseResult:
    request, authority, capability = _fixture("replay")
    gate = ActionGate(trusted_issuers={authority.kid})
    actuator = _SandboxActuator()
    _authorize_and_act(gate, capability, request, actuator)
    rejected, error = _rejected(
        lambda: _authorize_and_act(gate, capability, request, actuator)
    )
    actions = actuator.calls
    return _result(
        "MPT-003",
        "Consumed capability cannot be replayed",
        "First ALLOW, second DENY, one actuator call total",
        f"First ALLOW, second {'DENY' if rejected else 'ALLOW'}, {actions} actuator call total",
        rejected and actions == 1,
        {"second_attempt": error, "actuator_calls": actions},
    )


def _modified_binding() -> CaseResult:
    request, authority, capability = _fixture("modified-binding")
    gate = ActionGate(trusted_issuers={authority.kid})
    actuator = _SandboxActuator()
    changes = {
        "agent": "urn:kinegrant:mpt:agent:attacker",
        "target": "urn:kinegrant:mpt:target:other",
        "action": "close",
        "purpose": "model-training",
    }
    attempts: dict[str, Any] = {}
    for field, value in changes.items():
        changed = replace(
            request,
            request_id=f"{request.request_id}:{field}",
            **{field: value},
        )
        rejected, error = _rejected(
            lambda changed=changed: _authorize_and_act(
                gate, capability, changed, actuator
            )
        )
        attempts[field] = {"rejected": rejected, "reason": error}
    rejected_count = sum(item["rejected"] for item in attempts.values())
    return _result(
        "MPT-004",
        "Capability binding rejects modified request fields",
        "DENY modified agent, target, action, and purpose",
        f"DENY {rejected_count} of 4 modified requests",
        rejected_count == 4 and actuator.calls == 0,
        {"attempts": attempts, "actuator_calls": actuator.calls},
    )


def _wrong_issuer() -> CaseResult:
    request, _, capability = _fixture("wrong-issuer")
    different_authority = Ed25519KeyPair.generate()
    actuator = _SandboxActuator()
    rejected, error = _rejected(
        lambda: _authorize_and_act(
            ActionGate(trusted_issuers={different_authority.kid}),
            capability,
            request,
            actuator,
        )
    )
    return _result(
        "MPT-005",
        "Untrusted capability issuer is rejected",
        "DENY with zero actuator calls",
        f"{'DENY' if rejected else 'ALLOW'} with zero actuator calls",
        rejected and actuator.calls == 0,
        {"rejection": error, "actuator_calls": actuator.calls},
    )


def _expired() -> CaseResult:
    request, authority, capability = _fixture("expired")
    expiry = parse_time(capability["payload"]["expires_at"])
    actuator = _SandboxActuator()
    rejected, error = _rejected(
        lambda: _authorize_and_act(
            ActionGate(trusted_issuers={authority.kid}),
            capability,
            request,
            actuator,
            now=expiry,
        )
    )
    return _result(
        "MPT-006",
        "Expired capability is rejected",
        "DENY at expires_at with zero actuator calls",
        f"{'DENY' if rejected else 'ALLOW'} at expires_at",
        rejected and actuator.calls == 0,
        {
            "verification_time": capability["payload"]["expires_at"],
            "rejection": error,
            "actuator_calls": actuator.calls,
        },
    )


def _concurrent() -> CaseResult:
    request, authority, capability = _fixture("concurrent")
    gate = ActionGate(trusted_issuers={authority.kid})
    actuator = _SandboxActuator()

    def attempt(_: int) -> bool:
        try:
            _authorize_and_act(gate, capability, request, actuator)
            return True
        except PermissionError:
            return False

    attempt_count = 64
    with ThreadPoolExecutor(max_workers=16) as pool:
        outcomes = list(pool.map(attempt, range(attempt_count)))
    winners = sum(outcomes)
    return _result(
        "MPT-007",
        "Concurrent consumption has one winner",
        "Exactly one ALLOW across 64 concurrent attempts",
        f"{winners} ALLOW and {attempt_count - winners} DENY",
        winners == 1 and actuator.calls == 1,
        {
            "attempts": attempt_count,
            "allowed": winners,
            "denied": attempt_count - winners,
            "actuator_calls": actuator.calls,
        },
    )


def _persistent_replay() -> CaseResult:
    request, authority, capability = _fixture("persistent-replay")
    actuator = _SandboxActuator()
    with tempfile.TemporaryDirectory() as directory:
        database = Path(directory) / "replay.sqlite3"
        first = ActionGate(
            trusted_issuers={authority.kid}, replay_store=SQLiteReplayStore(database)
        )
        _authorize_and_act(first, capability, request, actuator)
        second = ActionGate(
            trusted_issuers={authority.kid}, replay_store=SQLiteReplayStore(database)
        )
        rejected, error = _rejected(
            lambda: _authorize_and_act(second, capability, request, actuator)
        )
    return _result(
        "MPT-008",
        "Replay remains rejected after gate restart",
        "First process ALLOW, restarted gate DENY",
        f"First gate ALLOW, restarted gate {'DENY' if rejected else 'ALLOW'}",
        rejected and actuator.calls == 1,
        {
            "persistent_store": "SQLiteReplayStore",
            "restart_rejection": error,
            "actuator_calls": actuator.calls,
        },
    )


def _receipt_trust() -> CaseResult:
    request, authority, capability = _fixture("receipt-trust")
    verified = ActionGate(trusted_issuers={authority.kid}).authorize(capability, request)
    executor = Ed25519KeyPair.generate()
    receipt = ReceiptLog(executor).append(verified, result="succeeded")
    trusted_valid = verify_receipt_chain(
        [receipt],
        trusted_executors={executor.kid},
        expected_capability_ids={verified["capability_id"]},
    )
    tampered = copy.deepcopy(receipt)
    tampered["payload"]["result"] = "failed"
    tamper_rejected = not verify_receipt_chain(
        [tampered], trusted_executors={executor.kid}
    )
    untrusted_rejected = not verify_receipt_chain([receipt], trusted_executors=set())
    passed = trusted_valid and tamper_rejected and untrusted_rejected
    return _result(
        "MPT-009",
        "Receipt trust and integrity are enforced",
        "Trusted receipt valid; tampered and untrusted receipts invalid",
        (
            f"trusted={'VALID' if trusted_valid else 'INVALID'}, "
            f"tampered={'REJECTED' if tamper_rejected else 'ACCEPTED'}, "
            f"untrusted={'REJECTED' if untrusted_rejected else 'ACCEPTED'}"
        ),
        passed,
        {
            "receipt_id": receipt["payload"]["receipt_id"],
            "trusted_valid": trusted_valid,
            "tamper_rejected": tamper_rejected,
            "untrusted_executor_rejected": untrusted_rejected,
        },
    )


CASES: tuple[tuple[str, Callable[[], CaseResult]], ...] = (
    ("MPT-001", _no_grant),
    ("MPT-002", _valid_once),
    ("MPT-003", _replay),
    ("MPT-004", _modified_binding),
    ("MPT-005", _wrong_issuer),
    ("MPT-006", _expired),
    ("MPT-007", _concurrent),
    ("MPT-008", _persistent_replay),
    ("MPT-009", _receipt_trust),
)


def run_machine_permission_test() -> dict[str, Any]:
    results: list[CaseResult] = []
    for case_id, operation in CASES:
        try:
            results.append(operation())
        except Exception as exc:  # Preserve machine-readable evidence on unexpected failures.
            results.append(
                _result(
                    case_id,
                    "Unexpected test failure",
                    "PASS",
                    f"ERROR: {type(exc).__name__}: {exc}",
                    False,
                    {"exception_type": type(exc).__name__},
                )
            )
    passed = sum(case["passed"] for case in results)
    failed = len(results) - passed
    return {
        "schema_version": "0.1",
        "run_id": f"urn:kinegrant:mpt:run:{uuid4()}",
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "protocol": "KGP-001 Experimental Open Draft 0.1",
        "reference_implementation": __version__,
        "overall_result": "PASS" if failed == 0 else "FAIL",
        "summary": {"total": len(results), "passed": passed, "failed": failed},
        "cases": results,
        "limitations": [
            "This software test does not prove physical-world actuation or functional safety.",
            "Receipts prove signed executor attestations, not independent physical truth.",
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the KineGrant Machine Permission Test")
    parser.add_argument("--output", type=Path, help="Write the JSON evidence to this path")
    args = parser.parse_args(argv)
    evidence = run_machine_permission_test()
    encoded = json.dumps(evidence, indent=2, sort_keys=True)
    if args.output:
        args.output.write_text(encoded + "\n", encoding="utf-8")
    print(encoded)
    return 0 if evidence["overall_result"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
