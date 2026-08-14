from __future__ import annotations

import argparse
import copy
import hashlib
import json
import platform
import re
import shutil
import subprocess
import tempfile
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from typing import Any, Callable
from uuid import uuid4

from . import __version__
from .attenuation import verify_attenuation
from .capability import CapabilityIssuer
from .compliance import ObligationCompliance
from .crypto import Ed25519KeyPair
from .distribution import RevocationDistributor
from .gate import ActionGate, SQLiteReplayStore, VerifiedCapability
from .models import ActionRequest, PolicyRule, parse_time
from .policy import PolicyEngine
from .policy_bundle import (
    PolicyAuthority,
    PolicyRegistry,
    rules_from_bundle,
    verify_policy_bundle,
)
from .receipt import ReceiptLog, verify_receipt_chain
from .revocation import (
    RevocationList,
    build_revocation_bundle,
    sign_revocation_bundle,
)
from .sequence import ActionJournal, ForbiddenCombination, SequencePolicy

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


def _independent_policy_commands() -> list[tuple[str, list[str] | None]]:
    root = Path(__file__).resolve().parents[2]
    js_cli = root / "implementations" / "kinegrant-js" / "src" / "cli.mjs"
    node = shutil.which("node") or str(
        Path(r"C:\Users\zoah\.cache\codex-runtimes\codex-primary-runtime")
        / "dependencies"
        / "node"
        / "bin"
        / "node.exe"
    )
    node_available = Path(node).is_file() and js_cli.exists()
    go_dir = root / "implementations" / "kinegrant-go"
    go_available = shutil.which("go") is not None
    return [
        ("kinegrant-js", [node, str(js_cli)] if node_available else None),
        (
            "kinegrant-go",
            ["go", "run", "./cmd/kinegrant-verify"]
            if go_available
            else None,
        ),
    ]


def _independent_policy_evidence(
    policy_id: str,
    bundle_v1: dict[str, Any],
    bundle_v2: dict[str, Any],
) -> dict[str, Any]:
    """Cross-verify policy bundles with the JS/Go verifiers when available."""
    results: dict[str, Any] = {}
    for tool, command in _independent_policy_commands():
        if command is None:
            results[tool] = "SKIP"
            continue
        try:
            with tempfile.TemporaryDirectory() as directory:
                base = Path(directory)
                v2_path = base / "bundle-v2.json"
                authorities_path = base / "authorities.json"
                bundles_path = base / "bundles.json"
                revoked_path = base / "revoked.json"
                v2_path.write_text(json.dumps(bundle_v2), encoding="utf-8")
                authorities_path.write_text(
                    json.dumps([bundle_v2["payload"]["issuer"]]),
                    encoding="utf-8",
                )
                bundles_path.write_text(
                    json.dumps([bundle_v1["payload"], bundle_v2["payload"]]),
                    encoding="utf-8",
                )
                revoked_path.write_text(
                    json.dumps([f"{policy_id}:2"]),
                    encoding="utf-8",
                )
                verify = subprocess.run(
                    [
                        *command,
                        "verify-policy-bundle",
                        str(v2_path),
                        str(authorities_path),
                        policy_id,
                    ],
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=60,
                )
                current = subprocess.run(
                    [
                        *command,
                        "current-policy-version",
                        str(bundles_path),
                    ],
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=60,
                )
                rollback = subprocess.run(
                    [
                        *command,
                        "current-policy-version",
                        str(bundles_path),
                        str(revoked_path),
                    ],
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=60,
                )
                ok = (
                    verify.returncode == 0
                    and "POLICY BUNDLE VALID" in verify.stdout
                    and current.returncode == 0
                    and json.loads(current.stdout).get("version") == 2
                    and rollback.returncode == 0
                    and json.loads(rollback.stdout).get("version") == 1
                )
                results[tool] = "PASS" if ok else "FAIL"
        except Exception:
            results[tool] = "FAIL"
    return results


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


def _physical_constraints() -> CaseResult:
    agent = "urn:kinegrant:mpt:agent:1"
    target = "urn:kinegrant:mpt:target:1"
    authority = Ed25519KeyPair.generate()
    allow = PolicyRule(
        "urn:kinegrant:mpt:policy:physical-allow",
        authority.kid,
        "urn:kinegrant:mpt:target:*",
        "allow",
        ("open",),
        subjects=(agent,),
        purposes=("permission-test",),
        constraints={"max_force_newtons": 50, "allowed_zones": ["urn:kinegrant:mpt:zone:*"]},
    )
    deny_over = PolicyRule(
        "urn:kinegrant:mpt:policy:physical-deny",
        authority.kid,
        "urn:kinegrant:mpt:target:*",
        "deny",
        ("open",),
        constraints={"max_force_newtons": 30},
    )
    engine = PolicyEngine(
        [allow, deny_over],
        trusted_policy_issuers={authority.kid},
    )

    def make_request(label: str, context: dict[str, object]) -> ActionRequest:
        return ActionRequest(
            f"urn:kinegrant:mpt:request:physical-{label}",
            agent,
            target,
            "open",
            "permission-test",
            context=context,
        )

    within = make_request("within", {"force_newtons": 20, "zone": "urn:kinegrant:mpt:zone:1"})
    over = make_request("over", {"force_newtons": 40, "zone": "urn:kinegrant:mpt:zone:1"})
    missing = make_request("missing", {})
    within_decision = engine.evaluate(within)
    over_decision = engine.evaluate(over)
    missing_decision = engine.evaluate(missing)

    actuator = _SandboxActuator()
    if within_decision.allowed:
        capability = CapabilityIssuer(authority).issue(
            within, within_decision, ttl_seconds=10
        )
        _authorize_and_act(
            ActionGate(trusted_issuers={authority.kid}),
            capability,
            within,
            actuator,
        )
    passed = (
        within_decision.allowed
        and not over_decision.allowed
        and not missing_decision.allowed
        and actuator.calls == 1
    )
    return _result(
        "MPT-010",
        "Physical constraints fail closed",
        "Within limit ALLOW; over limit and missing evidence DENY",
        (
            f"within={within_decision.reason}, over={over_decision.reason}, "
            f"missing={missing_decision.reason}, actuator_calls={actuator.calls}"
        ),
        passed,
        {
            "within_decision": within_decision.reason,
            "over_decision": over_decision.reason,
            "missing_decision": missing_decision.reason,
            "actuator_calls": actuator.calls,
        },
    )


def _attenuation() -> CaseResult:
    request, authority, _ = _fixture("attenuation")
    rule = PolicyRule(
        "urn:kinegrant:mpt:policy:attenuation",
        authority.kid,
        "urn:kinegrant:mpt:target:*",
        "allow",
        ("open", "close"),
        subjects=(request.agent,),
        purposes=(request.purpose,),
    )
    decision = PolicyEngine(
        [rule], trusted_policy_issuers={authority.kid}
    ).evaluate(request)
    issuer = CapabilityIssuer(authority)
    root = issuer.issue_scoped(
        request,
        decision,
        ttl_seconds=30,
        target="urn:kinegrant:mpt:target:*",
        actions=["open", "close"],
        purposes=["permission-test"],
    )
    child = issuer.issue_attenuated(
        root,
        target=request.target,
        actions=["open"],
        ttl_seconds=10,
        max_force_newtons=20,
    )
    gate = ActionGate(trusted_issuers={authority.kid})
    actuator = _SandboxActuator()
    try:
        verified = gate.authorize(child, request, parent_capability=root)
        actuator.execute(verified)
        child_accepted = True
    except PermissionError:
        child_accepted = False
    replay_rejected, replay_error = _rejected(
        lambda: _authorize_and_act(gate, child, request, actuator)
    )
    forged = copy.deepcopy(child)
    forged["payload"]["actions"] = ["open", "close"]
    widen_rejected, widen_error = _rejected(
        lambda: gate.authorize(forged, request, parent_capability=root)
    )
    other_root = issuer.issue_scoped(
        request,
        decision,
        ttl_seconds=30,
        target="urn:kinegrant:mpt:target:other",
        actions=["open"],
        purposes=["permission-test"],
    )
    parent_rejected, parent_error = _rejected(
        lambda: gate.authorize(child, request, parent_capability=other_root)
    )
    passed = (
        child_accepted
        and verify_attenuation(child["payload"], root["payload"])
        and replay_rejected
        and widen_rejected
        and parent_rejected
        and actuator.calls == 1
    )
    return _result(
        "MPT-011",
        "Scoped attenuation narrows and is parent-verified",
        "Child ALLOW once; replay, widening, and wrong parent DENY",
        (
            f"child={'ALLOW' if child_accepted else 'DENY'}, "
            f"replay={'DENY' if replay_rejected else 'ALLOW'}, "
            f"widen={'DENY' if widen_rejected else 'ALLOW'}, "
            f"wrong_parent={'DENY' if parent_rejected else 'ALLOW'}, "
            f"actuator_calls={actuator.calls}"
        ),
        passed,
        {
            "child_accepted": child_accepted,
            "attenuation_valid": verify_attenuation(child["payload"], root["payload"]),
            "replay_rejected": replay_rejected,
            "replay_error": replay_error,
            "widen_rejected": widen_rejected,
            "widen_error": widen_error,
            "parent_rejected": parent_rejected,
            "parent_error": parent_error,
            "actuator_calls": actuator.calls,
        },
    )


def _delegation() -> CaseResult:
    request, authority, _ = _fixture("delegation")
    rule = PolicyRule(
        "urn:kinegrant:mpt:policy:delegation",
        authority.kid,
        "urn:kinegrant:mpt:target:*",
        "allow",
        ("open",),
        subjects=(request.agent,),
        purposes=(request.purpose,),
    )
    decision = PolicyEngine(
        [rule], trusted_policy_issuers={authority.kid}
    ).evaluate(request)
    issuer = CapabilityIssuer(authority)
    root = issuer.issue_scoped(
        request,
        decision,
        ttl_seconds=30,
        target="urn:kinegrant:mpt:target:*",
        actions=["open"],
        purposes=["permission-test"],
        delegation_allowed=True,
        max_delegation_depth=1,
    )
    delegate_request = replace(
        request,
        request_id="urn:kinegrant:mpt:request:delegate",
        agent="urn:kinegrant:mpt:agent:2",
    )
    child = issuer.issue_attenuated(
        root,
        target=request.target,
        delegate_agent=delegate_request.agent,
        delegate_request=delegate_request,
    )
    gate = ActionGate(trusted_issuers={authority.kid})
    actuator = _SandboxActuator()
    try:
        verified = gate.authorize(child, delegate_request)
        actuator.execute(verified)
        delegate_allowed = True
    except PermissionError:
        delegate_allowed = False
    principal_rejected, principal_error = _rejected(
        lambda: _authorize_and_act(gate, child, request, actuator)
    )
    passed = (
        delegate_allowed
        and verify_attenuation(child["payload"], root["payload"])
        and principal_rejected
        and actuator.calls == 1
    )
    return _result(
        "MPT-012",
        "Cross-agent delegation binds the delegate request",
        "Delegate ALLOW once; principal agent DENY",
        (
            f"delegate={'ALLOW' if delegate_allowed else 'DENY'}, "
            f"principal={'DENY' if principal_rejected else 'ALLOW'}, "
            f"actuator_calls={actuator.calls}"
        ),
        passed,
        {
            "delegate_allowed": delegate_allowed,
            "principal_rejected": principal_rejected,
            "principal_error": principal_error,
            "actuator_calls": actuator.calls,
        },
    )


def _approval_tiers() -> CaseResult:
    request, authority, _ = _fixture("approval")
    rule = PolicyRule(
        "urn:kinegrant:mpt:policy:approval",
        authority.kid,
        request.target,
        "allow",
        (request.action,),
        subjects=(request.agent,),
        purposes=(request.purpose,),
        constraints={"min_approval_tier": 2},
    )
    decision = PolicyEngine(
        [rule], trusted_policy_issuers={authority.kid}
    ).evaluate(request)
    capability = CapabilityIssuer(authority).issue_scoped(
        request,
        decision,
        ttl_seconds=10,
        approval_tier=decision.required_approval_tier,
    )
    verified = ActionGate(trusted_issuers={authority.kid}).authorize(
        capability, request
    )
    executor = Ed25519KeyPair.generate()
    receipt = ReceiptLog(executor).append(
        verified, result="succeeded", request=request
    )
    chain_valid = verify_receipt_chain(
        [receipt],
        trusted_executors={executor.kid},
        expected_capability_ids={verified["capability_id"]},
    )
    passed = (
        decision.allowed
        and decision.required_approval_tier == 2
        and capability["payload"]["approval_tier"] == 2
        and receipt["payload"]["approval_tier"] == 2
        and chain_valid
    )
    return _result(
        "MPT-013",
        "Approval tiers propagate from policy to receipt",
        "Decision, capability, and receipt all carry tier 2",
        (
            f"decision_tier={decision.required_approval_tier}, "
            f"capability_tier={capability['payload']['approval_tier']}, "
            f"receipt_tier={receipt['payload']['approval_tier']}, "
            f"chain={'VALID' if chain_valid else 'INVALID'}"
        ),
        passed,
        {
            "decision_tier": decision.required_approval_tier,
            "capability_tier": capability["payload"]["approval_tier"],
            "receipt_tier": receipt["payload"]["approval_tier"],
            "receipt_chain_valid": chain_valid,
        },
    )


def _forbidden_combination() -> CaseResult:
    target = "urn:kinegrant:mpt:target:1"
    journal = ActionJournal()
    journal.record("record", target)
    journal.record("open", target)
    combination = ForbiddenCombination(
        "mpt-record-open-train",
        (("record", target), ("open", target)),
        trigger=("train_on_data", "*"),
    )
    policy = SequencePolicy([combination])
    train = ActionRequest(
        "urn:kinegrant:mpt:request:forbidden-train",
        "urn:kinegrant:mpt:agent:1",
        target,
        "train_on_data",
        "permission-test",
    )
    touch = ActionRequest(
        "urn:kinegrant:mpt:request:allowed-touch",
        "urn:kinegrant:mpt:agent:1",
        target,
        "touch",
        "permission-test",
    )
    train_verdict = policy.evaluate(train, journal)
    touch_verdict = policy.evaluate(touch, journal)
    passed = (
        not train_verdict.allowed
        and train_verdict.reason == "forbidden_combination"
        and touch_verdict.allowed
    )
    return _result(
        "MPT-014",
        "Forbidden combinations deny matching requests",
        "train_on_data DENY after record+open; unrelated action ALLOW",
        (
            f"train={train_verdict.reason}, "
            f"touch={touch_verdict.reason}, "
            f"matched={list(train_verdict.matched_combination_ids)}"
        ),
        passed,
        {
            "train_verdict": train_verdict.to_dict(),
            "touch_verdict": touch_verdict.to_dict(),
        },
    )


def _receipt_obligation_results() -> CaseResult:
    request, authority, capability = _fixture("mpt-015")
    verified = ActionGate(trusted_issuers={authority.kid}).authorize(
        capability,
        request,
    )
    executor = Ed25519KeyPair.generate()
    receipt = ReceiptLog(executor).append(
        verified,
        result="succeeded",
        obligation_results=[
            {"obligation": "emitActionReceipt", "status": "satisfied"}
        ],
    )
    chain_ok = verify_receipt_chain(
        [receipt],
        trusted_executors={executor.kid},
    )
    version = receipt["payload"]["version"]
    status = receipt["payload"]["obligation_results"][0]["status"]
    passed = chain_ok and version == "1.0" and status == "satisfied"
    return _result(
        "MPT-015",
        "Receipt 1.0 records obligation satisfaction",
        "RECEIPT 1.0 with satisfied obligation and valid chain",
        f"version={version}, status={status}, chain_valid={chain_ok}",
        passed,
        {
            "receipt_version": version,
            "obligation_status": status,
            "chain_valid": chain_ok,
        },
    )


def _obligation_evasion() -> CaseResult:
    label = "mpt-016"
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
        obligations=("logAuditEvent",),
    )
    decision = PolicyEngine(
        [rule],
        trusted_policy_issuers={rule.issuer},
    ).evaluate(request)
    authority = Ed25519KeyPair.generate()
    capability = CapabilityIssuer(authority).issue(
        request,
        decision,
        ttl_seconds=10,
    )
    verified = ActionGate(trusted_issuers={authority.kid}).authorize(
        capability,
        request,
    )
    executor = Ed25519KeyPair.generate()
    plain_receipt = ReceiptLog(executor).append(
        verified,
        result="succeeded",
    )
    verdict = ObligationCompliance().evaluate(
        capability,
        [plain_receipt],
        trusted_executors={executor.kid},
    )
    detected = not verdict.compliant and "audit-log commitment" in (
        verdict.reason or ""
    )
    return _result(
        "MPT-016",
        "Obligation compliance detects suppressed commitment",
        "NON-COMPLIANT with audit-log commitment missing",
        f"{'COMPLIANT' if verdict.compliant else 'NON-COMPLIANT'} "
        f"({verdict.reason})",
        detected,
        {
            "receipt_version": plain_receipt["payload"]["version"],
            "compliant": verdict.compliant,
            "reason": verdict.reason,
        },
    )


def _revocation_distribution() -> CaseResult:
    authority = Ed25519KeyPair.generate()
    capability_id = "kinegrant:cap:" + "f" * 64
    revocation_list = RevocationList()
    revocation_list.revoke(capability_id, reason="mpt revocation")
    bundle = sign_revocation_bundle(
        build_revocation_bundle(revocation_list, issuer=authority.kid),
        authority,
    )
    gate_a = RevocationList()
    gate_b = RevocationList()
    report = RevocationDistributor(
        trusted_authorities={authority.kid}
    ).distribute(
        bundle,
        {"gate-a": gate_a, "gate-b": gate_b},
    )
    passed = (
        report["overall_result"] == "PASS"
        and report["summary"]["added_total"] == 2
        and gate_a.is_revoked(capability_id)
        and gate_b.is_revoked(capability_id)
    )
    return _result(
        "MPT-017",
        "Fleet revocation distribution applies to all gates",
        "PASS fleet report with both gates revoked",
        f"{report['overall_result']} "
        f"added={report['summary']['added_total']}",
        passed,
        {
            "bundle_id": report["bundle_id"],
            "added_total": report["summary"]["added_total"],
            "gate_a_revoked": gate_a.is_revoked(capability_id),
            "gate_b_revoked": gate_b.is_revoked(capability_id),
        },
    )


def _policy_bundle_enforced() -> CaseResult:
    authority = PolicyAuthority(Ed25519KeyPair.generate())
    policy_id = "urn:kinegrant:mpt:policy:bundle-018"
    rules = [
        PolicyRule(
            policy_id,
            authority.kid,
            "urn:kinegrant:mpt:target:1",
            "allow",
            ("open",),
            subjects=("urn:kinegrant:mpt:agent:1",),
            purposes=("permission-test",),
        )
    ]
    bundle = authority.publish(policy_id, rules, ttl_seconds=3600)
    bundle_v2 = authority.publish(
        policy_id,
        [
            PolicyRule(
                policy_id,
                authority.kid,
                "urn:kinegrant:mpt:target:1",
                "allow",
                ("open",),
                purposes=("permission-test", "maintenance"),
            )
        ],
        ttl_seconds=3600,
    )
    bundle_rules = rules_from_bundle(
        bundle,
        trusted_authorities={authority.kid},
        expected_policy_id=policy_id,
    )
    request = ActionRequest(
        "urn:kinegrant:mpt:request:bundle-018",
        "urn:kinegrant:mpt:agent:1",
        "urn:kinegrant:mpt:target:1",
        "open",
        "permission-test",
    )
    decision = PolicyEngine(
        bundle_rules,
        trusted_policy_issuers={authority.kid},
    ).evaluate(request)
    passed = decision.allowed and policy_id in decision.matched_policy_ids
    return _result(
        "MPT-018",
        "Signed policy bundle is accepted and enforced",
        "ALLOW with the signed policy id matched",
        f"{'ALLOW' if passed else 'DENY'} matched={list(decision.matched_policy_ids)}",
        passed,
        {
            "policy_id": policy_id,
            "bundle_version": bundle["payload"]["version"],
            "matched_policy_ids": list(decision.matched_policy_ids),
            "independent_verifiers": _independent_policy_evidence(
                policy_id,
                bundle,
                bundle_v2,
            ),
        },
    )


def _policy_bundle_tamper_rejected() -> CaseResult:
    authority = PolicyAuthority(Ed25519KeyPair.generate())
    outsider = PolicyAuthority(Ed25519KeyPair.generate())
    policy_id = "urn:kinegrant:mpt:policy:bundle-019"
    rules = [
        PolicyRule(
            policy_id,
            authority.kid,
            "urn:kinegrant:mpt:target:1",
            "allow",
            ("open",),
            purposes=("permission-test",),
        )
    ]
    bundle = authority.publish(policy_id, rules, ttl_seconds=3600)
    bundle_v2 = authority.publish(
        policy_id,
        [
            PolicyRule(
                policy_id,
                authority.kid,
                "urn:kinegrant:mpt:target:1",
                "allow",
                ("open",),
                purposes=("permission-test", "maintenance"),
            )
        ],
        ttl_seconds=3600,
    )

    tampered = dict(bundle)
    tampered["payload"] = dict(bundle["payload"])
    tampered["payload"]["rules"] = []
    tamper_rejected, _ = _rejected(
        lambda: verify_policy_bundle(
            tampered,
            trusted_authorities={authority.kid},
        )
    )
    authority_rejected, _ = _rejected(
        lambda: verify_policy_bundle(
            bundle,
            trusted_authorities={outsider.kid},
        )
    )
    policy_rejected, _ = _rejected(
        lambda: verify_policy_bundle(
            bundle,
            trusted_authorities={authority.kid},
            expected_policy_id="urn:kinegrant:mpt:policy:other",
        )
    )
    passed = tamper_rejected and authority_rejected and policy_rejected
    return _result(
        "MPT-019",
        "Policy bundle tampering, wrong authority, and wrong policy are rejected",
        "ALL rejected (fail-closed)",
        f"tamper={tamper_rejected} authority={authority_rejected} "
        f"policy={policy_rejected}",
        passed,
        {
            "tamper_rejected": tamper_rejected,
            "wrong_authority_rejected": authority_rejected,
            "wrong_policy_rejected": policy_rejected,
            "independent_verifiers": _independent_policy_evidence(
                policy_id,
                bundle,
                bundle_v2,
            ),
        },
    )


def _policy_bundle_rollback() -> CaseResult:
    authority = PolicyAuthority(Ed25519KeyPair.generate())
    policy_id = "urn:kinegrant:mpt:policy:bundle-020"
    rules_v1 = [
        PolicyRule(
            policy_id,
            authority.kid,
            "urn:kinegrant:mpt:target:1",
            "allow",
            ("open",),
            purposes=("permission-test",),
        )
    ]
    rules_v2 = [
        PolicyRule(
            policy_id,
            authority.kid,
            "urn:kinegrant:mpt:target:1",
            "allow",
            ("open",),
            purposes=("permission-test", "maintenance"),
        )
    ]
    v1 = authority.publish(policy_id, rules_v1, ttl_seconds=3600)
    v2 = authority.publish(policy_id, rules_v2, ttl_seconds=3600)
    registry = PolicyRegistry(trusted_authorities={authority.kid})
    registry.activate(v1)
    registry.activate(v2)
    current_v2 = (
        registry.current(policy_id) is not None
        and registry.current(policy_id)["version"] == 2
    )
    registry.revoke(policy_id, 2, reason="emergency rollback")
    rolled_back = (
        registry.current(policy_id) is not None
        and registry.current(policy_id)["version"] == 1
    )
    registry.revoke(policy_id, 1, reason="full withdrawal")
    fail_closed = registry.current(policy_id) is None
    passed = current_v2 and rolled_back and fail_closed
    return _result(
        "MPT-020",
        "Policy version rollback and fail-closed with no current version",
        "v2 current, then v1 after revocation, then None",
        f"v2={current_v2} rolled_back={rolled_back} fail_closed={fail_closed}",
        passed,
        {
            "current_v2": current_v2,
            "rolled_back_to_v1": rolled_back,
            "fail_closed_none": fail_closed,
            "independent_verifiers": _independent_policy_evidence(
                policy_id,
                v1,
                v2,
            ),
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
    ("MPT-010", _physical_constraints),
    ("MPT-011", _attenuation),
    ("MPT-012", _delegation),
    ("MPT-013", _approval_tiers),
    ("MPT-014", _forbidden_combination),
    ("MPT-015", _receipt_obligation_results),
    ("MPT-016", _obligation_evasion),
    ("MPT-017", _revocation_distribution),
    ("MPT-018", _policy_bundle_enforced),
    ("MPT-019", _policy_bundle_tamper_rejected),
    ("MPT-020", _policy_bundle_rollback),
)


def run_machine_permission_test(*, source_commit: str | None = None) -> dict[str, Any]:
    if source_commit is not None and re.fullmatch(r"[0-9a-f]{40,64}", source_commit) is None:
        raise ValueError("source_commit must be a lowercase 40-64 character hex digest")
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
    "schema_version": "0.4",
        "run_id": f"urn:kinegrant:mpt:run:{uuid4()}",
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "protocol": "KGP-001 Experimental Open Draft 0.1",
        "reference_implementation": __version__,
        "source_commit": source_commit,
        "runner_digest": f"sha256:{hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}",
        "environment": {
            "python_version": platform.python_version(),
            "python_implementation": platform.python_implementation(),
            "platform": platform.platform(),
        },
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
    parser.add_argument(
        "--source-commit",
        help="Lowercase Git commit digest for the tested implementation",
    )
    args = parser.parse_args(argv)
    evidence = run_machine_permission_test(source_commit=args.source_commit)
    encoded = json.dumps(evidence, indent=2, sort_keys=True)
    if args.output:
        args.output.write_text(encoded + "\n", encoding="utf-8")
    print(encoded)
    return 0 if evidence["overall_result"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
