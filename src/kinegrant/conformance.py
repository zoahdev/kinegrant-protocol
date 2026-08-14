"""Conformance levels and executable suite (v1.0 groundwork).

KineGrant defines four conformance levels:

- L1 core semantics: default deny, deny overrides, trusted issuers, one-time
  capability, replay rejection, receipt chains;
- L2 scoped capabilities: attenuation, physical constraints, approval tiers,
  forbidden combinations, obligation compliance;
- L3 delegation and revocation: opt-in delegation, delegate binding,
  allowlists, offline revocation, fleet revocation distribution, signed
  policy bundles;
- L4 hardware trust: trusted clock, sensor evidence, checkpoints,
  attestations, post-quantum envelopes.

``ConformanceRunner`` executes each level against the reference
implementation and emits a machine-readable report with the marks earned.
Certification of third-party implementations is out of scope until the RFC
process approves a certification program.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Any, Callable

from .attenuation import verify_attenuation
from .attestation import build_device_attestation, verify_device_attestation
from .capability import CapabilityIssuer
from .checkpoint import build_receipt_checkpoint, verify_receipt_checkpoint
from .crypto import Ed25519KeyPair, MLDSA65KeyPair, verify_envelope
from .distribution import RevocationDistributor
from .gate import ActionGate, InMemoryReplayStore
from .gatekeeper_modelcheck import check_gatekeeper_boundary
from .gatekeeper import Gatekeeper
from .models import ActionRequest, PolicyRule
from .policy import PolicyEngine
from .policy_bundle import PolicyAuthority, PolicyRegistry, verify_policy_bundle
from .receipt import ReceiptLog, verify_receipt_chain
from .revocation import (
    RevocationList,
    build_revocation_bundle,
    sign_revocation_bundle,
)
from .sensor_evidence import (
    SensorReading,
    build_sensor_commitment,
    verify_sensor_commitment,
)
from .sequence import ActionJournal, ForbiddenCombination, SequencePolicy
from .trust import TrustedClock, TrustedClockError


@dataclass(frozen=True)
class ConformanceMark:
    level: str
    name: str
    passed: bool
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "level": self.level,
            "name": self.name,
            "passed": self.passed,
            "detail": self.detail,
        }


def _default_request() -> ActionRequest:
    return ActionRequest(
        "urn:kinegrant:conformance:request:1",
        "urn:kinegrant:conformance:agent:1",
        "urn:kinegrant:conformance:target:door-7",
        "open",
        "delivery",
    )


class ConformanceRunner:
    def __init__(self) -> None:
        self.authority = Ed25519KeyPair.generate()
        self.issuer = CapabilityIssuer(self.authority)
        self.request = _default_request()

    def run_level(self, level: str) -> tuple[ConformanceMark, ...]:
        runners: dict[str, Callable[[], tuple[ConformanceMark, ...]]] = {
            "L1": self._level1,
            "L2": self._level2,
            "L3": self._level3,
            "L4": self._level4,
        }
        if level not in runners:
            raise ValueError(f"unknown conformance level {level!r}")
        return runners[level]()

    def run_all(self) -> dict[str, Any]:
        marks = [mark for level in ("L1", "L2", "L3", "L4") for mark in self.run_level(level)]
        passed = sum(mark.passed for mark in marks)
        independent = self._independent_verification()
        return {
            "type": "kinegrant:ConformanceReport",
            "schema_version": "0.1",
            "overall_result": "PASS" if passed == len(marks) else "FAIL",
            "summary": {"total": len(marks), "passed": passed, "failed": len(marks) - passed},
            "marks": [mark.to_dict() for mark in marks],
            "independent_verification": independent,
            "limitations": [
                "Reference-implementation self-assessment; certification of "
                "third-party implementations awaits RFC approval.",
                "Independent verifiers (JavaScript, Go) cross-check generated "
                "capabilities and receipt chains; unavailable tools are "
                "recorded as skipped.",
            ],
        }

    def _independent_verification(self) -> dict[str, Any]:
        root = Path(__file__).resolve().parents[2]
        js_cli = root / "implementations" / "kinegrant-js" / "src" / "cli.mjs"
        go_dir = root / "implementations" / "kinegrant-go"
        node = shutil.which("node") or str(
            Path(
                r"C:\Users\zoah\.cache\codex-runtimes\codex-primary-runtime"
            )
            / "dependencies" / "node" / "bin" / "node.exe"
        )
        node_available = Path(node).is_file()
        go_available = shutil.which("go") is not None

        rule = PolicyRule(
            "urn:kinegrant:conformance:independent:rule",
            self.authority.kid,
            "urn:kinegrant:conformance:target:*",
            "allow",
            ("open",),
            obligations=("emitActionReceipt",),
        )
        engine = PolicyEngine([rule], trusted_policy_issuers={self.authority.kid})
        decision = engine.evaluate(self.request)
        capability = self.issuer.issue_scoped(
            self.request,
            decision,
            ttl_seconds=300,
            target=self.request.target,
            actions=["open"],
            purposes=["delivery"],
            wire_version="1.0",
        )
        gate = ActionGate(
            trusted_issuers={self.authority.kid},
            replay_store=InMemoryReplayStore(),
        )
        executor = Ed25519KeyPair.generate()
        log = ReceiptLog(executor)
        receipts = []
        for index in range(2):
            request = ActionRequest(
                f"urn:kinegrant:conformance:independent:request:{index}",
                "urn:kinegrant:conformance:agent:1",
                "urn:kinegrant:conformance:target:door-7",
                "open",
                "delivery",
            )
            verified = gate.authorize(
                self.issuer.issue_scoped(
                    request,
                    engine.evaluate(request),
                    ttl_seconds=300,
                    target=request.target,
                    actions=["open"],
                    purposes=["delivery"],
                    wire_version="1.0",
                ),
                request,
            )
            receipts.append(
                log.append(verified, result="succeeded", request=request)
            )

        checks: list[dict[str, Any]] = []
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            capability_path = base / "capability.json"
            request_path = base / "request.json"
            issuers_path = base / "issuers.json"
            receipts_path = base / "receipts.json"
            executors_path = base / "executors.json"
            capability_path.write_text(json.dumps(capability), encoding="utf-8")
            request_path.write_text(json.dumps(self.request.to_dict()), encoding="utf-8")
            issuers_path.write_text(
                json.dumps([self.authority.kid]),
                encoding="utf-8",
            )
            receipts_path.write_text(json.dumps(receipts), encoding="utf-8")
            executors_path.write_text(
                json.dumps([executor.kid]),
                encoding="utf-8",
            )

            for tool, command in (
                ("kinegrant-js", [node, str(js_cli)] if node_available else None),
                (
                    "kinegrant-go",
                    ["go", "run", "./cmd/kinegrant-verify"]
                    if go_available
                    else None,
                ),
            ):
                if command is None:
                    checks.append(
                        {
                            "tool": tool,
                            "capability": "SKIP",
                            "receipts": "SKIP",
                            "detail": "toolchain unavailable",
                        }
                    )
                    continue
                try:
                    capability_proc = subprocess.run(
                        [
                            *command,
                            "verify-capability",
                            str(capability_path),
                            str(request_path),
                            str(issuers_path),
                        ],
                        capture_output=True,
                        text=True,
                        encoding="utf-8",
                        errors="replace",
                        timeout=120,
                        cwd=go_dir if tool == "kinegrant-go" else None,
                    )
                    receipt_proc = subprocess.run(
                        [
                            *command,
                            "verify-receipts",
                            str(receipts_path),
                            str(executors_path),
                        ],
                        capture_output=True,
                        text=True,
                        encoding="utf-8",
                        errors="replace",
                        timeout=120,
                        cwd=go_dir if tool == "kinegrant-go" else None,
                    )
                    capability_ok = (
                        capability_proc.returncode == 0
                        and "CAPABILITY VALID" in capability_proc.stdout
                    )
                    receipts_ok = (
                        receipt_proc.returncode == 0
                        and "RECEIPT CHAIN VALID" in receipt_proc.stdout
                    )
                    checks.append(
                        {
                            "tool": tool,
                            "capability": "PASS" if capability_ok else "FAIL",
                            "receipts": "PASS" if receipts_ok else "FAIL",
                            "detail": (
                                capability_proc.stderr[:200]
                                if not capability_ok
                                else receipt_proc.stderr[:200]
                                if not receipts_ok
                                else "cross-verified"
                            ),
                        }
                    )
                except Exception as exc:  # a crashing verifier is a failure
                    checks.append(
                        {
                            "tool": tool,
                            "capability": "ERROR",
                            "receipts": "ERROR",
                            "detail": f"{type(exc).__name__}: {exc}",
                        }
                    )
        return {
            "schema_version": "0.1",
            "overall_result": (
                "PASS"
                if all(
                    check["capability"] in {"PASS", "SKIP"}
                    and check["receipts"] in {"PASS", "SKIP"}
                    for check in checks
                )
                else "FAIL"
            ),
            "checks": checks,
        }

    def _level1(self) -> tuple[ConformanceMark, ...]:
        marks = []
        allow = PolicyRule(
            "urn:kinegrant:conformance:policy:l1",
            self.authority.kid,
            "urn:kinegrant:conformance:target:*",
            "allow",
            ("open",),
            subjects=("urn:kinegrant:conformance:agent:*",),
            purposes=("delivery",),
        )
        engine = PolicyEngine([allow], trusted_policy_issuers={self.authority.kid})
        default_deny = engine.evaluate(
            ActionRequest(
                "urn:kinegrant:conformance:request:other",
                "urn:kinegrant:conformance:agent:1",
                "urn:kinegrant:other:target:other",
                "open",
                "delivery",
            )
        )
        marks.append(
            ConformanceMark("L1", "default_deny", not default_deny.allowed, default_deny.reason)
        )

        deny = PolicyRule(
            "urn:kinegrant:conformance:policy:l1-deny",
            self.authority.kid,
            "urn:kinegrant:conformance:target:*",
            "deny",
            ("open",),
        )
        conflict = PolicyEngine(
            [allow, deny], trusted_policy_issuers={self.authority.kid}
        ).evaluate(self.request)
        marks.append(
            ConformanceMark("L1", "deny_overrides", not conflict.allowed, conflict.reason)
        )

        decision = engine.evaluate(self.request)
        capability = self.issuer.issue(self.request, decision, ttl_seconds=30)
        gate = ActionGate(
            trusted_issuers={self.authority.kid},
            replay_store=InMemoryReplayStore(),
        )
        try:
            gate.authorize(capability, self.request)
            once = True
        except PermissionError:
            once = False
        try:
            gate.authorize(capability, self.request)
            replay_rejected = False
        except PermissionError:
            replay_rejected = True
        marks.append(ConformanceMark("L1", "single_use", once, "consumed once"))
        marks.append(
            ConformanceMark("L1", "replay_rejected", replay_rejected, "second use denied")
        )

        verified = ActionGate(trusted_issuers={self.authority.kid}).authorize(
            self.issuer.issue(self.request, decision, ttl_seconds=30),
            self.request,
        )
        executor = Ed25519KeyPair.generate()
        receipt = ReceiptLog(executor).append(verified, result="succeeded")
        chain_ok = verify_receipt_chain(
            [receipt],
            trusted_executors={executor.kid},
            expected_capability_ids={verified["capability_id"]},
        )
        marks.append(ConformanceMark("L1", "receipt_chain", chain_ok, "receipt verified"))
        return tuple(marks)

    def _level2(self) -> tuple[ConformanceMark, ...]:
        marks = []
        decision = PolicyEngine(
            [
                PolicyRule(
                    "urn:kinegrant:conformance:policy:l2",
                    self.authority.kid,
                    "urn:kinegrant:conformance:target:*",
                    "allow",
                    ("open", "close"),
                    purposes=("delivery",),
                )
            ],
            trusted_policy_issuers={self.authority.kid},
        ).evaluate(self.request)
        root = self.issuer.issue_scoped(
            self.request,
            decision,
            ttl_seconds=30,
            target="urn:kinegrant:conformance:target:*",
            actions=["open", "close"],
            purposes=["delivery"],
        )
        child = self.issuer.issue_attenuated(
            root,
            target=self.request.target,
            actions=["open"],
            ttl_seconds=10,
            max_force_newtons=20,
        )
        attenuation_ok = verify_attenuation(child["payload"], root["payload"])
        marks.append(ConformanceMark("L2", "attenuation", attenuation_ok, "parent verified"))

        physical_rule = PolicyRule(
            "urn:kinegrant:conformance:policy:l2-physical",
            self.authority.kid,
            "*",
            "allow",
            ("open",),
            constraints={"max_force_newtons": 50, "allowed_zones": ["urn:kinegrant:conformance:zone:*"]},
        )
        physical_engine = PolicyEngine(
            [physical_rule], trusted_policy_issuers={self.authority.kid}
        )
        within = physical_engine.evaluate(
            ActionRequest(
                "urn:kinegrant:conformance:request:within",
                "urn:kinegrant:conformance:agent:1",
                "urn:kinegrant:conformance:target:door-7",
                "open",
                "delivery",
                context={"force_newtons": 20, "zone": "urn:kinegrant:conformance:zone:1"},
            )
        )
        over = physical_engine.evaluate(
            ActionRequest(
                "urn:kinegrant:conformance:request:over",
                "urn:kinegrant:conformance:agent:1",
                "urn:kinegrant:conformance:target:door-7",
                "open",
                "delivery",
                context={"force_newtons": 99, "zone": "urn:kinegrant:conformance:zone:1"},
            )
        )
        marks.append(
            ConformanceMark(
                "L2", "physical_constraints",
                within.allowed and not over.allowed,
                f"within={within.reason}, over={over.reason}",
            )
        )

        approval = PolicyEngine(
            [
                PolicyRule(
                    "urn:kinegrant:conformance:policy:l2-approval",
                    self.authority.kid,
                    "urn:kinegrant:conformance:target:door-7",
                    "allow",
                    ("open",),
                    constraints={"min_approval_tier": 2},
                )
            ],
            trusted_policy_issuers={self.authority.kid},
        ).evaluate(self.request)
        marks.append(
            ConformanceMark(
                "L2", "approval_tiers", approval.required_approval_tier == 2,
                f"tier={approval.required_approval_tier}",
            )
        )

        journal = ActionJournal()
        journal.record("record", "urn:kinegrant:conformance:target:door-7")
        journal.record("open", "urn:kinegrant:conformance:target:door-7")
        sequence = SequencePolicy(
            [
                ForbiddenCombination(
                    "l2-combo",
                    (("record", "*"), ("open", "*")),
                    trigger=("train_on_data", "*"),
                )
            ]
        )
        combo = sequence.evaluate(
            ActionRequest(
                "urn:kinegrant:conformance:request:train",
                "urn:kinegrant:conformance:agent:1",
                "urn:kinegrant:conformance:target:door-7",
                "train_on_data",
                "audit",
            ),
            journal,
        )
        marks.append(
            ConformanceMark("L2", "forbidden_combination", not combo.allowed, combo.reason)
        )

        obligation_rule = PolicyRule(
            "urn:kinegrant:conformance:policy:l2-obligation",
            self.authority.kid,
            "urn:kinegrant:conformance:target:door-7",
            "allow",
            ("open",),
            obligations=("emitActionReceipt", "logAuditEvent"),
        )
        obligation_decision = PolicyEngine(
            [obligation_rule],
            trusted_policy_issuers={self.authority.kid},
        ).evaluate(self.request)
        obligation_capability = self.issuer.issue_scoped(
            self.request,
            obligation_decision,
            ttl_seconds=30,
            target=self.request.target,
            actions=["open"],
            purposes=["delivery"],
        )
        obligation_executor = Ed25519KeyPair.generate()
        obligation_outcome = Gatekeeper(
            gate=ActionGate(
                trusted_issuers={self.authority.kid},
                replay_store=InMemoryReplayStore(),
            ),
            sequence=SequencePolicy([]),
            journal=ActionJournal(),
            receipt_log=ReceiptLog(obligation_executor),
        ).execute(
            obligation_capability,
            self.request,
            lambda verified: None,
            obligation_results=[
                {"obligation": "emitActionReceipt", "status": "satisfied"},
                {"obligation": "logAuditEvent", "status": "satisfied"},
            ],
        )
        marks.append(
            ConformanceMark(
                "L2",
                "obligation_compliance",
                obligation_outcome.allowed
                and bool(obligation_outcome.obligation_compliant),
                f"stage={obligation_outcome.stage}, compliant="
                f"{obligation_outcome.obligation_compliant}",
            )
        )

        boundary_rule = PolicyRule(
            "urn:kinegrant:conformance:policy:l2-boundary",
            self.authority.kid,
            "urn:kinegrant:conformance:target:*",
            "allow",
            ("open", "enter"),
            obligations=("emitActionReceipt",),
        )
        boundary_engine = PolicyEngine(
            [boundary_rule],
            trusted_policy_issuers={self.authority.kid},
        )
        boundary_journal = ActionJournal()
        boundary_sequence = SequencePolicy(
            [
                ForbiddenCombination(
                    "l2-boundary-open-enter",
                    patterns=(
                        ("open", "urn:kinegrant:conformance:target:*"),
                    ),
                    trigger=("enter", "urn:kinegrant:conformance:target:*"),
                )
            ]
        )
        boundary_executor = Ed25519KeyPair.generate()
        boundary_gatekeeper = Gatekeeper(
            gate=ActionGate(
                trusted_issuers={self.authority.kid},
                replay_store=InMemoryReplayStore(),
            ),
            sequence=boundary_sequence,
            journal=boundary_journal,
            receipt_log=ReceiptLog(boundary_executor),
        )
        actuator_calls: list[str] = []
        open_capability = self.issuer.issue_scoped(
            self.request,
            boundary_engine.evaluate(self.request),
            ttl_seconds=30,
            target=self.request.target,
            actions=["open"],
            purposes=["delivery"],
        )
        first = boundary_gatekeeper.execute(
            open_capability,
            self.request,
            lambda verified: actuator_calls.append(verified["capability_id"]),
        )
        replay = boundary_gatekeeper.execute(
            open_capability,
            self.request,
            lambda verified: actuator_calls.append(verified["capability_id"]),
        )
        enter = ActionRequest(
            "urn:kinegrant:conformance:request:enter",
            "urn:kinegrant:conformance:agent:1",
            "urn:kinegrant:conformance:target:door-7",
            "enter",
            "delivery",
        )
        enter_capability = self.issuer.issue_scoped(
            enter,
            boundary_engine.evaluate(enter),
            ttl_seconds=30,
            target=enter.target,
            actions=["enter"],
            purposes=["delivery"],
        )
        sequence_denied = boundary_gatekeeper.execute(
            enter_capability,
            enter,
            lambda verified: actuator_calls.append(verified["capability_id"]),
        )
        revocation_list = RevocationList()
        revocation_list.revoke(open_capability["payload"]["capability_id"])
        revoked_gatekeeper = Gatekeeper(
            gate=ActionGate(
                trusted_issuers={self.authority.kid},
                replay_store=InMemoryReplayStore(),
            ),
            sequence=SequencePolicy([]),
            journal=ActionJournal(),
            receipt_log=ReceiptLog(Ed25519KeyPair.generate()),
            revocation_list=revocation_list,
        )
        revoked = revoked_gatekeeper.execute(
            open_capability,
            self.request,
            lambda verified: actuator_calls.append(verified["capability_id"]),
        )
        boundary_ok = (
            first.allowed
            and not replay.allowed
            and replay.stage == "gate"
            and not sequence_denied.allowed
            and sequence_denied.stage == "sequence"
            and not revoked.allowed
            and revoked.stage == "revocation"
            and len(actuator_calls) == 1
            and len(boundary_journal.entries) == 1
        )
        marks.append(
            ConformanceMark(
                "L2",
                "gatekeeper_boundary",
                boundary_ok,
                "open+replay denied+sequence denied+revocation denied",
            )
        )

        boundary_modelcheck = check_gatekeeper_boundary()
        marks.append(
            ConformanceMark(
                "L2",
                "gatekeeper_boundary_modelcheck",
                boundary_modelcheck["overall_result"] == "PASS",
                f"properties="
                f"{boundary_modelcheck['summary']['passed_properties']}/"
                f"{boundary_modelcheck['summary']['properties']}",
            )
        )
        return tuple(marks)

    def _level3(self) -> tuple[ConformanceMark, ...]:
        marks = []
        decision = PolicyEngine(
            [
                PolicyRule(
                    "urn:kinegrant:conformance:policy:l3",
                    self.authority.kid,
                    "*",
                    "allow",
                    ("open",),
                    purposes=("delivery",),
                )
            ],
            trusted_policy_issuers={self.authority.kid},
        ).evaluate(self.request)
        root = self.issuer.issue_scoped(
            self.request,
            decision,
            ttl_seconds=30,
            target="*",
            actions=["open"],
            purposes=["delivery"],
            delegation_allowed=True,
            max_delegation_depth=1,
            delegate_allowlist=["urn:kinegrant:conformance:agent:2"],
        )
        delegate_request = ActionRequest(
            "urn:kinegrant:conformance:request:delegate",
            "urn:kinegrant:conformance:agent:2",
            "urn:kinegrant:conformance:target:door-7",
            "open",
            "delivery",
        )
        child = self.issuer.issue_attenuated(
            root,
            target=delegate_request.target,
            delegate_agent=delegate_request.agent,
            delegate_request=delegate_request,
        )
        delegate_ok = verify_attenuation(child["payload"], root["payload"])
        marks.append(ConformanceMark("L3", "delegation", delegate_ok, "delegate bound"))

        outsider = ActionRequest(
            "urn:kinegrant:conformance:request:outsider",
            "urn:kinegrant:conformance:agent:3",
            "urn:kinegrant:conformance:target:door-7",
            "open",
            "delivery",
        )
        try:
            self.issuer.issue_attenuated(
                root,
                target=outsider.target,
                delegate_agent=outsider.agent,
                delegate_request=outsider,
            )
            allowlist_ok = False
        except ValueError:
            allowlist_ok = True
        marks.append(
            ConformanceMark("L3", "delegate_allowlist", allowlist_ok, "outsider denied")
        )

        rl = RevocationList()
        rl.revoke(root["payload"]["capability_id"])
        gate = ActionGate(
            trusted_issuers={self.authority.kid},
            replay_store=InMemoryReplayStore(),
            revocation_list=rl,
        )
        try:
            gate.authorize(child, delegate_request)
            revoked = False
        except PermissionError:
            revoked = True
        marks.append(ConformanceMark("L3", "revocation", revoked, "root revoked child"))

        distribution_rl = RevocationList()
        distribution_rl.revoke("kinegrant:cap:" + "d" * 64, reason="fleet maintenance")
        distribution_bundle = sign_revocation_bundle(
            build_revocation_bundle(
                distribution_rl,
                issuer=self.authority.kid,
            ),
            self.authority,
        )
        gate_a = RevocationList()
        gate_b = RevocationList()
        distribution_report = RevocationDistributor(
            trusted_authorities={self.authority.kid}
        ).distribute(
            distribution_bundle,
            {"gate-a": gate_a, "gate-b": gate_b},
        )
        distribution_ok = (
            distribution_report["overall_result"] == "PASS"
            and distribution_report["summary"]["added_total"] == 2
            and gate_a.is_revoked("kinegrant:cap:" + "d" * 64)
            and gate_b.is_revoked("kinegrant:cap:" + "d" * 64)
        )
        marks.append(
            ConformanceMark(
                "L3",
                "revocation_distribution",
                distribution_ok,
                "verified bundle applied to both gates",
            )
        )

        policy_authority = PolicyAuthority(Ed25519KeyPair.generate())
        policy_id = "urn:kinegrant:conformance:policy:trust"
        base_rules = [
            PolicyRule(
                policy_id,
                policy_authority.kid,
                "*",
                "allow",
                ("open",),
                purposes=("delivery",),
            )
        ]
        v1 = policy_authority.publish(policy_id, base_rules, ttl_seconds=3600)
        registry = PolicyRegistry(trusted_authorities={policy_authority.kid})
        registry.activate(v1)
        v2_rules = [
            PolicyRule(
                policy_id,
                policy_authority.kid,
                "*",
                "allow",
                ("open",),
                purposes=("delivery", "maintenance"),
            )
        ]
        v2 = policy_authority.publish(policy_id, v2_rules, ttl_seconds=3600)
        registry.activate(v2)
        current_ok = (
            registry.current(policy_id) is not None
            and registry.current(policy_id)["version"] == 2
        )
        registry.revoke(policy_id, 2, reason="conformance rollback")
        rollback_ok = (
            registry.current(policy_id) is not None
            and registry.current(policy_id)["version"] == 1
        )
        tampered = dict(v2)
        tampered["payload"] = dict(v2["payload"])
        tampered["payload"]["rules"] = []
        try:
            verify_policy_bundle(
                tampered,
                trusted_authorities={policy_authority.kid},
            )
            tamper_rejected = False
        except ValueError:
            tamper_rejected = True
        policy_bundle_ok = current_ok and rollback_ok and tamper_rejected
        marks.append(
            ConformanceMark(
                "L3",
                "policy_bundle_trust",
                policy_bundle_ok,
                "signed versions verified, revoked version rolled back",
            )
        )
        return tuple(marks)

    def _level4(self) -> tuple[ConformanceMark, ...]:
        marks = []
        clock = TrustedClock(max_forward_jump_seconds=3600)
        clock.now()
        from .models import utc_now

        base = utc_now()
        sequence = iter([base, base - timedelta(seconds=1)])
        backwards = TrustedClock(source=lambda: next(sequence))
        backwards.now()
        try:
            backwards.now()
            clock_ok = False
        except TrustedClockError:
            clock_ok = True
        marks.append(ConformanceMark("L4", "trusted_clock", clock_ok, "backwards rejected"))

        sensor = Ed25519KeyPair.generate()
        commitment = build_sensor_commitment(
            [
                SensorReading(
                    "door_position",
                    {"open": True},
                    "sensor:door-7",
                    0.99,
                    "2026-08-14T00:00:00Z",
                )
            ],
            sensor_kid=sensor.kid,
            key_pair=sensor,
        )
        sensor_ok = verify_sensor_commitment(commitment, trusted_sensors={sensor.kid})
        marks.append(
            ConformanceMark("L4", "sensor_evidence", sensor_ok is not None, "commitment verified")
        )

        notary = Ed25519KeyPair.generate()
        checkpoint = build_receipt_checkpoint(
            "sha256:" + "a" * 64,
            notary_kid=notary.kid,
            key_pair=notary,
        )
        checkpoint_ok = verify_receipt_checkpoint(
            checkpoint, trusted_notaries={notary.kid}
        ) == "sha256:" + "a" * 64
        marks.append(ConformanceMark("L4", "receipt_checkpoint", checkpoint_ok, "notarized"))

        device = Ed25519KeyPair.generate()
        attestation = build_device_attestation(
            device_id="urn:kinegrant:conformance:device:1",
            firmware_digest="sha256:" + "a" * 64,
            boot_counter=1,
            device_key=device,
        )
        verify_device_attestation(
            attestation, trusted_devices={device.kid}
        )
        marks.append(
            ConformanceMark("L4", "device_attestation", True, "attestation verified")
        )

        mldsa = MLDSA65KeyPair.generate()
        envelope = mldsa.sign_envelope({"a": 1})
        mldsa_ok = verify_envelope(envelope) == {"a": 1}
        marks.append(
            ConformanceMark("L4", "post_quantum_envelopes", mldsa_ok, "ML-DSA-65 verified")
        )
        return tuple(marks)


def main(argv: list[str] | None = None) -> int:
    report = ConformanceRunner().run_all()
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["overall_result"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
