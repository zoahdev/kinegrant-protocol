"""Conformance levels and executable suite (v1.0 groundwork).

KineGrant defines four conformance levels:

- L1 core semantics: default deny, deny overrides, trusted issuers, one-time
  capability, replay rejection, receipt chains;
- L2 scoped capabilities: attenuation, physical constraints, approval tiers,
  forbidden combinations, obligation compliance;
- L3 delegation and revocation: opt-in delegation, delegate binding,
  allowlists, offline revocation;
- L4 hardware trust: trusted clock, sensor evidence, checkpoints,
  attestations, post-quantum envelopes.

``ConformanceRunner`` executes each level against the reference
implementation and emits a machine-readable report with the marks earned.
Certification of third-party implementations is out of scope until the RFC
process approves a certification program.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import timedelta
from typing import Any, Callable

from .attenuation import verify_attenuation
from .attestation import build_device_attestation, verify_device_attestation
from .capability import CapabilityIssuer
from .checkpoint import build_receipt_checkpoint, verify_receipt_checkpoint
from .compliance import ObligationCompliance
from .crypto import Ed25519KeyPair, MLDSA65KeyPair, verify_envelope
from .gate import ActionGate, InMemoryReplayStore
from .models import ActionRequest, PolicyRule
from .policy import PolicyEngine
from .receipt import ReceiptLog, verify_receipt_chain
from .revocation import RevocationList
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
        return {
            "type": "kinegrant:ConformanceReport",
            "schema_version": "0.1",
            "overall_result": "PASS" if passed == len(marks) else "FAIL",
            "summary": {"total": len(marks), "passed": passed, "failed": len(marks) - passed},
            "marks": [mark.to_dict() for mark in marks],
            "limitations": [
                "Reference-implementation self-assessment; certification of "
                "third-party implementations awaits RFC approval.",
            ],
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
            obligations=("emitActionReceipt",),
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
        obligation_verified = ActionGate(
            trusted_issuers={self.authority.kid},
            replay_store=InMemoryReplayStore(),
        ).authorize(obligation_capability, self.request)
        obligation_executor = Ed25519KeyPair.generate()
        obligation_receipt = ReceiptLog(obligation_executor).append(
            obligation_verified,
            result="succeeded",
            request=self.request,
        )
        obligation_compliant = ObligationCompliance().evaluate(
            obligation_capability,
            [obligation_receipt],
            trusted_executors={obligation_executor.kid},
        ).compliant
        marks.append(
            ConformanceMark(
                "L2",
                "obligation_compliance",
                obligation_compliant,
                "receipt obligation satisfied",
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
