"""Simulated two-stack robot demonstration with fault injection.

Two different robot stacks (a ROS 2-style action client and a Matter-style
command client) obey the *same* external KineGrant policy. The demo injects
faults -- replay, untrusted issuer, prompt-injection style request, physical
limit violation, and a forbidden combination -- and records every outcome in
a machine-readable report.

This is a software simulation of the v0.3 exit criterion ("two different robot
stacks obey the same external policy"); it does not move a real actuator.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from threading import Lock
from typing import Any, Callable

from ..adapters.matter import matter_command_request
from ..adapters.ros2 import ros_action_request
from ..capability import CapabilityIssuer
from ..crypto import Ed25519KeyPair
from ..gate import ActionGate, VerifiedCapability
from ..gatekeeper import Gatekeeper
from ..models import ActionRequest, PolicyRule
from ..policy import PolicyEngine
from ..receipt import ReceiptLog
from ..sequence import ActionJournal, ForbiddenCombination, SequencePolicy


class _Counter:
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


@dataclass(frozen=True)
class DemoOutcome:
    scenario: str
    stack: str
    action: str
    allowed: bool
    reason: str
    actuator_calls: int
    expected: str
    obligation_compliant: bool | None = None

    @property
    def passed(self) -> bool:
        return self.allowed == ("ALLOW" in self.expected)

    def to_dict(self) -> dict[str, Any]:
        return {
            "scenario": self.scenario,
            "stack": self.stack,
            "action": self.action,
            "allowed": self.allowed,
            "reason": self.reason,
            "actuator_calls": self.actuator_calls,
            "expected": self.expected,
            "obligation_compliant": self.obligation_compliant,
            "passed": self.passed,
        }


class RobotStack:
    """Adapter wrapper that turns one transport's request into an ActionRequest."""

    def __init__(self, name: str, builder: Callable[..., ActionRequest]) -> None:
        self.name = name
        self.builder = builder

    def request(
        self,
        *,
        action: str,
        target: str,
        purpose: str,
        agent: str,
        context: dict[str, Any] | None = None,
    ) -> ActionRequest:
        return self.builder(
            request_id=f"urn:kinegrant:demo:request:{self.name}:{action}:{target}",
            action=action,
            target=target,
            purpose=purpose,
            agent=agent,
            context=context,
        )


def default_policy(issuer: str) -> list[PolicyRule]:
    return [
        PolicyRule(
            "urn:kinegrant:demo:policy:allow-basic",
            issuer,
            "*",
            "allow",
            ("open", "close", "record"),
            subjects=("urn:kinegrant:demo:agent:*",),
            purposes=("delivery", "maintenance", "audit"),
            constraints={"max_force_newtons": 50, "allowed_zones": ["urn:kinegrant:demo:zone:*"]},
            obligations=("emitActionReceipt",),
        ),
        PolicyRule(
            "urn:kinegrant:demo:policy:deny-training",
            issuer,
            "*",
            "deny",
            ("train_on_data",),
        ),
    ]


class RobotDemo:
    def __init__(self) -> None:
        self.authority = Ed25519KeyPair.generate()
        self.issuer = CapabilityIssuer(self.authority)
        self.engine = PolicyEngine(
            default_policy(self.authority.kid),
            trusted_policy_issuers={self.authority.kid},
        )
        self.gate = ActionGate(trusted_issuers={self.authority.kid})
        self.journal = ActionJournal()
        self.executor = Ed25519KeyPair.generate()
        self.log = ReceiptLog(self.executor)
        self.sequence = SequencePolicy(
            [
                ForbiddenCombination(
                    "record-open-then-train",
                    (("record", "*"), ("open", "*")),
                    trigger=("train_on_data", "*"),
                )
            ]
        )
        self.gatekeeper = Gatekeeper(
            gate=self.gate,
            sequence=self.sequence,
            journal=self.journal,
            receipt_log=self.log,
        )
        self.ros2 = RobotStack(
            "ros2",
            lambda *, action, target, purpose, agent, context, request_id: ros_action_request(
                node_identity=agent,
                action_name=action,
                physical_target=target,
                purpose=purpose,
                request_id=request_id,
                context=context,
            ),
        )
        self.matter = RobotStack(
            "matter",
            lambda *, action, target, purpose, agent, context, request_id: matter_command_request(
                fabric_identity=agent,
                node_id=target.rsplit(":", 1)[-1],
                endpoint=1,
                cluster="DoorLock",
                command=action,
                purpose=purpose,
                request_id=request_id,
                context=context,
            ),
        )
        self.actuators = {"ros2": _Counter(), "matter": _Counter()}
        self.outcomes: list[DemoOutcome] = []

    def _issue(self, request: ActionRequest) -> dict[str, Any]:
        decision = self.engine.evaluate(request)
        if not decision.allowed:
            raise PermissionError(decision.reason)
        return self.issuer.issue_scoped(
            request,
            decision,
            ttl_seconds=30,
            target=request.target,
            actions=[request.action],
            purposes=[request.purpose],
            approval_tier=decision.required_approval_tier,
        )

    def attempt(
        self,
        scenario: str,
        stack: RobotStack,
        *,
        action: str,
        target: str,
        purpose: str,
        agent: str = "urn:kinegrant:demo:agent:robot-1",
        context: dict[str, Any] | None = None,
        expected: str,
    ) -> DemoOutcome:
        request = stack.request(
            action=action,
            target=target,
            purpose=purpose,
            agent=agent,
            context=context,
        )
        sequence = self.sequence.evaluate(request, self.journal)
        if not sequence.allowed:
            outcome = DemoOutcome(
                scenario, stack.name, action, False,
                f"forbidden_combination:{sequence.reason}", self.actuators[stack.name].calls, expected,
            )
            self.outcomes.append(outcome)
            return outcome
        try:
            capability = self._issue(request)
            outcome = self.gatekeeper.execute(
                capability,
                request,
                self.actuators[stack.name].execute,
            )
            obligation_compliant = outcome.obligation_compliant
            allowed = outcome.allowed
            reason = "allow" if allowed else (outcome.reason or outcome.stage)
        except (PermissionError, ValueError) as exc:
            allowed = False
            reason = f"{type(exc).__name__}: {exc}"
            obligation_compliant = None
        outcome = DemoOutcome(
            scenario, stack.name, action, allowed, reason,
            self.actuators[stack.name].calls, expected, obligation_compliant,
        )
        self.outcomes.append(outcome)
        return outcome

    def _manual(
        self,
        scenario: str,
        stack: RobotStack,
        operation: Callable[[], None],
        *,
        action: str,
        expected: str,
    ) -> DemoOutcome:
        try:
            operation()
            allowed = True
            reason = "allow"
        except (PermissionError, ValueError) as exc:
            allowed = False
            reason = f"{type(exc).__name__}: {exc}"
        outcome = DemoOutcome(
            scenario, stack.name, action, allowed, reason,
            self.actuators[stack.name].calls, expected,
        )
        self.outcomes.append(outcome)
        return outcome

    def run(self) -> dict[str, Any]:
        target = "urn:kinegrant:demo:target:door-7"
        zone_context = {"zone": "urn:kinegrant:demo:zone:1", "force_newtons": 20}

        self.attempt("happy-path", self.ros2, action="open", target=target,
                     purpose="delivery", context=zone_context, expected="ALLOW")
        self.attempt("happy-path", self.matter, action="close", target=target,
                     purpose="delivery", context=zone_context, expected="ALLOW")

        self._manual(
            "replay",
            self.ros2,
            self._replay_injection,
            action="open",
            expected="DENY",
        )
        self._manual(
            "untrusted-issuer",
            self.matter,
            self._untrusted_issuer_injection,
            action="close",
            expected="DENY",
        )
        self.attempt(
            "prompt-injection",
            self.ros2,
            action="delete_all",
            target=target,
            purpose="delivery",
            expected="DENY",
        )
        self.attempt(
            "physical-violation",
            self.matter,
            action="open",
            target=target,
            purpose="delivery",
            context={"zone": "urn:kinegrant:demo:zone:1", "force_newtons": 99},
            expected="DENY",
        )
        self.attempt(
            "record",
            self.ros2,
            action="record",
            target=target,
            purpose="audit",
            context=zone_context,
            expected="ALLOW",
        )

        # Forbidden combination: record + open were already observed, so
        # training on the same space must be denied.
        self.attempt(
            "forbidden-combination",
            self.matter,
            action="train_on_data",
            target=target,
            purpose="audit",
            expected="DENY",
        )

        passed = sum(outcome.passed for outcome in self.outcomes)
        compliance_ok = all(
            outcome.obligation_compliant
            for outcome in self.outcomes
            if outcome.allowed
        )
        return {
            "type": "kinegrant:RobotDemoReport",
            "schema_version": "0.1",
            "overall_result": (
                "PASS"
                if passed == len(self.outcomes) and compliance_ok
                else "FAIL"
            ),
            "summary": {
                "total": len(self.outcomes),
                "passed": passed,
                "failed": len(self.outcomes) - passed,
            },
            "actuator_calls": {
                stack: counter.calls for stack, counter in self.actuators.items()
            },
            "obligation_compliance_ok": compliance_ok,
            "outcomes": [outcome.to_dict() for outcome in self.outcomes],
            "limitations": [
                "Software simulation only; no physical actuation is claimed.",
                "Transport details are approximated by the adapters.",
            ],
        }

    def _replay_injection(self) -> None:
        target = "urn:kinegrant:demo:target:door-7"
        request = self.ros2.request(
            action="open", target=target, purpose="delivery",
            agent="urn:kinegrant:demo:agent:robot-1",
            context={"zone": "urn:kinegrant:demo:zone:1", "force_newtons": 20},
        )
        decision = self.engine.evaluate(request)
        capability = self.issuer.issue_scoped(
            request, decision, ttl_seconds=30, target=target,
            actions=["open"], purposes=["delivery"],
        )
        first = self.gate.authorize(capability, request)
        self.actuators["ros2"].execute(first)
        self.journal.record("open", target)
        self.gate.authorize(capability, request)  # must raise PermissionError

    def _untrusted_issuer_injection(self) -> None:
        target = "urn:kinegrant:demo:target:door-7"
        request = self.matter.request(
            action="close", target=target, purpose="delivery",
            agent="urn:kinegrant:demo:agent:robot-2",
            context={"zone": "urn:kinegrant:demo:zone:1", "force_newtons": 20},
        )
        decision = self.engine.evaluate(request)
        rogue = CapabilityIssuer(Ed25519KeyPair.generate())
        capability = rogue.issue_scoped(
            request, decision, ttl_seconds=30, target=target,
            actions=["close"], purposes=["delivery"],
        )
        self.gate.authorize(capability, request)  # must raise PermissionError


def main(argv: list[str] | None = None) -> int:
    report = RobotDemo().run()
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["overall_result"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
