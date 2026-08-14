"""Matter / OPC UA / ROS 2 bridge demonstration.

Shows transport-shaped adapters producing KineGrant ActionRequests that flow
through one shared policy and gate, with explicit adapter-fidelity checks
(transport context and target shapes). Non-normative software demonstration;
no real Matter fabric, OPC UA server, or ROS 2 runtime is used.
"""

from __future__ import annotations

import json
from typing import Any

from ..adapters.matter import matter_command_request
from ..adapters.opcua import opcua_method_request
from ..adapters.ros2 import ros_action_request
from ..capability import CapabilityIssuer
from ..crypto import Ed25519KeyPair
from ..gate import ActionGate
from ..gatekeeper import Gatekeeper
from ..models import ActionRequest, PolicyRule
from ..policy import PolicyEngine
from ..receipt import ReceiptLog
from ..sequence import ActionJournal, SequencePolicy
from .robot_demo import RobotStack


def _build_ros2(*, action, target, purpose, agent, context, request_id):
    return ros_action_request(
        node_identity=agent,
        action_name=action,
        physical_target=target,
        purpose=purpose,
        request_id=request_id,
        context=context,
    )


def _build_matter(*, action, target, purpose, agent, context, request_id):
    return matter_command_request(
        fabric_identity=agent,
        node_id=target.rsplit(":", 1)[-1],
        endpoint=1,
        cluster="DoorLock",
        command=action,
        purpose=purpose,
        request_id=request_id,
        context=context,
    )


def _build_opcua(*, action, target, purpose, agent, context, request_id):
    return opcua_method_request(
        session_identity=agent,
        server_uri="opc.tcp://demo:4840",
        node_id=f"ns=1;s={target.rsplit(':', 1)[-1]}",
        method=action,
        purpose=purpose,
        request_id=request_id,
        context=context,
    )


def _policy(issuer: str) -> list[PolicyRule]:
    return [
        PolicyRule(
            "urn:kinegrant:demo:policy:bridge-allow",
            issuer,
            "*",
            "allow",
            ("open", "close"),
            subjects=("urn:kinegrant:demo:agent:*",),
            purposes=("delivery", "maintenance"),
            constraints={"max_force_newtons": 50, "allowed_zones": ["urn:kinegrant:demo:zone:*"]},
            obligations=("emitActionReceipt",),
        ),
        PolicyRule(
            "urn:kinegrant:demo:policy:bridge-deny-training",
            issuer,
            "*",
            "deny",
            ("train_on_data",),
        ),
    ]


class BridgeDemo:
    def __init__(self) -> None:
        self.authority = Ed25519KeyPair.generate()
        self.issuer = CapabilityIssuer(self.authority)
        self.engine = PolicyEngine(
            _policy(self.authority.kid),
            trusted_policy_issuers={self.authority.kid},
        )
        self.gate = ActionGate(trusted_issuers={self.authority.kid})
        self.executor = Ed25519KeyPair.generate()
        self.log = ReceiptLog(self.executor)
        self.journal = ActionJournal()
        self.sequence = SequencePolicy([])
        self.gatekeeper = Gatekeeper(
            gate=self.gate,
            sequence=self.sequence,
            journal=self.journal,
            receipt_log=self.log,
        )
        self.stacks = {
            "ros2": RobotStack("ros2", _build_ros2),
            "matter": RobotStack("matter", _build_matter),
            "opcua": RobotStack("opcua", _build_opcua),
        }
        self.outcomes: list[dict[str, Any]] = []
        self.fidelity: dict[str, dict[str, str]] = {}

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
        stack_name: str,
        *,
        action: str,
        purpose: str,
        expected: str,
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        stack = self.stacks[stack_name]
        request = stack.request(
            action=action,
            target="urn:kinegrant:demo:target:door-7",
            purpose=purpose,
            agent="urn:kinegrant:demo:agent:robot-1",
            context=context,
        )
        transport = request.context.get("transport")
        self.fidelity[stack_name] = {"target": request.target, "transport": str(transport)}
        try:
            capability = self._issue(request)
            outcome = self.gatekeeper.execute(
                capability,
                request,
                lambda verified: None,
            )
            allowed = outcome.allowed
            reason = "allow" if allowed else (outcome.reason or outcome.stage)
            obligation_compliant = outcome.obligation_compliant
        except (PermissionError, ValueError) as exc:
            allowed = False
            reason = f"{type(exc).__name__}: {exc}"
            obligation_compliant = None
        outcome = {
            "scenario": scenario,
            "stack": stack_name,
            "action": action,
            "allowed": allowed,
            "reason": reason,
            "expected": expected,
            "obligation_compliant": obligation_compliant,
            "passed": allowed == ("ALLOW" in expected),
        }
        self.outcomes.append(outcome)
        return outcome

    def run(self) -> dict[str, Any]:
        zone = {"zone": "urn:kinegrant:demo:zone:1", "force_newtons": 20}
        self.attempt("allowed", "matter", action="close", purpose="delivery", context=zone, expected="ALLOW")
        self.attempt("allowed", "opcua", action="open", purpose="maintenance", context=zone, expected="ALLOW")
        self.attempt("allowed", "ros2", action="close", purpose="delivery", context=zone, expected="ALLOW")
        self.attempt("wrong-purpose", "matter", action="open", purpose="training", context=zone, expected="DENY")

        expected_transports = {"ros2": "ros2", "matter": "matter", "opcua": "opcua"}
        fidelity_ok = all(
            self.fidelity[name]["transport"] == expected
            for name, expected in expected_transports.items()
        ) and all(
            self.fidelity[name]["target"].startswith(prefix)
            for name, prefix in (("matter", "matter:"), ("opcua", "opcua:"))
        )
        compliance_ok = all(
            outcome["obligation_compliant"]
            for outcome in self.outcomes
            if outcome["allowed"]
        )
        passed = sum(outcome["passed"] for outcome in self.outcomes)
        overall = (
            "PASS"
            if passed == len(self.outcomes) and fidelity_ok and compliance_ok
            else "FAIL"
        )
        return {
            "type": "kinegrant:BridgeDemoReport",
            "schema_version": "0.1",
            "overall_result": overall,
            "summary": {"total": len(self.outcomes), "passed": passed, "failed": len(self.outcomes) - passed},
            "adapter_fidelity": self.fidelity,
            "fidelity_ok": fidelity_ok,
            "obligation_compliance_ok": compliance_ok,
            "outcomes": self.outcomes,
            "limitations": [
                "Software demonstration only; no real transport was used.",
                "Non-normative reference bridges are not certifications.",
            ],
        }


def main(argv: list[str] | None = None) -> int:
    report = BridgeDemo().run()
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["overall_result"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
