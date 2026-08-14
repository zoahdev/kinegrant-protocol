"""Cross-system ROS 2 + MCP action-gate demonstration (v0.6 draft).

One shared KineGrant policy governs two different execution stacks:

- a ROS 2-style stack that sends action goals through ``Ros2GoalGate``; and
- an MCP-style agent stack that calls tools through ``mcp_tool_request``.

Both stacks use the same PolicyEngine, CapabilityIssuer, ActionGate, signed
ReceiptLog, ActionJournal, and SequencePolicy. Fault injection covers replay,
untrusted issuers, wrong purpose, physical-limit violation, and forbidden
combinations. This is a non-normative software demonstration: no real ROS 2
node or MCP server is used.
"""

from __future__ import annotations

import json
from typing import Any

from ..adapters.mcp import mcp_tool_request
from ..adapters.ros2 import ros_action_request
from ..bridges.ros2 import Ros2GoalGate
from ..capability import CapabilityIssuer
from ..crypto import Ed25519KeyPair
from ..gate import ActionGate
from ..models import ActionRequest, PolicyRule
from ..policy import PolicyEngine
from ..receipt import ReceiptLog, verify_receipt_chain
from ..sequence import ActionJournal, ForbiddenCombination, SequencePolicy

AGENT = "urn:kinegrant:demo:agent:robot-1"
TARGET = "urn:kinegrant:demo:target:door-7"
ZONE = "urn:kinegrant:demo:zone:1"


def _policy(issuer: str) -> list[PolicyRule]:
    return [
        PolicyRule(
            "urn:kinegrant:demo:policy:cross-allow",
            issuer,
            "urn:kinegrant:demo:target:*",
            "allow",
            ("open", "close", "enter"),
            subjects=("urn:kinegrant:demo:agent:*",),
            purposes=("delivery", "maintenance"),
            constraints={"max_force_newtons": 50, "allowed_zones": ["urn:kinegrant:demo:zone:*"]},
            obligations=("emitActionReceipt",),
        ),
        PolicyRule(
            "urn:kinegrant:demo:policy:cross-deny-training",
            issuer,
            "*",
            "deny",
            ("train_on_data",),
        ),
    ]


def _sequence_policy() -> SequencePolicy:
    return SequencePolicy(
        [
            ForbiddenCombination(
                "urn:kinegrant:demo:combo:open-enter",
                patterns=(
                    ("open", "urn:kinegrant:demo:target:*"),
                ),
                trigger=("enter", "urn:kinegrant:demo:target:*"),
            )
        ]
    )


class Ros2McpDemo:
    """Shared-policy demo over a ROS 2-style stack and an MCP-style stack."""

    def __init__(self) -> None:
        self.authority = Ed25519KeyPair.generate()
        self.untrusted = Ed25519KeyPair.generate()
        self.issuer = CapabilityIssuer(self.authority)
        self.untrusted_issuer = CapabilityIssuer(self.untrusted)
        self.engine = PolicyEngine(
            _policy(self.authority.kid),
            trusted_policy_issuers={self.authority.kid},
        )
        self.gate = ActionGate(trusted_issuers={self.authority.kid})
        self.ros2_gate = Ros2GoalGate(self.gate)
        self.log = ReceiptLog(self.authority)
        self.journal = ActionJournal()
        self.sequence = _sequence_policy()
        self.outcomes: list[dict[str, Any]] = []
        self._last_capability: dict[str, Any] | None = None

    def _request(
        self,
        stack: str,
        *,
        action: str,
        purpose: str,
        request_id: str,
        context: dict[str, Any],
    ) -> ActionRequest:
        if stack == "ros2":
            return ros_action_request(
                node_identity=AGENT,
                action_name=action,
                physical_target=TARGET,
                purpose=purpose,
                request_id=request_id,
                context=context,
            )
        return mcp_tool_request(
            server_identity=AGENT,
            tool_name=action,
            physical_target=TARGET,
            purpose=purpose,
            request_id=request_id,
            context=context,
        )

    def _consume(
        self,
        stack: str,
        request: ActionRequest,
        *,
        capability: dict[str, Any] | None = None,
        untrusted: bool = False,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        verdict = self.sequence.evaluate(request, self.journal)
        if not verdict.allowed:
            matched = ",".join(verdict.matched_combination_ids)
            raise PermissionError(f"forbidden_combination:{matched}")
        decision = self.engine.evaluate(request)
        if not decision.allowed:
            raise PermissionError(decision.reason)
        issuer = self.untrusted_issuer if untrusted else self.issuer
        issued = capability or issuer.issue_scoped(
            request,
            decision,
            ttl_seconds=30,
            target=request.target,
            actions=[request.action],
            purposes=[request.purpose],
            approval_tier=decision.required_approval_tier,
        )
        if stack == "ros2":
            verified = self.ros2_gate.accept_goal(issued, request)
        else:
            verified = self.gate.authorize(issued, request)
        return issued, verified

    def _attempt(
        self,
        scenario: str,
        stack: str,
        *,
        action: str,
        purpose: str,
        expected: str,
        context: dict[str, Any],
        replay: bool = False,
        untrusted: bool = False,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        request = self._request(
            stack,
            action=action,
            purpose=purpose,
            request_id=request_id or f"req-{scenario}",
            context=context,
        )
        try:
            capability, verified = self._consume(
                stack,
                request,
                capability=self._last_capability if replay else None,
                untrusted=untrusted,
            )
            if replay or untrusted:
                raise AssertionError("denied scenario unexpectedly passed")
            self.log.append(verified, result="succeeded", request=request)
            self.journal.record(action=request.action, target=request.target)
            self._last_capability = capability
            allowed = True
            reason = "allow"
        except (PermissionError, ValueError, AssertionError) as exc:
            allowed = False
            reason = f"{type(exc).__name__}: {exc}"
        outcome = {
            "scenario": scenario,
            "stack": stack,
            "action": action,
            "purpose": purpose,
            "allowed": allowed,
            "reason": reason,
            "expected": expected,
            "passed": allowed == ("ALLOW" in expected),
        }
        self.outcomes.append(outcome)
        return outcome

    def run(self) -> dict[str, Any]:
        within = {"zone": ZONE, "force_newtons": 20}
        over_limit = {"zone": ZONE, "force_newtons": 80}
        self._attempt(
            "ros2-allow-open", "ros2", action="open", purpose="delivery",
            expected="ALLOW", context=within, request_id="req-open-1",
        )
        self._attempt(
            "mcp-allow-close", "mcp", action="close", purpose="maintenance",
            expected="ALLOW", context=within, request_id="req-close-1",
        )
        self._attempt(
            "ros2-replay", "ros2", action="open", purpose="delivery",
            expected="DENY", context=within, replay=True, request_id="req-open-1",
        )
        self._attempt(
            "mcp-untrusted-issuer", "mcp", action="close", purpose="maintenance",
            expected="DENY", context=within, untrusted=True, request_id="req-close-2",
        )
        self._attempt(
            "ros2-wrong-purpose", "ros2", action="open", purpose="training",
            expected="DENY", context=within, request_id="req-open-2",
        )
        self._attempt(
            "mcp-physical-limit", "mcp", action="open", purpose="delivery",
            expected="DENY", context=over_limit, request_id="req-open-3",
        )
        self._attempt(
            "ros2-enter-after-open", "ros2", action="enter", purpose="delivery",
            expected="DENY", context=within, request_id="req-enter-1",
        )

        receipts_ok = verify_receipt_chain(
            self.log.entries,
            trusted_executors={self.authority.kid},
        )
        passed = sum(outcome["passed"] for outcome in self.outcomes)
        overall = (
            "PASS"
            if passed == len(self.outcomes) and receipts_ok and len(self.log.entries) == 2
            else "FAIL"
        )
        return {
            "type": "kinegrant:Ros2McpDemoReport",
            "schema_version": "0.1",
            "overall_result": overall,
            "summary": {
                "total": len(self.outcomes),
                "passed": passed,
                "failed": len(self.outcomes) - passed,
            },
            "receipt_count": len(self.log.entries),
            "receipts_verified": receipts_ok,
            "outcomes": self.outcomes,
            "limitations": [
                "Software demonstration only; no real ROS 2 node or MCP server was used.",
                "Non-normative reference bridges are not certifications.",
            ],
        }


def main(argv: list[str] | None = None) -> int:
    report = Ros2McpDemo().run()
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["overall_result"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
