"""Executable fleet-policy example.

Walks a fleet-operator lifecycle in one runnable trace:

1. A policy authority issues one signed policy bundle.
2. The bundle is distributed to two gates (``gate-a``, ``gate-b``).
3. Each gate evaluates an allowed action and a denied action.
4. The fleet distribution report is verified against the bundle.
5. The policy is revoked; the previously allowed action is now denied.

This is a software simulation; it does not move a real actuator.
"""

from __future__ import annotations

import json
from typing import Any

from kinegrant.crypto import Ed25519KeyPair
from kinegrant.models import ActionRequest, PolicyRule
from kinegrant.policy import PolicyEngine
from kinegrant.policy_bundle import (
    PolicyAuthority,
    PolicyDistributor,
    PolicyRegistry,
    rules_from_bundle,
    verify_policy_distribution_report,
)


def _rules(policy_id: str, authority: PolicyAuthority) -> tuple[PolicyRule, ...]:
    return (
        PolicyRule(
            policy_id,
            authority.kid,
            "urn:space:demo:door-1",
            "allow",
            ("open",),
            subjects=("urn:robot:demo:delivery-1",),
            purposes=("delivery",),
            obligations=("emitActionReceipt",),
        ),
    )


def _allowed_request() -> ActionRequest:
    return ActionRequest(
        "urn:kinegrant:demo:request:allowed",
        "urn:robot:demo:delivery-1",
        "urn:space:demo:door-1",
        "open",
        "delivery",
    )


def _denied_request() -> ActionRequest:
    return ActionRequest(
        "urn:kinegrant:demo:request:denied",
        "urn:robot:demo:delivery-1",
        "urn:space:demo:door-1",
        "open",
        "training",
    )


def _engine_from_registry(
    registry: PolicyRegistry, policy_id: str, authority: PolicyAuthority
) -> PolicyEngine:
    bundle = registry.current(policy_id)
    if bundle is None:
        raise RuntimeError("policy not activated at this gate")
    return PolicyEngine(
        rules_from_bundle(bundle, trusted_authorities={authority.kid}),
        trusted_policy_issuers={authority.kid},
    )


def run() -> dict[str, Any]:
    authority = PolicyAuthority(Ed25519KeyPair.generate())
    policy_id = "urn:kinegrant:demo:policy:fleet-door"

    # 1. Publish one signed policy bundle.
    bundle = authority.publish(
        policy_id,
        _rules(policy_id, authority),
        ttl_seconds=3600,
    )

    # 2. Distribute it to two gates.
    gate_a_registry = PolicyRegistry(trusted_authorities={authority.kid})
    gate_b_registry = PolicyRegistry(trusted_authorities={authority.kid})
    distributor = PolicyDistributor(trusted_authorities={authority.kid})
    report = distributor.distribute(
        bundle,
        {"gate-a": gate_a_registry, "gate-b": gate_b_registry},
    )

    # 3. Verify the fleet report, then evaluate at each gate.
    verified = verify_policy_distribution_report(
        report,
        bundle,
        trusted_authorities={authority.kid},
    )
    gate_a_engine = _engine_from_registry(gate_a_registry, policy_id, authority)
    gate_b_engine = _engine_from_registry(gate_b_registry, policy_id, authority)
    allowed_a = gate_a_engine.evaluate(_allowed_request()).allowed
    allowed_b = gate_b_engine.evaluate(_allowed_request()).allowed
    denied_a = not gate_a_engine.evaluate(_denied_request()).allowed
    denied_b = not gate_b_engine.evaluate(_denied_request()).allowed

    # 4. Revoke the policy; the allowed action must now be denied.
    gate_a.revoke(policy_id, 1, reason="fleet rollback")
    gate_b.revoke(policy_id, 1, reason="fleet rollback")
    revoked_a = gate_a.current(policy_id) is None
    revoked_b = gate_b.current(policy_id) is None
    empty_engine = PolicyEngine((), trusted_policy_issuers={authority.kid})
    allowed_after_revoke = empty_engine.evaluate(_allowed_request()).allowed

    passed = (
        verified["overall_result"] == "PASS"
        and report["summary"]["applied_total"] == 2
        and allowed_a
        and allowed_b
        and denied_a
        and denied_b
        and revoked_a
        and revoked_b
        and not allowed_after_revoke
    )
    return {
        "type": "kinegrant:FleetPolicyDemo",
        "schema_version": "0.1",
        "passed": passed,
        "phases": {
            "distribution": {
                "applied_total": report["summary"]["applied_total"],
                "verified": verified["overall_result"],
            },
            "evaluation": {
                "allowed_gate_a": allowed_a,
                "allowed_gate_b": allowed_b,
                "denied_gate_a": denied_a,
                "denied_gate_b": denied_b,
            },
            "revocation": {
                "revoked_gate_a": revoked_a,
                "revoked_gate_b": revoked_b,
                "allowed_after_revoke": allowed_after_revoke,
            },
        },
    }


def main() -> int:
    result = run()
    print(json.dumps(result, indent=2, sort_keys=True))
    print(
        "summary: distribute=2 gates, allowed=2/2, denied=2/2, "
        "revoked=2/2, allowed_after_revoke=False"
    )
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())