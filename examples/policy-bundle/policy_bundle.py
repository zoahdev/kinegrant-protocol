"""Executable policy-bundle lifecycle example (v2.4).

Walks the complete signed policy distribution lifecycle in one runnable
trace: publish -> enforce -> ODRL round trip -> fleet distribution ->
upgrade (no downgrade) -> static analysis -> bounded coverage -> revocation
rollback -> fail-closed with no current version. Every phase records a
machine-readable outcome and the final ``passed`` flag requires all phases.

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
    analyze_policy_bundle,
    bundle_to_odrl,
    policy_bundle_coverage,
    rules_from_bundle,
    verify_policy_bundle,
)
from kinegrant.adapters.odrl import odrl_to_rules


def _rules(policy_id: str, authority: PolicyAuthority, purposes: tuple[str, ...]) -> list[PolicyRule]:
    return [
        PolicyRule(
            policy_id,
            authority.kid,
            "urn:space:demo:door-1",
            "allow",
            ("open",),
            subjects=("urn:robot:demo:delivery-1",),
            purposes=purposes,
            obligations=("emitActionReceipt",),
        )
    ]


def _request() -> ActionRequest:
    return ActionRequest(
        "urn:kinegrant:demo:request:1",
        "urn:robot:demo:delivery-1",
        "urn:space:demo:door-1",
        "open",
        "delivery",
    )


def run() -> dict[str, Any]:
    phases: dict[str, Any] = {}
    authority = PolicyAuthority(Ed25519KeyPair.generate())
    policy_id = "urn:kinegrant:demo:policy:delivery-door"

    # Phase 1: publish, enforce, and map to ODRL.
    v1 = authority.publish(
        policy_id,
        _rules(policy_id, authority, ("delivery",)),
        ttl_seconds=3600,
    )
    request = _request()
    engine = PolicyEngine(
        rules_from_bundle(v1, trusted_authorities={authority.kid}),
        trusted_policy_issuers={authority.kid},
    )
    decision = engine.evaluate(request)
    odrl_document = bundle_to_odrl(
        v1,
        trusted_authorities={authority.kid},
    )
    round_trip = PolicyEngine(
        odrl_to_rules(odrl_document),
        trusted_policy_issuers={authority.kid},
    ).evaluate(request)
    phases["publish_enforce_odrl"] = {
        "allowed": decision.allowed,
        "odrl_round_trip_allowed": round_trip.allowed,
        "odrl_uid": odrl_document["uid"],
    }

    # Phase 2: fleet distribution, upgrade, no downgrade.
    gate_a = PolicyRegistry(trusted_authorities={authority.kid})
    gate_b = PolicyRegistry(trusted_authorities={authority.kid})
    fleet = PolicyDistributor(
        trusted_authorities={authority.kid}
    ).distribute(v1, {"gate-a": gate_a, "gate-b": gate_b})
    v2 = authority.publish(
        policy_id,
        _rules(policy_id, authority, ("delivery", "maintenance")),
        ttl_seconds=3600,
    )
    upgrade = PolicyDistributor(
        trusted_authorities={authority.kid}
    ).distribute(v2, {"gate-a": gate_a, "gate-b": gate_b})
    noop = PolicyDistributor(
        trusted_authorities={authority.kid}
    ).distribute(v1, {"gate-a": gate_a})
    phases["fleet"] = {
        "initial_applied": fleet["summary"]["applied_total"],
        "upgrade_applied": upgrade["summary"]["applied_total"],
        "downgrade_noop": noop["summary"]["already_present_total"],
        "gate_a_current": gate_a.current(policy_id)["version"],
    }

    # Phase 3: static analysis and bounded coverage on the current version.
    analysis = analyze_policy_bundle(
        v2,
        trusted_authorities={authority.kid},
    )
    coverage = policy_bundle_coverage(
        v2,
        trusted_authorities={authority.kid},
        targets=("urn:space:demo:door-1",),
    )
    phases["audit"] = {
        "analysis_result": analysis["overall_result"],
        "coverage_result": coverage["overall_result"],
        "coverage_allowed": coverage["summary"]["allowed"],
    }

    # Phase 4: revocation rollback and fail-closed.
    registry = PolicyRegistry(trusted_authorities={authority.kid})
    registry.activate(v1)
    registry.activate(v2)
    registry.revoke(policy_id, 2, reason="emergency rollback")
    rolled_back = registry.current(policy_id)["version"]
    registry.revoke(policy_id, 1, reason="full withdrawal")
    fail_closed = registry.current(policy_id) is None
    phases["revocation"] = {
        "rolled_back_to": rolled_back,
        "fail_closed_none": fail_closed,
    }

    # Phase 5: fail-closed verification of tampering and wrong authority.
    tampered = dict(v2)
    tampered["payload"] = dict(v2["payload"])
    tampered["payload"]["rules"] = []
    tamper_rejected = False
    try:
        verify_policy_bundle(tampered, trusted_authorities={authority.kid})
    except ValueError:
        tamper_rejected = True
    outsider = PolicyAuthority(Ed25519KeyPair.generate())
    authority_rejected = False
    try:
        verify_policy_bundle(v2, trusted_authorities={outsider.kid})
    except ValueError:
        authority_rejected = True
    phases["fail_closed"] = {
        "tamper_rejected": tamper_rejected,
        "wrong_authority_rejected": authority_rejected,
    }

    passed = (
        decision.allowed
        and round_trip.allowed
        and fleet["summary"]["applied_total"] == 2
        and upgrade["summary"]["applied_total"] == 2
        and noop["summary"]["already_present_total"] == 1
        and analysis["overall_result"] == "PASS"
        and coverage["overall_result"] == "PASS"
        and rolled_back == 1
        and fail_closed
        and tamper_rejected
        and authority_rejected
    )
    return {
        "type": "kinegrant:PolicyBundleLifecycleDemo",
        "schema_version": "0.1",
        "passed": passed,
        "phases": phases,
    }


def main() -> int:
    print(json.dumps(run(), indent=2, sort_keys=True))
    return 0 if run()["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
