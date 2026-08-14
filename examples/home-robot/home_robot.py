"""Home-robot deployment trace: open one door for delivery."""

from __future__ import annotations

import json
import sys

from kinegrant.capability import CapabilityIssuer
from kinegrant.compliance import ObligationCompliance
from kinegrant.crypto import Ed25519KeyPair
from kinegrant.gate import ActionGate, InMemoryReplayStore
from kinegrant.models import ActionRequest, PolicyRule
from kinegrant.policy import PolicyEngine
from kinegrant.receipt import ReceiptLog, verify_receipt_chain


def run() -> dict:
    authority = Ed25519KeyPair.generate()
    executor = Ed25519KeyPair.generate()
    issuer = CapabilityIssuer(authority)
    rule = PolicyRule(
        "urn:kinegrant:home:policy:delivery-door",
        authority.kid,
        "urn:kinegrant:home:target:door-*",
        "allow",
        ("open",),
        subjects=("urn:kinegrant:home:agent:*",),
        purposes=("delivery",),
        constraints={"max_force_newtons": 40, "allowed_zones": ["urn:kinegrant:home:zone:*"]},
        obligations=("emitActionReceipt",),
    )
    engine = PolicyEngine([rule], trusted_policy_issuers={authority.kid})
    request = ActionRequest(
        "urn:kinegrant:home:request:1",
        "urn:kinegrant:home:agent:delivery-robot-07",
        "urn:kinegrant:home:target:door-7",
        "open",
        "delivery",
        context={"zone": "urn:kinegrant:home:zone:1", "force_newtons": 12},
    )
    decision = engine.evaluate(request)
    capability = issuer.issue_scoped(
        request,
        decision,
        ttl_seconds=30,
        target=request.target,
        actions=["open"],
        purposes=["delivery"],
    )
    gate = ActionGate(
        trusted_issuers={authority.kid},
        replay_store=InMemoryReplayStore(),
    )
    verified = gate.authorize(capability, request)
    receipt = ReceiptLog(executor).append(
        verified,
        result="succeeded",
        request=request,
    )
    chain_ok = verify_receipt_chain(
        [receipt],
        trusted_executors={executor.kid},
        expected_capability_ids={verified["capability_id"]},
    )
    compliance = ObligationCompliance().evaluate(
        capability,
        [receipt],
        trusted_executors={executor.kid},
    )
    trace = {
        "scenario": "home-robot-delivery",
        "decision": decision.to_dict(),
        "capability_id": verified["capability_id"],
        "receipt_id": receipt["payload"]["receipt_id"],
        "chain_valid": chain_ok,
        "obligation_compliant": compliance.compliant,
        "passed": decision.allowed and chain_ok and compliance.compliant,
    }
    print(json.dumps(trace, indent=2, sort_keys=True))
    return trace


def main(argv: list[str] | None = None) -> int:
    return 0 if run()["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
