"""KineGrant beginner example: request -> policy -> capability -> gate -> receipt.

This walks the complete authorization boundary with heavy comments so you can
see what each step does and why it exists. Run it from the repository root:

    pip install -e .
    python examples/hello-kinegrant.py

Expected: the "open door" request passes and produces a signed receipt; the
"record" request is denied by the same policy.
"""
from __future__ import annotations

import json

from kinegrant import (
    ActionGate,
    ActionRequest,
    CapabilityIssuer,
    Ed25519KeyPair,
    PolicyEngine,
    PolicyRule,
    ReceiptLog,
    verify_receipt_chain,
)


def main() -> None:
    # 1. POLICY --- the robot owner describes what this robot may do.
    #    deny-overrides + default deny: anything not explicitly allowed is
    #    rejected, and any deny rule wins over any allow rule.
    rules = (
        PolicyRule(
            policy_id="urn:kinegrant:policy:front-door",
            issuer="urn:person:space-owner",   # who is trusted to grant this
            target="urn:space:my-building:door-1",
            effect="allow",
            actions=("open",),                 # only opening is permitted
            subjects=("urn:robot:delivery-1",),
            purposes=("delivery",),            # only for deliveries
            obligations=("emitActionReceipt",),  # must leave an audit trail
        ),
        PolicyRule(
            policy_id="urn:kinegrant:policy:no-recording",
            issuer="urn:person:space-owner",
            target="urn:space:my-building:door-1",
            effect="deny",
            actions=("record",),               # recording is never permitted
            subjects=("*",),
            purposes=("*",),
        ),
    )
    engine = PolicyEngine(rules, trusted_policy_issuers={"urn:person:space-owner"})

    # 2. REQUEST --- the robot asks to open the door for a delivery.
    request = ActionRequest(
        request_id="demo-request-001",
        agent="urn:robot:delivery-1",
        target="urn:space:my-building:door-1",
        action="open",
        purpose="delivery",
    )
    decision = engine.evaluate(request)
    print("1. policy decision:", "allow" if decision.allowed else "deny")
    assert decision.allowed

    # 3. CAPABILITY --- an authority turns the allow decision into a
    #    short-lived, one-time, Ed25519-signed token bound to this exact
    #    request. Nothing reusable is minted.
    authority = Ed25519KeyPair.generate()
    capability = CapabilityIssuer(authority).issue(request, decision, ttl_seconds=60)

    # 4. GATE --- the door-side gate re-checks the capability (signature,
    #    issuer trust, expiry, replay) and atomically consumes it once.
    gate = ActionGate(trusted_issuers={authority.kid})
    claims = gate.authorize(capability, request)    # second use would raise
    print("2. gate consumed capability:", claims["capability_id"])

    # 5. RECEIPT --- the executor (the door) signs a hash-chained receipt so
    #    auditors can later prove what happened and who did it.
    executor = Ed25519KeyPair.generate()
    log = ReceiptLog(executor)
    receipt = log.append(claims, result="succeeded", evidence_hash="sha256:" + "00" * 32)
    # The receipt is a signed envelope: {alg, kid, payload, signature}.
    print("3. signed receipt for capability:", receipt["payload"]["capability_id"])
    print(
        "4. receipt chain valid:",
        verify_receipt_chain(
            log.entries,
            trusted_executors={executor.kid},
            expected_capability_ids={claims["capability_id"]},
        ),
    )

    # 6. DENIAL --- the same policy refuses to let the robot record.
    bad_request = ActionRequest(
        request_id="demo-request-002",
        agent="urn:robot:delivery-1",
        target="urn:space:my-building:door-1",
        action="record",
        purpose="surveillance",
    )
    denial = engine.evaluate(bad_request)
    print("5. recording decision:", "allow" if denial.allowed else "deny")
    assert not denial.allowed

    print(json.dumps({"passed": True}, indent=2))


if __name__ == "__main__":
    main()
