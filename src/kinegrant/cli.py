from __future__ import annotations

import json

from .adapters.odrl import odrl_to_rules
from .capability import CapabilityIssuer
from .crypto import Ed25519KeyPair
from .gate import ActionGate
from .models import ActionRequest
from .policy import PolicyEngine
from .receipt import ReceiptLog, verify_receipt_chain


def run_demo() -> dict[str, object]:
    policy_document = {
        "@context": "http://www.w3.org/ns/odrl.jsonld",
        "uid": "urn:kinegrant:policy:delivery-door",
        "assigner": "urn:person:space-owner",
        "permission": [
            {
                "target": "urn:space:demo:door-7",
                "assignee": "urn:robot:delivery-1",
                "action": "open",
                "constraint": [
                    {"leftOperand": "purpose", "operator": "eq", "rightOperand": "delivery"},
                    {"leftOperand": "risk_tier", "operator": "eq", "rightOperand": 1},
                ],
                "duty": {"action": "emitActionReceipt"},
            }
        ],
        "prohibition": [
            {
                "target": "urn:space:demo:door-7",
                "assignee": "*",
                "action": ["record", "train_on_data"],
            }
        ],
    }
    request = ActionRequest(
        request_id="demo-request-001",
        agent="urn:robot:delivery-1",
        target="urn:space:demo:door-7",
        action="open",
        purpose="delivery",
        context={"risk_tier": 1, "human_present": True},
    )

    rules = odrl_to_rules(policy_document)
    engine = PolicyEngine(rules, trusted_policy_issuers={"urn:person:space-owner"})
    decision = engine.evaluate(request)
    authority = Ed25519KeyPair.generate()
    capability = CapabilityIssuer(authority).issue(request, decision, ttl_seconds=60)
    gate = ActionGate(trusted_issuers={authority.kid})
    claims = gate.authorize(capability, request)

    executor = Ed25519KeyPair.generate()
    log = ReceiptLog(executor)
    receipt = log.append(claims, result="succeeded", evidence_hash="sha256:" + "00" * 32)
    return {
        "decision": decision.to_dict(),
        "capability": capability,
        "receipt": receipt,
        "receipt_chain_valid": verify_receipt_chain(
            log.entries,
            trusted_executors={executor.kid},
            expected_capability_ids={claims["capability_id"]},
        ),
    }


def main() -> None:
    print(json.dumps(run_demo(), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
