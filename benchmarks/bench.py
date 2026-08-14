"""Micro-benchmarks for the KineGrant reference implementation.

Prints a JSON report of operations per second for policy evaluation, capability
issuance, gate authorization, receipt append, obligation compliance, and JCS
digesting. Results are machine-readable and CI-smoked with conservative lower
bounds.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from kinegrant.audit import ReceiptAuditor
from kinegrant.capability import CapabilityIssuer
from kinegrant.compliance import ObligationCompliance
from kinegrant.crypto import Ed25519KeyPair
from kinegrant.distribution import RevocationDistributor
from kinegrant.gate import ActionGate, InMemoryReplayStore
from kinegrant.gatekeeper import Gatekeeper
from kinegrant.models import ActionRequest, PolicyRule
from kinegrant.policy import PolicyEngine
from kinegrant.receipt import ReceiptLog
from kinegrant.revocation import (
    RevocationList,
    build_revocation_bundle,
    sign_revocation_bundle,
)
from kinegrant.sequence import ActionJournal, SequencePolicy


def _measure(operation, iterations: int) -> float:
    start = time.perf_counter()
    for _ in range(iterations):
        operation()
    elapsed = time.perf_counter() - start
    return iterations / elapsed if elapsed > 0 else float("inf")


def run(iterations: int = 2000) -> dict:
    authority = Ed25519KeyPair.generate()
    issuer = CapabilityIssuer(authority)
    rule = PolicyRule(
        "urn:kinegrant:bench:policy:1",
        authority.kid,
        "*",
        "allow",
        ("open",),
        obligations=("emitActionReceipt",),
    )
    engine = PolicyEngine([rule], trusted_policy_issuers={authority.kid})
    request = ActionRequest(
        "urn:kinegrant:bench:request:1",
        "urn:kinegrant:bench:agent:1",
        "urn:kinegrant:bench:target:door-7",
        "open",
        "delivery",
    )
    decision = engine.evaluate(request)
    executor = Ed25519KeyPair.generate()

    def policy_eval() -> None:
        engine.evaluate(request)

    def issue_cap() -> None:
        issuer.issue(request, decision, ttl_seconds=300)

    def gate_auth() -> None:
        capability = issuer.issue(request, decision, ttl_seconds=300)
        ActionGate(
            trusted_issuers={authority.kid},
            replay_store=InMemoryReplayStore(),
        ).authorize(capability, request)

    def receipt_append() -> None:
        capability = issuer.issue(request, decision, ttl_seconds=300)
        verified = ActionGate(
            trusted_issuers={authority.kid},
            replay_store=InMemoryReplayStore(),
        ).authorize(capability, request)
        ReceiptLog(executor).append(verified, result="succeeded")

    def obligation_compliance() -> None:
        capability = issuer.issue(request, decision, ttl_seconds=300)
        verified = ActionGate(
            trusted_issuers={authority.kid},
            replay_store=InMemoryReplayStore(),
        ).authorize(capability, request)
        receipt = ReceiptLog(executor).append(verified, result="succeeded")
        ObligationCompliance().evaluate(
            capability,
            [receipt],
            trusted_executors={executor.kid},
        )

    def gatekeeper_execute() -> None:
        capability = issuer.issue(request, decision, ttl_seconds=300)
        Gatekeeper(
            gate=ActionGate(
                trusted_issuers={authority.kid},
                replay_store=InMemoryReplayStore(),
            ),
            sequence=SequencePolicy([]),
            journal=ActionJournal(),
            receipt_log=ReceiptLog(executor),
        ).execute(capability, request, lambda verified: None)

    audit_log = ReceiptLog(executor)
    for index in range(10):
        audit_request = ActionRequest(
            f"urn:kinegrant:bench:audit:{index}",
            "urn:kinegrant:bench:agent:1",
            "urn:kinegrant:bench:target:door-7",
            "open",
            "delivery",
        )
        audit_decision = engine.evaluate(audit_request)
        audit_capability = issuer.issue(audit_request, audit_decision, ttl_seconds=300)
        audit_verified = ActionGate(
            trusted_issuers={authority.kid},
            replay_store=InMemoryReplayStore(),
        ).authorize(audit_capability, audit_request)
        audit_log.append(audit_verified, result="succeeded")

    def audit_summary() -> None:
        ReceiptAuditor(
            audit_log.entries,
            trusted_executors={executor.kid},
        ).summary()

    distribution_authority = Ed25519KeyPair.generate()
    distribution_rl = RevocationList()
    for index in range(5):
        distribution_rl.revoke("kinegrant:cap:" + f"{index:064x}")
    distribution_bundle = sign_revocation_bundle(
        build_revocation_bundle(
            distribution_rl,
            issuer=distribution_authority.kid,
        ),
        distribution_authority,
    )

    def revocation_distribute() -> None:
        RevocationDistributor(
            trusted_authorities={distribution_authority.kid}
        ).distribute(
            distribution_bundle,
            {
                "gate-1": RevocationList(),
                "gate-2": RevocationList(),
            },
        )

    from kinegrant.canonical import canonical_json

    def jcs_digest() -> None:
        canonical_json(request.to_dict())

    return {
        "type": "kinegrant:BenchmarkReport",
        "schema_version": "0.1",
        "iterations": iterations,
        "operations_per_second": {
            "policy_evaluate": round(_measure(policy_eval, iterations), 1),
            "capability_issue": round(_measure(issue_cap, iterations), 1),
            "gate_authorize": round(_measure(gate_auth, iterations), 1),
            "receipt_append": round(_measure(receipt_append, max(1, iterations // 10)), 1),
            "obligation_compliance": round(
                _measure(obligation_compliance, max(1, iterations // 10)), 1
            ),
            "gatekeeper_execute": round(
                _measure(gatekeeper_execute, max(1, iterations // 10)), 1
            ),
            "audit_summary": round(
                _measure(audit_summary, max(1, iterations // 10)), 1
            ),
            "revocation_distribute": round(
                _measure(revocation_distribute, max(1, iterations // 10)), 1
            ),
            "jcs_digest": round(_measure(jcs_digest, iterations), 1),
        },
    }


def main(argv: list[str] | None = None) -> int:
    report = run()
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
