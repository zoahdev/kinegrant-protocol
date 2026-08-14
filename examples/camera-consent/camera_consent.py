"""Camera-consent deployment trace: record allowed, training denied."""

from __future__ import annotations

import json
import sys

from kinegrant.capability import CapabilityIssuer
from kinegrant.crypto import Ed25519KeyPair
from kinegrant.gate import ActionGate, InMemoryReplayStore
from kinegrant.models import ActionRequest, PolicyRule
from kinegrant.policy import PolicyEngine
from kinegrant.sequence import ActionJournal, ForbiddenCombination, SequencePolicy


def run() -> dict:
    authority = Ed25519KeyPair.generate()
    issuer = CapabilityIssuer(authority)
    target = "urn:kinegrant:camera:target:lobby"
    allow_record = PolicyRule(
        "urn:kinegrant:camera:policy:record",
        authority.kid,
        target,
        "allow",
        ("record",),
        subjects=("urn:kinegrant:camera:agent:*",),
        purposes=("security",),
    )
    deny_training = PolicyRule(
        "urn:kinegrant:camera:policy:deny-training",
        authority.kid,
        target,
        "deny",
        ("train_on_data",),
    )
    engine = PolicyEngine(
        [allow_record, deny_training],
        trusted_policy_issuers={authority.kid},
    )
    journal = ActionJournal()
    sequence = SequencePolicy(
        [
            ForbiddenCombination(
                "record-then-train",
                (("record", target),),
                trigger=("train_on_data", target),
            )
        ]
    )
    record_request = ActionRequest(
        "urn:kinegrant:camera:request:record",
        "urn:kinegrant:camera:agent:camera-01",
        target,
        "record",
        "security",
    )
    train_request = ActionRequest(
        "urn:kinegrant:camera:request:train",
        "urn:kinegrant:camera:agent:camera-01",
        target,
        "train_on_data",
        "model-improvement",
    )

    record_decision = engine.evaluate(record_request)
    capability = issuer.issue_scoped(
        record_request,
        record_decision,
        ttl_seconds=30,
        target=target,
        actions=["record"],
        purposes=["security"],
    )
    gate = ActionGate(
        trusted_issuers={authority.kid},
        replay_store=InMemoryReplayStore(),
    )
    verified = gate.authorize(capability, record_request)
    journal.record("record", target)

    policy_denied = not engine.evaluate(train_request).allowed
    sequence_verdict = sequence.evaluate(train_request, journal)
    trace = {
        "scenario": "camera-consent",
        "record_allowed": record_decision.allowed,
        "record_consumed": verified["capability_id"].startswith("kinegrant:cap:"),
        "train_policy_denied": policy_denied,
        "train_sequence_denied": not sequence_verdict.allowed,
        "passed": (
            record_decision.allowed
            and policy_denied
            and not sequence_verdict.allowed
        ),
    }
    print(json.dumps(trace, indent=2, sort_keys=True))
    return trace


def main(argv: list[str] | None = None) -> int:
    return 0 if run()["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
