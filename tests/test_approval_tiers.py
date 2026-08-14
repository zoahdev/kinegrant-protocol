from __future__ import annotations

import json
import unittest
from pathlib import Path

import jsonschema

from kinegrant.capability import CapabilityIssuer
from kinegrant.crypto import Ed25519KeyPair
from kinegrant.gate import ActionGate, InMemoryReplayStore
from kinegrant.models import ActionRequest, PolicyRule
from kinegrant.policy import PolicyEngine
from kinegrant.vocabulary import approval_tier_from_risk


class ApprovalTierTests(unittest.TestCase):
    def setUp(self) -> None:
        self.issuer = CapabilityIssuer(Ed25519KeyPair.generate())
        self.request = ActionRequest(
            request_id="req-tier-1",
            agent="robot-1",
            target="door-7",
            action="open",
            purpose="delivery",
        )

    def rule(self, tier: int | None = None, policy_id: str = "tier-1") -> PolicyRule:
        constraints = {} if tier is None else {"min_approval_tier": tier}
        return PolicyRule(
            policy_id=policy_id,
            issuer=self.issuer.key_pair.kid,
            target="door-7",
            effect="allow",
            actions=("open",),
            constraints=constraints,
        )

    def test_decision_carries_required_approval_tier(self) -> None:
        engine = PolicyEngine(
            [self.rule(tier=2)],
            trusted_policy_issuers={self.issuer.key_pair.kid},
        )
        decision = engine.evaluate(self.request)
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.required_approval_tier, 2)
        self.assertEqual(decision.to_dict()["required_approval_tier"], 2)

    def test_multiple_allows_use_highest_tier(self) -> None:
        engine = PolicyEngine(
            [self.rule(tier=1, policy_id="t1"), self.rule(tier=2, policy_id="t2")],
            trusted_policy_issuers={self.issuer.key_pair.kid},
        )
        decision = engine.evaluate(self.request)
        self.assertEqual(decision.required_approval_tier, 2)

    def test_default_tier_is_zero(self) -> None:
        engine = PolicyEngine(
            [self.rule()],
            trusted_policy_issuers={self.issuer.key_pair.kid},
        )
        decision = engine.evaluate(self.request)
        self.assertEqual(decision.required_approval_tier, 0)

    def test_invalid_tiers_are_rejected_at_construction(self) -> None:
        for bad in (-1, 3, True, "2"):
            with self.assertRaises(ValueError):
                PolicyEngine(
                    [self.rule(tier=bad)],  # type: ignore[arg-type]
                    trusted_policy_issuers={self.issuer.key_pair.kid},
                )

    def test_risk_tier_mapping(self) -> None:
        self.assertEqual(approval_tier_from_risk(1), 0)
        self.assertEqual(approval_tier_from_risk(2), 0)
        self.assertEqual(approval_tier_from_risk(3), 1)
        self.assertEqual(approval_tier_from_risk(4), 2)
        self.assertEqual(approval_tier_from_risk(5), 2)
        for bad in (0, 6, True):
            with self.assertRaises(ValueError):
                approval_tier_from_risk(bad)  # type: ignore[arg-type]

    def test_approval_tier_flows_into_v02_capability(self) -> None:
        engine = PolicyEngine(
            [self.rule(tier=2)],
            trusted_policy_issuers={self.issuer.key_pair.kid},
        )
        decision = engine.evaluate(self.request)
        envelope = self.issuer.issue_scoped(
            self.request,
            decision,
            approval_tier=decision.required_approval_tier,
        )
        self.assertEqual(envelope["payload"]["approval_tier"], 2)
        gate = ActionGate(
            trusted_issuers={self.issuer.key_pair.kid},
            replay_store=InMemoryReplayStore(),
        )
        verified = gate.authorize(envelope, self.request)
        self.assertEqual(verified["approval_tier"], 2)

    def test_decision_matches_published_schema(self) -> None:
        engine = PolicyEngine(
            [self.rule(tier=1)],
            trusted_policy_issuers={self.issuer.key_pair.kid},
        )
        schema_path = (
            Path(__file__).resolve().parents[1]
            / "spec"
            / "schemas"
            / "decision.schema.json"
        )
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        jsonschema.validate(engine.evaluate(self.request).to_dict(), schema)


if __name__ == "__main__":
    unittest.main()
