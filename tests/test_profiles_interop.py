from __future__ import annotations

import unittest

from kinegrant.adapters.ieee7012 import myterms_to_rules
from kinegrant.adapters.odrl import KGP_ODRL_PROFILE, odrl_to_rules
from kinegrant.models import ActionRequest
from kinegrant.policy import PolicyEngine


class OdrlProfileTests(unittest.TestCase):
    def policy(self, permission: dict, *, profile: str | None = KGP_ODRL_PROFILE) -> dict:
        return {
            "@context": "http://www.w3.org/ns/odrl/2/",
            "@type": "Offer",
            "uid": "urn:kgp:odrl:door-7",
            "profile": profile,
            "assigner": "trusted-issuer",
            "permission": [permission],
        }

    def engine(self, doc: dict) -> PolicyEngine:
        return PolicyEngine(
            odrl_to_rules(doc),
            trusted_policy_issuers={"trusted-issuer"},
        )

    def request(self, **context: object) -> ActionRequest:
        return ActionRequest(
            request_id="req-odrl-1",
            agent="robot-1",
            target="door-7",
            action="open",
            purpose="delivery",
            context=context,
        )

    def test_kgp_physical_constraints_map_to_rules(self) -> None:
        doc = self.policy(
            {
                "target": "door-7",
                "assignee": "*",
                "action": "open",
                "constraint": [
                    {"leftOperand": "maxForceNewtons", "operator": "eq", "rightOperand": 50},
                    {"leftOperand": "maxVelocityMps", "operator": "lteq", "rightOperand": 1.5},
                    {"leftOperand": "allowedZones", "operator": "eq", "rightOperand": ["dock-1", "dock-2"]},
                    {"leftOperand": "minApprovalTier", "operator": "eq", "rightOperand": 1},
                ],
            }
        )
        rules = odrl_to_rules(doc)
        self.assertEqual(len(rules), 1)
        self.assertEqual(rules[0].constraints["max_force_newtons"], 50)
        self.assertEqual(rules[0].constraints["max_velocity_mps"], 1.5)
        self.assertEqual(rules[0].constraints["allowed_zones"], ["dock-1", "dock-2"])
        self.assertEqual(rules[0].constraints["min_approval_tier"], 1)
        self.assertEqual(rules[0].source["profile"], KGP_ODRL_PROFILE)

    def test_kgp_constraints_are_enforced_by_policy_engine(self) -> None:
        doc = self.policy(
            {
                "target": "door-7",
                "assignee": "*",
                "action": "open",
                "constraint": [
                    {"leftOperand": "maxForceNewtons", "operator": "eq", "rightOperand": 50},
                    {"leftOperand": "allowedZones", "operator": "eq", "rightOperand": ["dock-*"]},
                ],
            }
        )
        engine = self.engine(doc)
        self.assertTrue(
            engine.evaluate(self.request(force_newtons=20, zone="dock-1")).allowed
        )
        self.assertFalse(
            engine.evaluate(self.request(force_newtons=80, zone="dock-1")).allowed
        )
        self.assertFalse(
            engine.evaluate(self.request(force_newtons=20, zone="lobby")).allowed
        )
        self.assertFalse(engine.evaluate(self.request(force_newtons=20)).allowed)

    def test_kgp_constraints_without_profile_fail_closed(self) -> None:
        doc = self.policy(
            {
                "target": "door-7",
                "assignee": "*",
                "action": "open",
                "constraint": [
                    {"leftOperand": "maxForceNewtons", "operator": "eq", "rightOperand": 50},
                ],
            },
            profile="http://www.w3.org/ns/odrl/2/",
        )
        with self.assertRaises(ValueError):
            odrl_to_rules(doc)

    def test_invalid_kgp_values_are_rejected(self) -> None:
        cases = [
            {"leftOperand": "maxForceNewtons", "operator": "eq", "rightOperand": -1},
            {"leftOperand": "minApprovalTier", "operator": "eq", "rightOperand": 3},
            {"leftOperand": "allowedZones", "operator": "eq", "rightOperand": []},
        ]
        for constraint in cases:
            doc = self.policy(
                {
                    "target": "door-7",
                    "assignee": "*",
                    "action": "open",
                    "constraint": [constraint],
                }
            )
            with self.assertRaises(ValueError):
                odrl_to_rules(doc)


class Ieee7012ProfileTests(unittest.TestCase):
    def test_myterms_physical_constraints_flow_into_rules(self) -> None:
        doc = {
            "id": "urn:kgp:myterms:door-7",
            "subject": "person:owner",
            "issuer": "trusted-issuer",
            "target": "door-7",
            "profile": "https://kinegrant.com/profiles/ieee7012/kgp-v0.2",
            "version": "0.2",
            "terms": [
                {
                    "effect": "allow",
                    "action": "open",
                    "agents": ["robot-1"],
                    "purposes": ["delivery"],
                    "constraints": {
                        "max_force_newtons": 40,
                        "allowed_zones": ["dock-*"],
                        "min_approval_tier": 1,
                    },
                }
            ],
        }
        rules = myterms_to_rules(doc)
        self.assertEqual(rules[0].constraints["max_force_newtons"], 40)
        self.assertEqual(rules[0].constraints["allowed_zones"], ["dock-*"])
        self.assertEqual(rules[0].constraints["min_approval_tier"], 1)
        self.assertEqual(rules[0].source["profile"], doc["profile"])
        self.assertEqual(rules[0].source["version"], "0.2")

        engine = PolicyEngine(
            rules,
            trusted_policy_issuers={"trusted-issuer"},
        )
        request = ActionRequest(
            request_id="req-ieee-1",
            agent="robot-1",
            target="door-7",
            action="open",
            purpose="delivery",
            context={"force_newtons": 10, "zone": "dock-a"},
        )
        decision = engine.evaluate(request)
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.required_approval_tier, 1)

    def test_myterms_still_rejects_unknown_document_fields(self) -> None:
        doc = {
            "id": "urn:kgp:myterms:door-7",
            "subject": "person:owner",
            "target": "door-7",
            "terms": [{"effect": "deny", "action": "open"}],
            "unexpected": True,
        }
        with self.assertRaises(ValueError):
            myterms_to_rules(doc)


if __name__ == "__main__":
    unittest.main()
