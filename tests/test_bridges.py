from __future__ import annotations

import unittest

from kinegrant.bridges import Ros2GoalGate, Sros2PolicyMapping
from kinegrant.capability import CapabilityIssuer
from kinegrant.crypto import Ed25519KeyPair
from kinegrant.gate import ActionGate, InMemoryReplayStore
from kinegrant.models import ActionRequest, PolicyRule
from kinegrant.policy import PolicyEngine


class Ros2GoalGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.authority = Ed25519KeyPair.generate()
        self.issuer = CapabilityIssuer(self.authority)
        self.request = ActionRequest(
            request_id="req-ros2-1",
            agent="robot-1",
            target="door-7",
            action="open",
            purpose="delivery",
        )
        rule = PolicyRule(
            policy_id="ros2-rule-1",
            issuer=self.authority.kid,
            target="door-7",
            effect="allow",
            actions=("open",),
        )
        self.decision = PolicyEngine(
            [rule], trusted_policy_issuers={self.authority.kid}
        ).evaluate(self.request)
        self.goal_gate = Ros2GoalGate(
            ActionGate(
                trusted_issuers={self.authority.kid},
                replay_store=InMemoryReplayStore(),
            )
        )

    def test_accept_goal_verifies_and_consumes(self) -> None:
        capability = self.issuer.issue(self.request, self.decision, ttl_seconds=30)
        accepted, verified, reason = self.goal_gate.try_accept_goal(capability, self.request)
        self.assertTrue(accepted)
        self.assertIsNotNone(verified)
        self.assertIsNone(reason)

    def test_replay_is_rejected_as_goal(self) -> None:
        capability = self.issuer.issue(self.request, self.decision, ttl_seconds=30)
        self.goal_gate.accept_goal(capability, self.request)
        accepted, _, reason = self.goal_gate.try_accept_goal(capability, self.request)
        self.assertFalse(accepted)
        self.assertIn("replay", reason or "")


class Sros2PolicyMappingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.rules = [
            PolicyRule(
                policy_id="p-allow",
                issuer="issuer",
                target="door-*",
                effect="allow",
                actions=("open", "close"),
                subjects=("robot-*",),
                purposes=("delivery",),
            ),
            PolicyRule(
                policy_id="p-deny",
                issuer="issuer",
                target="*",
                effect="deny",
                actions=("train_on_data",),
            ),
        ]

    def test_mapping_is_deterministic_and_complete(self) -> None:
        mapping = Sros2PolicyMapping(self.rules, domain=1).to_dict()
        self.assertEqual(mapping["schema"], "kinegrant:sros2-mapping:v0.1")
        self.assertEqual(mapping["domain"], 1)
        self.assertEqual(mapping["enforcement"], "enforce")
        actions = {item["action"] for item in mapping["declarations"]}
        self.assertEqual(actions, {"open", "close", "train_on_data"})
        deny = [item for item in mapping["declarations"] if item["action"] == "train_on_data"]
        self.assertEqual(deny[0]["effect"], "deny")
        self.assertEqual(mapping, Sros2PolicyMapping(self.rules, domain=1).to_dict())

    def test_xml_rendering_escapes_and_contains_rules(self) -> None:
        xml = Sros2PolicyMapping(self.rules).to_xml()
        self.assertIn("<policy version=\"0.2.0\">", xml)
        self.assertIn("kg/open/goal", xml)
        self.assertIn("kg/train_on_data/goal", xml)
        self.assertIn("p-allow", xml)

    def test_invalid_domain_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            Sros2PolicyMapping(self.rules, domain=-1)


if __name__ == "__main__":
    unittest.main()
