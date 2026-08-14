from __future__ import annotations

import unittest

from kinegrant.adapters.odrl import (
    KGP_ODRL_PROFILE,
    odrl_forbidden_combinations,
    odrl_to_rules,
    odrl_to_sequence_policy,
    rules_to_odrl,
)
from kinegrant.capability import CapabilityIssuer
from kinegrant.crypto import Ed25519KeyPair
from kinegrant.gate import ActionGate
from kinegrant.models import ActionRequest, PolicyRule
from kinegrant.policy import PolicyEngine
from kinegrant.sequence import ActionJournal


def _request(
    action: str = "open",
    purpose: str = "delivery",
    target: str = "door-7",
) -> ActionRequest:
    return ActionRequest(
        request_id="req-odrl-seq-1",
        agent="robot-1",
        target=target,
        action=action,
        purpose=purpose,
        context={"force_newtons": 20, "zone": "dock-1"},
    )


class OdrlObligationTests(unittest.TestCase):
    def _policy(self, permission: dict, extra: dict | None = None) -> dict:
        doc = {
            "@context": "http://www.w3.org/ns/odrl/2/",
            "@type": "Offer",
            "uid": "urn:kgp:odrl:door-7",
            "profile": KGP_ODRL_PROFILE,
            "assigner": "trusted-issuer",
            "permission": [permission],
        }
        if extra:
            doc.update(extra)
        return doc

    def test_known_duty_maps_to_obligation(self) -> None:
        doc = self._policy(
            {
                "target": "door-7",
                "assignee": "*",
                "action": "open",
                "duty": {"action": "emitActionReceipt"},
            }
        )
        rules = odrl_to_rules(doc)
        self.assertEqual(rules[0].obligations, ("emitActionReceipt",))

    def test_unknown_duty_fails_closed(self) -> None:
        doc = self._policy(
            {
                "target": "door-7",
                "assignee": "*",
                "action": "open",
                "duty": {"action": "compensate"},
            }
        )
        with self.assertRaises(ValueError):
            odrl_to_rules(doc)

    def test_obligation_survives_issue_and_gate(self) -> None:
        key = Ed25519KeyPair.generate()
        doc = {
            "@context": "http://www.w3.org/ns/odrl/2/",
            "@type": "Offer",
            "uid": "urn:kgp:odrl:door-7",
            "profile": KGP_ODRL_PROFILE,
            "assigner": key.kid,
            "permission": [
                {
                    "target": "door-7",
                    "assignee": "*",
                    "action": "open",
                    "duty": {"action": "emitActionReceipt"},
                }
            ],
        }
        engine = PolicyEngine(odrl_to_rules(doc), trusted_policy_issuers={key.kid})
        request = _request()
        decision = engine.evaluate(request)
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.obligations, ("emitActionReceipt",))
        capability = CapabilityIssuer(key).issue_scoped(
            request,
            decision,
            ttl_seconds=30,
            target=request.target,
            actions=[request.action],
            purposes=[request.purpose],
        )
        verified = ActionGate(trusted_issuers={key.kid}).authorize(capability, request)
        self.assertEqual(verified["obligations"], ["emitActionReceipt"])

    def test_prohibited_combination_requires_profile(self) -> None:
        doc = self._policy(
            {"target": "door-7", "assignee": "*", "action": "open"},
            extra={
                "profile": "http://www.w3.org/ns/odrl/2/",
                "kg:prohibitedCombination": [
                    {
                        "uid": "combo-1",
                        "patterns": [{"action": "open", "target": "door-7"}],
                    }
                ],
            },
        )
        with self.assertRaises(ValueError):
            odrl_forbidden_combinations(doc)

    def test_forbidden_combination_denies_after_journal(self) -> None:
        doc = self._policy(
            {"target": "door-7", "assignee": "*", "action": "open"},
            extra={
                "kg:prohibitedCombination": [
                    {
                        "uid": "combo-record-train",
                        "patterns": [
                            {"action": "record", "target": "space-*"},
                        ],
                        "trigger": {"action": "train_on_data", "target": "space-*"},
                    }
                ]
            },
        )
        policy = odrl_to_sequence_policy(doc)
        journal = ActionJournal()
        self.assertTrue(policy.evaluate(_request("open"), journal).allowed)
        self.assertTrue(policy.evaluate(_request("train_on_data", target="space-1"), journal).allowed)
        journal.record("record", "space-1")
        self.assertFalse(
            policy.evaluate(_request("train_on_data", target="space-1"), journal).allowed
        )
        self.assertEqual(
            odrl_forbidden_combinations(doc)[0].combination_id,
            "combo-record-train",
        )

    def test_rules_to_odrl_round_trip(self) -> None:
        rules = [
            PolicyRule(
                "urn:kgp:rule:allow-open",
                "trusted-issuer",
                "door-7",
                "allow",
                ("open",),
                subjects=("robot-1",),
                purposes=("delivery",),
                constraints={"max_force_newtons": 50, "allowed_zones": ["dock-*"]},
                obligations=("emitActionReceipt",),
            ),
            PolicyRule(
                "urn:kgp:rule:deny-train",
                "trusted-issuer",
                "*",
                "deny",
                ("train_on_data",),
            ),
        ]
        document = rules_to_odrl(
            rules,
            policy_uid="urn:kgp:odrl:round-trip",
            assigner="trusted-issuer",
        )
        self.assertEqual(document["profile"], KGP_ODRL_PROFILE)
        parsed = odrl_to_rules(document)
        self.assertEqual(len(parsed), 2)
        allow = next(rule for rule in parsed if rule.effect == "allow")
        deny = next(rule for rule in parsed if rule.effect == "deny")
        self.assertEqual(allow.actions, ("open",))
        self.assertEqual(allow.constraints["max_force_newtons"], 50)
        self.assertEqual(allow.constraints["allowed_zones"], ["dock-*"])
        self.assertEqual(allow.obligations, ("emitActionReceipt",))
        self.assertEqual(deny.actions, ("train_on_data",))

    def test_forbidden_combination_round_trip(self) -> None:
        from kinegrant.sequence import ForbiddenCombination

        combination = ForbiddenCombination(
            "urn:kgp:combo:open-enter",
            patterns=(("open", "door-*"), ("enter", "door-*")),
            window_seconds=600,
            trigger=("enter", "door-*"),
        )
        document = rules_to_odrl(
            [],
            policy_uid="urn:kgp:odrl:combos",
            assigner="trusted-issuer",
            forbidden_combinations=[combination],
        )
        parsed = odrl_forbidden_combinations(document)
        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed[0].combination_id, combination.combination_id)
        self.assertEqual(parsed[0].patterns, combination.patterns)
        self.assertEqual(parsed[0].window_seconds, 600)
        self.assertEqual(parsed[0].trigger, ("enter", "door-*"))


if __name__ == "__main__":
    unittest.main()
