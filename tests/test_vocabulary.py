from __future__ import annotations

import json
import unittest
from pathlib import Path

import jsonschema

from kinegrant.models import ActionRequest, PolicyRule
from kinegrant.policy import PolicyEngine
from kinegrant.vocabulary import (
    ACTION_TERMS,
    action_spec,
    known_action,
    registry,
    validate_actions,
)


class VocabularyTests(unittest.TestCase):
    def test_canonical_terms_are_present_and_sorted(self) -> None:
        expected = {
            "kg.action.observe",
            "kg.action.record",
            "kg.action.touch",
            "kg.action.grasp",
            "kg.action.move",
            "kg.action.open",
            "kg.action.enter",
            "kg.action.retain",
            "kg.action.train_on_data",
        }
        self.assertEqual(set(ACTION_TERMS), expected)
        self.assertEqual(ACTION_TERMS, tuple(sorted(ACTION_TERMS)))

    def test_action_spec_is_declarative(self) -> None:
        spec = action_spec("kg.action.train_on_data")
        self.assertEqual(spec.category, "data")
        self.assertEqual(spec.risk_tier, 4)
        self.assertTrue(spec.data_sensitivity)

    def test_unknown_action_is_rejected(self) -> None:
        self.assertFalse(known_action("kg.action.wave"))
        with self.assertRaises(KeyError):
            action_spec("kg.action.wave")
        with self.assertRaises(ValueError):
            validate_actions(["kg.action.open", "kg.action.wave"])

    def test_registry_matches_published_schema(self) -> None:
        schema_path = (
            Path(__file__).resolve().parents[1]
            / "spec"
            / "schemas"
            / "action-vocabulary.schema.json"
        )
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        jsonschema.validate(registry(), schema)

    def test_policy_engine_fails_closed_on_unknown_action_when_required(self) -> None:
        engine = PolicyEngine(require_known_actions=True)
        request = ActionRequest(
            request_id="req-1",
            agent="robot-1",
            target="hallway",
            action="kg.action.wave",
            purpose="greeting",
        )
        decision = engine.evaluate(request)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "unknown_action")

    def test_policy_engine_rejects_rules_with_unknown_actions_when_required(self) -> None:
        rule = PolicyRule(
            policy_id="p1",
            issuer="trusted-issuer",
            target="*",
            effect="allow",
            actions=("kg.action.wave",),
        )
        with self.assertRaises(ValueError):
            PolicyEngine([rule], require_known_actions=True)

    def test_legacy_mode_still_accepts_unknown_actions(self) -> None:
        engine = PolicyEngine(require_known_actions=False)
        request = ActionRequest(
            request_id="req-2",
            agent="robot-1",
            target="hallway",
            action="custom_wave",
            purpose="greeting",
        )
        self.assertFalse(engine.evaluate(request).allowed)

    def test_canonical_terms_flow_through_policy_evaluation(self) -> None:
        rule = PolicyRule(
            policy_id="p2",
            issuer="trusted",
            target="door-7",
            effect="allow",
            actions=("kg.action.open",),
        )
        engine = PolicyEngine(
            [rule],
            trusted_policy_issuers={"trusted"},
            require_known_actions=True,
        )
        request = ActionRequest(
            request_id="req-3",
            agent="robot-1",
            target="door-7",
            action="kg.action.open",
            purpose="delivery",
        )
        self.assertTrue(engine.evaluate(request).allowed)


if __name__ == "__main__":
    unittest.main()
