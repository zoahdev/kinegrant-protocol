from __future__ import annotations

import unittest

from kinegrant.identity import (
    agent_id,
    is_agent_id,
    is_kinegrant_identifier,
    is_policy_id,
    is_target_id,
    parse_identifier,
    policy_id,
    random_agent_id,
    random_policy_id,
    random_target_id,
    target_id,
)


class IdentityTests(unittest.TestCase):
    def test_builders_produce_valid_identifiers(self) -> None:
        self.assertEqual(
            agent_id("zoah", "delivery-robot-07"),
            "urn:kinegrant:agent:zoah:delivery-robot-07",
        )
        self.assertEqual(
            target_id("zoah", "door-7"),
            "urn:kinegrant:target:zoah:door-7",
        )
        self.assertEqual(
            policy_id("zoah", "delivery-door#permission-0"),
            "urn:kinegrant:policy:zoah:delivery-door#permission-0",
        )

    def test_parse_round_trip(self) -> None:
        value = "urn:kinegrant:agent:zoah:delivery-robot-07"
        parsed = parse_identifier(value)
        self.assertEqual(parsed.kind, "agent")
        self.assertEqual(parsed.namespace, "zoah")
        self.assertEqual(parsed.local_id, "delivery-robot-07")
        self.assertEqual(parsed.value, value)

    def test_kind_predicates(self) -> None:
        self.assertTrue(is_agent_id("urn:kinegrant:agent:zoah:r1"))
        self.assertTrue(is_target_id("urn:kinegrant:target:zoah:d1"))
        self.assertTrue(is_policy_id("urn:kinegrant:policy:zoah:p1"))
        self.assertFalse(is_agent_id("urn:kinegrant:target:zoah:d1"))
        self.assertTrue(is_kinegrant_identifier("urn:kinegrant:agent:zoah:r1"))

    def test_invalid_identifiers_are_rejected(self) -> None:
        bad = [
            "urn:kinegrant:agent:zoah:",          # empty local id
            "urn:kinegrant:agent::r1",             # empty namespace
            "urn:kinegrant:agent:Zoah:r1",         # uppercase
            "urn:kinegrant:widget:zoah:r1",        # unknown kind
            "kinegrant:agent:zoah:r1",             # missing urn:
            "urn:kinegrant:agent:zoah:r1/extra",   # slash
        ]
        for value in bad:
            self.assertFalse(is_kinegrant_identifier(value))
            with self.assertRaises(ValueError):
                parse_identifier(value)

    def test_invalid_parts_are_rejected(self) -> None:
        with self.assertRaises(ValueError):
            agent_id("UPPER", "r1")
        with self.assertRaises(ValueError):
            agent_id("zoah", "has space")
        with self.assertRaises(ValueError):
            agent_id("", "r1")

    def test_random_identifiers_are_valid(self) -> None:
        for builder in (random_agent_id, random_target_id, random_policy_id):
            value = builder("zoah")
            self.assertTrue(is_kinegrant_identifier(value))
            parsed = parse_identifier(value)
            self.assertEqual(parsed.namespace, "zoah")

    def test_local_ids_allow_nested_colons(self) -> None:
        value = policy_id("zoah", "delivery-door#permission-0")
        self.assertEqual(parse_identifier(value).local_id, "delivery-door#permission-0")
        value2 = policy_id("zoah", "delivery:door#p1")
        self.assertEqual(parse_identifier(value2).value, value2)


if __name__ == "__main__":
    unittest.main()
