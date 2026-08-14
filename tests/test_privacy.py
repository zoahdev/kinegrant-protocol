from __future__ import annotations

import unittest
from datetime import timedelta

from kinegrant.models import utc_now
from kinegrant.privacy import (
    RotatingIdentifierRegistry,
    redact,
    verify_redaction,
)


class RotatingIdentifierTests(unittest.TestCase):
    def test_issue_and_resolve_round_trip(self) -> None:
        registry = RotatingIdentifierRegistry(lifetime_seconds=300)
        ephemeral = registry.issue("demo", "urn:kinegrant:agent:demo:robot-1")
        self.assertTrue(ephemeral.startswith("urn:kinegrant:ephemeral:demo:"))
        self.assertEqual(
            registry.resolve(ephemeral),
            "urn:kinegrant:agent:demo:robot-1",
        )

    def test_expiry_is_enforced(self) -> None:
        now = utc_now()
        registry = RotatingIdentifierRegistry(lifetime_seconds=10)
        ephemeral = registry.issue("demo", "static-1", now=now)
        self.assertEqual(registry.resolve(ephemeral, now=now + timedelta(seconds=9)), "static-1")
        with self.assertRaises(ValueError):
            registry.resolve(ephemeral, now=now + timedelta(seconds=11))

    def test_rotate_revokes_previous(self) -> None:
        registry = RotatingIdentifierRegistry()
        first = registry.issue("demo", "static-1")
        second = registry.rotate("demo", "static-1")
        self.assertNotEqual(first, second)
        with self.assertRaises(ValueError):
            registry.resolve(first)
        self.assertEqual(registry.resolve(second), "static-1")

    def test_revoke_and_invalid_input(self) -> None:
        registry = RotatingIdentifierRegistry()
        ephemeral = registry.issue("demo", "static-1")
        registry.revoke(ephemeral)
        with self.assertRaises(ValueError):
            registry.resolve(ephemeral)
        with self.assertRaises(ValueError):
            registry.issue("UPPER", "static-1")
        with self.assertRaises(ValueError):
            RotatingIdentifierRegistry(lifetime_seconds=0)


class SelectiveDisclosureTests(unittest.TestCase):
    def test_redaction_reveals_only_visible_fields(self) -> None:
        document = {"agent": "robot-1", "target": "door-7", "purpose": "delivery"}
        envelope = redact(document, visible=["target"])
        self.assertEqual(envelope["visible_fields"], ["target"])
        self.assertEqual(envelope["hidden_fields"], ["agent", "purpose"])
        self.assertTrue(verify_redaction(envelope, document))
        self.assertIsNone(envelope["redacted"]["agent"])
        self.assertEqual(envelope["redacted"]["target"], "door-7")

    def test_hidden_set_works(self) -> None:
        document = {"agent": "robot-1", "target": "door-7"}
        envelope = redact(document, hidden=["agent"])
        self.assertTrue(verify_redaction(envelope, document))
        self.assertIsNone(envelope["redacted"]["agent"])

    def test_tampered_redaction_fails(self) -> None:
        document = {"agent": "robot-1", "target": "door-7"}
        envelope = redact(document, visible=["target"])
        envelope["redacted"]["target"] = "other-door"
        self.assertFalse(verify_redaction(envelope, document))

    def test_wrong_document_fails(self) -> None:
        document = {"agent": "robot-1", "target": "door-7"}
        envelope = redact(document, visible=["target"])
        self.assertFalse(verify_redaction(envelope, {"agent": "robot-1", "target": "door-8"}))

    def test_both_visible_and_hidden_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            redact({"a": 1}, visible=["a"], hidden=["b"])


if __name__ == "__main__":
    unittest.main()
