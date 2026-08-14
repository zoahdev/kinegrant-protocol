from __future__ import annotations

import unittest

from kinegrant.discovery import ThingRegistry


def thing_description(thing_id: str = "urn:kinegrant:target:demo:door-7") -> dict:
    return {
        "id": thing_id,
        "actions": {
            "open": {"title": "Open door", "safe": True, "idempotent": True},
            "close": {"title": "Close door", "safe": True, "idempotent": True},
        },
    }


class ThingRegistryTests(unittest.TestCase):
    def test_authenticated_registration_resolves_policy_pointer(self) -> None:
        registry = ThingRegistry()
        thing_id = registry.register(
            thing_description(),
            policy_pointer="urn:kinegrant:policy:demo:door-7",
            authenticated=True,
        )
        resolution = registry.resolve(thing_id)
        self.assertTrue(resolution.authenticated)
        self.assertEqual(
            resolution.policy_pointer, "urn:kinegrant:policy:demo:door-7"
        )
        self.assertEqual(resolution.action("open").safe, True)
        with self.assertRaises(KeyError):
            resolution.action("wave")

    def test_unauthenticated_registration_cannot_carry_granting_pointer(self) -> None:
        registry = ThingRegistry()
        with self.assertRaisesRegex(ValueError, "unauthenticated"):
            registry.register(
                thing_description(),
                policy_pointer="urn:kinegrant:policy:demo:door-7",
                authenticated=False,
            )
        thing_id = registry.register(thing_description(), authenticated=False)
        resolution = registry.resolve(thing_id)
        self.assertFalse(resolution.authenticated)
        self.assertIsNone(resolution.policy_pointer)

    def test_duplicate_and_unknown_things_are_rejected(self) -> None:
        registry = ThingRegistry()
        thing_id = registry.register(thing_description(), authenticated=True)
        with self.assertRaises(ValueError):
            registry.register(thing_description(), authenticated=True)
        with self.assertRaises(ValueError):
            registry.resolve("urn:kinegrant:target:demo:missing")
        registry.remove(thing_id)
        with self.assertRaises(ValueError):
            registry.resolve(thing_id)

    def test_multiple_things_are_listed_and_isolated(self) -> None:
        registry = ThingRegistry()
        first = registry.register(
            thing_description("urn:kinegrant:target:demo:door-7"),
            authenticated=True,
            policy_pointer="urn:kinegrant:policy:demo:door-7",
        )
        second = registry.register(
            thing_description("urn:kinegrant:target:demo:gate-1"),
            authenticated=True,
            policy_pointer="urn:kinegrant:policy:demo:gate-1",
        )
        self.assertEqual(registry.list_ids(), (first, second))
        self.assertNotEqual(
            registry.resolve(first).policy_pointer,
            registry.resolve(second).policy_pointer,
        )

    def test_discovery_failure_does_not_grant(self) -> None:
        registry = ThingRegistry()
        with self.assertRaises(ValueError):
            registry.resolve("urn:kinegrant:target:demo:unknown")


if __name__ == "__main__":
    unittest.main()
