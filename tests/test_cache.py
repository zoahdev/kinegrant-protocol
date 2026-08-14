from __future__ import annotations

import unittest
from datetime import timedelta

from kinegrant.cache import CachedPolicyEngine
from kinegrant.crypto import Ed25519KeyPair
from kinegrant.models import ActionRequest, PolicyRule, utc_now
from kinegrant.policy import PolicyEngine


class CachedPolicyEngineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.authority = Ed25519KeyPair.generate()
        self.allow = PolicyRule(
            "cache-rule-allow",
            self.authority.kid,
            "door-*",
            "allow",
            ("open",),
            subjects=("robot-1",),
            purposes=("delivery",),
        )
        self.engine = PolicyEngine(
            [self.allow],
            trusted_policy_issuers={self.authority.kid},
        )
        self.cached = CachedPolicyEngine(self.engine, capacity=4)
        self.request = ActionRequest(
            "req-cache-1",
            "robot-1",
            "door-7",
            "open",
            "delivery",
        )

    def test_second_evaluation_hits_cache(self) -> None:
        first = self.cached.evaluate(self.request)
        second = self.cached.evaluate(self.request)
        self.assertTrue(first.allowed)
        self.assertTrue(second.allowed)
        self.assertEqual(first.to_dict(), second.to_dict())
        self.assertEqual(self.cached.hits, 1)
        self.assertEqual(self.cached.misses, 1)
        self.assertEqual(self.cached.cache_size, 1)

    def test_different_request_misses(self) -> None:
        self.cached.evaluate(self.request)
        other = ActionRequest(
            "req-cache-2",
            "robot-1",
            "door-8",
            "open",
            "delivery",
        )
        self.cached.evaluate(other)
        self.assertEqual(self.cached.misses, 2)
        self.assertEqual(self.cached.hits, 0)
        self.assertEqual(self.cached.cache_size, 2)

    def test_policy_change_invalidates_cache(self) -> None:
        self.cached.evaluate(self.request)
        self.assertEqual(self.cached.cache_size, 1)
        self.engine.add(
            PolicyRule(
                "cache-rule-deny",
                self.authority.kid,
                "door-*",
                "deny",
                ("open",),
            )
        )
        denied = self.cached.evaluate(self.request)
        self.assertFalse(denied.allowed)
        self.assertEqual(self.cached.misses, 2)
        self.assertEqual(self.cached.cache_size, 1)

    def test_capacity_evicts_least_recently_used(self) -> None:
        small = CachedPolicyEngine(self.engine, capacity=2)
        requests = [
            ActionRequest(
                f"req-cache-cap-{index}",
                "robot-1",
                f"door-{index}",
                "open",
                "delivery",
            )
            for index in range(3)
        ]
        for request in requests:
            small.evaluate(request)
        self.assertEqual(small.cache_size, 2)
        small.evaluate(requests[0])  # evicted -> miss again
        self.assertEqual(small.misses, 4)

    def test_future_request_is_not_cached(self) -> None:
        future = ActionRequest(
            "req-cache-future",
            "robot-1",
            "door-7",
            "open",
            "delivery",
            issued_at=utc_now() + timedelta(hours=1),
        )
        decision = self.cached.evaluate(future)
        self.assertEqual(decision.reason, "future_request")
        self.assertEqual(self.cached.cache_size, 0)

    def test_clear_resets_statistics(self) -> None:
        self.cached.evaluate(self.request)
        self.cached.clear()
        self.assertEqual(self.cached.cache_size, 0)
        self.assertEqual(self.cached.hits, 0)
        self.assertEqual(self.cached.misses, 0)

    def test_invalid_capacity_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            CachedPolicyEngine(self.engine, capacity=0)


if __name__ == "__main__":
    unittest.main()
