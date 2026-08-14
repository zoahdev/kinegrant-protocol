from __future__ import annotations

import unittest

from kinegrant.models import ActionRequest, PolicyRule
from kinegrant.policy import PolicyEngine


def make_request(**context: object) -> ActionRequest:
    return ActionRequest(
        request_id="req-phy-1",
        agent="robot-1",
        target="door-7",
        action="open",
        purpose="delivery",
        context=context,
    )


class PhysicalConstraintTests(unittest.TestCase):
    def setUp(self) -> None:
        self.trusted = {"trusted-issuer"}

    def policy(self, **constraints: object) -> PolicyEngine:
        rule = PolicyRule(
            policy_id="phy-1",
            issuer="trusted-issuer",
            target="door-7",
            effect="allow",
            actions=("open",),
            constraints=constraints,
        )
        return PolicyEngine([rule], trusted_policy_issuers=self.trusted)

    def test_force_within_limit_is_allowed(self) -> None:
        engine = self.policy(max_force_newtons=50)
        self.assertTrue(engine.evaluate(make_request(force_newtons=10)).allowed)

    def test_force_over_limit_is_denied(self) -> None:
        engine = self.policy(max_force_newtons=50)
        decision = engine.evaluate(make_request(force_newtons=51))
        self.assertFalse(decision.allowed)

    def test_missing_force_fails_closed(self) -> None:
        engine = self.policy(max_force_newtons=50)
        self.assertFalse(engine.evaluate(make_request()).allowed)

    def test_velocity_limit_is_enforced(self) -> None:
        engine = self.policy(max_velocity_mps=1.5)
        self.assertTrue(engine.evaluate(make_request(velocity_mps=1.4)).allowed)
        self.assertFalse(engine.evaluate(make_request(velocity_mps=1.6)).allowed)
        self.assertFalse(engine.evaluate(make_request()).allowed)

    def test_zone_allowlist_is_enforced(self) -> None:
        engine = self.policy(allowed_zones=["zone-*"])
        self.assertTrue(engine.evaluate(make_request(zone="zone-a")).allowed)
        self.assertFalse(engine.evaluate(make_request(zone="other")).allowed)
        self.assertFalse(engine.evaluate(make_request()).allowed)

    def test_combined_physical_constraints(self) -> None:
        engine = self.policy(
            max_force_newtons=40,
            max_velocity_mps=2.0,
            allowed_zones=["dock-*"],
        )
        ok = engine.evaluate(
            make_request(force_newtons=20, velocity_mps=1.0, zone="dock-1")
        )
        self.assertTrue(ok.allowed)
        self.assertFalse(
            engine.evaluate(
                make_request(force_newtons=20, velocity_mps=3.0, zone="dock-1")
            ).allowed
        )
        self.assertFalse(
            engine.evaluate(
                make_request(force_newtons=20, velocity_mps=1.0, zone="lobby")
            ).allowed
        )

    def test_invalid_constraint_values_are_rejected_at_construction(self) -> None:
        for bad in (-1, "50", True):
            with self.assertRaises(ValueError):
                self.policy(max_force_newtons=bad)  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            self.policy(allowed_zones=[])
        with self.assertRaises(ValueError):
            self.policy(allowed_zones=["ok", ""])

    def test_deny_rule_with_force_ceiling_denies_violations(self) -> None:
        allow = PolicyRule(
            policy_id="allow-1",
            issuer="trusted-issuer",
            target="door-7",
            effect="allow",
            actions=("open",),
        )
        deny_high_force = PolicyRule(
            policy_id="deny-1",
            issuer="trusted-issuer",
            target="door-7",
            effect="deny",
            actions=("open",),
            constraints={"max_force_newtons": 10},
        )
        engine = PolicyEngine(
            [allow, deny_high_force],
            trusted_policy_issuers=self.trusted,
        )
        self.assertFalse(
            engine.evaluate(make_request(force_newtons=20)).allowed
        )
        self.assertFalse(
            engine.evaluate(make_request()).allowed
        )
        self.assertTrue(
            engine.evaluate(make_request(force_newtons=5)).allowed
        )

    def test_deny_rule_with_zone_rejects_matching_zone(self) -> None:
        allow = PolicyRule(
            policy_id="allow-2",
            issuer="trusted-issuer",
            target="door-7",
            effect="allow",
            actions=("open",),
        )
        deny_zone = PolicyRule(
            policy_id="deny-2",
            issuer="trusted-issuer",
            target="door-7",
            effect="deny",
            actions=("open",),
            constraints={"allowed_zones": ["restricted-*"]},
        )
        engine = PolicyEngine(
            [allow, deny_zone],
            trusted_policy_issuers=self.trusted,
        )
        self.assertFalse(
            engine.evaluate(make_request(zone="restricted-a")).allowed
        )
        self.assertTrue(
            engine.evaluate(make_request(zone="public")).allowed
        )


if __name__ == "__main__":
    unittest.main()
