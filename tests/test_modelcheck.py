from __future__ import annotations

import unittest

from kinegrant.models import PolicyRule
from kinegrant.modelcheck import bounded_model_check
from kinegrant.policy import PolicyEngine


class BoundedModelCheckTests(unittest.TestCase):
    def setUp(self) -> None:
        self.allow = PolicyRule(
            policy_id="allow-open",
            issuer="trusted",
            target="door-7",
            effect="allow",
            actions=("open",),
            subjects=("robot-1",),
            purposes=("delivery",),
        )
        self.deny = PolicyRule(
            policy_id="deny-close",
            issuer="trusted",
            target="*",
            effect="deny",
            actions=("close",),
        )
        self.engine = PolicyEngine(
            [self.allow, self.deny],
            trusted_policy_issuers={"trusted"},
        )

    def test_clean_policy_passes(self) -> None:
        report = bounded_model_check(
            self.engine,
            agents=["robot-1"],
            targets=["door-7", "other"],
            actions=["open", "close"],
            purposes=["delivery", "training"],
        )
        self.assertEqual(report["overall_result"], "PASS")
        self.assertEqual(report["exceptions"], 0)
        self.assertEqual(report["space_size"], 8)
        self.assertEqual(report["allowed"], 1)
        self.assertEqual(report["shadowed_allows"], [])

    def test_rules_are_reachable(self) -> None:
        report = bounded_model_check(
            self.engine,
            agents=["robot-1"],
            targets=["door-7"],
            actions=["open", "close"],
            purposes=["delivery"],
        )
        by_id = {item["policy_id"]: item for item in report["rules"]}
        self.assertTrue(by_id["allow-open"]["reachable"])
        self.assertTrue(by_id["deny-close"]["reachable"])

    def test_shadowed_allow_is_flagged(self) -> None:
        engine = PolicyEngine(
            [
                PolicyRule(
                    "allow-shadowed",
                    "trusted",
                    "door-7",
                    "allow",
                    ("open",),
                ),
                PolicyRule(
                    "deny-all",
                    "trusted",
                    "*",
                    "deny",
                    ("*",),
                ),
            ],
            trusted_policy_issuers={"trusted"},
        )
        report = bounded_model_check(
            engine,
            agents=["robot-1"],
            targets=["door-7"],
            actions=["open"],
            purposes=["delivery"],
        )
        self.assertEqual(report["overall_result"], "FAIL")
        self.assertEqual(report["shadowed_allows"], ["allow-shadowed"])

    def test_max_requests_is_enforced(self) -> None:
        report = bounded_model_check(
            self.engine,
            agents=["a", "b", "c"],
            targets=["t1", "t2", "t3"],
            actions=["open"],
            purposes=["delivery"],
            max_requests=5,
        )
        self.assertEqual(report["evaluated"], 5)

    def test_invalid_max_requests_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            bounded_model_check(
                self.engine,
                agents=["a"],
                targets=["t"],
                actions=["open"],
                purposes=["delivery"],
                max_requests=0,
            )


if __name__ == "__main__":
    unittest.main()
