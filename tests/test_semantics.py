from __future__ import annotations

import unittest

from kinegrant.models import ActionRequest, PolicyRule
from kinegrant.policy import PolicyEngine
from kinegrant.semantics import PolicyInvariants, explain_decision


class PolicyInvariantsTests(unittest.TestCase):
    def test_allow_all_is_flagged(self) -> None:
        rule = PolicyRule(
            policy_id="p1",
            issuer="trusted",
            target="*",
            effect="allow",
            actions=("*",),
        )
        findings = PolicyInvariants([rule], trusted_policy_issuers={"trusted"}).analyze()
        self.assertTrue(any(item.check == "allow_all" for item in findings))

    def test_deny_shadows_allow_is_flagged(self) -> None:
        allow = PolicyRule(
            policy_id="allow",
            issuer="trusted",
            target="door-*",
            effect="allow",
            actions=("open",),
            subjects=("robot-*",),
            purposes=("delivery",),
        )
        deny = PolicyRule(
            policy_id="deny",
            issuer="trusted",
            target="door-*",
            effect="deny",
            actions=("open",),
            subjects=("robot-*",),
            purposes=("delivery",),
        )
        findings = PolicyInvariants(
            [allow, deny], trusted_policy_issuers={"trusted"}
        ).analyze()
        self.assertTrue(any(item.check == "deny_shadows_allow" for item in findings))

    def test_untrusted_allow_is_flagged(self) -> None:
        rule = PolicyRule(
            policy_id="p1",
            issuer="stranger",
            target="door-7",
            effect="allow",
            actions=("open",),
        )
        findings = PolicyInvariants([rule], trusted_policy_issuers={"trusted"}).analyze()
        self.assertTrue(any(item.check == "untrusted_allow" for item in findings))

    def test_empty_policy_is_flagged(self) -> None:
        findings = PolicyInvariants([]).analyze()
        self.assertTrue(any(item.check == "empty_policy" for item in findings))

    def test_clean_policy_has_no_findings(self) -> None:
        rule = PolicyRule(
            policy_id="p1",
            issuer="trusted",
            target="door-7",
            effect="allow",
            actions=("open",),
            subjects=("robot-1",),
            purposes=("delivery",),
        )
        findings = PolicyInvariants([rule], trusted_policy_issuers={"trusted"}).analyze()
        self.assertTrue(all(item.passes for item in findings))


class ExplainDecisionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.allow = PolicyRule(
            policy_id="allow-1",
            issuer="trusted",
            target="door-7",
            effect="allow",
            actions=("open",),
            subjects=("robot-1",),
            purposes=("delivery",),
        )
        self.deny = PolicyRule(
            policy_id="deny-1",
            issuer="trusted",
            target="door-7",
            effect="deny",
            actions=("open",),
        )
        self.engine = PolicyEngine(
            [self.allow, self.deny],
            trusted_policy_issuers={"trusted"},
        )
        self.request = ActionRequest(
            request_id="req-explain-1",
            agent="robot-1",
            target="door-7",
            action="open",
            purpose="delivery",
        )

    def test_explanation_lists_applicable_and_excluded_rules(self) -> None:
        explanation = explain_decision(self.engine, self.request)
        applicable = {item["policy_id"] for item in explanation["applicable_rules"]}
        self.assertEqual(applicable, {"allow-1", "deny-1"})
        self.assertEqual(explanation["decision"]["allowed"], False)
        self.assertEqual(explanation["decision"]["reason"], "explicit_deny")

    def test_explanation_records_exclusion_reason(self) -> None:
        other = ActionRequest(
            request_id="req-explain-2",
            agent="robot-9",
            target="door-7",
            action="open",
            purpose="delivery",
        )
        explanation = explain_decision(self.engine, other)
        excluded = {
            item["policy_id"]: item["reason"]
            for item in explanation["excluded_rules"]
        }
        self.assertEqual(excluded["allow-1"], "subject_mismatch")


if __name__ == "__main__":
    unittest.main()
