from __future__ import annotations

import copy
import unittest

from kinegrant.capability import CapabilityIssuer
from kinegrant.compliance import ObligationCompliance
from kinegrant.crypto import Ed25519KeyPair
from kinegrant.gate import ActionGate, InMemoryReplayStore
from kinegrant.models import ActionRequest, PolicyRule
from kinegrant.policy import PolicyEngine
from kinegrant.receipt import ReceiptLog


class ObligationComplianceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.authority = Ed25519KeyPair.generate()
        self.executor = Ed25519KeyPair.generate()
        self.issuer = CapabilityIssuer(self.authority)
        self.request = ActionRequest(
            request_id="req-compliance-1",
            agent="robot-1",
            target="door-7",
            action="open",
            purpose="delivery",
        )
        self.rule = PolicyRule(
            policy_id="compliance-rule-1",
            issuer=self.authority.kid,
            target="door-*",
            effect="allow",
            actions=("open",),
            obligations=("emitActionReceipt",),
        )
        self.engine = PolicyEngine(
            [self.rule],
            trusted_policy_issuers={self.authority.kid},
        )
        self.decision = self.engine.evaluate(self.request)
        self.capability = self.issuer.issue_scoped(
            self.request,
            self.decision,
            ttl_seconds=30,
            target=self.request.target,
            actions=["open"],
            purposes=["delivery"],
        )
        self.verified = ActionGate(
            trusted_issuers={self.authority.kid},
            replay_store=InMemoryReplayStore(),
        ).authorize(self.capability, self.request)
        self.log = ReceiptLog(self.executor)

    def evaluate(
        self,
        receipts,
        *,
        trusted_executors=None,
        capability=None,
    ):
        return ObligationCompliance().evaluate(
            capability if capability is not None else self.capability,
            receipts,
            trusted_executors=(
                trusted_executors
                if trusted_executors is not None
                else {self.executor.kid}
            ),
        )

    def test_satisfied_when_receipt_exists(self) -> None:
        receipt = self.log.append(
            self.verified,
            result="succeeded",
            request=self.request,
        )
        verdict = self.evaluate([receipt])
        self.assertTrue(verdict.compliant)
        self.assertEqual(verdict.results[0].status, "satisfied")

    def test_receipt_10_satisfied_is_compliant(self) -> None:
        receipt = self.log.append(
            self.verified,
            result="succeeded",
            request=self.request,
            obligation_results=[
                {"obligation": "emitActionReceipt", "status": "satisfied"}
            ],
        )
        self.assertEqual(receipt["payload"]["version"], "1.0")
        self.assertTrue(self.evaluate([receipt]).compliant)

    def test_receipt_10_failed_obligation_fails_compliance(self) -> None:
        receipt = self.log.append(
            self.verified,
            result="succeeded",
            request=self.request,
            obligation_results=[
                {
                    "obligation": "emitActionReceipt",
                    "status": "failed",
                    "failure_reason": "receipt store unavailable",
                }
            ],
        )
        verdict = self.evaluate([receipt])
        self.assertFalse(verdict.compliant)
        self.assertIn("receipt store unavailable", verdict.reason or "")

    def test_missing_receipt_fails_compliance(self) -> None:
        verdict = self.evaluate([])
        self.assertFalse(verdict.compliant)
        self.assertIn("missing receipt", verdict.reason or "")

    def test_receipt_for_other_capability_fails(self) -> None:
        other_request = ActionRequest(
            request_id="req-compliance-2",
            agent="robot-2",
            target="door-8",
            action="open",
            purpose="delivery",
        )
        other_rule = PolicyRule(
            policy_id="compliance-rule-2",
            issuer=self.authority.kid,
            target="door-*",
            effect="allow",
            actions=("open",),
            obligations=("emitActionReceipt",),
        )
        other_engine = PolicyEngine(
            [other_rule],
            trusted_policy_issuers={self.authority.kid},
        )
        other_decision = other_engine.evaluate(other_request)
        other_capability = self.issuer.issue_scoped(
            other_request,
            other_decision,
            ttl_seconds=30,
            target=other_request.target,
            actions=["open"],
            purposes=["delivery"],
        )
        other_verified = ActionGate(
            trusted_issuers={self.authority.kid},
            replay_store=InMemoryReplayStore(),
        ).authorize(other_capability, other_request)
        other_receipt = self.log.append(
            other_verified,
            result="succeeded",
            request=other_request,
        )
        verdict = self.evaluate([other_receipt])
        self.assertFalse(verdict.compliant)
        self.assertIn("missing receipt", verdict.reason or "")

    def test_invalid_chain_fails_compliance(self) -> None:
        receipt = self.log.append(
            self.verified,
            result="succeeded",
            request=self.request,
        )
        tampered = copy.deepcopy(receipt)
        tampered["payload"]["result"] = "failed"
        verdict = self.evaluate([tampered])
        self.assertFalse(verdict.compliant)
        self.assertIn("receipt chain is invalid", verdict.reason or "")

    def test_untrusted_executor_fails_compliance(self) -> None:
        receipt = self.log.append(
            self.verified,
            result="succeeded",
            request=self.request,
        )
        other = Ed25519KeyPair.generate()
        verdict = self.evaluate([receipt], trusted_executors={other.kid})
        self.assertFalse(verdict.compliant)

    def test_unknown_obligation_fails_closed(self) -> None:
        capability = copy.deepcopy(self.capability)
        capability["payload"]["obligations"] = ["logAudit"]
        re_signed = self.authority.sign_envelope(capability["payload"])
        verdict = self.evaluate([], capability=re_signed)
        self.assertFalse(verdict.compliant)
        self.assertIn("unknown obligation", verdict.reason or "")

    def test_no_obligations_is_compliant(self) -> None:
        rule = PolicyRule(
            policy_id="compliance-rule-3",
            issuer=self.authority.kid,
            target="door-*",
            effect="allow",
            actions=("open",),
        )
        engine = PolicyEngine([rule], trusted_policy_issuers={self.authority.kid})
        decision = engine.evaluate(self.request)
        capability = self.issuer.issue_scoped(
            self.request,
            decision,
            ttl_seconds=30,
        )
        verdict = ObligationCompliance().evaluate(
            capability,
            [],
            trusted_executors={self.executor.kid},
        )
        self.assertTrue(verdict.compliant)
        self.assertEqual(verdict.results, ())

    def test_log_audit_event_obligation_end_to_end(self) -> None:
        rule = PolicyRule(
            policy_id="compliance-rule-audit",
            issuer=self.authority.kid,
            target="door-*",
            effect="allow",
            actions=("open",),
            obligations=("emitActionReceipt", "logAuditEvent"),
        )
        engine = PolicyEngine([rule], trusted_policy_issuers={self.authority.kid})
        decision = engine.evaluate(self.request)
        self.assertEqual(
            decision.obligations,
            ("emitActionReceipt", "logAuditEvent"),
        )
        capability = self.issuer.issue_scoped(
            self.request,
            decision,
            ttl_seconds=30,
            target=self.request.target,
            actions=["open"],
            purposes=["delivery"],
        )
        verified = ActionGate(
            trusted_issuers={self.authority.kid},
            replay_store=InMemoryReplayStore(),
        ).authorize(capability, self.request)
        receipt = self.log.append(
            verified,
            result="succeeded",
            request=self.request,
            obligation_results=[
                {"obligation": "emitActionReceipt", "status": "satisfied"},
                {"obligation": "logAuditEvent", "status": "satisfied"},
            ],
        )
        self.assertEqual(receipt["payload"]["version"], "1.0")
        verdict = self.evaluate([receipt], capability=capability)
        self.assertTrue(verdict.compliant)
        self.assertEqual(len(verdict.results), 2)
        self.assertTrue(all(result.status == "satisfied" for result in verdict.results))

    def test_log_audit_event_requires_receipt_commitment(self) -> None:
        rule = PolicyRule(
            policy_id="compliance-rule-audit-only",
            issuer=self.authority.kid,
            target="door-*",
            effect="allow",
            actions=("open",),
            obligations=("logAuditEvent",),
        )
        engine = PolicyEngine([rule], trusted_policy_issuers={self.authority.kid})
        decision = engine.evaluate(self.request)
        capability = self.issuer.issue_scoped(
            self.request,
            decision,
            ttl_seconds=30,
            target=self.request.target,
            actions=["open"],
            purposes=["delivery"],
        )
        verified = ActionGate(
            trusted_issuers={self.authority.kid},
            replay_store=InMemoryReplayStore(),
        ).authorize(capability, self.request)
        plain_receipt = self.log.append(
            verified,
            result="succeeded",
            request=self.request,
        )
        self.assertEqual(plain_receipt["payload"]["version"], "0.1")
        verdict = self.evaluate([plain_receipt], capability=capability)
        self.assertFalse(verdict.compliant)
        self.assertIn("audit-log commitment", verdict.reason or "")

    def test_preserve_evidence_obligation_end_to_end(self) -> None:
        rule = PolicyRule(
            policy_id="compliance-rule-evidence",
            issuer=self.authority.kid,
            target="door-*",
            effect="allow",
            actions=("open",),
            obligations=(
                "emitActionReceipt",
                "logAuditEvent",
                "preserveEvidence",
            ),
        )
        engine = PolicyEngine([rule], trusted_policy_issuers={self.authority.kid})
        decision = engine.evaluate(self.request)
        self.assertEqual(
            decision.obligations,
            ("emitActionReceipt", "logAuditEvent", "preserveEvidence"),
        )
        capability = self.issuer.issue_scoped(
            self.request,
            decision,
            ttl_seconds=30,
            target=self.request.target,
            actions=["open"],
            purposes=["delivery"],
        )
        verified = ActionGate(
            trusted_issuers={self.authority.kid},
            replay_store=InMemoryReplayStore(),
        ).authorize(capability, self.request)
        receipt = self.log.append(
            verified,
            result="succeeded",
            request=self.request,
            obligation_results=[
                {"obligation": "emitActionReceipt", "status": "satisfied"},
                {"obligation": "logAuditEvent", "status": "satisfied"},
                {"obligation": "preserveEvidence", "status": "satisfied"},
            ],
        )
        self.assertEqual(receipt["payload"]["version"], "1.0")
        verdict = self.evaluate([receipt], capability=capability)
        self.assertTrue(verdict.compliant)
        self.assertEqual(len(verdict.results), 3)

    def test_preserve_evidence_requires_receipt_commitment(self) -> None:
        rule = PolicyRule(
            policy_id="compliance-rule-evidence-only",
            issuer=self.authority.kid,
            target="door-*",
            effect="allow",
            actions=("open",),
            obligations=("preserveEvidence",),
        )
        engine = PolicyEngine([rule], trusted_policy_issuers={self.authority.kid})
        decision = engine.evaluate(self.request)
        capability = self.issuer.issue_scoped(
            self.request,
            decision,
            ttl_seconds=30,
            target=self.request.target,
            actions=["open"],
            purposes=["delivery"],
        )
        verified = ActionGate(
            trusted_issuers={self.authority.kid},
            replay_store=InMemoryReplayStore(),
        ).authorize(capability, self.request)
        plain_receipt = self.log.append(
            verified,
            result="succeeded",
            request=self.request,
        )
        self.assertEqual(plain_receipt["payload"]["version"], "0.1")
        verdict = self.evaluate([plain_receipt], capability=capability)
        self.assertFalse(verdict.compliant)
        self.assertIn("evidence-preservation commitment", verdict.reason or "")

    def test_trusted_executors_are_required(self) -> None:
        with self.assertRaises(ValueError):
            ObligationCompliance().evaluate(self.capability, [])
        with self.assertRaises(ValueError):
            ObligationCompliance().evaluate(
                self.capability,
                [],
                trusted_executors=set(),
            )


if __name__ == "__main__":
    unittest.main()
