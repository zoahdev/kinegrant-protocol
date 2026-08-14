from __future__ import annotations

import unittest

from kinegrant.capability import CapabilityIssuer
from kinegrant.crypto import Ed25519KeyPair
from kinegrant.gate import ActionGate, InMemoryReplayStore
from kinegrant.gatekeeper import Gatekeeper
from kinegrant.models import ActionRequest, PolicyRule
from kinegrant.policy import PolicyEngine
from kinegrant.receipt import ReceiptLog, verify_receipt_chain
from kinegrant.revocation import RevocationList
from kinegrant.sequence import ActionJournal, ForbiddenCombination, SequencePolicy


class GatekeeperTests(unittest.TestCase):
    def setUp(self) -> None:
        self.authority = Ed25519KeyPair.generate()
        self.executor = Ed25519KeyPair.generate()
        self.issuer = CapabilityIssuer(self.authority)
        self.request = ActionRequest(
            request_id="req-gatekeeper-1",
            agent="robot-1",
            target="door-7",
            action="open",
            purpose="delivery",
        )
        self.target = "door-7"

    def build(
        self,
        *,
        obligations: tuple[str, ...] = ("emitActionReceipt",),
        actions: tuple[str, ...] = ("open", "close", "enter"),
    ) -> tuple[Gatekeeper, dict, list[str]]:
        rule = PolicyRule(
            policy_id="gatekeeper-rule-1",
            issuer=self.authority.kid,
            target="door-*",
            effect="allow",
            actions=actions,
            obligations=obligations,
        )
        engine = PolicyEngine([rule], trusted_policy_issuers={self.authority.kid})
        decision = engine.evaluate(self.request)
        capability = self.issuer.issue_scoped(
            self.request,
            decision,
            ttl_seconds=30,
            target=self.request.target,
            actions=list(actions),
            purposes=["delivery"],
        )
        journal = ActionJournal()
        sequence = SequencePolicy(
            [
                ForbiddenCombination(
                    "open-enter",
                    patterns=(("open", self.target),),
                    trigger=("enter", self.target),
                )
            ]
        )
        gatekeeper = Gatekeeper(
            gate=ActionGate(
                trusted_issuers={self.authority.kid},
                replay_store=InMemoryReplayStore(),
            ),
            sequence=sequence,
            journal=journal,
            receipt_log=ReceiptLog(self.executor),
        )
        actuator_calls: list[str] = []
        return gatekeeper, capability, actuator_calls

    def test_happy_path_runs_full_boundary(self) -> None:
        gatekeeper, capability, calls = self.build()
        outcome = gatekeeper.execute(
            capability,
            self.request,
            lambda verified: calls.append(verified["capability_id"]),
        )
        self.assertTrue(outcome.allowed)
        self.assertEqual(outcome.stage, "complete")
        self.assertIsNotNone(outcome.receipt_id)
        self.assertTrue(outcome.obligation_compliant)
        self.assertTrue(outcome.journal_recorded)
        self.assertEqual(len(calls), 1)
        self.assertTrue(
            verify_receipt_chain(
                gatekeeper.receipt_log.entries,
                trusted_executors={self.executor.kid},
            )
        )
        self.assertEqual(len(gatekeeper.journal.entries), 1)

    def test_sequence_violation_denied_before_gate(self) -> None:
        gatekeeper, capability, calls = self.build()
        gatekeeper.journal.record("open", self.target)
        enter = ActionRequest(
            request_id="req-gatekeeper-enter",
            agent="robot-1",
            target="door-7",
            action="enter",
            purpose="delivery",
        )
        decision = PolicyEngine(
            [
                PolicyRule(
                    "gatekeeper-enter-rule",
                    self.authority.kid,
                    "door-*",
                    "allow",
                    ("enter",),
                    obligations=("emitActionReceipt",),
                )
            ],
            trusted_policy_issuers={self.authority.kid},
        ).evaluate(enter)
        enter_capability = self.issuer.issue_scoped(
            enter,
            decision,
            ttl_seconds=30,
            target="door-7",
            actions=["enter"],
            purposes=["delivery"],
        )
        outcome = gatekeeper.execute(
            enter_capability,
            enter,
            lambda verified: calls.append(verified["capability_id"]),
        )
        self.assertFalse(outcome.allowed)
        self.assertEqual(outcome.stage, "sequence")
        self.assertIn("forbidden_combination", outcome.reason or "")
        self.assertEqual(calls, [])
        self.assertEqual(len(gatekeeper.receipt_log.entries), 0)

    def test_replay_is_denied_at_gate(self) -> None:
        gatekeeper, capability, calls = self.build()
        first = gatekeeper.execute(
            capability,
            self.request,
            lambda verified: calls.append(verified["capability_id"]),
        )
        second = gatekeeper.execute(
            capability,
            self.request,
            lambda verified: calls.append(verified["capability_id"]),
        )
        self.assertTrue(first.allowed)
        self.assertFalse(second.allowed)
        self.assertEqual(second.stage, "gate")
        self.assertIn("replay", second.reason or "")
        self.assertEqual(len(calls), 1)

    def test_actuator_failure_records_failed_receipt(self) -> None:
        gatekeeper, capability, calls = self.build()

        def boom(verified) -> None:
            calls.append(verified["capability_id"])
            raise RuntimeError("servo jam")

        outcome = gatekeeper.execute(capability, self.request, boom)
        self.assertFalse(outcome.allowed)
        self.assertEqual(outcome.stage, "actuator")
        self.assertIn("servo jam", outcome.reason or "")
        self.assertEqual(len(calls), 1)
        self.assertEqual(len(gatekeeper.receipt_log.entries), 1)
        self.assertEqual(
            gatekeeper.receipt_log.entries[0]["payload"]["result"],
            "failed",
        )
        self.assertEqual(len(gatekeeper.journal.entries), 0)

    def test_obligation_evasion_is_detected(self) -> None:
        gatekeeper, capability, calls = self.build(obligations=("logAuditEvent",))
        outcome = gatekeeper.execute(
            capability,
            self.request,
            lambda verified: calls.append(verified["capability_id"]),
        )
        self.assertFalse(outcome.allowed)
        self.assertEqual(outcome.stage, "obligation")
        self.assertIn("audit-log commitment", outcome.reason or "")
        self.assertEqual(len(calls), 1)
        self.assertFalse(outcome.journal_recorded)

    def test_outcome_is_serializable(self) -> None:
        gatekeeper, capability, calls = self.build()
        outcome = gatekeeper.execute(
            capability,
            self.request,
            lambda verified: calls.append(verified["capability_id"]),
        )
        data = outcome.to_dict()
        self.assertEqual(data["allowed"], True)
        self.assertEqual(data["stage"], "complete")
        self.assertIn("capability_id", data)
        self.assertIn("receipt_id", data)
        self.assertIn("obligation_compliant", data)
        self.assertIn("journal_recorded", data)

    def test_revoked_capability_denied_at_revocation_stage(self) -> None:
        gatekeeper, capability, calls = self.build()
        revocation_list = RevocationList()
        revocation_list.revoke(capability["payload"]["capability_id"])
        gk = Gatekeeper(
            gate=ActionGate(
                trusted_issuers={self.authority.kid},
                replay_store=InMemoryReplayStore(),
            ),
            sequence=SequencePolicy([]),
            journal=ActionJournal(),
            receipt_log=ReceiptLog(self.executor),
            revocation_list=revocation_list,
        )
        outcome = gk.execute(
            capability,
            self.request,
            lambda verified: calls.append(verified["capability_id"]),
        )
        self.assertFalse(outcome.allowed)
        self.assertEqual(outcome.stage, "revocation")
        self.assertIn("revoked", outcome.reason or "")
        self.assertEqual(calls, [])
        self.assertEqual(len(gk.receipt_log.entries), 0)


if __name__ == "__main__":
    unittest.main()
