from __future__ import annotations

import copy
import json
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

from kinegrant.audit import ReceiptAuditor, main
from kinegrant.capability import CapabilityIssuer
from kinegrant.crypto import Ed25519KeyPair
from kinegrant.gate import ActionGate, InMemoryReplayStore
from kinegrant.models import ActionRequest, PolicyRule, utc_now
from kinegrant.policy import PolicyEngine
from kinegrant.receipt import ReceiptLog


class ReceiptAuditorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.authority = Ed25519KeyPair.generate()
        self.executor = Ed25519KeyPair.generate()
        self.issuer = CapabilityIssuer(self.authority)
        self.gate = ActionGate(
            trusted_issuers={self.authority.kid},
            replay_store=InMemoryReplayStore(),
        )
        self.log = ReceiptLog(self.executor)
        self.capabilities: dict[str, dict] = {}
        self.requests: dict[str, ActionRequest] = {}

        rule = PolicyRule(
            "urn:kinegrant:audit:rule",
            self.authority.kid,
            "urn:kinegrant:audit:target:*",
            "allow",
            ("open", "close"),
            obligations=("emitActionReceipt",),
        )
        self.engine = PolicyEngine([rule], trusted_policy_issuers={self.authority.kid})
        cases = [
            ("r1", "robot-1", "urn:kinegrant:audit:target:door-7", "open", "delivery", "succeeded"),
            ("r2", "robot-1", "urn:kinegrant:audit:target:door-7", "close", "maintenance", "succeeded"),
            ("r3", "robot-2", "urn:kinegrant:audit:target:door-8", "open", "delivery", "failed"),
        ]
        now = utc_now()
        for index, (request_id, agent, target, action, purpose, result) in enumerate(cases):
            request = ActionRequest(
                f"urn:kinegrant:audit:request:{request_id}",
                agent,
                target,
                action,
                purpose,
            )
            self.requests[request_id] = request
            decision = self.engine.evaluate(request)
            capability = self.issuer.issue(request, decision, ttl_seconds=300)
            self.capabilities[request_id] = capability
            verified = self.gate.authorize(capability, request)
            self.log.append(
                verified,
                result=result,
                failure_reason=(
                    "actuator timeout" if result == "failed" else None
                ),
            )
            now += timedelta(seconds=1)
        self.auditor = ReceiptAuditor(
            self.log.entries,
            trusted_executors={self.executor.kid},
        )

    def test_chain_is_valid(self) -> None:
        self.assertTrue(self.auditor.chain_valid())

    def test_query_by_capability_and_agent_and_result(self) -> None:
        capability_id = self.capabilities["r1"]["payload"]["capability_id"]
        by_capability = self.auditor.query(capability_id=capability_id)
        self.assertEqual(len(by_capability), 1)
        self.assertEqual(by_capability[0]["action"], "open")
        by_agent = self.auditor.query(agent="robot-1")
        self.assertEqual(len(by_agent), 2)
        by_result = self.auditor.query(result="failed")
        self.assertEqual(len(by_result), 1)
        self.assertEqual(by_result[0]["failure_reason"], "actuator timeout")
        by_action = self.auditor.query(action="open", agent="robot-2")
        self.assertEqual(len(by_action), 1)

    def test_query_by_time_range(self) -> None:
        base = utc_now()
        all_receipts = self.auditor.query()
        self.assertEqual(len(all_receipts), 3)
        recent = self.auditor.query(since=base - timedelta(seconds=1))
        self.assertEqual(len(recent), 3)
        none = self.auditor.query(since=base + timedelta(days=1))
        self.assertEqual(none, ())

    def test_summary_counts(self) -> None:
        summary = self.auditor.summary()
        self.assertTrue(summary["chain_valid"])
        self.assertEqual(summary["total"], 3)
        self.assertEqual(summary["by_result"], {"failed": 1, "succeeded": 2})
        self.assertEqual(summary["by_action"], {"close": 1, "open": 2})
        self.assertIsNotNone(summary["first_finished_at"])
        self.assertIsNotNone(summary["last_finished_at"])

    def test_invalid_chain_fails_closed(self) -> None:
        tampered = copy.deepcopy(self.log.entries)
        tampered[1]["payload"]["result"] = "aborted"
        auditor = ReceiptAuditor(tampered, trusted_executors={self.executor.kid})
        self.assertFalse(auditor.chain_valid())
        with self.assertRaises(ValueError):
            auditor.query()
        summary = auditor.summary(strict=False)
        self.assertFalse(summary["chain_valid"])

    def test_untrusted_executor_fails_closed(self) -> None:
        other = Ed25519KeyPair.generate()
        auditor = ReceiptAuditor(self.log.entries, trusted_executors={other.kid})
        self.assertFalse(auditor.chain_valid())
        with self.assertRaises(ValueError):
            auditor.query()

    def test_compliance_for_satisfied_capability(self) -> None:
        capability = self.capabilities["r1"]
        verdict = self.auditor.compliance_for(capability)
        self.assertTrue(verdict.compliant)

    def test_compliance_for_requires_trust(self) -> None:
        auditor = ReceiptAuditor(self.log.entries)
        with self.assertRaises(ValueError):
            auditor.compliance_for(self.capabilities["r1"])

    def test_self_test_returns_zero(self) -> None:
        self.assertEqual(main(["--self-test"]), 0)

    def test_cli_file_mode(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            receipts_path = base / "receipts.json"
            executors_path = base / "executors.json"
            receipts_path.write_text(
                json.dumps(list(self.log.entries)),
                encoding="utf-8",
            )
            executors_path.write_text(
                json.dumps([self.executor.kid]),
                encoding="utf-8",
            )
            exit_code = main([str(receipts_path), str(executors_path)])
            self.assertEqual(exit_code, 0)


if __name__ == "__main__":
    unittest.main()
