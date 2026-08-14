from __future__ import annotations

import json
import unittest
from pathlib import Path

import jsonschema

from kinegrant.capability import CapabilityIssuer
from kinegrant.canonical import content_id
from kinegrant.crypto import Ed25519KeyPair
from kinegrant.gate import ActionGate, InMemoryReplayStore
from kinegrant.models import ActionRequest, PolicyRule, isoformat, utc_now
from kinegrant.policy import PolicyEngine
from kinegrant.receipt import ReceiptLog, verify_receipt_chain


class ReceiptV10Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.issuer = CapabilityIssuer(Ed25519KeyPair.generate())
        self.executor = Ed25519KeyPair.generate()
        self.request = ActionRequest(
            request_id="req-v10-1",
            agent="robot-1",
            target="door-7",
            action="open",
            purpose="delivery",
        )
        rule = PolicyRule(
            policy_id="v10-rule-1",
            issuer=self.issuer.key_pair.kid,
            target="door-*",
            effect="allow",
            actions=("open",),
            obligations=("emitActionReceipt",),
        )
        engine = PolicyEngine(
            [rule],
            trusted_policy_issuers={self.issuer.key_pair.kid},
        )
        decision = engine.evaluate(self.request)
        capability = self.issuer.issue_scoped(
            self.request,
            decision,
            ttl_seconds=30,
        )
        self.verified = ActionGate(
            trusted_issuers={self.issuer.key_pair.kid},
            replay_store=InMemoryReplayStore(),
        ).authorize(capability, self.request)
        self.log = ReceiptLog(self.executor)

    def test_default_receipt_stays_v01(self) -> None:
        receipt = self.log.append(
            self.verified,
            result="succeeded",
            request=self.request,
        )
        payload = receipt["payload"]
        self.assertEqual(payload["version"], "0.1")
        self.assertNotIn("obligation_results", payload)
        self.assertNotIn("failure_reason", payload)
        self.assertTrue(
            verify_receipt_chain(
                [receipt],
                trusted_executors={self.executor.kid},
            )
        )

    def test_extended_receipt_is_v10_and_verifies(self) -> None:
        receipt = self.log.append(
            self.verified,
            result="succeeded",
            request=self.request,
            obligation_results=[
                {"obligation": "emitActionReceipt", "status": "satisfied"}
            ],
        )
        payload = receipt["payload"]
        self.assertEqual(payload["version"], "1.0")
        self.assertEqual(
            payload["obligation_results"],
            [{"obligation": "emitActionReceipt", "status": "satisfied"}],
        )
        self.assertTrue(
            verify_receipt_chain(
                [receipt],
                trusted_executors={self.executor.kid},
            )
        )

    def test_failure_reason_receipt_is_v10(self) -> None:
        receipt = self.log.append(
            self.verified,
            result="failed",
            request=self.request,
            failure_reason="actuator timeout",
        )
        self.assertEqual(receipt["payload"]["version"], "1.0")
        self.assertEqual(receipt["payload"]["failure_reason"], "actuator timeout")
        self.assertTrue(
            verify_receipt_chain(
                [receipt],
                trusted_executors={self.executor.kid},
            )
        )

    def test_failed_obligation_requires_reason(self) -> None:
        with self.assertRaises(ValueError):
            self.log.append(
                self.verified,
                result="succeeded",
                request=self.request,
                obligation_results=[
                    {"obligation": "emitActionReceipt", "status": "failed"}
                ],
            )

    def test_invalid_obligation_results_are_rejected(self) -> None:
        cases = [
            [],
            [{"obligation": "logAudit", "status": "satisfied"}],
            [{"obligation": "emitActionReceipt", "status": "done"}],
            [{"obligation": "emitActionReceipt", "status": "satisfied", "extra": 1}],
        ]
        for case in cases:
            with self.assertRaises(ValueError, msg=str(case)):
                self.log.append(
                    self.verified,
                    result="succeeded",
                    request=self.request,
                    obligation_results=case,
                )

    def test_empty_failure_reason_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self.log.append(
                self.verified,
                result="failed",
                request=self.request,
                failure_reason="",
            )

    def test_tampered_v10_receipt_is_rejected(self) -> None:
        receipt = self.log.append(
            self.verified,
            result="succeeded",
            request=self.request,
            obligation_results=[
                {"obligation": "emitActionReceipt", "status": "satisfied"}
            ],
        )
        tampered = json.loads(json.dumps(receipt))
        tampered["payload"]["obligation_results"][0]["status"] = "failed"
        self.assertFalse(
            verify_receipt_chain(
                [tampered],
                trusted_executors={self.executor.kid},
            )
        )

    def test_v10_without_extension_is_rejected(self) -> None:
        now = utc_now()
        payload = {
            "type": "kinegrant:PhysicalActionReceipt",
            "version": "1.0",
            "executor": self.executor.kid,
            "capability_id": self.verified["capability_id"],
            "request_digest": self.request.digest,
            "agent": self.request.agent,
            "target": self.request.target,
            "action": self.request.action,
            "purpose": self.request.purpose,
            "result": "succeeded",
            "started_at": isoformat(now),
            "finished_at": isoformat(now),
            "evidence_hash": None,
            "previous_receipt_hash": None,
        }
        payload["receipt_id"] = content_id("kinegrant:receipt", payload)
        envelope = self.executor.sign_envelope(payload)
        self.assertFalse(
            verify_receipt_chain(
                [envelope],
                trusted_executors={self.executor.kid},
            )
        )

    def test_receipt_10_matches_published_schema(self) -> None:
        receipt = self.log.append(
            self.verified,
            result="failed",
            request=self.request,
            obligation_results=[
                {
                    "obligation": "emitActionReceipt",
                    "status": "failed",
                    "failure_reason": "receipt store unavailable",
                }
            ],
            failure_reason="actuator timeout",
        )
        schema_path = (
            Path(__file__).resolve().parents[1]
            / "spec"
            / "schemas"
            / "receipt-1.0.schema.json"
        )
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        jsonschema.validate(receipt, schema)


if __name__ == "__main__":
    unittest.main()
