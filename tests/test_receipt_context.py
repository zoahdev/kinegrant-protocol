from __future__ import annotations

import json
import unittest
from pathlib import Path

import jsonschema

from kinegrant.capability import CapabilityIssuer
from kinegrant.crypto import Ed25519KeyPair
from kinegrant.gate import ActionGate, InMemoryReplayStore
from kinegrant.models import ActionRequest, PolicyRule
from kinegrant.policy import PolicyEngine
from kinegrant.receipt import ReceiptLog, verify_receipt_chain


class ReceiptContextTests(unittest.TestCase):
    def setUp(self) -> None:
        self.issuer = CapabilityIssuer(Ed25519KeyPair.generate())
        self.executor = Ed25519KeyPair.generate()
        self.gate = ActionGate(
            trusted_issuers={self.issuer.key_pair.kid},
            replay_store=InMemoryReplayStore(),
        )
        self.request = ActionRequest(
            request_id="req-receipt-1",
            agent="robot-1",
            target="door-7",
            action="open",
            purpose="delivery",
        )
        rule = PolicyRule(
            policy_id="receipt-rule-1",
            issuer=self.issuer.key_pair.kid,
            target="door-*",
            effect="allow",
            actions=("open",),
            constraints={"min_approval_tier": 2},
        )
        engine = PolicyEngine(
            [rule],
            trusted_policy_issuers={self.issuer.key_pair.kid},
        )
        decision = engine.evaluate(self.request)
        root = self.issuer.issue_scoped(
            self.request,
            decision,
            ttl_seconds=30,
            approval_tier=decision.required_approval_tier,
        )
        self.child = self.issuer.issue_attenuated(
            root,
            target="door-7",
            max_force_newtons=40,
            max_velocity_mps=1.5,
            allowed_zones=["dock-*"],
        )
        self.verified = self.gate.authorize(self.child, self.request)
        self.log = ReceiptLog(self.executor)

    def test_receipt_carries_authorization_context_from_v02_capability(self) -> None:
        receipt = self.log.append(
            self.verified,
            result="succeeded",
            evidence_hash="sha256:" + "0" * 64,
            request=self.request,
        )
        payload = receipt["payload"]
        self.assertEqual(payload["approval_tier"], 2)
        self.assertEqual(payload["constraints"]["max_force_newtons"], 40)
        self.assertEqual(payload["constraints"]["max_velocity_mps"], 1.5)
        self.assertEqual(payload["constraints"]["allowed_zones"], ["dock-*"])
        self.assertEqual(
            payload["parent_capability_id"],
            self.child["payload"]["parent_capability_id"],
        )

    def test_receipt_matches_published_schema(self) -> None:
        receipt = self.log.append(
            self.verified,
            result="succeeded",
            request=self.request,
        )
        schema_path = (
            Path(__file__).resolve().parents[1]
            / "spec"
            / "schemas"
            / "receipt.schema.json"
        )
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        jsonschema.validate(receipt, schema)

    def test_receipt_chain_verifies_with_context(self) -> None:
        first = self.log.append(
            self.verified,
            result="succeeded",
            request=self.request,
        )
        second_request = ActionRequest(
            request_id="req-receipt-2",
            agent="robot-1",
            target="door-7",
            action="open",
            purpose="delivery",
        )
        rule = PolicyRule(
            policy_id="receipt-rule-2",
            issuer=self.issuer.key_pair.kid,
            target="door-7",
            effect="allow",
            actions=("open",),
        )
        engine = PolicyEngine(
            [rule],
            trusted_policy_issuers={self.issuer.key_pair.kid},
        )
        decision = engine.evaluate(second_request)
        v1 = self.issuer.issue(second_request, decision, ttl_seconds=30)
        verified2 = self.gate.authorize(v1, second_request)
        second = self.log.append(verified2, result="failed")
        self.assertTrue(
            verify_receipt_chain(
                [first, second],
                trusted_executors={self.executor.kid},
            )
        )
        self.assertNotIn("approval_tier", second["payload"])
        self.assertNotIn("constraints", second["payload"])

    def test_tampered_constraints_break_chain(self) -> None:
        receipt = self.log.append(
            self.verified,
            result="succeeded",
            request=self.request,
        )
        forged = json.loads(json.dumps(receipt))
        forged["payload"]["constraints"]["max_force_newtons"] = 999
        self.assertFalse(verify_receipt_chain([forged]))


if __name__ == "__main__":
    unittest.main()
