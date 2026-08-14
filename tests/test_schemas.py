from __future__ import annotations

import json
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

from kinegrant.capability import CapabilityIssuer
from kinegrant.crypto import Ed25519KeyPair
from kinegrant.gate import ActionGate
from kinegrant.models import ActionRequest, PolicyRule
from kinegrant.policy import PolicyEngine
from kinegrant.receipt import ReceiptLog

SCHEMA_DIR = Path(__file__).parents[1] / "spec" / "schemas"


def validate(name: str, value: object) -> None:
    schema = json.loads((SCHEMA_DIR / name).read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(value)


class SchemaTests(unittest.TestCase):
    def test_all_core_objects_match_published_schemas(self) -> None:
        request = ActionRequest("schema:r1", "robot:1", "door:1", "open", "delivery")
        rule = PolicyRule(
            "schema:p1", "owner:1", "door:1", "allow", ("open",),
            subjects=("robot:1",), purposes=("delivery",), obligations=("emitActionReceipt",),
        )
        decision = PolicyEngine([rule], trusted_policy_issuers={"owner:1"}).evaluate(request)
        authority = Ed25519KeyPair.generate()
        capability = CapabilityIssuer(authority).issue(request, decision)
        claims = ActionGate(trusted_issuers={authority.kid}).authorize(capability, request)
        receipt = ReceiptLog(Ed25519KeyPair.generate()).append(claims, result="succeeded")

        validate("action-request.schema.json", request.to_dict())
        validate("policy-rule.schema.json", rule.to_dict())
        validate("decision.schema.json", decision.to_dict())
        validate("capability.schema.json", capability)
        validate("receipt.schema.json", receipt)

    def test_schema_files_are_strict_draft_2020_12(self) -> None:
        for path in SCHEMA_DIR.glob("*.schema.json"):
            schema = json.loads(path.read_text(encoding="utf-8"))
            self.assertFalse(schema.get("additionalProperties", True), path.name)
            Draft202012Validator.check_schema(schema)

    def test_receipt_10_schema_accepts_additive_extensions(self) -> None:
        request = ActionRequest("schema:r2", "robot:1", "door:1", "open", "delivery")
        rule = PolicyRule(
            "schema:p2", "owner:1", "door:1", "allow", ("open",),
            subjects=("robot:1",), purposes=("delivery",),
            obligations=("emitActionReceipt",),
        )
        decision = PolicyEngine([rule], trusted_policy_issuers={"owner:1"}).evaluate(request)
        authority = Ed25519KeyPair.generate()
        capability = CapabilityIssuer(authority).issue(request, decision)
        claims = ActionGate(trusted_issuers={authority.kid}).authorize(capability, request)
        receipt = ReceiptLog(Ed25519KeyPair.generate()).append(
            claims,
            result="succeeded",
            obligation_results=[
                {"obligation": "emitActionReceipt", "status": "satisfied"}
            ],
        )
        validate("receipt-1.0.schema.json", receipt)


if __name__ == "__main__":
    unittest.main()
