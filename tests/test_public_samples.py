from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

from kinegrant.receipt import verify_receipt_chain


ROOT = Path(__file__).parents[1]
SAMPLE_PATH = ROOT / "examples" / "sample-receipt-v0.1.json"
SCHEMA_PATH = ROOT / "spec" / "schemas" / "receipt.schema.json"


class PublicReceiptSampleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.receipt = json.loads(SAMPLE_PATH.read_text(encoding="utf-8"))

    def test_public_sample_matches_schema_and_verifies_with_trust(self) -> None:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        Draft202012Validator(
            schema,
            format_checker=FormatChecker(),
        ).validate(self.receipt)
        self.assertTrue(
            verify_receipt_chain(
                [self.receipt],
                trusted_executors={self.receipt["kid"]},
                expected_capability_ids={self.receipt["payload"]["capability_id"]},
            )
        )

    def test_public_sample_tampering_is_rejected(self) -> None:
        tampered = copy.deepcopy(self.receipt)
        tampered["payload"]["action"] = "different_action"
        self.assertFalse(
            verify_receipt_chain(
                [tampered],
                trusted_executors={tampered["kid"]},
            )
        )

    def test_public_sample_needs_explicit_executor_trust(self) -> None:
        self.assertFalse(
            verify_receipt_chain(
                [self.receipt],
                trusted_executors={"kinegrant:key:ed25519:" + "A" * 43},
            )
        )


if __name__ == "__main__":
    unittest.main()
