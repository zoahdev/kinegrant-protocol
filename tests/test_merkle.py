from __future__ import annotations

import unittest

from kinegrant.merkle import (
    merkle_proofs,
    merkle_redact,
    verify_field,
    verify_merkle_redaction,
)


class MerkleDisclosureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.document = {
            "agent": "robot-1",
            "target": "door-7",
            "purpose": "delivery",
        }

    def test_every_field_has_a_valid_proof(self) -> None:
        proofs = merkle_proofs(self.document)
        for field, entry in proofs.items():
            self.assertTrue(
                verify_field(entry["root"], field, entry["value"], entry["proof"])
            )

    def test_redaction_reveals_selected_fields(self) -> None:
        redaction = merkle_redact(self.document, visible=["target"])
        self.assertTrue(verify_merkle_redaction(redaction))
        self.assertEqual(len(redaction["visible"]), 1)
        self.assertEqual(redaction["visible"][0]["field"], "target")
        self.assertEqual(redaction["visible"][0]["value"], "door-7")

    def test_tampered_value_fails_verification(self) -> None:
        proofs = merkle_proofs(self.document)
        entry = proofs["target"]
        self.assertFalse(
            verify_field(entry["root"], "target", "other-door", entry["proof"])
        )

    def test_wrong_field_fails_verification(self) -> None:
        proofs = merkle_proofs(self.document)
        entry = proofs["target"]
        self.assertFalse(
            verify_field(entry["root"], "agent", entry["value"], entry["proof"])
        )

    def test_unknown_visible_field_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            merkle_redact(self.document, visible=["nope"])

    def test_deterministic_root(self) -> None:
        first = merkle_proofs(self.document)
        second = merkle_proofs(self.document)
        self.assertEqual(first["target"]["root"], second["target"]["root"])

    def test_non_power_of_two_documents_work(self) -> None:
        document = {"a": 1, "b": 2, "c": 3, "d": 4, "e": 5}
        redaction = merkle_redact(document, visible=["a", "e"])
        self.assertTrue(verify_merkle_redaction(redaction))


if __name__ == "__main__":
    unittest.main()
