from __future__ import annotations

import json
import tempfile
import unittest
from hashlib import sha256
from pathlib import Path
from unittest.mock import patch

from challenge.reproduce import create_reproduction
from challenge.verify_reproduction import verify_reproduction

ROOT = Path(__file__).resolve().parents[1]


class ExternalReproductionTests(unittest.TestCase):
    def test_public_codespaces_link_targets_runnable_branch(self) -> None:
        expected = (
            "https://codespaces.new/zoahdev/kinegrant-protocol"
            "?ref=main&quickstart=1"
        )
        self.assertIn(expected, (ROOT / "README.md").read_text(encoding="utf-8"))
        self.assertIn(expected, (ROOT / "REPRODUCING.md").read_text(encoding="utf-8"))

    def _create(self, output: Path, commit: str) -> dict:
        def fake_git(args: list[str]) -> str:
            return commit if args == ["rev-parse", "HEAD"] else ""

        with patch("challenge.reproduce._git", side_effect=fake_git):
            return create_reproduction(output, source_commit=commit)

    def test_packet_is_generated_and_independently_verified(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            report = self._create(output, "a" * 40)
            verified = verify_reproduction(output / "reproduction-report.json")

            self.assertEqual(report["overall_result"], "PASS")
            self.assertEqual(verified["source"]["commit"], "a" * 40)
            self.assertEqual(verified["verification"]["passed_cases"], 9)
            self.assertTrue((output / "sample-receipt-v0.1.json").is_file())
            self.assertTrue(
                (output / "materials/challenge/verify_reproduction.py").is_file()
            )
            report_path = output / "reproduction-report.json"
            expected_checksum = sha256(report_path.read_bytes()).hexdigest()
            self.assertEqual(
                (output / "reproduction-report.sha256").read_text(encoding="ascii"),
                f"{expected_checksum}  reproduction-report.json\n",
            )

    def test_claimed_commit_must_match_checkout(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with patch("challenge.reproduce._git", return_value="b" * 40):
                with self.assertRaisesRegex(ValueError, "checked-out Git commit"):
                    create_reproduction(Path(directory), source_commit="a" * 40)

    def test_changed_evidence_bytes_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            self._create(output, "b" * 40)
            evidence_path = output / "machine-permission-test.evidence.json"
            evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
            evidence["overall_result"] = "FAIL"
            evidence_path.write_text(json.dumps(evidence), encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "mismatch"):
                verify_reproduction(output / "reproduction-report.json")

    def test_artifact_path_cannot_escape_packet_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            self._create(output, "c" * 40)
            report_path = output / "reproduction-report.json"
            report = json.loads(report_path.read_text(encoding="utf-8"))
            report["artifacts"][0]["path"] = "../outside.json"
            report_path.write_text(json.dumps(report), encoding="utf-8")

            with self.assertRaises(Exception):
                verify_reproduction(report_path)

    def test_changed_receipt_bytes_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            self._create(output, "d" * 40)
            receipt_path = output / "sample-receipt-v0.1.json"
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            receipt["payload"]["action"] = "tampered_action"
            receipt_path.write_text(json.dumps(receipt), encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "receipt (size|digest) mismatch"):
                verify_reproduction(output / "reproduction-report.json")

    def test_changed_portable_material_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            self._create(output, "e" * 40)
            verifier_path = output / "materials/challenge/verify_evidence.py"
            verifier_path.write_text("# changed\n", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "material digest mismatch"):
                verify_reproduction(output / "reproduction-report.json")


if __name__ == "__main__":
    unittest.main()
