from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from challenge.reproduce import create_reproduction
from challenge.verify_reproduction import verify_reproduction


class ExternalReproductionTests(unittest.TestCase):
    def test_packet_is_generated_and_independently_verified(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            report = create_reproduction(output, source_commit="a" * 40)
            verified = verify_reproduction(output / "reproduction-report.json")

            self.assertEqual(report["overall_result"], "PASS")
            self.assertEqual(verified["source"]["commit"], "a" * 40)
            self.assertEqual(verified["verification"]["passed_cases"], 9)

    def test_changed_evidence_bytes_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            create_reproduction(output, source_commit="b" * 40)
            evidence_path = output / "machine-permission-test.evidence.json"
            evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
            evidence["overall_result"] = "FAIL"
            evidence_path.write_text(json.dumps(evidence), encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "mismatch"):
                verify_reproduction(output / "reproduction-report.json")

    def test_artifact_path_cannot_escape_packet_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            create_reproduction(output, source_commit="c" * 40)
            report_path = output / "reproduction-report.json"
            report = json.loads(report_path.read_text(encoding="utf-8"))
            report["artifacts"][0]["path"] = "../outside.json"
            report_path.write_text(json.dumps(report), encoding="utf-8")

            with self.assertRaises(Exception):
                verify_reproduction(report_path)


if __name__ == "__main__":
    unittest.main()
