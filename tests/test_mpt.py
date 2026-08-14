from __future__ import annotations

import json
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

from challenge.verify_evidence import verify_evidence
from kinegrant.mpt import main, run_machine_permission_test


class MachinePermissionTestTests(unittest.TestCase):
    def test_all_required_permission_cases_pass(self) -> None:
        evidence = run_machine_permission_test()
        self.assertEqual(evidence["overall_result"], "PASS")
        self.assertEqual(evidence["summary"], {"total": 17, "passed": 17, "failed": 0})
        self.assertEqual(
            [case["id"] for case in evidence["cases"]],
            [f"MPT-{number:03d}" for number in range(1, 18)],
        )

    def test_evidence_matches_published_schema(self) -> None:
        schema_path = (
            Path(__file__).parents[1]
            / "spec"
            / "schemas"
            / "machine-permission-test-evidence.schema.json"
        )
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema, format_checker=FormatChecker()).validate(
            run_machine_permission_test()
        )

    def test_evidence_records_source_runner_and_environment(self) -> None:
        evidence = run_machine_permission_test(source_commit="a" * 40)
        self.assertEqual(evidence["source_commit"], "a" * 40)
        self.assertRegex(evidence["runner_digest"], r"^sha256:[0-9a-f]{64}$")
        self.assertTrue(evidence["environment"]["python_version"])
        with self.assertRaisesRegex(ValueError, "source_commit"):
            run_machine_permission_test(source_commit="not-a-commit")

    def test_cli_emits_machine_readable_pass(self) -> None:
        output = StringIO()
        with redirect_stdout(output):
            exit_code = main([])
        self.assertEqual(exit_code, 0)
        self.assertEqual(json.loads(output.getvalue())["overall_result"], "PASS")

    def test_independent_verifier_checks_summary_consistency(self) -> None:
        evidence = run_machine_permission_test()
        verify_evidence(evidence)
        evidence["summary"]["passed"] = 8
        with self.assertRaisesRegex(ValueError, "summary is inconsistent"):
            verify_evidence(evidence)


if __name__ == "__main__":
    unittest.main()
