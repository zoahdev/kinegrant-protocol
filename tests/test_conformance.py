from __future__ import annotations

import json
import unittest
from contextlib import redirect_stdout
from io import StringIO

from kinegrant.conformance import ConformanceRunner, main


class ConformanceSuiteTests(unittest.TestCase):
    def setUp(self) -> None:
        self.report = ConformanceRunner().run_all()

    def test_overall_pass(self) -> None:
        self.assertEqual(self.report["overall_result"], "PASS")
        self.assertEqual(
            self.report["summary"],
            {"total": 22, "passed": 22, "failed": 0},
        )

    def test_all_four_levels_are_present(self) -> None:
        levels = {mark["level"] for mark in self.report["marks"]}
        self.assertEqual(levels, {"L1", "L2", "L3", "L4"})

    def test_independent_verification_cross_checks(self) -> None:
        independent = self.report["independent_verification"]
        self.assertEqual(independent["overall_result"], "PASS")
        self.assertTrue(independent["checks"])
        for check in independent["checks"]:
            self.assertIn(check["capability"], {"PASS", "SKIP"})
            self.assertIn(check["receipts"], {"PASS", "SKIP"})
        self.assertTrue(
            any(check["capability"] == "PASS" for check in independent["checks"])
        )

    def test_level_marks_cover_key_properties(self) -> None:
        names = {mark["name"] for mark in self.report["marks"]}
        for required in (
            "default_deny",
            "deny_overrides",
            "single_use",
            "replay_rejected",
            "receipt_chain",
            "attenuation",
            "physical_constraints",
            "approval_tiers",
            "forbidden_combination",
            "obligation_compliance",
            "gatekeeper_boundary",
            "gatekeeper_boundary_modelcheck",
            "delegation",
            "delegate_allowlist",
            "revocation",
            "revocation_distribution",
            "policy_bundle_trust",
            "trusted_clock",
            "sensor_evidence",
            "receipt_checkpoint",
            "device_attestation",
            "post_quantum_envelopes",
        ):
            self.assertIn(required, names)

    def test_cli_emits_machine_readable_pass(self) -> None:
        output = StringIO()
        with redirect_stdout(output):
            exit_code = main([])
        self.assertEqual(exit_code, 0)
        self.assertEqual(json.loads(output.getvalue())["overall_result"], "PASS")


if __name__ == "__main__":
    unittest.main()
