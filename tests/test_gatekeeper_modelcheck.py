from __future__ import annotations

import unittest

from kinegrant.gatekeeper_modelcheck import check_gatekeeper_boundary


class GatekeeperBoundaryModelCheckTests(unittest.TestCase):
    def setUp(self) -> None:
        self.report = check_gatekeeper_boundary()

    def test_overall_pass(self) -> None:
        self.assertEqual(self.report["overall_result"], "PASS")
        self.assertEqual(self.report["summary"]["failed_properties"], 0)

    def test_all_properties_present(self) -> None:
        names = {prop["name"] for prop in self.report["properties"]}
        for required in (
            "actuator_runs_only_after_sequence_gate_revocation",
            "journal_only_on_fully_compliant_success",
            "replay_prevents_double_execution",
            "denials_carry_stage",
            "obligation_failure_keeps_evidence_not_journal",
        ):
            self.assertIn(required, names)

    def test_all_stages_are_exercised(self) -> None:
        stages = {scenario["outcome"]["stage"] for scenario in self.report["scenarios"]}
        for required in ("complete", "sequence", "gate", "revocation", "obligation", "actuator"):
            self.assertIn(required, stages)

    def test_allow_scenario_records_everything_once(self) -> None:
        allow = next(
            scenario for scenario in self.report["scenarios"] if scenario["name"] == "allow"
        )
        self.assertTrue(allow["outcome"]["allowed"])
        self.assertEqual(allow["after"]["actuator"], allow["before"]["actuator"] + 1)
        self.assertEqual(allow["after"]["receipts"], allow["before"]["receipts"] + 1)
        self.assertEqual(allow["after"]["journal"], allow["before"]["journal"] + 1)

    def test_report_is_machine_readable(self) -> None:
        self.assertEqual(
            self.report["type"],
            "kinegrant:GatekeeperBoundaryModelCheck",
        )
        self.assertEqual(self.report["schema_version"], "0.1")
        self.assertGreaterEqual(len(self.report["scenarios"]), 6)


if __name__ == "__main__":
    unittest.main()
