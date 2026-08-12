from __future__ import annotations

from contextlib import redirect_stdout
import hashlib
from io import StringIO
import json
from pathlib import Path
import tempfile
import unittest

from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import ValidationError

from kinegrant.crypto import Ed25519KeyPair
from proof.verify_esp32c3_evidence import EXPECTED_CASES, main, verify_evidence


ROOT = Path(__file__).parents[1]
TEMPLATE_PATH = ROOT / "proof" / "esp32-c3" / "physical-proof-evidence.template.json"
SCHEMA_PATH = ROOT / "proof" / "esp32-c3" / "schemas" / "physical-proof-evidence.schema.json"


def load_template() -> dict:
    return json.loads(TEMPLATE_PATH.read_text(encoding="utf-8"))


def completed_simulation() -> dict:
    evidence = load_template()
    evidence["overall_result"] = "SIMULATION_PASS"
    evidence["generated_at"] = "2026-08-11T01:02:00Z"
    evidence["started_at"] = "2026-08-11T01:00:00Z"
    evidence["finished_at"] = "2026-08-11T01:01:00Z"
    evidence["verification"] = {key: True for key in evidence["verification"]}
    for case in evidence["cases"]:
        attempts, calls, movements, denials = EXPECTED_CASES[case["id"]]
        case["attempts"] = attempts
        case["passed"] = True
        case["measurements"] = {
            "actuator_calls": calls,
            "observed_movements": movements,
            "denials": denials,
            "abnormal_resets": 0,
            "overheat_events": 0,
        }
        case["notes"] = "Synthetic verifier test; not physical evidence."
    evidence["limitations"] = ["Synthetic verifier test; not physical evidence."]
    return evidence


class ESP32C3PhysicalEvidenceTests(unittest.TestCase):
    def test_not_run_template_is_schema_valid_and_explicit(self) -> None:
        evidence = load_template()
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema, format_checker=FormatChecker()).validate(evidence)
        verify_evidence(evidence)
        self.assertEqual(evidence["overall_result"], "NOT_RUN")
        self.assertEqual(evidence["evidence_mode"], "simulation")

        output = StringIO()
        with redirect_stdout(output):
            self.assertEqual(main([str(TEMPLATE_PATH)]), 1)
            self.assertEqual(main([str(TEMPLATE_PATH), "--allow-not-run"]), 0)
        self.assertIn("NOT_RUN", output.getvalue())

    def test_simulation_pass_cannot_be_labelled_physical(self) -> None:
        evidence = completed_simulation()
        verify_evidence(evidence)
        evidence["overall_result"] = "PHYSICAL_PASS"
        with self.assertRaises(ValidationError):
            verify_evidence(evidence)

    def test_not_run_cannot_claim_completed_trust_checks(self) -> None:
        evidence = load_template()
        evidence["verification"]["device_acks_verified"] = True
        with self.assertRaisesRegex(ValueError, "NOT_RUN evidence cannot contain successful"):
            verify_evidence(evidence)

    def test_acceptance_counts_are_independently_checked(self) -> None:
        evidence = completed_simulation()
        evidence["cases"][6]["attempts"] = 63
        with self.assertRaisesRegex(ValueError, "HWP-007 measurements differ"):
            verify_evidence(evidence)

    def test_physical_pass_verifies_required_artifact_bytes(self) -> None:
        evidence = completed_simulation()
        evidence["evidence_mode"] = "physical"
        evidence["overall_result"] = "PHYSICAL_PASS"
        evidence["run_id"] = "urn:kinegrant:esp32c3-proof:run:11111111-1111-1111-1111-111111111111"
        evidence["generated_at"] = "2026-08-11T01:02:00Z"
        evidence["source_commit"] = "a" * 40
        evidence["device"].update(
            {
                "board_model": "ESP32-C3 test fixture",
                "device_id": "device:esp32c3:paper-barrier:test",
                "device_key": Ed25519KeyPair.generate().kid,
                "firmware_version": "test-only",
            }
        )
        evidence["environment"].update(
            {
                "host_platform": "test",
                "servo_model": "test fixture",
                "servo_supply_voltage": 5.0,
                "power_plan_reviewed": True,
            }
        )

        roles = (
            "firmware",
            "pinout_record",
            "wiring_photo",
            "serial_log",
            "host_log",
            "video",
            "receipts",
            "device_acks",
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            artifacts = []
            digests = {}
            for role in roles:
                content = f"synthetic-{role}".encode()
                path = root / f"{role}.bin"
                path.write_bytes(content)
                digest = "sha256:" + hashlib.sha256(content).hexdigest()
                digests[role] = digest
                artifacts.append(
                    {
                        "role": role,
                        "path": path.name,
                        "media_type": "application/octet-stream",
                        "sha256": digest,
                        "bytes": len(content),
                    }
                )
            evidence["artifacts"] = artifacts
            evidence["device"]["firmware_digest"] = digests["firmware"]
            evidence["device"]["pinout_record_digest"] = digests["pinout_record"]
            for case in evidence["cases"]:
                case["artifact_digests"] = list(digests.values())

            verify_evidence(evidence, artifact_root=root)
            (root / "serial_log.bin").write_bytes(b"tampered")
            with self.assertRaisesRegex(ValueError, "artifact bytes or digest mismatch"):
                verify_evidence(evidence, artifact_root=root)

    def test_physical_pass_requires_artifact_root(self) -> None:
        evidence = completed_simulation()
        evidence["evidence_mode"] = "physical"
        evidence["overall_result"] = "PHYSICAL_PASS"
        evidence["run_id"] = "urn:kinegrant:esp32c3-proof:run:22222222-2222-2222-2222-222222222222"
        evidence["generated_at"] = "2026-08-11T01:02:00Z"
        evidence["source_commit"] = "b" * 40
        evidence["device"].update(
            {
                "board_model": "ESP32-C3 test fixture",
                "device_id": "device:esp32c3:paper-barrier:test",
                "device_key": Ed25519KeyPair.generate().kid,
                "firmware_version": "test-only",
                "firmware_digest": "sha256:" + "1" * 64,
                "pinout_record_digest": "sha256:" + "2" * 64,
            }
        )
        evidence["environment"].update(
            {"servo_supply_voltage": 5.0, "power_plan_reviewed": True}
        )
        with self.assertRaisesRegex(ValueError, "missing artifact roles"):
            verify_evidence(evidence)


if __name__ == "__main__":
    unittest.main()
