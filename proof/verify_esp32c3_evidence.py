from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
import json
from pathlib import Path
import sys
from typing import Any, Mapping

from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import SchemaError, ValidationError


SCHEMA_PATH = (
    Path(__file__).parent
    / "esp32-c3"
    / "schemas"
    / "physical-proof-evidence.schema.json"
)

EXPECTED_CASES = {
    "HWP-001": (20, 0, 0, 20),
    "HWP-002": (20, 20, 20, 0),
    "HWP-003": (20, 0, 0, 20),
    "HWP-004": (3, 0, 0, 3),
    "HWP-005": (1, 0, 0, 1),
    "HWP-006": (2, 0, 0, 2),
    "HWP-007": (64, 1, 1, 63),
    "HWP-008": (1, 0, 0, 1),
    "HWP-009": (2, 0, 0, 2),
    "HWP-010": (4, 0, 0, 0),
    "HWP-011": (100, 100, 100, 0),
}

REQUIRED_PHYSICAL_ARTIFACT_ROLES = {
    "firmware",
    "pinout_record",
    "wiring_photo",
    "serial_log",
    "host_log",
    "video",
    "receipts",
    "device_acks",
}


def _parse_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamps must include a timezone")
    return parsed


def _sha256_file(path: Path) -> tuple[str, int]:
    hasher = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(chunk)
            size += len(chunk)
    return "sha256:" + hasher.hexdigest(), size


def _resolve_artifact(root: Path, relative: str) -> Path:
    candidate = Path(relative)
    if candidate.is_absolute() or ".." in candidate.parts:
        raise ValueError(f"artifact path is not a safe relative path: {relative}")
    resolved_root = root.resolve()
    resolved = (root / candidate).resolve()
    if resolved != resolved_root and resolved_root not in resolved.parents:
        raise ValueError(f"artifact path escapes the evidence root: {relative}")
    return resolved


def verify_evidence(
    evidence: Mapping[str, Any],
    *,
    artifact_root: Path | None = None,
) -> None:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(evidence)

    cases = evidence["cases"]
    identifiers = [case["id"] for case in cases]
    if len(identifiers) != len(set(identifiers)):
        raise ValueError("case identifiers must be unique")
    if set(identifiers) != set(EXPECTED_CASES):
        missing = sorted(set(EXPECTED_CASES) - set(identifiers))
        extra = sorted(set(identifiers) - set(EXPECTED_CASES))
        raise ValueError(f"physical case set mismatch; missing={missing}, extra={extra}")

    artifacts = evidence["artifacts"]
    artifact_digests = [artifact["sha256"] for artifact in artifacts]
    if len(artifact_digests) != len(set(artifact_digests)):
        raise ValueError("artifact digests must be unique")
    known_digests = set(artifact_digests)
    for case in cases:
        unknown = set(case["artifact_digests"]) - known_digests
        if unknown:
            raise ValueError(f"{case['id']} references unknown artifact digests")
    if artifact_root is not None:
        for artifact in artifacts:
            path = _resolve_artifact(artifact_root, artifact["path"])
            if not path.is_file():
                raise ValueError(f"artifact file is missing: {artifact['path']}")
            digest, size = _sha256_file(path)
            if digest != artifact["sha256"] or size != artifact["bytes"]:
                raise ValueError(f"artifact bytes or digest mismatch: {artifact['path']}")

    result = evidence["overall_result"]
    mode = evidence["evidence_mode"]
    if result == "NOT_RUN":
        if any(case["attempts"] or case["passed"] for case in cases):
            raise ValueError("NOT_RUN evidence cannot contain attempted or passed cases")
        if evidence["started_at"] is not None or evidence["finished_at"] is not None:
            raise ValueError("NOT_RUN evidence cannot contain run timestamps")
        if any(evidence["verification"].values()):
            raise ValueError("NOT_RUN evidence cannot contain successful trust checks")
        return

    if evidence["started_at"] is None or evidence["finished_at"] is None:
        raise ValueError("completed evidence requires start and finish timestamps")
    started_at = _parse_time(evidence["started_at"])
    finished_at = _parse_time(evidence["finished_at"])
    generated_at = _parse_time(evidence["generated_at"])
    if finished_at < started_at:
        raise ValueError("finished_at cannot precede started_at")
    if generated_at < finished_at:
        raise ValueError("generated_at cannot precede finished_at")

    all_cases_passed = all(case["passed"] for case in cases)
    all_trust_checks_passed = all(evidence["verification"].values())
    expected_result = (
        "PHYSICAL_PASS" if mode == "physical" else "SIMULATION_PASS"
    ) if all_cases_passed and all_trust_checks_passed else "FAIL"
    if result != expected_result:
        raise ValueError("overall_result is inconsistent with cases and trust checks")

    if result in {"PHYSICAL_PASS", "SIMULATION_PASS"}:
        for case in cases:
            expected = EXPECTED_CASES[case["id"]]
            observed = (
                case["attempts"],
                case["measurements"]["actuator_calls"],
                case["measurements"]["observed_movements"],
                case["measurements"]["denials"],
            )
            if observed != expected:
                raise ValueError(
                    f"{case['id']} measurements differ from the acceptance profile: "
                    f"expected={expected}, observed={observed}"
                )
        endurance = next(case for case in cases if case["id"] == "HWP-011")
        if endurance["measurements"]["abnormal_resets"] != 0:
            raise ValueError("HWP-011 recorded an abnormal reset")
        if endurance["measurements"]["overheat_events"] != 0:
            raise ValueError("HWP-011 recorded an overheat event")

    if mode != "physical" or result != "PHYSICAL_PASS":
        return

    if evidence["source_commit"] is None:
        raise ValueError("physical evidence requires an exact source commit")
    if evidence["run_id"].endswith("00000000-0000-0000-0000-000000000000"):
        raise ValueError("physical evidence cannot use the template run identifier")
    device = evidence["device"]
    for field in ("device_key", "firmware_digest", "pinout_record_digest"):
        if device[field] is None:
            raise ValueError(f"physical evidence requires device.{field}")
    for field in ("board_model", "device_id", "firmware_version"):
        if device[field].startswith(("UN", "NOT_")):
            raise ValueError(f"physical evidence contains placeholder device.{field}")
    environment = evidence["environment"]
    if environment["servo_supply_voltage"] is None:
        raise ValueError("physical evidence requires measured servo supply voltage")
    if not environment["power_plan_reviewed"]:
        raise ValueError("physical evidence requires power-plan review")
    roles = {artifact["role"] for artifact in artifacts}
    missing_roles = REQUIRED_PHYSICAL_ARTIFACT_ROLES - roles
    if missing_roles:
        raise ValueError(
            "physical evidence is missing artifact roles: "
            + ", ".join(sorted(missing_roles))
        )
    if any(not case["artifact_digests"] for case in cases):
        raise ValueError("every physical case must reference at least one artifact")
    referenced_digests = {
        digest for case in cases for digest in case["artifact_digests"]
    }
    unreferenced_digests = known_digests - referenced_digests
    if unreferenced_digests:
        raise ValueError("every physical artifact must be referenced by a case")
    if device["firmware_digest"] not in {
        artifact["sha256"] for artifact in artifacts if artifact["role"] == "firmware"
    }:
        raise ValueError("device firmware_digest does not match a firmware artifact")
    if device["pinout_record_digest"] not in {
        artifact["sha256"] for artifact in artifacts if artifact["role"] == "pinout_record"
    }:
        raise ValueError("device pinout_record_digest does not match a pinout artifact")
    if artifact_root is None:
        raise ValueError("physical evidence requires --artifact-root for byte verification")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify KineGrant ESP32-C3 proof evidence and artifact bytes"
    )
    parser.add_argument("evidence", type=Path)
    parser.add_argument("--artifact-root", type=Path)
    parser.add_argument(
        "--allow-not-run",
        action="store_true",
        help="return success for a valid NOT_RUN template",
    )
    args = parser.parse_args(argv)
    try:
        evidence = json.loads(args.evidence.read_text(encoding="utf-8"))
        verify_evidence(evidence, artifact_root=args.artifact_root)
    except (OSError, SchemaError, ValidationError, ValueError) as exc:
        print(f"INVALID: {exc}", file=sys.stderr)
        return 2

    result = evidence["overall_result"]
    suffix = " (not physical evidence)" if evidence["evidence_mode"] == "simulation" else ""
    print(f"{result}: {evidence['run_id']}{suffix}")
    if result in {"PHYSICAL_PASS", "SIMULATION_PASS"}:
        return 0
    if result == "NOT_RUN" and args.allow_not_run:
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
