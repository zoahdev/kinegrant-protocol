from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Mapping

from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import SchemaError, ValidationError

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from challenge.verify_evidence import verify_evidence

SCHEMA_RELATIVE = Path("spec/schemas/reproduction-report.schema.json")
EVIDENCE_SCHEMA_RELATIVE = Path(
    "spec/schemas/machine-permission-test-evidence.schema.json"
)


def _sha256(path: Path) -> str:
    return f"sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}"


def _safe_path(base: Path, relative: str) -> Path:
    candidate = (base / relative).resolve()
    try:
        candidate.relative_to(base.resolve())
    except ValueError as exc:
        raise ValueError(f"path escapes its allowed root: {relative}") from exc
    return candidate


def verify_reproduction(report_path: Path) -> Mapping[str, Any]:
    report_path = report_path.resolve()
    packet_materials = report_path.parent / "materials"
    materials_root = packet_materials if packet_materials.is_dir() else ROOT
    report = json.loads(report_path.read_text(encoding="utf-8"))
    schema = json.loads(
        (materials_root / SCHEMA_RELATIVE).read_text(encoding="utf-8")
    )
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(report)

    material_paths: set[str] = set()
    for material in report["materials"]:
        relative = material["path"]
        if relative in material_paths:
            raise ValueError(f"duplicate material path: {relative}")
        material_paths.add(relative)
        path = _safe_path(materials_root, relative)
        if not path.is_file() or _sha256(path) != material["sha256"]:
            raise ValueError(f"material digest mismatch: {relative}")

    required_materials = {
        "challenge/reproduce.py",
        "challenge/verify_evidence.py",
        "challenge/verify_reproduction.py",
        "spec/schemas/machine-permission-test-evidence.schema.json",
        "spec/schemas/reproduction-report.schema.json",
        "examples/sample-receipt-v0.1.json",
        "spec/schemas/receipt.schema.json",
    }
    if material_paths != required_materials:
        raise ValueError("materials do not match the required reproduction set")

    artifacts = report["artifacts"]
    if len(artifacts) != 2:
        raise ValueError("exactly one MPT evidence and one receipt artifact are required")
    artifact_by_path = {artifact["path"]: artifact for artifact in artifacts}
    if set(artifact_by_path) != {
        "machine-permission-test.evidence.json",
        "sample-receipt-v0.1.json",
    }:
        raise ValueError("reproduction artifacts do not match the required set")
    artifact = artifact_by_path["machine-permission-test.evidence.json"]
    evidence_path = _safe_path(report_path.parent, artifact["path"])
    if not evidence_path.is_file():
        raise ValueError(f"missing artifact: {artifact['path']}")
    if evidence_path.stat().st_size != artifact["bytes"]:
        raise ValueError("evidence size mismatch")
    if _sha256(evidence_path) != artifact["sha256"]:
        raise ValueError("evidence digest mismatch")

    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    verify_evidence(
        evidence, schema_path=materials_root / EVIDENCE_SCHEMA_RELATIVE
    )
    if evidence["source_commit"] != report["source"]["commit"]:
        raise ValueError("source commit differs between report and evidence")
    if evidence["reference_implementation"] != report["reference_implementation"]:
        raise ValueError("reference implementation differs between report and evidence")
    if evidence["overall_result"] != report["overall_result"]:
        raise ValueError("overall result differs between report and evidence")
    if evidence["summary"]["total"] != report["verification"]["required_cases"]:
        raise ValueError("required case count differs from the evidence")
    if evidence["summary"]["passed"] != report["verification"]["passed_cases"]:
        raise ValueError("passed case count differs from the evidence")

    receipt_artifact = artifact_by_path["sample-receipt-v0.1.json"]
    receipt_path = _safe_path(report_path.parent, receipt_artifact["path"])
    if not receipt_path.is_file():
        raise ValueError("missing receipt artifact")
    if receipt_path.stat().st_size != receipt_artifact["bytes"]:
        raise ValueError("receipt size mismatch")
    if _sha256(receipt_path) != receipt_artifact["sha256"]:
        raise ValueError("receipt digest mismatch")
    if receipt_path.read_bytes() != (
        materials_root / "examples" / receipt_path.name
    ).read_bytes():
        raise ValueError("receipt differs from the committed public sample")
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify a KineGrant external reproduction packet"
    )
    parser.add_argument("report", type=Path)
    args = parser.parse_args(argv)
    try:
        report = verify_reproduction(args.report)
    except (OSError, json.JSONDecodeError, SchemaError, ValidationError, ValueError) as exc:
        print(f"INVALID: {exc}", file=sys.stderr)
        return 2
    print(f"{report['overall_result']}: {report['report_id']} (packet verified)")
    return 0 if report["overall_result"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
