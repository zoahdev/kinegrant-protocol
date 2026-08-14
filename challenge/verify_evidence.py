from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Mapping

from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import SchemaError, ValidationError

SCHEMA_PATH = (
    Path(__file__).parents[1]
    / "spec"
    / "schemas"
    / "machine-permission-test-evidence.schema.json"
)
REQUIRED_CASES = {f"MPT-{number:03d}" for number in range(1, 15)}


def verify_evidence(
    evidence: Mapping[str, Any], *, schema_path: Path = SCHEMA_PATH
) -> None:
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(evidence)

    cases = evidence["cases"]
    identifiers = [case["id"] for case in cases]
    if len(identifiers) != len(set(identifiers)):
        raise ValueError("case identifiers must be unique")
    missing = REQUIRED_CASES - set(identifiers)
    if missing:
        raise ValueError(f"missing required cases: {', '.join(sorted(missing))}")

    passed = sum(case["passed"] for case in cases)
    expected_summary = {
        "total": len(cases),
        "passed": passed,
        "failed": len(cases) - passed,
    }
    if evidence["summary"] != expected_summary:
        raise ValueError("summary is inconsistent with case results")
    expected_result = "PASS" if expected_summary["failed"] == 0 else "FAIL"
    if evidence["overall_result"] != expected_result:
        raise ValueError("overall_result is inconsistent with case results")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify KineGrant MPT JSON evidence")
    parser.add_argument("evidence", type=Path)
    args = parser.parse_args(argv)
    try:
        evidence = json.loads(args.evidence.read_text(encoding="utf-8"))
        verify_evidence(evidence)
    except (OSError, SchemaError, ValidationError, ValueError) as exc:
        print(f"INVALID: {exc}", file=sys.stderr)
        return 2
    print(
        f"{evidence['overall_result']}: {evidence['run_id']} "
        f"({evidence['summary']['passed']}/{evidence['summary']['total']} cases)"
    )
    return 0 if evidence["overall_result"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
