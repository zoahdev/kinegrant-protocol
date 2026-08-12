from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from jsonschema.exceptions import SchemaError, ValidationError

ROOT = Path(__file__).resolve().parents[1]
for import_root in (ROOT, ROOT / "src"):
    if str(import_root) not in sys.path:
        sys.path.insert(0, str(import_root))

from challenge.verify_evidence import verify_evidence
from challenge.verify_reproduction import verify_reproduction
from kinegrant import __version__
from kinegrant.mpt import run_machine_permission_test

EVIDENCE_NAME = "machine-permission-test.evidence.json"
REPORT_NAME = "reproduction-report.json"
REPORT_CHECKSUM_NAME = "reproduction-report.sha256"
MATERIALS = (
    "challenge/reproduce.py",
    "challenge/verify_evidence.py",
    "challenge/verify_reproduction.py",
    "spec/schemas/machine-permission-test-evidence.schema.json",
    "spec/schemas/reproduction-report.schema.json",
    "examples/sample-receipt-v0.1.json",
    "spec/schemas/receipt.schema.json",
)


def _sha256(path: Path) -> str:
    return f"sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}"


def _write_json(path: Path, value: object) -> None:
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    temporary.replace(path)


def _git(args: list[str]) -> str | None:
    try:
        completed = subprocess.run(
            ["git", *args],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (FileNotFoundError, subprocess.SubprocessError):
        return None
    return completed.stdout.strip()


def _source_commit(explicit: str | None) -> str | None:
    checkout_commit = _git(["rev-parse", "HEAD"])
    candidate = explicit or os.environ.get("GITHUB_SHA") or checkout_commit
    if candidate is None:
        return None
    candidate = candidate.strip().lower()
    if re.fullmatch(r"[0-9a-f]{40,64}", candidate) is None:
        raise ValueError("source commit must be a lowercase 40-64 character hex digest")
    if checkout_commit is not None and candidate != checkout_commit.strip().lower():
        raise ValueError("source commit does not match the checked-out Git commit")
    return candidate


def _working_tree_dirty() -> bool | None:
    status = _git(["status", "--porcelain"])
    return None if status is None else bool(status)


def create_reproduction(
    output_dir: Path, *, source_commit: str | None = None
) -> dict[str, Any]:
    dirty = _working_tree_dirty()
    output_dir.mkdir(parents=True, exist_ok=True)
    commit = _source_commit(source_commit)
    evidence = run_machine_permission_test(source_commit=commit)
    verify_evidence(evidence)

    evidence_path = output_dir / EVIDENCE_NAME
    _write_json(evidence_path, evidence)
    receipt_source = ROOT / "examples" / "sample-receipt-v0.1.json"
    receipt_path = output_dir / receipt_source.name
    receipt_path.write_bytes(receipt_source.read_bytes())
    materials_root = output_dir / "materials"
    for relative in MATERIALS:
        destination = materials_root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / relative, destination)

    report = {
        "schema_version": "0.1",
        "report_id": f"urn:kinegrant:reproduction:{uuid4()}",
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "protocol": "KGP-001 Experimental Open Draft 0.1",
        "reference_implementation": __version__,
        "source": {
            "commit": commit,
            "working_tree_dirty": dirty,
        },
        "environment": {
            "python_version": platform.python_version(),
            "python_implementation": platform.python_implementation(),
            "platform": platform.platform(),
        },
        "materials": [
            {"path": path, "sha256": _sha256(ROOT / path)} for path in MATERIALS
        ],
        "artifacts": [
            {
                "path": EVIDENCE_NAME,
                "media_type": "application/json",
                "bytes": evidence_path.stat().st_size,
                "sha256": _sha256(evidence_path),
            },
            {
                "path": receipt_path.name,
                "media_type": "application/json",
                "bytes": receipt_path.stat().st_size,
                "sha256": _sha256(receipt_path),
            },
        ],
        "verification": {
            "verifier": "challenge/verify_reproduction.py",
            "required_cases": 9,
            "passed_cases": evidence["summary"]["passed"],
        },
        "overall_result": evidence["overall_result"],
        "limitations": [
            "This report reproduces the software permission boundary only.",
            "It does not prove physical actuation, functional safety, or production readiness.",
            "A receipt is a signed executor attestation, not independent physical truth.",
        ],
    }
    report_path = output_dir / REPORT_NAME
    _write_json(report_path, report)
    verify_reproduction(report_path)
    checksum = hashlib.sha256(report_path.read_bytes()).hexdigest()
    (output_dir / REPORT_CHECKSUM_NAME).write_text(
        f"{checksum}  {REPORT_NAME}\n", encoding="ascii"
    )
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate a self-checking KineGrant external reproduction packet"
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("reproduction-output"),
        help="Directory for the evidence and reproduction report",
    )
    parser.add_argument(
        "--source-commit",
        help="Lowercase Git commit digest for the tested implementation",
    )
    args = parser.parse_args(argv)
    try:
        report = create_reproduction(
            args.output_dir, source_commit=args.source_commit
        )
    except (OSError, SchemaError, ValidationError, ValueError) as exc:
        print(f"REPRODUCTION_ERROR: {exc}", file=sys.stderr)
        return 2
    print(
        json.dumps(
            {
                "overall_result": report["overall_result"],
                "report": str(args.output_dir / REPORT_NAME),
                "report_checksum": str(args.output_dir / REPORT_CHECKSUM_NAME),
                "evidence": str(args.output_dir / EVIDENCE_NAME),
            },
            sort_keys=True,
        )
    )
    return 0 if report["overall_result"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
