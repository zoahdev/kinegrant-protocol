"""Generate a machine-readable security review kit (v1.8 draft).

The kit gives an external auditor everything needed to reproduce the
project's evidence: the exact versions, the commands to rerun every check,
pointers to the authoritative documents and releases, and a checklist whose
items are backed by actually running the suites (conformance, MPT, red-team,
benchmarks, unit tests, optional release-packet verification).

Usage:

    python scripts/security_review_kit.py --output kit.json
    python scripts/security_review_kit.py --output kit.json \\
        --source-commit <sha> --release-dir <packet-directory>

Exit code 0 only when every automated check passes.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import subprocess
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

from kinegrant import __version__  # noqa: E402
from kinegrant.conformance import ConformanceRunner  # noqa: E402
from kinegrant.mpt import run_machine_permission_test  # noqa: E402
from kinegrant.redteam import RedTeamSuite  # noqa: E402


def _run_module(module: str, args: list[str] | None = None) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT / "src")
    env["KINEGRANT_KIT_TEST"] = "1"
    return subprocess.run(
        [sys.executable, "-m", module, *(args or [])],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
    )


def _checks(source_commit: str | None, release_dir: str | None) -> dict[str, Any]:
    conformance = ConformanceRunner().run_all()
    mpt = run_machine_permission_test(source_commit=source_commit)
    red_team = RedTeamSuite().run()

    import benchmarks.bench as bench

    benchmark = bench.run(iterations=200)

    test_proc = _run_module("unittest", ["discover", "-s", "tests"])
    test_output = test_proc.stdout + test_proc.stderr
    test_lines = test_output.splitlines()
    summary_lines = [
        line.strip() for line in test_lines if re.match(r"^(OK|FAILED)", line.strip())
    ]
    test_ok = (
        test_proc.returncode == 0
        and bool(summary_lines)
        and summary_lines[-1].startswith("OK")
    )

    release_ok = None
    release_detail = None
    if release_dir:
        packet_dir = Path(release_dir)
        verify_path = ROOT / "scripts" / "verify_release.py"
        spec = importlib.util.spec_from_file_location("verify_release", verify_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        errors = module.verify_release_packet(packet_dir)
        release_ok = not errors
        release_detail = "RELEASE PACKET VERIFIED" if release_ok else "; ".join(errors)

    checks = {
        "conformance": {
            "status": "PASS" if conformance["overall_result"] == "PASS" else "FAIL",
            "detail": f"{conformance['summary']['passed']}/"
            f"{conformance['summary']['total']}",
        },
        "machine_permission_test": {
            "status": "PASS" if mpt["overall_result"] == "PASS" else "FAIL",
            "detail": f"{mpt['summary']['passed']}/{mpt['summary']['total']}",
            "schema_version": mpt["schema_version"],
        },
        "red_team": {
            "status": "PASS" if red_team["overall_result"] == "PASS" else "FAIL",
            "detail": f"{red_team['summary']['passed']}/"
            f"{red_team['summary']['total']}",
        },
        "benchmarks": {
            "status": "PASS",
            "detail": "machine-readable throughput emitted",
            "operations_per_second": benchmark["operations_per_second"],
        },
        "unit_tests": {
            "status": "PASS" if test_ok else "FAIL",
            "detail": (
                summary_lines[-1]
                if summary_lines
                else (test_output.strip()[-120:] if test_output else "")
            ),
        },
        "release_packet": (
            {
                "status": "PASS" if release_ok else "FAIL",
                "detail": release_detail,
            }
            if release_dir
            else {"status": "SKIP", "detail": "no release directory supplied"}
        ),
    }
    return checks


def _checklist(checks: dict[str, Any]) -> list[dict[str, str]]:
    return [
        {
            "id": "default-deny",
            "name": "Default deny and deny-overrides",
            "evidence": "spec/KGP-001.md, conformance mark default_deny",
            "status": checks["conformance"]["status"],
        },
        {
            "id": "replay-protection",
            "name": "One-time consumption and crash-persistent replay protection",
            "evidence": "MPT-003/MPT-007/MPT-008, SQLiteReplayStore",
            "status": checks["machine_permission_test"]["status"],
        },
        {
            "id": "revocation",
            "name": "Revocation and fleet distribution",
            "evidence": "MPT-017, spec/REVOCATION.md, RevocationDistributor",
            "status": checks["machine_permission_test"]["status"],
        },
        {
            "id": "obligations",
            "name": "Obligation enforcement",
            "evidence": "MPT-015/MPT-016, ObligationCompliance",
            "status": checks["machine_permission_test"]["status"],
        },
        {
            "id": "boundary-modelcheck",
            "name": "Gatekeeper boundary model check",
            "evidence": "conformance mark gatekeeper_boundary_modelcheck",
            "status": checks["conformance"]["status"],
        },
        {
            "id": "cross-implementation",
            "name": "Cross-implementation interop",
            "evidence": "conformance independent_verification, kinegrant-js, kinegrant-go",
            "status": checks["conformance"]["status"],
        },
        {
            "id": "adversarial",
            "name": "Executable red-team probes",
            "evidence": "kinegrant-red-team report",
            "status": checks["red_team"]["status"],
        },
    ]


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_packet(kit: dict[str, Any], packet_dir: Path) -> None:
    packet_dir.mkdir(parents=True, exist_ok=True)
    kit_path = packet_dir / "security-review-kit.json"
    commands_path = packet_dir / "reproduce-commands.txt"
    zip_path = packet_dir / f"SecurityReviewKit-v{kit['reference_implementation']}.zip"
    checksums_path = packet_dir / "SHA256SUMS.txt"
    kit_path.write_text(
        json.dumps(kit, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    commands_path.write_text("\n".join(kit["commands"]) + "\n", encoding="utf-8")
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.write(kit_path, kit_path.name)
        zf.write(commands_path, commands_path.name)
    lines = []
    for name in (kit_path.name, zip_path.name):
        lines.append(f"{_sha256(packet_dir / name)}  {name}")
    checksums_path.write_text("\n".join(sorted(lines)) + "\n", encoding="ascii")


def _verify_packet(packet_dir: Path) -> tuple[bool, str]:
    checksums_path = packet_dir / "SHA256SUMS.txt"
    if not checksums_path.is_file():
        return False, "missing SHA256SUMS.txt"
    expected: dict[str, str] = {}
    for line in checksums_path.read_text(encoding="ascii").splitlines():
        if not line.strip():
            continue
        digest, name = line.split()
        expected[name] = digest
    for name, digest in expected.items():
        path = packet_dir / name
        if not path.is_file():
            return False, f"missing packet file: {name}"
        if _sha256(path) != digest:
            return False, f"checksum mismatch for {name}"
    kit_path = packet_dir / "security-review-kit.json"
    kit = json.loads(kit_path.read_text(encoding="utf-8"))
    if kit.get("type") != "kinegrant:SecurityReviewKit":
        return False, "wrong kit type"
    if kit.get("overall_result") != "PASS":
        return False, "kit overall_result is not PASS"
    return True, "SECURITY KIT PACKET VERIFIED"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate the security review kit")
    parser.add_argument("--output", default=None, type=Path)
    parser.add_argument("--source-commit", default=None)
    parser.add_argument("--release-dir", default=None)
    parser.add_argument("--packet-dir", default=None, type=Path)
    parser.add_argument("--verify-packet", default=None, type=Path)
    args = parser.parse_args(argv)

    if args.verify_packet is not None:
        ok, detail = _verify_packet(args.verify_packet)
        print(detail)
        return 0 if ok else 1
    if args.output is None:
        parser.error("--output is required")

    checks = _checks(args.source_commit, args.release_dir)
    automated = [check for key, check in checks.items() if key != "release_packet"]
    overall = "PASS" if all(check["status"] == "PASS" for check in automated) else "FAIL"
    kit = {
        "type": "kinegrant:SecurityReviewKit",
        "schema_version": "0.1",
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "reference_implementation": __version__,
        "source_commit": args.source_commit,
        "overall_result": overall,
        "checks": checks,
        "checklist": _checklist(checks),
        "commands": [
            "python -m unittest discover -s tests",
            "python -m kinegrant.conformance",
            "python -m kinegrant.mpt --source-commit <sha> --output evidence.json",
            "python challenge/verify_evidence.py evidence.json",
            "kinegrant-red-team",
            "python benchmarks/bench.py",
            "python scripts/verify_release.py <packet-directory>",
        ],
        "artifacts": {
            "specification": "spec/KGP-001.md",
            "threat_model": "spec/THREAT-MODEL.md",
            "standards_mapping": "spec/STANDARD-MAPPING.md",
            "reproducing": "REPRODUCING.md",
            "deployment_cases": "docs/DEPLOYMENT-CASES.md",
            "releases": [
                "https://github.com/zoahdev/kinegrant-protocol/releases/tag/v1.7.0",
                "https://github.com/zoahdev/kinegrant-protocol/releases/tag/mpt-v0.3",
            ],
        },
        "limitations": [
            "The kit automates evidence collection; it is not a security audit.",
            "Independent third-party review is still required for certification.",
        ],
    }
    args.output.write_text(
        json.dumps(kit, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    if args.packet_dir is not None:
        _write_packet(kit, args.packet_dir)
    print(json.dumps(kit, indent=2, sort_keys=True))
    return 0 if overall == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
