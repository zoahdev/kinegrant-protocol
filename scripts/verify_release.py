"""Offline verification of a KineGrant release packet.

Given a directory containing a SHA256SUMS file, the source archive, and the
conformance report, this script verifies:

- every file listed in SHA256SUMS matches its SHA-256 digest;
- the conformance report is present and PASSes;
- if an MPT evidence file is present, the independent verifier accepts it.

Exit code 0 on success, 2 on any invalid input.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_release_packet(
    packet_dir: Path,
    *,
    checksums_name: str = "SHA256SUMS.txt",
) -> list[str]:
    """Verify a release packet; return a list of error messages (empty = OK)."""
    errors: list[str] = []
    checksums_path = packet_dir / checksums_name
    if not checksums_path.is_file():
        return [f"missing checksums file {checksums_name}"]
    expected: dict[str, str] = {}
    for line in checksums_path.read_text(encoding="ascii").splitlines():
        if not line.strip():
            continue
        parts = line.split()
        if len(parts) != 2:
            errors.append(f"malformed checksum line: {line!r}")
            continue
        digest, name = parts
        expected[name] = digest
    for name, digest in expected.items():
        path = packet_dir / name
        if not path.is_file():
            errors.append(f"missing packet file: {name}")
            continue
        actual = _sha256(path)
        if actual != digest:
            errors.append(f"checksum mismatch for {name}")

    report_candidates = sorted(packet_dir.glob("conformance-report*.json"))
    if not report_candidates:
        errors.append("missing conformance report")
    else:
        report = json.loads(report_candidates[0].read_text(encoding="utf-8"))
        if report.get("overall_result") != "PASS":
            errors.append("conformance report is not PASS")

    evidence_candidates = sorted(packet_dir.glob("machine-permission-test*.json"))
    if evidence_candidates:
        sys.path.insert(0, str(ROOT))
        try:
            from challenge.verify_evidence import verify_evidence

            evidence = json.loads(evidence_candidates[0].read_text(encoding="utf-8"))
            verify_evidence(evidence)
        except Exception as exc:
            errors.append(f"MPT evidence invalid: {exc}")
        finally:
            sys.path.pop(0)
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify a KineGrant release packet")
    parser.add_argument("packet_dir", type=Path)
    parser.add_argument("--checksums-name", default="SHA256SUMS.txt")
    args = parser.parse_args(argv)
    errors = verify_release_packet(args.packet_dir, checksums_name=args.checksums_name)
    if errors:
        for error in errors:
            print(f"INVALID: {error}", file=sys.stderr)
        return 2
    print("RELEASE PACKET VERIFIED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
