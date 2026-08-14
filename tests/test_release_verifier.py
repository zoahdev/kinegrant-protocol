from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from scripts.verify_release import verify_release_packet

ROOT = Path(__file__).resolve().parents[1]


def _write(path: Path, content: str | bytes) -> None:
    if isinstance(content, bytes):
        path.write_bytes(content)
    else:
        path.write_text(content, encoding="utf-8")


class ReleaseVerifierTests(unittest.TestCase):
    def _packet(self, directory: Path, *, tamper: bool = False) -> None:
        _write(directory / "source.zip", b"fake source")
        _write(
            directory / "conformance-report.json",
            json.dumps({"overall_result": "PASS", "summary": {"total": 17, "passed": 17}}),
        )
        _write(directory / "artifact.txt", "hello")
        lines = []
        for name in ("source.zip", "conformance-report.json", "artifact.txt"):
            digest = __import__("hashlib").sha256(
                (directory / name).read_bytes()
            ).hexdigest()
            lines.append(f"{digest}  {name}")
        _write(directory / "SHA256SUMS.txt", "\n".join(lines) + "\n")
        if tamper:
            _write(directory / "artifact.txt", "tampered")

    def test_valid_packet_verifies(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            self._packet(Path(directory))
            errors = verify_release_packet(Path(directory))
            self.assertEqual(errors, [])

    def test_tampered_artifact_is_detected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            self._packet(Path(directory), tamper=True)
            errors = verify_release_packet(Path(directory))
            self.assertTrue(any("checksum mismatch" in error for error in errors))

    def test_missing_conformance_report_is_detected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            self._packet(Path(directory))
            (Path(directory) / "conformance-report.json").unlink()
            errors = verify_release_packet(Path(directory))
            self.assertTrue(any("conformance report" in error for error in errors))

    def test_mpt_evidence_is_verified_when_present(self) -> None:
        evidence = (ROOT / "work" / "mpt-v0.2-packet" / "machine-permission-test.evidence.json")
        if not evidence.exists():
            self.skipTest("reference MPT evidence not available")
        with tempfile.TemporaryDirectory() as directory:
            packet = Path(directory)
            _write(packet / "source.zip", b"fake")
            _write(
                packet / "conformance-report.json",
                json.dumps({"overall_result": "PASS"}),
            )
            target = packet / evidence.name
            target.write_bytes(evidence.read_bytes())
            lines = []
            for name in ("source.zip", "conformance-report.json", evidence.name):
                digest = __import__("hashlib").sha256(
                    (packet / name).read_bytes()
                ).hexdigest()
                lines.append(f"{digest}  {name}")
            _write(packet / "SHA256SUMS.txt", "\n".join(lines) + "\n")
            errors = verify_release_packet(packet)
            self.assertEqual(errors, [])


if __name__ == "__main__":
    unittest.main()
