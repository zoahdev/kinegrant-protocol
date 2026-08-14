from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from kinegrant.crypto import Ed25519KeyPair
from kinegrant.models import PolicyRule
from kinegrant.policy_bundle import PolicyAuthority

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "verify" / "verify_policy_bundle.mjs"


def _node() -> str | None:
    found = shutil.which("node")
    if found:
        return found
    bundled = (
        Path(r"C:\Users\zoah\.cache\codex-runtimes\codex-primary-runtime")
        / "dependencies"
        / "node"
        / "bin"
        / "node.exe"
    )
    return str(bundled) if bundled.exists() else None


@unittest.skipUnless(_node(), "node.js is not available")
class BrowserVerifierInteropTests(unittest.TestCase):
    def setUp(self) -> None:
        self.authority = PolicyAuthority(Ed25519KeyPair.generate())
        self.policy_id = "urn:kinegrant:browser:policy:door"
        self.rules_v1 = [
            PolicyRule(
                self.policy_id,
                self.authority.kid,
                "urn:space:browser:door-1",
                "allow",
                ("open",),
                purposes=("delivery",),
            )
        ]
        self.v1 = self.authority.publish(
            self.policy_id,
            self.rules_v1,
            ttl_seconds=3600,
        )
        self.v2 = self.authority.publish(
            self.policy_id,
            [
                PolicyRule(
                    self.policy_id,
                    self.authority.kid,
                    "urn:space:browser:door-1",
                    "allow",
                    ("open",),
                    purposes=("delivery", "maintenance"),
                )
            ],
            ttl_seconds=3600,
        )

    def _run(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [_node(), CLI, *args],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=60,
        )

    def test_browser_verifier_accepts_python_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            bundle_path = base / "bundle.json"
            authorities_path = base / "authorities.json"
            bundle_path.write_text(json.dumps(self.v2), encoding="utf-8")
            authorities_path.write_text(
                json.dumps([self.authority.kid]),
                encoding="utf-8",
            )
            verified = self._run(
                "verify",
                str(bundle_path),
                str(authorities_path),
                self.policy_id,
            )
            self.assertEqual(verified.returncode, 0, verified.stderr)
            self.assertIn("POLICY BUNDLE VALID", verified.stdout)

    def test_browser_verifier_current_version_and_rollback(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            bundles_path = base / "bundles.json"
            revoked_path = base / "revoked.json"
            bundles_path.write_text(
                json.dumps([self.v1["payload"], self.v2["payload"]]),
                encoding="utf-8",
            )
            revoked_path.write_text(
                json.dumps([f"{self.policy_id}:2"]),
                encoding="utf-8",
            )
            current = self._run("current", str(bundles_path))
            self.assertEqual(current.returncode, 0, current.stderr)
            self.assertEqual(json.loads(current.stdout)["version"], 2)
            rollback = self._run("current", str(bundles_path), str(revoked_path))
            self.assertEqual(rollback.returncode, 0, rollback.stderr)
            self.assertEqual(json.loads(rollback.stdout)["version"], 1)

    def test_browser_verifier_rejects_tampered_bundle(self) -> None:
        tampered = dict(self.v2)
        tampered["payload"] = dict(self.v2["payload"])
        tampered["payload"]["rules"] = []
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            bundle_path = base / "bundle.json"
            authorities_path = base / "authorities.json"
            bundle_path.write_text(json.dumps(tampered), encoding="utf-8")
            authorities_path.write_text(
                json.dumps([self.authority.kid]),
                encoding="utf-8",
            )
            rejected = self._run(
                "verify",
                str(bundle_path),
                str(authorities_path),
                self.policy_id,
            )
            self.assertEqual(rejected.returncode, 2)
            self.assertIn("INVALID", rejected.stderr)


if __name__ == "__main__":
    unittest.main()
