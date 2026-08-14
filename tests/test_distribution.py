from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

from kinegrant.crypto import Ed25519KeyPair
from kinegrant.distribution import RevocationDistributor, main
from kinegrant.revocation import (
    RevocationList,
    build_revocation_bundle,
    sign_revocation_bundle,
)


class RevocationDistributorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.authority = Ed25519KeyPair.generate()
        self.rl = RevocationList()
        self.rl.revoke("kinegrant:cap:" + "a" * 64, reason="maintenance")
        self.rl.revoke("kinegrant:cap:" + "b" * 64, reason="compromise")
        self.bundle = sign_revocation_bundle(
            build_revocation_bundle(self.rl, issuer=self.authority.kid),
            self.authority,
        )

    def gates(self) -> dict[str, RevocationList]:
        return {
            "gate-1": RevocationList(),
            "gate-2": RevocationList(),
            "gate-3": RevocationList(),
        }

    def test_distributes_to_all_gates(self) -> None:
        gates = self.gates()
        report = RevocationDistributor(
            trusted_authorities={self.authority.kid}
        ).distribute(self.bundle, gates)
        self.assertEqual(report["overall_result"], "PASS")
        self.assertEqual(report["summary"]["gates"], 3)
        self.assertEqual(report["summary"]["added_total"], 6)
        self.assertEqual(report["summary"]["already_present_total"], 0)
        self.assertIn("kinegrant:revocation-bundle:", report["bundle_id"])
        for gate in gates.values():
            self.assertTrue(gate.is_revoked("kinegrant:cap:" + "a" * 64))
            self.assertTrue(gate.is_revoked("kinegrant:cap:" + "b" * 64))

    def test_application_is_idempotent(self) -> None:
        gates = self.gates()
        distributor = RevocationDistributor(
            trusted_authorities={self.authority.kid}
        )
        first = distributor.distribute(self.bundle, gates)
        second = distributor.distribute(self.bundle, gates)
        self.assertEqual(first["summary"]["added_total"], 6)
        self.assertEqual(second["summary"]["added_total"], 0)
        self.assertEqual(second["summary"]["already_present_total"], 6)

    def test_untrusted_authority_fails_closed(self) -> None:
        other = Ed25519KeyPair.generate()
        gates = self.gates()
        with self.assertRaises(ValueError):
            RevocationDistributor(
                trusted_authorities={other.kid}
            ).distribute(self.bundle, gates)
        for gate in gates.values():
            self.assertEqual(gate.entries, ())

    def test_tampered_bundle_fails_closed(self) -> None:
        tampered = copy.deepcopy(self.bundle)
        tampered["payload"]["revocations"][0]["reason"] = "changed"
        gates = self.gates()
        with self.assertRaises(ValueError):
            RevocationDistributor(
                trusted_authorities={self.authority.kid}
            ).distribute(tampered, gates)
        for gate in gates.values():
            self.assertEqual(gate.entries, ())

    def test_expected_previous_digest_is_enforced(self) -> None:
        gates = self.gates()
        with self.assertRaises(ValueError):
            RevocationDistributor(
                trusted_authorities={self.authority.kid},
                expected_previous_digest="sha256:" + "c" * 64,
            ).distribute(self.bundle, gates)
        for gate in gates.values():
            self.assertEqual(gate.entries, ())

    def test_self_test_returns_zero(self) -> None:
        self.assertEqual(main(["--self-test"]), 0)

    def test_cli_file_mode(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            bundle_path = base / "bundle.json"
            gates_path = base / "gates.json"
            authorities_path = base / "authorities.json"
            bundle_path.write_text(json.dumps(self.bundle), encoding="utf-8")
            gates_path.write_text(
                json.dumps(
                    {
                        "gate-1": self.gates()["gate-1"].to_dict(),
                        "gate-2": self.gates()["gate-2"].to_dict(),
                    }
                ),
                encoding="utf-8",
            )
            authorities_path.write_text(
                json.dumps([self.authority.kid]),
                encoding="utf-8",
            )
            exit_code = main(
                [
                    str(bundle_path),
                    str(gates_path),
                    str(authorities_path),
                ]
            )
            self.assertEqual(exit_code, 0)


if __name__ == "__main__":
    unittest.main()
