from __future__ import annotations

import csv
import json
from pathlib import Path
import tempfile
import unittest

from kinegrant.crypto import Ed25519KeyPair, public_key_from_id
from proof.provision_esp32c3 import generate_provisioning, main


class ESP32C3ProvisioningTests(unittest.TestCase):
    def test_secret_csv_and_public_record_are_separated(self) -> None:
        executor = Ed25519KeyPair.generate()
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "provision"
            record = generate_provisioning(
                "device:esp32c3:paper-barrier:test", executor.kid, output
            )
            public_key_from_id(record["device_kid"])
            public_text = (output / "provisioning-public-record.json").read_text(
                encoding="utf-8"
            )
            self.assertNotIn("device_seed", public_text)
            self.assertNotIn("hex2bin", public_text)
            self.assertEqual(json.loads(public_text), record)
            with (output / "provisioning-secret.csv").open(
                newline="", encoding="utf-8"
            ) as handle:
                rows = list(csv.reader(handle))
            self.assertEqual(rows[-1][0:3], ["device_seed", "data", "hex2bin"])
            self.assertEqual(len(rows[-1][3]), 64)

    def test_unsafe_identifier_invalid_kid_and_nonempty_output_are_refused(self) -> None:
        executor = Ed25519KeyPair.generate()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaises(ValueError):
                generate_provisioning("device with spaces", executor.kid, root / "a")
            with self.assertRaises(ValueError):
                generate_provisioning("device:test", "not-a-kid", root / "b")
            occupied = root / "c"
            occupied.mkdir()
            (occupied / "keep.txt").write_text("keep", encoding="utf-8")
            with self.assertRaises(FileExistsError):
                generate_provisioning("device:test", executor.kid, occupied)

    def test_cli_refuses_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            (output / "existing").write_text("keep", encoding="utf-8")
            self.assertEqual(
                main(
                    [
                        "--device-id",
                        "device:test",
                        "--executor-kid",
                        Ed25519KeyPair.generate().kid,
                        "--output-dir",
                        str(output),
                    ]
                ),
                2,
            )


if __name__ == "__main__":
    unittest.main()
