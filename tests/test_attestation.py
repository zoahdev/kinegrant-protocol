from __future__ import annotations

import copy
import unittest

from kinegrant.attestation import build_device_attestation, verify_device_attestation
from kinegrant.crypto import Ed25519KeyPair, MLDSA65KeyPair
from kinegrant.keys import BackedKeyPair, SoftwareEd25519Backend


DIGEST = "sha256:" + "a" * 64


class DeviceAttestationTests(unittest.TestCase):
    def test_round_trip_with_ed25519(self) -> None:
        device = Ed25519KeyPair.generate()
        attestation = build_device_attestation(
            device_id="urn:kinegrant:target:demo:door-controller-1",
            firmware_digest=DIGEST,
            boot_counter=3,
            device_key=device,
            measured_boot=[{"stage": "bootloader", "digest": DIGEST}],
        )
        payload = verify_device_attestation(
            attestation,
            trusted_devices={device.kid},
        )
        self.assertEqual(payload["boot_counter"], 3)
        self.assertEqual(payload["measured_boot"][0]["stage"], "bootloader")

    def test_round_trip_with_mldsa(self) -> None:
        device = MLDSA65KeyPair.generate()
        attestation = build_device_attestation(
            device_id="urn:kinegrant:target:demo:door-controller-1",
            firmware_digest=DIGEST,
            boot_counter=1,
            device_key=device,
        )
        verify_device_attestation(attestation, trusted_devices={device.kid})

    def test_round_trip_with_backed_key(self) -> None:
        backend = SoftwareEd25519Backend.generate()
        device = BackedKeyPair(backend)
        attestation = build_device_attestation(
            device_id="urn:kinegrant:target:demo:door-controller-1",
            firmware_digest=DIGEST,
            boot_counter=0,
            device_key=device,
        )
        verify_device_attestation(attestation, trusted_devices={backend.kid})

    def test_tampered_firmware_digest_is_rejected(self) -> None:
        device = Ed25519KeyPair.generate()
        attestation = build_device_attestation(
            device_id="urn:kinegrant:target:demo:door-controller-1",
            firmware_digest=DIGEST,
            boot_counter=1,
            device_key=device,
        )
        tampered = copy.deepcopy(attestation)
        tampered["payload"]["firmware_digest"] = "sha256:" + "b" * 64
        with self.assertRaises(ValueError):
            verify_device_attestation(tampered)

    def test_untrusted_device_is_rejected(self) -> None:
        device = Ed25519KeyPair.generate()
        attestation = build_device_attestation(
            device_id="urn:kinegrant:target:demo:door-controller-1",
            firmware_digest=DIGEST,
            boot_counter=1,
            device_key=device,
        )
        with self.assertRaises(ValueError):
            verify_device_attestation(attestation, trusted_devices=set())

    def test_invalid_fields_are_rejected(self) -> None:
        device = Ed25519KeyPair.generate()
        with self.assertRaises(ValueError):
            build_device_attestation(
                device_id="urn:kinegrant:target:demo:door-controller-1",
                firmware_digest="not-a-digest",
                boot_counter=1,
                device_key=device,
            )
        with self.assertRaises(ValueError):
            build_device_attestation(
                device_id="urn:kinegrant:target:demo:door-controller-1",
                firmware_digest=DIGEST,
                boot_counter=-1,
                device_key=device,
            )
        with self.assertRaises(ValueError):
            build_device_attestation(
                device_id="urn:kinegrant:target:demo:door-controller-1",
                firmware_digest=DIGEST,
                boot_counter=1,
                device_key=device,
                measured_boot=[{"stage": "bootloader", "digest": "bad"}],
            )


if __name__ == "__main__":
    unittest.main()
