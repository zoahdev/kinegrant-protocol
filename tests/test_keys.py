from __future__ import annotations

import unittest

from kinegrant.crypto import verify_envelope
from kinegrant.keys import (
    BackedKeyPair,
    SoftwareEd25519Backend,
    SoftwareMLDSA65Backend,
    key_id_from_backend,
)


class SigningBackendTests(unittest.TestCase):
    def test_ed25519_backed_envelope_verifies(self) -> None:
        backend = SoftwareEd25519Backend.generate()
        key_pair = BackedKeyPair(backend)
        envelope = key_pair.sign_envelope({"hello": "world"})
        self.assertEqual(envelope["kid"], backend.kid)
        self.assertEqual(verify_envelope(envelope), {"hello": "world"})
        self.assertEqual(key_id_from_backend(backend), backend.kid)

    def test_mldsa_backed_envelope_verifies(self) -> None:
        backend = SoftwareMLDSA65Backend.generate()
        key_pair = BackedKeyPair(backend, alg="ML-DSA-65")
        envelope = key_pair.sign_envelope({"a": 1})
        self.assertEqual(envelope["alg"], "ML-DSA-65")
        self.assertEqual(verify_envelope(envelope), {"a": 1})
        self.assertEqual(key_id_from_backend(backend), backend.kid)

    def test_tampered_payload_is_rejected(self) -> None:
        key_pair = BackedKeyPair(SoftwareEd25519Backend.generate())
        envelope = key_pair.sign_envelope({"a": 1})
        envelope["payload"]["a"] = 2
        with self.assertRaises(ValueError):
            verify_envelope(envelope)

    def test_private_key_material_is_not_exposed(self) -> None:
        backend = SoftwareEd25519Backend.generate()
        self.assertFalse(hasattr(backend, "private_key"))
        self.assertFalse(hasattr(backend, "private_bytes"))
        self.assertTrue(hasattr(backend, "public_key"))

    def test_invalid_algorithm_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            BackedKeyPair(SoftwareEd25519Backend.generate(), alg="RSA")


if __name__ == "__main__":
    unittest.main()
