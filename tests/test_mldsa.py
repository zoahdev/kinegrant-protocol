from __future__ import annotations

import unittest

from kinegrant.crypto import (
    MLDSA65KeyPair,
    public_key_from_id,
    verify_envelope,
)


class MLDSATests(unittest.TestCase):
    def test_sign_and_verify_round_trip(self) -> None:
        key = MLDSA65KeyPair.generate()
        envelope = key.sign_envelope({"hello": "world", "n": 1})
        self.assertEqual(envelope["alg"], "ML-DSA-65")
        self.assertTrue(envelope["kid"].startswith("kinegrant:key:mldsa65:"))
        self.assertEqual(verify_envelope(envelope), {"hello": "world", "n": 1})

    def test_kid_round_trips_through_public_key_from_id(self) -> None:
        key = MLDSA65KeyPair.generate()
        restored = public_key_from_id(key.kid)
        signature = key.private_key.sign(b"payload")
        restored.verify(signature, b"payload")

    def test_tampered_payload_is_rejected(self) -> None:
        key = MLDSA65KeyPair.generate()
        envelope = key.sign_envelope({"a": 1})
        envelope["payload"]["a"] = 2
        with self.assertRaises(ValueError):
            verify_envelope(envelope)

    def test_tampered_signature_is_rejected(self) -> None:
        key = MLDSA65KeyPair.generate()
        envelope = key.sign_envelope({"a": 1})
        envelope["signature"] = envelope["signature"][:-1] + (
            "A" if envelope["signature"][-1] != "A" else "B"
        )
        with self.assertRaises(ValueError):
            verify_envelope(envelope)

    def test_wrong_kid_is_rejected(self) -> None:
        key = MLDSA65KeyPair.generate()
        other = MLDSA65KeyPair.generate()
        envelope = key.sign_envelope({"a": 1})
        envelope["kid"] = other.kid
        with self.assertRaises(ValueError):
            verify_envelope(envelope)


if __name__ == "__main__":
    unittest.main()
