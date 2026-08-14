from __future__ import annotations

import copy
import unittest

from kinegrant.checkpoint import (
    build_receipt_checkpoint,
    verify_receipt_checkpoint,
)
from kinegrant.crypto import Ed25519KeyPair, MLDSA65KeyPair
from kinegrant.models import digest


class ReceiptCheckpointTests(unittest.TestCase):
    def test_round_trip_with_ed25519(self) -> None:
        notary = Ed25519KeyPair.generate()
        chain_digest = digest({"receipts": ["r1", "r2"]})
        checkpoint = build_receipt_checkpoint(
            chain_digest,
            notary_kid=notary.kid,
            key_pair=notary,
            period="daily",
        )
        self.assertEqual(
            verify_receipt_checkpoint(
                checkpoint,
                trusted_notaries={notary.kid},
            ),
            chain_digest,
        )

    def test_round_trip_with_mldsa(self) -> None:
        notary = MLDSA65KeyPair.generate()
        chain_digest = digest({"receipts": ["r1"]})
        checkpoint = build_receipt_checkpoint(
            chain_digest,
            notary_kid=notary.kid,
            key_pair=notary,
        )
        verify_receipt_checkpoint(checkpoint, trusted_notaries={notary.kid})

    def test_tampered_chain_digest_is_rejected(self) -> None:
        notary = Ed25519KeyPair.generate()
        checkpoint = build_receipt_checkpoint(
            digest({"receipts": ["r1"]}),
            notary_kid=notary.kid,
            key_pair=notary,
        )
        tampered = copy.deepcopy(checkpoint)
        tampered["payload"]["chain_digest"] = "sha256:" + "0" * 64
        with self.assertRaises(ValueError):
            verify_receipt_checkpoint(tampered)

    def test_untrusted_notary_is_rejected(self) -> None:
        notary = Ed25519KeyPair.generate()
        checkpoint = build_receipt_checkpoint(
            digest({"receipts": ["r1"]}),
            notary_kid=notary.kid,
            key_pair=notary,
        )
        with self.assertRaises(ValueError):
            verify_receipt_checkpoint(checkpoint, trusted_notaries=set())

    def test_issuer_mismatch_is_rejected(self) -> None:
        notary = Ed25519KeyPair.generate()
        with self.assertRaises(ValueError):
            build_receipt_checkpoint(
                digest({"receipts": ["r1"]}),
                notary_kid="kinegrant:key:ed25519:wrong",
                key_pair=notary,
            )

    def test_invalid_chain_digest_is_rejected(self) -> None:
        notary = Ed25519KeyPair.generate()
        with self.assertRaises(ValueError):
            build_receipt_checkpoint(
                "not-a-digest",
                notary_kid=notary.kid,
                key_pair=notary,
            )


if __name__ == "__main__":
    unittest.main()
