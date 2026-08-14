"""External receipt checkpoints (v0.4).

A receipt checkpoint is a signed statement by a notary about the digest of a
receipt chain at a point in time. It gives external parties a way to confirm
that a chain existed and was not silently rewritten, without exposing the
receipts themselves. Checkpoints prove notarization, not physical truth.
"""

from __future__ import annotations

import re
from typing import Any, Mapping

from .canonical import content_id
from .crypto import verify_envelope
from .models import isoformat, utc_now

_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def build_receipt_checkpoint(
    chain_digest: str,
    *,
    notary_kid: str,
    key_pair: Any,
    period: str = "daily",
    issued_at: str | None = None,
) -> dict[str, Any]:
    """Build a signed receipt checkpoint for a chain digest."""
    if _SHA256_RE.fullmatch(chain_digest) is None:
        raise ValueError("chain_digest must be a sha256 digest")
    if not isinstance(period, str) or not period:
        raise ValueError("period must be a non-empty string")
    if not isinstance(notary_kid, str) or not notary_kid:
        raise ValueError("notary_kid must be a non-empty string")
    if getattr(key_pair, "kid", None) != notary_kid:
        raise ValueError("notary_kid must match the signing key pair")
    body = {
        "type": "kinegrant:ReceiptCheckpoint",
        "schema_version": "0.1",
        "notary": notary_kid,
        "chain_digest": chain_digest,
        "period": period,
        "issued_at": issued_at or isoformat(utc_now()),
    }
    body["checkpoint_id"] = content_id(
        "kinegrant:receipt-checkpoint",
        {key: value for key, value in body.items() if key != "checkpoint_id"},
    )
    return key_pair.sign_envelope(body)


def verify_receipt_checkpoint(
    checkpoint: Mapping[str, Any],
    *,
    trusted_notaries: set[str] | None = None,
) -> str:
    """Verify a signed checkpoint and return its chain digest."""
    payload = verify_envelope(checkpoint)
    if payload.get("type") != "kinegrant:ReceiptCheckpoint":
        raise ValueError("wrong checkpoint type")
    if payload.get("schema_version") != "0.1":
        raise ValueError("unsupported checkpoint version")
    if payload.get("notary") != checkpoint.get("kid"):
        raise ValueError("checkpoint notary does not match signing key")
    if trusted_notaries is not None and payload.get("notary") not in trusted_notaries:
        raise ValueError("untrusted notary")
    chain_digest = payload.get("chain_digest")
    if not isinstance(chain_digest, str) or _SHA256_RE.fullmatch(chain_digest) is None:
        raise ValueError("chain_digest must be a sha256 digest")
    checkpoint_id = payload.get("checkpoint_id")
    expected_id = content_id(
        "kinegrant:receipt-checkpoint",
        {key: value for key, value in payload.items() if key != "checkpoint_id"},
    )
    if checkpoint_id != expected_id:
        raise ValueError("checkpoint identifier is inconsistent")
    return chain_digest
