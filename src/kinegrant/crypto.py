from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.mldsa import (
    MLDSA65PrivateKey,
    MLDSA65PublicKey,
)

from .canonical import canonical_json

DOMAIN = b"KINEGRANT-SIGNED-ENVELOPE-V1\x00"
_B64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _unb64url(value: str) -> bytes:
    if not value or _B64URL_RE.fullmatch(value) is None:
        raise ValueError("invalid base64url encoding")
    try:
        decoded = base64.b64decode(
            value + "=" * (-len(value) % 4),
            altchars=b"-_",
            validate=True,
        )
    except (binascii.Error, ValueError) as exc:
        raise ValueError("invalid base64url encoding") from exc
    if _b64url(decoded) != value:
        raise ValueError("non-canonical base64url encoding")
    return decoded


def key_id(public_key: Ed25519PublicKey) -> str:
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return "kinegrant:key:ed25519:" + _b64url(raw)


def public_key_from_id(kid: str) -> Ed25519PublicKey | MLDSA65PublicKey:
    if kid.startswith("kinegrant:key:ed25519:"):
        raw = _unb64url(kid[len("kinegrant:key:ed25519:") :])
        if len(raw) != 32:
            raise ValueError("invalid Ed25519 public key length")
        return Ed25519PublicKey.from_public_bytes(raw)
    if kid.startswith("kinegrant:key:mldsa65:"):
        raw = _unb64url(kid[len("kinegrant:key:mldsa65:") :])
        if len(raw) != 1952:
            raise ValueError("invalid ML-DSA-65 public key length")
        return MLDSA65PublicKey.from_public_bytes(raw)
    raise ValueError("unsupported key identifier")


@dataclass(frozen=True)
class Ed25519KeyPair:
    private_key: Ed25519PrivateKey

    @classmethod
    def generate(cls) -> "Ed25519KeyPair":
        return cls(Ed25519PrivateKey.generate())

    @property
    def kid(self) -> str:
        return key_id(self.private_key.public_key())

    def sign_envelope(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        protected = {"alg": "EdDSA", "kid": self.kid, "payload": dict(payload)}
        signature = self.private_key.sign(DOMAIN + canonical_json(protected))
        return {**protected, "signature": _b64url(signature)}


def verify_envelope(envelope: Mapping[str, Any]) -> dict[str, Any]:
    alg = envelope.get("alg")
    if alg not in {"EdDSA", "ML-DSA-65"}:
        raise ValueError("unsupported signature algorithm")
    kid = envelope.get("kid")
    payload = envelope.get("payload")
    signature = envelope.get("signature")
    if not isinstance(kid, str) or not isinstance(payload, dict) or not isinstance(signature, str):
        raise ValueError("malformed signed envelope")

    protected = {"alg": alg, "kid": kid, "payload": payload}
    try:
        raw_signature = _unb64url(signature)
        if alg == "EdDSA" and len(raw_signature) != 64:
            raise ValueError("invalid Ed25519 signature length")
        if alg == "ML-DSA-65" and len(raw_signature) != 3309:
            raise ValueError("invalid ML-DSA-65 signature length")
        public_key_from_id(kid).verify(
            raw_signature,
            DOMAIN + canonical_json(protected),
        )
    except (InvalidSignature, ValueError) as exc:
        raise ValueError("invalid signature") from exc
    return payload


@dataclass(frozen=True)
class MLDSA65KeyPair:
    """Post-quantum signing option using FIPS 204 ML-DSA-65.

    Envelopes use ``alg: "ML-DSA-65"`` and ``kid`` values prefixed with
    ``kinegrant:key:mldsa65:``. This is an experimental parallel to Ed25519;
    the wire schemas still target EdDSA envelopes until the draft stabilizes.
    """

    private_key: MLDSA65PrivateKey

    @classmethod
    def generate(cls) -> "MLDSA65KeyPair":
        return cls(MLDSA65PrivateKey.generate())

    @property
    def kid(self) -> str:
        return "kinegrant:key:mldsa65:" + _b64url(
            self.private_key.public_key().public_bytes_raw()
        )

    def sign_envelope(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        protected = {"alg": "ML-DSA-65", "kid": self.kid, "payload": dict(payload)}
        signature = self.private_key.sign(DOMAIN + canonical_json(protected))
        return {**protected, "signature": _b64url(signature)}
