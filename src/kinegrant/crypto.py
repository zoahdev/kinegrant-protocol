from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

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


def public_key_from_id(kid: str) -> Ed25519PublicKey:
    prefix = "kinegrant:key:ed25519:"
    if not kid.startswith(prefix):
        raise ValueError("unsupported key identifier")
    raw = _unb64url(kid[len(prefix) :])
    if len(raw) != 32:
        raise ValueError("invalid Ed25519 public key length")
    return Ed25519PublicKey.from_public_bytes(raw)


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
    if envelope.get("alg") != "EdDSA":
        raise ValueError("unsupported signature algorithm")
    kid = envelope.get("kid")
    payload = envelope.get("payload")
    signature = envelope.get("signature")
    if not isinstance(kid, str) or not isinstance(payload, dict) or not isinstance(signature, str):
        raise ValueError("malformed signed envelope")

    protected = {"alg": "EdDSA", "kid": kid, "payload": payload}
    try:
        raw_signature = _unb64url(signature)
        if len(raw_signature) != 64:
            raise ValueError("invalid Ed25519 signature length")
        public_key_from_id(kid).verify(
            raw_signature,
            DOMAIN + canonical_json(protected),
        )
    except (InvalidSignature, ValueError) as exc:
        raise ValueError("invalid signature") from exc
    return payload
