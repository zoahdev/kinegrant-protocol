"""Signing backends for hardware-backed keys (v0.4).

``SigningBackend`` is the narrow interface a secure element exposes: sign
bytes, reveal the public key id. Private key material never crosses the
interface. ``BackedKeyPair`` adapts any backend to the KineGrant envelope
format, so capabilities and attestations can be signed by a hardware key
without changing the wire format.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Protocol

from .canonical import canonical_json
from .crypto import DOMAIN, Ed25519KeyPair, MLDSA65KeyPair, key_id


class SigningBackend(Protocol):
    """Secure-element style signing interface; private keys are non-exportable."""

    def sign(self, data: bytes) -> bytes: ...

    @property
    def kid(self) -> str: ...


@dataclass(frozen=True)
class SoftwareEd25519Backend:
    """Reference software backend backed by an Ed25519 key (tests only)."""

    key_pair: Ed25519KeyPair

    @classmethod
    def generate(cls) -> "SoftwareEd25519Backend":
        return cls(Ed25519KeyPair.generate())

    def sign(self, data: bytes) -> bytes:
        return self.key_pair.private_key.sign(data)

    @property
    def kid(self) -> str:
        return self.key_pair.kid

    @property
    def public_key(self) -> Any:
        return self.key_pair.private_key.public_key()


@dataclass(frozen=True)
class SoftwareMLDSA65Backend:
    """Reference software backend backed by an ML-DSA-65 key (tests only)."""

    key_pair: MLDSA65KeyPair

    @classmethod
    def generate(cls) -> "SoftwareMLDSA65Backend":
        return cls(MLDSA65KeyPair.generate())

    def sign(self, data: bytes) -> bytes:
        return self.key_pair.private_key.sign(data)

    @property
    def kid(self) -> str:
        return self.key_pair.kid

    @property
    def public_key(self) -> Any:
        return self.key_pair.private_key.public_key()


class BackedKeyPair:
    """Envelope signer whose private key lives only inside a backend."""

    def __init__(self, backend: SigningBackend, *, alg: str = "EdDSA") -> None:
        if alg not in {"EdDSA", "ML-DSA-65"}:
            raise ValueError("unsupported signature algorithm")
        if not hasattr(backend, "kid") or not hasattr(backend, "sign"):
            raise TypeError("backend must provide sign() and kid")
        self.backend = backend
        self.alg = alg

    @property
    def kid(self) -> str:
        return self.backend.kid

    def sign_envelope(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        protected = {"alg": self.alg, "kid": self.kid, "payload": dict(payload)}
        signature = self.backend.sign(DOMAIN + canonical_json(protected))
        from .crypto import _b64url

        return {**protected, "signature": _b64url(signature)}


def key_id_from_backend(backend: SigningBackend) -> str:
    """Return the canonical kid for a backend's public key."""
    public_key = backend.public_key
    if backend.kid.startswith("kinegrant:key:mldsa65:"):
        from .crypto import _b64url

        return "kinegrant:key:mldsa65:" + _b64url(public_key.public_bytes_raw())
    return key_id(public_key)
