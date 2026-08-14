"""Sensor-evidence commitments (v0.4).

A sensor-evidence commitment records what a sensor attested about the
physical world: the kind of reading, a hash of the raw value, the source,
confidence, and the observation time. The commitment may be signed by the
sensor key and is bound into a KGP receipt through ``evidence_hash``.

Commitments prove attestation, not physical truth; confidence and provenance
stay explicit.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from .canonical import content_id, digest
from .crypto import verify_envelope
from .models import isoformat, utc_now

_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def _value_hash(value: Mapping[str, Any]) -> str:
    return digest(value)


@dataclass(frozen=True)
class SensorReading:
    kind: str
    value: Mapping[str, Any]
    source_id: str
    confidence: float
    observed_at: str

    def __post_init__(self) -> None:
        if not isinstance(self.kind, str) or not self.kind:
            raise ValueError("kind must be a non-empty string")
        if not isinstance(self.value, Mapping):
            raise ValueError("value must be an object")
        if not isinstance(self.source_id, str) or not self.source_id:
            raise ValueError("source_id must be a non-empty string")
        if not isinstance(self.confidence, (int, float)) or isinstance(
            self.confidence, bool
        ) or not 0 <= self.confidence <= 1:
            raise ValueError("confidence must be a number between 0 and 1")
        if not isinstance(self.observed_at, str) or not self.observed_at:
            raise ValueError("observed_at must be a non-empty string")

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "value_hash": _value_hash(self.value),
            "source_id": self.source_id,
            "confidence": self.confidence,
            "observed_at": self.observed_at,
        }


def build_sensor_commitment(
    readings: Iterable[SensorReading],
    *,
    sensor_kid: str | None = None,
    key_pair: Any = None,
    committed_at: str | None = None,
) -> dict[str, Any]:
    """Build a sensor-evidence commitment, optionally signed by the sensor."""
    entries = [reading.to_dict() for reading in readings]
    if not entries:
        raise ValueError("at least one sensor reading is required")
    body = {
        "type": "kinegrant:SensorEvidenceCommitment",
        "schema_version": "0.1",
        "readings": entries,
        "readings_digest": digest({"readings": entries}),
        "sensor": sensor_kid,
        "committed_at": committed_at or isoformat(utc_now()),
    }
    body["commitment_id"] = content_id(
        "kinegrant:sensor-evidence",
        {key: value for key, value in body.items() if key != "commitment_id"},
    )
    if key_pair is not None:
        if sensor_kid is None or sensor_kid != getattr(key_pair, "kid", None):
            raise ValueError("sensor_kid must match the signing key pair")
        return key_pair.sign_envelope(body)
    return body


def verify_sensor_commitment(
    commitment: Mapping[str, Any],
    *,
    trusted_sensors: set[str] | None = None,
) -> dict[str, Any]:
    """Verify structure, digest consistency, and optional sensor signature."""
    if commitment.get("alg") is not None:
        payload = verify_envelope(commitment)
        if trusted_sensors is not None and payload.get("sensor") not in trusted_sensors:
            raise ValueError("untrusted sensor")
    else:
        payload = dict(commitment)
    if payload.get("type") != "kinegrant:SensorEvidenceCommitment":
        raise ValueError("wrong commitment type")
    if payload.get("schema_version") != "0.1":
        raise ValueError("unsupported commitment version")
    readings = payload.get("readings")
    if not isinstance(readings, list) or not readings:
        raise ValueError("readings must be a non-empty array")
    if payload.get("readings_digest") != digest({"readings": readings}):
        raise ValueError("readings digest is inconsistent")
    commitment_id = payload.get("commitment_id")
    expected_id = content_id(
        "kinegrant:sensor-evidence",
        {key: value for key, value in payload.items() if key != "commitment_id"},
    )
    if commitment_id != expected_id:
        raise ValueError("commitment identifier is inconsistent")
    return payload


def evidence_hash_for_commitment(commitment: Mapping[str, Any]) -> str:
    """Return the sha256 evidence hash to pass to ``ReceiptLog.append``."""
    payload = verify_sensor_commitment(commitment)
    return digest(payload)
