"""Device attestation and measured boot declarations (v0.4).

A device attestation binds a device id to its firmware digest, a persistent
boot counter, and an ordered measured-boot chain, signed by the device key.
It is a claim about software state, not a proof of physical-world truth;
secure boot enforcement is deployment hardware work.
"""

from __future__ import annotations

import re
from typing import Any, Iterable, Mapping

from .canonical import content_id
from .crypto import verify_envelope
from .models import isoformat, utc_now

_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def build_device_attestation(
    *,
    device_id: str,
    firmware_digest: str,
    boot_counter: int,
    device_key: Any,
    measured_boot: Iterable[Mapping[str, str]] = (),
    issued_at: str | None = None,
) -> dict[str, Any]:
    """Build a signed device attestation."""
    if not isinstance(device_id, str) or not device_id:
        raise ValueError("device_id must be a non-empty string")
    if _SHA256_RE.fullmatch(firmware_digest) is None:
        raise ValueError("firmware_digest must be a sha256 digest")
    if (
        not isinstance(boot_counter, int)
        or isinstance(boot_counter, bool)
        or boot_counter < 0
    ):
        raise ValueError("boot_counter must be a non-negative integer")
    stages = []
    for stage in measured_boot:
        if not isinstance(stage, Mapping):
            raise ValueError("measured_boot entries must be objects")
        name = stage.get("stage")
        stage_digest = stage.get("digest")
        if not isinstance(name, str) or not name:
            raise ValueError("measured_boot stage must be a non-empty string")
        if not isinstance(stage_digest, str) or _SHA256_RE.fullmatch(stage_digest) is None:
            raise ValueError("measured_boot digest must be a sha256 digest")
        stages.append({"stage": name, "digest": stage_digest})
    kid = getattr(device_key, "kid", None)
    if kid is None:
        raise ValueError("device_key must expose a kid")
    body = {
        "type": "kinegrant:DeviceAttestation",
        "schema_version": "0.1",
        "device_id": device_id,
        "firmware_digest": firmware_digest,
        "boot_counter": boot_counter,
        "measured_boot": stages,
        "device": kid,
        "issued_at": issued_at or isoformat(utc_now()),
    }
    body["attestation_id"] = content_id(
        "kinegrant:device-attestation",
        {key: value for key, value in body.items() if key != "attestation_id"},
    )
    return device_key.sign_envelope(body)


def verify_device_attestation(
    attestation: Mapping[str, Any],
    *,
    trusted_devices: set[str] | None = None,
) -> dict[str, Any]:
    """Verify a device attestation and return its payload."""
    payload = verify_envelope(attestation)
    if payload.get("type") != "kinegrant:DeviceAttestation":
        raise ValueError("wrong attestation type")
    if payload.get("schema_version") != "0.1":
        raise ValueError("unsupported attestation version")
    if payload.get("device") != attestation.get("kid"):
        raise ValueError("attestation device does not match signing key")
    if trusted_devices is not None and payload.get("device") not in trusted_devices:
        raise ValueError("untrusted device")
    firmware_digest = payload.get("firmware_digest")
    if not isinstance(firmware_digest, str) or _SHA256_RE.fullmatch(firmware_digest) is None:
        raise ValueError("firmware_digest must be a sha256 digest")
    boot_counter = payload.get("boot_counter")
    if (
        not isinstance(boot_counter, int)
        or isinstance(boot_counter, bool)
        or boot_counter < 0
    ):
        raise ValueError("boot_counter must be a non-negative integer")
    stages = payload.get("measured_boot")
    if not isinstance(stages, list):
        raise ValueError("measured_boot must be an array")
    for stage in stages:
        if not isinstance(stage, Mapping):
            raise ValueError("measured_boot entries must be objects")
        if not isinstance(stage.get("stage"), str) or not stage.get("stage"):
            raise ValueError("measured_boot stage must be a non-empty string")
        if not isinstance(stage.get("digest"), str) or _SHA256_RE.fullmatch(
            stage.get("digest")
        ) is None:
            raise ValueError("measured_boot digest must be a sha256 digest")
    attestation_id = payload.get("attestation_id")
    expected_id = content_id(
        "kinegrant:device-attestation",
        {key: value for key, value in payload.items() if key != "attestation_id"},
    )
    if attestation_id != expected_id:
        raise ValueError("attestation identifier is inconsistent")
    return payload
