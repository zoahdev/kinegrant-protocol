"""Wire-format compatibility policy (v1.0 groundwork)."""

from __future__ import annotations

SUPPORTED_WIRE_VERSIONS = ("0.1", "0.2", "1.0")


def supports(version: str) -> bool:
    return version in SUPPORTED_WIRE_VERSIONS


def check_compatibility(required: str, provided: str) -> bool:
    """Return True when *provided* satisfies *required* under the draft policy.

    Draft 0.x versions are incompatible with each other unless explicitly
    listed: a consumer that requires 0.2 accepts only 0.2; one that requires
    0.1 also accepts 0.1. Additive fields within a version stay compatible.
    """
    return required == provided and supports(provided)
