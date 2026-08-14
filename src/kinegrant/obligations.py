"""Known capability obligation vocabulary (stable, additive)."""

from __future__ import annotations

# Additive-only set: every implementation (Python, JavaScript, Go) and every
# published schema must accept exactly this set. New obligations are added
# here, in the schemas, and in the independent verifiers together.
KNOWN_OBLIGATIONS = frozenset(
    {"emitActionReceipt", "logAuditEvent", "preserveEvidence"}
)
