"""KineGrant Protocol reference implementation."""

__version__ = "0.1.1"

from .capability import CapabilityIssuer
from .crypto import Ed25519KeyPair, verify_envelope
from .gate import ActionGate, InMemoryReplayStore, SQLiteReplayStore, VerifiedCapability
from .models import ActionRequest, Decision, PolicyRule
from .policy import PolicyEngine
from .receipt import ReceiptLog, verify_receipt_chain
from .vocabulary import ACTION_TERMS, ActionSpec, action_spec, known_action, registry, validate_actions

__all__ = [
    "ACTION_TERMS",
    "ActionGate",
    "ActionRequest",
    "ActionSpec",
    "CapabilityIssuer",
    "Decision",
    "Ed25519KeyPair",
    "InMemoryReplayStore",
    "PolicyEngine",
    "PolicyRule",
    "ReceiptLog",
    "SQLiteReplayStore",
    "VerifiedCapability",
    "action_spec",
    "known_action",
    "registry",
    "validate_actions",
    "verify_envelope",
    "verify_receipt_chain",
]
