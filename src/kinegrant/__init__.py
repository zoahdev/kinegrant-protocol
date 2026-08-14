"""KineGrant Protocol reference implementation."""

__version__ = "0.1.1"

from .capability import CapabilityIssuer
from .attenuation import attenuate_capability, verify_attenuation
from .checkpoint import build_receipt_checkpoint, verify_receipt_checkpoint
from .crypto import Ed25519KeyPair, MLDSA65KeyPair, verify_envelope
from .discovery import DiscoveryResolution, ThingActions, ThingRegistry
from .gate import ActionGate, InMemoryReplayStore, SQLiteReplayStore, VerifiedCapability
from .identity import (
    KineGrantIdentifier,
    agent_id,
    is_agent_id,
    is_kinegrant_identifier,
    is_policy_id,
    is_target_id,
    parse_identifier,
    policy_id,
    random_agent_id,
    random_policy_id,
    random_target_id,
    target_id,
)
from .models import ActionRequest, Decision, PolicyRule
from .policy import PolicyEngine
from .receipt import ReceiptLog, verify_receipt_chain
from .revocation import (
    RevocationEntry,
    RevocationList,
    build_revocation_bundle,
    sign_revocation_bundle,
    verify_revocation_bundle,
)
from .sequence import (
    ActionJournal,
    ForbiddenCombination,
    SequencePolicy,
    SequenceVerdict,
)
from .sensor_evidence import (
    SensorReading,
    build_sensor_commitment,
    evidence_hash_for_commitment,
    verify_sensor_commitment,
)
from .trust import TrustedClock, TrustedClockError
from .vocabulary import (
    ACTION_TERMS,
    ActionSpec,
    action_spec,
    approval_tier_from_risk,
    known_action,
    registry,
    validate_actions,
)

__all__ = [
    "ACTION_TERMS",
    "ActionGate",
    "ActionJournal",
    "ActionRequest",
    "ActionSpec",
    "CapabilityIssuer",
    "Decision",
    "DiscoveryResolution",
    "Ed25519KeyPair",
    "InMemoryReplayStore",
    "KineGrantIdentifier",
    "MLDSA65KeyPair",
    "PolicyEngine",
    "PolicyRule",
    "ReceiptLog",
    "RevocationEntry",
    "RevocationList",
    "SensorReading",
    "ThingActions",
    "ThingRegistry",
    "TrustedClock",
    "TrustedClockError",
    "SQLiteReplayStore",
    "SequencePolicy",
    "SequenceVerdict",
    "VerifiedCapability",
    "ForbiddenCombination",
    "agent_id",
    "action_spec",
    "approval_tier_from_risk",
    "attenuate_capability",
    "build_revocation_bundle",
    "build_receipt_checkpoint",
    "build_sensor_commitment",
    "known_action",
    "evidence_hash_for_commitment",
    "is_agent_id",
    "is_kinegrant_identifier",
    "is_policy_id",
    "is_target_id",
    "parse_identifier",
    "policy_id",
    "random_agent_id",
    "random_policy_id",
    "random_target_id",
    "registry",
    "target_id",
    "sign_revocation_bundle",
    "validate_actions",
    "verify_envelope",
    "verify_attenuation",
    "verify_receipt_checkpoint",
    "verify_revocation_bundle",
    "verify_sensor_commitment",
    "verify_receipt_chain",
]
