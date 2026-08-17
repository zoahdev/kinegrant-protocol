"""KineGrant Protocol reference implementation."""

__version__ = "2.65.5"

from .capability import CapabilityIssuer
from .attenuation import attenuate_capability, verify_attenuation
from .attestation import build_device_attestation, verify_device_attestation
from .checkpoint import build_receipt_checkpoint, verify_receipt_checkpoint
from .conformance import ConformanceMark, ConformanceRunner
from .crypto import Ed25519KeyPair, MLDSA65KeyPair, verify_envelope
from .discovery import DiscoveryResolution, ThingActions, ThingRegistry
from .fuzz import AdapterFuzzHarness
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
from .keys import (
    BackedKeyPair,
    SigningBackend,
    SoftwareEd25519Backend,
    SoftwareMLDSA65Backend,
    key_id_from_backend,
)
from .merkle import (
    merkle_proofs,
    merkle_redact,
    verify_field,
    verify_merkle_redaction,
)
from .modelcheck import bounded_model_check
from .models import ActionRequest, Decision, PolicyRule
from .policy import PolicyEngine
from .privacy import RotatingIdentifierRegistry, redact, verify_redaction
from .receipt import ReceiptLog, verify_receipt_chain
from .redteam import RED_TEAM_CASES, RedTeamSuite
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
from .semantics import PolicyInvariants, RuleInvariant, explain_decision
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
from .wire import SUPPORTED_WIRE_VERSIONS, check_compatibility, supports

__all__ = [
    "ACTION_TERMS",
    "ActionGate",
    "ActionJournal",
    "ActionRequest",
    "ActionSpec",
    "AdapterFuzzHarness",
    "BackedKeyPair",
    "CapabilityIssuer",
    "ConformanceMark",
    "ConformanceRunner",
    "Decision",
    "DiscoveryResolution",
    "Ed25519KeyPair",
    "InMemoryReplayStore",
    "KineGrantIdentifier",
    "MLDSA65KeyPair",
    "bounded_model_check",
    "PolicyEngine",
    "PolicyInvariants",
    "PolicyRule",
    "RED_TEAM_CASES",
    "ReceiptLog",
    "RedTeamSuite",
    "RotatingIdentifierRegistry",
    "RuleInvariant",
    "RevocationEntry",
    "RevocationList",
    "SensorReading",
    "ThingActions",
    "ThingRegistry",
    "TrustedClock",
    "TrustedClockError",
    "SQLiteReplayStore",
    "SigningBackend",
    "SoftwareEd25519Backend",
    "SoftwareMLDSA65Backend",
    "SequencePolicy",
    "SequenceVerdict",
    "SUPPORTED_WIRE_VERSIONS",
    "VerifiedCapability",
    "ForbiddenCombination",
    "agent_id",
    "action_spec",
    "approval_tier_from_risk",
    "attenuate_capability",
    "check_compatibility",
    "build_revocation_bundle",
    "build_device_attestation",
    "build_receipt_checkpoint",
    "build_sensor_commitment",
    "known_action",
    "merkle_proofs",
    "merkle_redact",
    "evidence_hash_for_commitment",
    "explain_decision",
    "is_agent_id",
    "is_kinegrant_identifier",
    "is_policy_id",
    "is_target_id",
    "parse_identifier",
    "policy_id",
    "random_agent_id",
    "random_policy_id",
    "random_target_id",
    "redact",
    "registry",
    "target_id",
    "sign_revocation_bundle",
    "supports",
    "validate_actions",
    "verify_envelope",
    "verify_attenuation",
    "verify_field",
    "verify_device_attestation",
    "verify_redaction",
    "verify_merkle_redaction",
    "verify_receipt_checkpoint",
    "verify_revocation_bundle",
    "verify_sensor_commitment",
    "verify_receipt_chain",
]
