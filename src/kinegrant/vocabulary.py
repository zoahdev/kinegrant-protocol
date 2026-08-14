"""Machine-readable physical action vocabulary for KGP-001.

Every action a robot or other physical-AI system may request is identified by
an explicit, versioned term. Terms are strict: an unknown term must fail closed
in deployments that enable ``require_known_actions`` rather than being silently
widened into a different action.

Term naming follows the ``kg.action.<verb>`` namespace. Aliases are not part of
the wire format; adapters map legacy strings into canonical terms before a
request reaches the policy engine.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class ActionSpec:
    """Declarative description of one canonical physical action term."""

    term: str
    category: str
    risk_tier: int
    requires_target: bool
    requires_purpose: bool
    data_sensitivity: bool
    description: str


ACTIONS: dict[str, ActionSpec] = {
    "kg.action.observe": ActionSpec(
        term="kg.action.observe",
        category="sense",
        risk_tier=1,
        requires_target=True,
        requires_purpose=True,
        data_sensitivity=False,
        description=(
            "Sensing a target without storing or transmitting the observation; "
            "e.g., a robot looking at a door to plan a delivery approach."
        ),
    ),
    "kg.action.record": ActionSpec(
        term="kg.action.record",
        category="data",
        risk_tier=2,
        requires_target=True,
        requires_purpose=True,
        data_sensitivity=True,
        description=(
            "Persisting an observation (audio, video, point cloud, or derived "
            "measurements) for a stated purpose."
        ),
    ),
    "kg.action.touch": ActionSpec(
        term="kg.action.touch",
        category="manipulate",
        risk_tier=2,
        requires_target=True,
        requires_purpose=True,
        data_sensitivity=False,
        description=(
            "Making reversible contact with a target, such as pressing a button "
            "or nudging a light object."
        ),
    ),
    "kg.action.grasp": ActionSpec(
        term="kg.action.grasp",
        category="manipulate",
        risk_tier=3,
        requires_target=True,
        requires_purpose=True,
        data_sensitivity=False,
        description=(
            "Securely gripping and optionally lifting a target object, with "
            "damage risk to the object or environment."
        ),
    ),
    "kg.action.move": ActionSpec(
        term="kg.action.move",
        category="transform",
        risk_tier=3,
        requires_target=True,
        requires_purpose=True,
        data_sensitivity=False,
        description=(
            "Changing the position or configuration of a target, a robot "
            "locomotion step, or a payload relocation."
        ),
    ),
    "kg.action.open": ActionSpec(
        term="kg.action.open",
        category="access",
        risk_tier=2,
        requires_target=True,
        requires_purpose=True,
        data_sensitivity=False,
        description=(
            "Opening a barrier, door, lid, container, or software-adjacent "
            "physical lock for a stated purpose."
        ),
    ),
    "kg.action.enter": ActionSpec(
        term="kg.action.enter",
        category="access",
        risk_tier=3,
        requires_target=True,
        requires_purpose=True,
        data_sensitivity=False,
        description=(
            "Causing a robot or carried item to pass through a boundary into "
            "an enclosed or restricted space."
        ),
    ),
    "kg.action.retain": ActionSpec(
        term="kg.action.retain",
        category="transform",
        risk_tier=2,
        requires_target=True,
        requires_purpose=True,
        data_sensitivity=False,
        description=(
            "Keeping possession of a target after the immediate task, e.g., "
            "holding a delivered package until handoff."
        ),
    ),
    "kg.action.train_on_data": ActionSpec(
        term="kg.action.train_on_data",
        category="data",
        risk_tier=4,
        requires_target=True,
        requires_purpose=True,
        data_sensitivity=True,
        description=(
            "Using observations of a target or space to train, fine-tune, or "
            "improve an AI model. The most sensitive default-denied action."
        ),
    ),
}

ACTION_TERMS: tuple[str, ...] = tuple(sorted(ACTIONS))

_CATEGORIES = {"sense", "data", "manipulate", "transform", "access"}


def known_action(term: str) -> bool:
    """Return True when *term* is a canonical action in the v0.2 vocabulary."""
    return term in ACTIONS


def action_spec(term: str) -> ActionSpec:
    """Return the declarative spec for a canonical action term."""
    try:
        return ACTIONS[term]
    except KeyError:
        raise KeyError(
            f"unknown KineGrant action {term!r}; known terms: {', '.join(ACTION_TERMS)}"
        ) from None


def validate_actions(actions: Iterable[str], *, context: str = "actions") -> None:
    """Reject unknown action terms so callers can fail closed before signing."""
    unknown = sorted({action for action in actions if not known_action(action)})
    if unknown:
        raise ValueError(
            f"unknown {context}: {', '.join(unknown)}; "
            f"known terms: {', '.join(ACTION_TERMS)}"
        )


def approval_tier_from_risk(risk_tier: int) -> int:
    """Map an action risk tier to the minimum approval tier.

    0 = automatic, 1 = operator approval required, 2 = human present required.
    Risk tiers 1-2 are automatic, tier 3 requires operator approval, and
    tiers 4-5 require a human present.
    """
    if not isinstance(risk_tier, int) or isinstance(risk_tier, bool) or not 1 <= risk_tier <= 5:
        raise ValueError("risk_tier must be an integer between 1 and 5")
    if risk_tier <= 2:
        return 0
    if risk_tier == 3:
        return 1
    return 2


def registry() -> dict[str, dict[str, object]]:
    """Return the vocabulary as a schema-valid JSON object."""
    return {
        spec.term: {
            "term": spec.term,
            "category": spec.category,
            "risk_tier": spec.risk_tier,
            "requires_target": spec.requires_target,
            "requires_purpose": spec.requires_purpose,
            "data_sensitivity": spec.data_sensitivity,
            "description": spec.description,
        }
        for spec in ACTIONS.values()
    }


def _validate_registry() -> None:
    for spec in ACTIONS.values():
        if spec.term not in ACTION_TERMS:
            raise AssertionError("term must be present in ACTION_TERMS")
        if spec.category not in _CATEGORIES:
            raise AssertionError(f"invalid category {spec.category!r}")
        if not 1 <= spec.risk_tier <= 5:
            raise AssertionError(f"risk_tier must be 1..5, got {spec.risk_tier}")
        if not spec.requires_target:
            raise AssertionError(f"{spec.term} must require a target")
        if not spec.requires_purpose:
            raise AssertionError(f"{spec.term} must require a purpose")


_validate_registry()
