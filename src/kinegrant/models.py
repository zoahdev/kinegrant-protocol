from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal

from .canonical import digest

Effect = Literal["allow", "deny"]


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def isoformat(value: datetime) -> str:
    if value.tzinfo is None:
        raise ValueError("timestamps must include a timezone")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def parse_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamps must include a timezone")
    return parsed.astimezone(timezone.utc)


@dataclass(frozen=True)
class ActionRequest:
    request_id: str
    agent: str
    target: str
    action: str
    purpose: str
    issued_at: datetime = field(default_factory=utc_now)
    context: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for name in ("request_id", "agent", "target", "action", "purpose"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} must be a non-empty string")
        if not isinstance(self.context, dict):
            raise ValueError("context must be an object")
        # Validate this at construction time rather than much later during signing.
        isoformat(self.issued_at)

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "kinegrant:ActionRequest",
            "version": "0.1",
            "request_id": self.request_id,
            "agent": self.agent,
            "target": self.target,
            "action": self.action,
            "purpose": self.purpose,
            "issued_at": isoformat(self.issued_at),
            "context": self.context,
        }

    @property
    def digest(self) -> str:
        return digest(self.to_dict())


@dataclass(frozen=True)
class PolicyRule:
    policy_id: str
    issuer: str
    target: str
    effect: Effect
    actions: tuple[str, ...]
    subjects: tuple[str, ...] = ("*",)
    purposes: tuple[str, ...] = ("*",)
    constraints: dict[str, Any] = field(default_factory=dict)
    obligations: tuple[str, ...] = ()
    priority: int = 0
    source: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.effect not in ("allow", "deny"):
            raise ValueError("effect must be allow or deny")
        if not self.actions:
            raise ValueError("a policy rule must contain at least one action")
        for name in ("policy_id", "issuer", "target"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} must be a non-empty string")
        for name in ("actions", "subjects", "purposes"):
            values = getattr(self, name)
            if not values or any(not isinstance(item, str) or not item.strip() for item in values):
                raise ValueError(f"{name} must contain non-empty strings")
        if not isinstance(self.constraints, dict) or not isinstance(self.source, dict):
            raise ValueError("constraints and source must be objects")

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy_id": self.policy_id,
            "issuer": self.issuer,
            "target": self.target,
            "effect": self.effect,
            "actions": list(self.actions),
            "subjects": list(self.subjects),
            "purposes": list(self.purposes),
            "constraints": self.constraints,
            "obligations": list(self.obligations),
            "priority": self.priority,
            "source": self.source,
        }


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    request_digest: str
    policy_digest: str
    matched_policy_ids: tuple[str, ...] = ()
    obligations: tuple[str, ...] = ()
    required_approval_tier: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "reason": self.reason,
            "request_digest": self.request_digest,
            "policy_digest": self.policy_digest,
            "matched_policy_ids": list(self.matched_policy_ids),
            "obligations": list(self.obligations),
            "required_approval_tier": self.required_approval_tier,
        }
