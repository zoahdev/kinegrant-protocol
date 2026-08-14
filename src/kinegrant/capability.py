from __future__ import annotations

import secrets
from datetime import timedelta
from typing import Any

from .canonical import content_id
from .crypto import Ed25519KeyPair
from .models import ActionRequest, Decision, isoformat, utc_now
from .obligations import KNOWN_OBLIGATIONS
from .attenuation import attenuate_capability


def _capability_content_id(body: dict[str, Any]) -> str:
    """Content id excludes self-referential chain fields."""
    unsigned = {
        key: value
        for key, value in body.items()
        if key not in ("capability_id", "root_capability_id")
    }
    return content_id("kinegrant:cap", unsigned)


class CapabilityIssuer:
    def __init__(self, key_pair: Ed25519KeyPair) -> None:
        self.key_pair = key_pair

    def issue(
        self,
        request: ActionRequest,
        decision: Decision,
        *,
        ttl_seconds: int = 30,
    ) -> dict[str, Any]:
        if not decision.allowed:
            raise PermissionError("cannot issue a capability for a denied request")
        if decision.request_digest != request.digest:
            raise ValueError("decision does not belong to this request")
        if not decision.matched_policy_ids:
            raise ValueError("allowed decision has no matching policy")
        if not 1 <= ttl_seconds <= 300:
            raise ValueError("capability TTL must be between 1 and 300 seconds")
        unknown_obligations = set(decision.obligations) - KNOWN_OBLIGATIONS
        if unknown_obligations:
            raise PermissionError("unsupported policy obligation")

        issued_at = utc_now()
        body = {
            "type": "kinegrant:PhysicalActionCapability",
            "version": "0.1",
            "issuer": self.key_pair.kid,
            "agent": request.agent,
            "target": request.target,
            "action": request.action,
            "purpose": request.purpose,
            "request_digest": request.digest,
            "policy_digest": decision.policy_digest,
            "matched_policy_ids": list(decision.matched_policy_ids),
            "obligations": list(decision.obligations),
            "issued_at": isoformat(issued_at),
            "not_before": isoformat(issued_at),
            "expires_at": isoformat(issued_at + timedelta(seconds=ttl_seconds)),
            "nonce": secrets.token_urlsafe(18),
        }
        body["capability_id"] = content_id("kinegrant:cap", body)
        return self.key_pair.sign_envelope(body)

    def issue_scoped(
        self,
        request: ActionRequest,
        decision: Decision,
        *,
        ttl_seconds: int = 30,
        actions: tuple[str, ...] | list[str] | None = None,
        purposes: tuple[str, ...] | list[str] | None = None,
        target: str | None = None,
        approval_tier: int = 0,
        delegation_allowed: bool = False,
        max_delegation_depth: int = 0,
        delegate_allowlist: list[str] | None = None,
        wire_version: str = "0.2",
    ) -> dict[str, Any]:
        """Issue a v0.2 capability with a narrowed-but-still-scoped grant."""
        if not decision.allowed:
            raise PermissionError("cannot issue a capability for a denied request")
        if decision.request_digest != request.digest:
            raise ValueError("decision does not belong to this request")
        if not 1 <= ttl_seconds <= 300:
            raise ValueError("capability TTL must be between 1 and 300 seconds")
        if not isinstance(approval_tier, int) or isinstance(approval_tier, bool) or not 0 <= approval_tier <= 2:
            raise ValueError("approval_tier must be an integer between 0 and 2")
        if not isinstance(delegation_allowed, bool):
            raise ValueError("delegation_allowed must be a boolean")
        if (
            not isinstance(max_delegation_depth, int)
            or isinstance(max_delegation_depth, bool)
            or not 0 <= max_delegation_depth <= 3
        ):
            raise ValueError("max_delegation_depth must be an integer between 0 and 3")
        if delegate_allowlist is not None and (
            not isinstance(delegate_allowlist, list)
            or any(not isinstance(item, str) or not item for item in delegate_allowlist)
        ):
            raise ValueError("delegate_allowlist must be a list of non-empty strings or None")
        if wire_version not in ("0.2", "1.0"):
            raise ValueError("wire_version must be 0.2 or 1.0")
        scope_actions = list(actions or (request.action,))
        scope_purposes = list(purposes or (request.purpose,))
        scope_target = target or request.target
        if not scope_actions or any(not isinstance(action, str) or not action for action in scope_actions):
            raise ValueError("actions must be a non-empty list of non-empty strings")
        if not scope_purposes or any(not isinstance(purpose, str) or not purpose for purpose in scope_purposes):
            raise ValueError("purposes must be a non-empty list of non-empty strings")
        if not isinstance(scope_target, str) or not scope_target.strip():
            raise ValueError("target must be a non-empty string")

        issued_at = utc_now()
        body = {
            "type": "kinegrant:PhysicalActionCapability",
            "version": wire_version,
            "issuer": self.key_pair.kid,
            "agent": request.agent,
            "target": scope_target,
            "actions": scope_actions,
            "purposes": scope_purposes,
            "request_digest": request.digest,
            "policy_digest": decision.policy_digest,
            "matched_policy_ids": list(decision.matched_policy_ids),
            "obligations": list(decision.obligations),
            "issued_at": isoformat(issued_at),
            "not_before": isoformat(issued_at),
            "expires_at": isoformat(issued_at + timedelta(seconds=ttl_seconds)),
            "nonce": secrets.token_urlsafe(18),
            "parent_capability_id": None,
            "constraints": {},
            "approval_tier": approval_tier,
            "delegation_allowed": delegation_allowed,
            "max_delegation_depth": max_delegation_depth,
            "delegate_agent": None,
            "delegation_depth": 0,
            "delegate_allowlist": delegate_allowlist,
        }
        body["capability_id"] = _capability_content_id(body)
        body["root_capability_id"] = body["capability_id"]
        return self.key_pair.sign_envelope(body)

    def issue_attenuated(
        self,
        parent_envelope: dict[str, Any],
        *,
        target: str | None = None,
        actions: list[str] | None = None,
        purposes: list[str] | None = None,
        ttl_seconds: int | None = None,
        max_force_newtons: int | float | None = None,
        max_velocity_mps: int | float | None = None,
        allowed_zones: list[str] | None = None,
        delegate_agent: str | None = None,
        delegate_request: ActionRequest | None = None,
    ) -> dict[str, Any]:
        """Sign a strictly narrower child of an already-issued capability."""
        from .crypto import verify_envelope

        parent_payload = verify_envelope(parent_envelope)
        if parent_payload.get("issuer") != self.key_pair.kid:
            raise ValueError("parent capability was not issued by this key")
        body = attenuate_capability(
            parent_payload,
            target=target,
            actions=actions,
            purposes=purposes,
            ttl_seconds=ttl_seconds,
            max_force_newtons=max_force_newtons,
            max_velocity_mps=max_velocity_mps,
            allowed_zones=allowed_zones,
            delegate_agent=delegate_agent,
            delegate_request=delegate_request,
        )
        return self.key_pair.sign_envelope(body)
