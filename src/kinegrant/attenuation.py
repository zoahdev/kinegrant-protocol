"""Capability attenuation for KGP-001 v0.2.

Attenuation derives a strictly narrower capability from an already-issued one.
A v0.2 capability carries a scope (target pattern, action list, purpose list)
instead of one exact triple, so a child may narrow:

- keep the same agent (cross-agent delegation is future work);
- narrow the target pattern to a literal the parent pattern matches
  (e.g. ``door-*`` -> ``door-7``);
- narrow the action and purpose sets to subsets of the parent's;
- shorten the lifetime within the parent's validity window;
- tighten physical constraints (force/velocity ceilings, zone allowlist);
- keep the same approval tier.

An independent verifier can compare the parent and child payloads with
``verify_attenuation`` without trusting either party.
"""

from __future__ import annotations

import secrets
from datetime import timedelta
from fnmatch import fnmatchcase
from typing import Any

from .canonical import content_id
from .models import ActionRequest, isoformat, parse_time, utc_now

VERSION = "0.2"
MAX_TTL_SECONDS = 300
_CONSTRAINT_KEYS = {"max_force_newtons", "max_velocity_mps", "allowed_zones"}


def _matches(value: str, patterns: list[str]) -> bool:
    return any(fnmatchcase(value, pattern) for pattern in patterns)


def _require_parent(parent: dict[str, Any]) -> None:
    if parent.get("type") != "kinegrant:PhysicalActionCapability":
        raise ValueError("parent is not a KineGrant capability")
    if parent.get("version") not in ("0.1", "0.2"):
        raise ValueError("unsupported parent capability version")
    for field in (
        "issuer", "agent", "target",
        "request_digest", "policy_digest", "matched_policy_ids",
        "obligations", "not_before", "expires_at", "capability_id",
    ):
        if field not in parent:
            raise ValueError(f"parent capability is missing {field}")
    if parent.get("version") == "0.2":
        for field in (
            "actions",
            "purposes",
            "delegation_allowed",
            "max_delegation_depth",
            "delegate_agent",
            "delegation_depth",
        ):
            if field not in parent:
                raise ValueError(f"parent capability is missing {field}")
    else:
        for field in ("action", "purpose"):
            if field not in parent:
                raise ValueError(f"parent capability is missing {field}")
    if not isinstance(parent["matched_policy_ids"], list) or not parent["matched_policy_ids"]:
        raise ValueError("parent capability has no matching policy")


def _parent_scope(parent: dict[str, Any]) -> tuple[str, list[str], list[str]]:
    if parent.get("version") == "0.2":
        target = parent["target"]
        actions = parent["actions"]
        purposes = parent["purposes"]
    else:
        target = parent["target"]
        actions = [parent["action"]]
        purposes = [parent["purpose"]]
    if not isinstance(target, str) or not target.strip():
        raise ValueError("parent target scope must be a non-empty string")
    if not isinstance(actions, list) or not actions or any(
        not isinstance(action, str) or not action for action in actions
    ):
        raise ValueError("parent action scope must be a non-empty list of non-empty strings")
    if not isinstance(purposes, list) or not purposes or any(
        not isinstance(purpose, str) or not purpose for purpose in purposes
    ):
        raise ValueError("parent purpose scope must be a non-empty list of non-empty strings")
    return target, actions, purposes


def _narrow_time(
    parent: dict[str, Any],
    ttl_seconds: int | None,
) -> tuple[object, object]:
    now = utc_now()
    parent_not_before = parse_time(parent["not_before"])
    parent_expires_at = parse_time(parent["expires_at"])
    if ttl_seconds is None:
        remaining = int((parent_expires_at - now).total_seconds())
        ttl_seconds = max(1, min(MAX_TTL_SECONDS, remaining))
    if not isinstance(ttl_seconds, int) or isinstance(ttl_seconds, bool) or not 1 <= ttl_seconds <= MAX_TTL_SECONDS:
        raise ValueError("attenuated TTL must be an integer between 1 and 300 seconds")
    child_not_before = now
    child_expires_at = now + timedelta(seconds=ttl_seconds)
    if child_not_before < parent_not_before or child_expires_at > parent_expires_at:
        raise ValueError("attenuation cannot extend the parent capability lifetime")
    return child_not_before, child_expires_at


def _narrow_constraints(
    parent: dict[str, Any],
    *,
    max_force_newtons: int | float | None,
    max_velocity_mps: int | float | None,
    allowed_zones: list[str] | None,
) -> dict[str, Any]:
    parent_constraints = parent.get("constraints", {})
    if not isinstance(parent_constraints, dict):
        raise ValueError("parent constraints must be an object")
    child: dict[str, Any] = {}

    def _limit(name: str, value: object) -> None:
        if value is None:
            return
        if not isinstance(value, (int, float)) or isinstance(value, bool) or value < 0:
            raise ValueError(f"{name} must be a non-negative number")
        parent_value = parent_constraints.get(name)
        if parent_value is not None and value > parent_value:
            raise ValueError(f"attenuation cannot raise {name} above the parent limit")
        child[name] = value

    _limit("max_force_newtons", max_force_newtons)
    _limit("max_velocity_mps", max_velocity_mps)

    if allowed_zones is not None:
        if not isinstance(allowed_zones, list) or not allowed_zones or any(
            not isinstance(zone, str) or not zone.strip() for zone in allowed_zones
        ):
            raise ValueError("allowed_zones must be a non-empty list of non-empty strings")
        parent_zones = parent_constraints.get("allowed_zones")
        if parent_zones is not None:
            if not isinstance(parent_zones, list):
                raise ValueError("parent allowed_zones must be a list")
            for zone in allowed_zones:
                if not _matches(zone, parent_zones):
                    raise ValueError(f"zone {zone!r} is outside the parent allowlist")
        child["allowed_zones"] = list(allowed_zones)
    return child


def attenuate_capability(
    parent: dict[str, Any],
    *,
    agent: str | None = None,
    actions: list[str] | None = None,
    target: str | None = None,
    purposes: list[str] | None = None,
    ttl_seconds: int | None = None,
    max_force_newtons: int | float | None = None,
    max_velocity_mps: int | float | None = None,
    allowed_zones: list[str] | None = None,
    delegate_agent: str | None = None,
    delegate_request: ActionRequest | None = None,
) -> dict[str, Any]:
    """Return a strictly narrower unsigned v0.2 capability body."""
    _require_parent(parent)

    if agent is not None and agent != parent["agent"]:
        raise ValueError("cross-agent delegation is not supported in v0.2 attenuation")
    child_agent = parent["agent"]

    parent_target, parent_actions, parent_purposes = _parent_scope(parent)

    if target is not None:
        if not isinstance(target, str) or not target.strip():
            raise ValueError("target must be a non-empty string")
        if target != parent_target and not _matches(target, [parent_target]):
            raise ValueError(f"target {target!r} is outside the parent target scope")
    child_target = target or parent_target

    if actions is not None:
        if not isinstance(actions, list) or not actions or any(
            not isinstance(action, str) or not action for action in actions
        ):
            raise ValueError("actions must be a non-empty list of non-empty strings")
        if any(action not in parent_actions for action in actions):
            raise ValueError("attenuation cannot add actions beyond the parent capability")
    child_actions = actions if actions is not None else parent_actions

    if purposes is not None:
        if not isinstance(purposes, list) or not purposes or any(
            not isinstance(purpose, str) or not purpose for purpose in purposes
        ):
            raise ValueError("purposes must be a non-empty list of non-empty strings")
        if any(purpose not in parent_purposes for purpose in purposes):
            raise ValueError("attenuation cannot add purposes beyond the parent capability")
    child_purposes = purposes if purposes is not None else parent_purposes

    child_not_before, child_expires_at = _narrow_time(parent, ttl_seconds)
    child_constraints = _narrow_constraints(
        parent,
        max_force_newtons=max_force_newtons,
        max_velocity_mps=max_velocity_mps,
        allowed_zones=allowed_zones,
    )

    parent_delegation_allowed = parent.get("delegation_allowed", False)
    parent_max_depth = parent.get("max_delegation_depth", 0)
    parent_delegate = parent.get("delegate_agent")
    parent_depth = parent.get("delegation_depth", 0)
    if not isinstance(parent_delegation_allowed, bool):
        raise ValueError("parent delegation_allowed must be a boolean")
    if (
        not isinstance(parent_max_depth, int)
        or isinstance(parent_max_depth, bool)
        or not 0 <= parent_max_depth <= 3
    ):
        raise ValueError("parent max_delegation_depth must be an integer between 0 and 3")
    if parent_delegate is not None and (
        not isinstance(parent_delegate, str) or not parent_delegate
    ):
        raise ValueError("parent delegate_agent must be a non-empty string or null")
    if (
        not isinstance(parent_depth, int)
        or isinstance(parent_depth, bool)
        or not 0 <= parent_depth <= 3
    ):
        raise ValueError("parent delegation_depth must be an integer between 0 and 3")

    if delegate_agent is None:
        child_delegate = parent_delegate
        child_depth = parent_depth
        child_delegation_allowed = parent_delegation_allowed
        child_max_depth = parent_max_depth
        child_request_digest = parent["request_digest"]
    else:
        if not isinstance(delegate_agent, str) or not delegate_agent.strip():
            raise ValueError("delegate_agent must be a non-empty string")
        if delegate_agent == parent["agent"]:
            raise ValueError("delegate_agent must differ from the principal agent")
        if not parent_delegation_allowed:
            raise ValueError("parent capability does not allow delegation")
        if parent_depth >= parent_max_depth:
            raise ValueError("delegation depth limit reached")
        if delegate_request is None:
            raise ValueError("delegate_agent requires a delegate ActionRequest")
        if delegate_request.agent != delegate_agent:
            raise ValueError("delegate request agent must match delegate_agent")
        if not _matches(delegate_request.target, [child_target]):
            raise ValueError("delegate request target is outside the child scope")
        if delegate_request.action not in child_actions:
            raise ValueError("delegate request action is outside the child scope")
        if delegate_request.purpose not in child_purposes:
            raise ValueError("delegate request purpose is outside the child scope")
        child_delegate = delegate_agent
        child_depth = parent_depth + 1
        child_delegation_allowed = False
        child_max_depth = 0
        child_request_digest = delegate_request.digest

    approval_tier = parent.get("approval_tier", 0)
    if not isinstance(approval_tier, int) or isinstance(approval_tier, bool) or not 0 <= approval_tier <= 2:
        raise ValueError("parent approval_tier must be an integer between 0 and 2")

    body = {
        "type": "kinegrant:PhysicalActionCapability",
        "version": VERSION,
        "issuer": parent["issuer"],
        "agent": child_agent,
        "target": child_target,
        "actions": child_actions,
        "purposes": child_purposes,
        "request_digest": child_request_digest,
        "policy_digest": parent["policy_digest"],
        "matched_policy_ids": list(parent["matched_policy_ids"]),
        "obligations": list(parent["obligations"]),
        "issued_at": isoformat(child_not_before),
        "not_before": isoformat(child_not_before),
        "expires_at": isoformat(child_expires_at),
        "nonce": secrets.token_urlsafe(18),
        "parent_capability_id": parent["capability_id"],
        "constraints": child_constraints,
        "approval_tier": approval_tier,
        "delegation_allowed": child_delegation_allowed,
        "max_delegation_depth": child_max_depth,
        "delegate_agent": child_delegate,
        "delegation_depth": child_depth,
    }
    body["capability_id"] = content_id("kinegrant:cap", body)
    return body


def verify_attenuation(
    child: dict[str, Any],
    parent: dict[str, Any],
) -> bool:
    """Return True when *child* is a strict, verifiable attenuation of *parent*."""
    try:
        _require_parent(parent)
        if child.get("type") != "kinegrant:PhysicalActionCapability":
            return False
        if child.get("version") != VERSION:
            return False
        if child.get("parent_capability_id") != parent.get("capability_id"):
            return False
        if child.get("issuer") != parent.get("issuer"):
            return False
        if child.get("agent") != parent.get("agent"):
            return False
        if child.get("policy_digest") != parent.get("policy_digest"):
            return False
        child_policies = child.get("matched_policy_ids", [])
        parent_policies = parent.get("matched_policy_ids", [])
        if not isinstance(child_policies, list) or not isinstance(parent_policies, list):
            return False
        if not set(child_policies).issubset(set(parent_policies)) or not child_policies:
            return False
        child_target = child.get("target", "")
        parent_target, parent_actions, parent_purposes = _parent_scope(parent)
        if child_target != parent_target and not _matches(child_target, [parent_target]):
            return False
        child_actions = child.get("actions", [])
        if not isinstance(child_actions, list) or not isinstance(parent_actions, list):
            return False
        if not child_actions or any(action not in parent_actions for action in child_actions):
            return False
        child_purposes = child.get("purposes", [])
        if not isinstance(child_purposes, list) or not isinstance(parent_purposes, list):
            return False
        if not child_purposes or any(purpose not in parent_purposes for purpose in child_purposes):
            return False

        parent_allowed = parent.get("delegation_allowed", False)
        parent_max_depth = parent.get("max_delegation_depth", 0)
        parent_delegate = parent.get("delegate_agent")
        parent_depth = parent.get("delegation_depth", 0)
        child_allowed = child.get("delegation_allowed", False)
        child_max_depth = child.get("max_delegation_depth", 0)
        child_delegate = child.get("delegate_agent")
        child_depth = child.get("delegation_depth", 0)
        for value, name in (
            (parent_allowed, "parent delegation_allowed"),
            (child_allowed, "child delegation_allowed"),
        ):
            if not isinstance(value, bool):
                return False
        for value, name in (
            (parent_max_depth, "parent max_delegation_depth"),
            (child_max_depth, "child max_delegation_depth"),
            (parent_depth, "parent delegation_depth"),
            (child_depth, "child delegation_depth"),
        ):
            if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= 3:
                return False
        if child_delegate == parent_delegate:
            if child_depth != parent_depth:
                return False
            if child.get("request_digest") != parent.get("request_digest"):
                return False
        else:
            if not parent_allowed:
                return False
            if parent_depth >= parent_max_depth:
                return False
            if child_depth != parent_depth + 1:
                return False
            if not isinstance(child_delegate, str) or not child_delegate:
                return False
            if child_delegate == child.get("agent"):
                return False
            if child_allowed is not False:
                return False
            if child_max_depth != 0:
                return False
        if child_max_depth > parent_max_depth:
            return False
        if child_allowed and not parent_allowed:
            return False
        if parse_time(child["not_before"]) < parse_time(parent["not_before"]):
            return False
        if parse_time(child["expires_at"]) > parse_time(parent["expires_at"]):
            return False
        if child.get("approval_tier", 0) != parent.get("approval_tier", 0):
            return False
        child_constraints = child.get("constraints", {})
        parent_constraints = parent.get("constraints", {})
        if not isinstance(child_constraints, dict) or not isinstance(parent_constraints, dict):
            return False
        if set(child_constraints) - _CONSTRAINT_KEYS:
            return False
        for name in ("max_force_newtons", "max_velocity_mps"):
            child_value = child_constraints.get(name)
            if child_value is None:
                continue
            parent_value = parent_constraints.get(name)
            # An unrestricted parent may gain a limit; an already-limited
            # parent may only be tightened further.
            if parent_value is not None and child_value > parent_value:
                return False
        child_zones = child_constraints.get("allowed_zones")
        if child_zones is not None:
            parent_zones = parent_constraints.get("allowed_zones")
            if not isinstance(child_zones, list):
                return False
            if parent_zones is not None:
                if not isinstance(parent_zones, list):
                    return False
                if any(not _matches(zone, parent_zones) for zone in child_zones):
                    return False
        return True
    except (KeyError, TypeError, ValueError):
        return False
