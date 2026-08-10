from __future__ import annotations

from typing import Any, Mapping

from ..models import ActionRequest
from ._context import trusted_context


def _thing_id(description: Mapping[str, Any]) -> str:
    value = description.get("id") or description.get("@id")
    if not isinstance(value, str):
        raise ValueError("WoT Thing Description requires an id")
    return value


def describe_wot_actions(description: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    actions = description.get("actions", {})
    if not isinstance(actions, Mapping):
        raise ValueError("WoT actions must be an object")
    return {
        str(name): {
            "target": _thing_id(description),
            "title": metadata.get("title", name) if isinstance(metadata, Mapping) else name,
            "safe": bool(metadata.get("safe", False)) if isinstance(metadata, Mapping) else False,
            "idempotent": bool(metadata.get("idempotent", False)) if isinstance(metadata, Mapping) else False,
        }
        for name, metadata in actions.items()
    }


def wot_action_request(
    description: Mapping[str, Any],
    *,
    action_name: str,
    agent: str,
    purpose: str,
    request_id: str,
    context: dict[str, Any] | None = None,
) -> ActionRequest:
    actions = describe_wot_actions(description)
    if action_name not in actions:
        raise ValueError(f"unknown WoT action: {action_name}")
    return ActionRequest(
        request_id=request_id,
        agent=agent,
        target=_thing_id(description),
        action=action_name,
        purpose=purpose,
        context=trusted_context({"transport": "wot", "adapter_profile": "wot-action-v0.1"}, context),
    )
