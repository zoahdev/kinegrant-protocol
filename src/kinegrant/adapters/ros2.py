from __future__ import annotations

from typing import Any

from ..models import ActionRequest


def ros_action_request(
    *,
    node_identity: str,
    action_name: str,
    physical_target: str,
    purpose: str,
    request_id: str,
    namespace: str = "/",
    context: dict[str, Any] | None = None,
) -> ActionRequest:
    return ActionRequest(
        request_id=request_id,
        agent=node_identity,
        target=physical_target,
        action=action_name,
        purpose=purpose,
        context={"transport": "ros2", "namespace": namespace, **(context or {})},
    )
