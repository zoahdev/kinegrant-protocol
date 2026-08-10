from __future__ import annotations

from typing import Any

from ..models import ActionRequest


def matter_command_request(
    *,
    fabric_identity: str,
    node_id: str,
    endpoint: int,
    cluster: str,
    command: str,
    purpose: str,
    request_id: str,
    context: dict[str, Any] | None = None,
) -> ActionRequest:
    return ActionRequest(
        request_id=request_id,
        agent=fabric_identity,
        target=f"matter:{node_id}:{endpoint}:{cluster}",
        action=command,
        purpose=purpose,
        context={"transport": "matter", **(context or {})},
    )
