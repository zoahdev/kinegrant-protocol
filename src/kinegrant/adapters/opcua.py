from __future__ import annotations

from typing import Any

from ..models import ActionRequest


def opcua_method_request(
    *,
    session_identity: str,
    server_uri: str,
    node_id: str,
    method: str,
    purpose: str,
    request_id: str,
    context: dict[str, Any] | None = None,
) -> ActionRequest:
    return ActionRequest(
        request_id=request_id,
        agent=session_identity,
        target=f"opcua:{server_uri}:{node_id}",
        action=method,
        purpose=purpose,
        context={"transport": "opcua", **(context or {})},
    )
