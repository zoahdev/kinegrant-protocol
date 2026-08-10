from __future__ import annotations

from typing import Any
from urllib.parse import quote

from ..models import ActionRequest
from ._context import trusted_context


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
        target=f"opcua:{quote(server_uri, safe='')}:{quote(node_id, safe='')}",
        action=method,
        purpose=purpose,
        context=trusted_context({"transport": "opcua", "adapter_profile": "opcua-method-v0.1"}, context),
    )
