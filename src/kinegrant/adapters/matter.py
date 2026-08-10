from __future__ import annotations

from typing import Any
from urllib.parse import quote

from ..models import ActionRequest
from ._context import trusted_context


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
        target=f"matter:{quote(str(node_id), safe='')}:{endpoint}:{quote(cluster, safe='')}",
        action=command,
        purpose=purpose,
        context=trusted_context({"transport": "matter", "adapter_profile": "matter-command-v0.1"}, context),
    )
