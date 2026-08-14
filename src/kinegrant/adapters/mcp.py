"""Model Context Protocol (MCP) tool-call adapter (non-normative reference).

MCP is the transport that many agentic AI systems use to let a model call
tools on remote servers. KineGrant treats such a tool call as a physical
action request: the MCP server is the authenticated agent, the tool is the
action, and the server's operator supplies the physical target and purpose.
The adapter is deliberately narrow and fail-closed: the caller cannot spoof
adapter-owned context fields such as ``transport`` or ``adapter_profile``.
"""

from __future__ import annotations

from typing import Any

from ..models import ActionRequest
from ._context import trusted_context


def mcp_tool_request(
    *,
    server_identity: str,
    tool_name: str,
    physical_target: str,
    purpose: str,
    request_id: str,
    server_uri: str | None = None,
    context: dict[str, Any] | None = None,
) -> ActionRequest:
    """Convert an MCP-style tool call into a KineGrant :class:`ActionRequest`.

    ``server_identity`` is the authenticated MCP server principal, ``tool_name``
    maps to the KineGrant action, and ``physical_target`` is the actuator-level
    target the tool call would affect. ``server_uri`` is recorded as
    policy-visible context, never as identity.
    """
    return ActionRequest(
        request_id=request_id,
        agent=server_identity,
        target=physical_target,
        action=tool_name,
        purpose=purpose,
        context=trusted_context(
            {
                "transport": "mcp",
                "adapter_profile": "mcp-tool-v0.1",
                "server_uri": server_uri or "mcp://local",
            },
            context,
        ),
    )
