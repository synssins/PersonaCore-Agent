"""The LAN-facing streamable-HTTP MCP endpoint (contract §1-§3, subtask B4).

``https://<operator-chosen-interface>:<port>/mcp``, TLS with a pinned self-signed
certificate, a 32-byte bearer token, and a static families-only tool allowlist.

The two decisions this subtask was asked to make — the `mcp` package versus
extending the inline JSON-RPC, and the pre-authentication input bound — are
recorded with their reasoning in ``DECISION.md`` beside this file.

Modules:
    :mod:`~workstation_agent.network_mcp.tools`
        The static allowlist. The authority on what leaves this workstation, and
        the list subtask B5 generates the registration from.
    :mod:`~workstation_agent.network_mcp.certs`
        The persisted self-signed certificate and its pinned fingerprint.
    :mod:`~workstation_agent.network_mcp.credentials`
        The persisted bearer token.
    :mod:`~workstation_agent.network_mcp.listeners`
        One listening socket per operator-chosen address, and why the sockets
        are opened here rather than by uvicorn.
    :mod:`~workstation_agent.network_mcp.hardening`
        The security boundary: path, method, auth, bounds, caps, and systematic
        hostile-input rejection.
    :mod:`~workstation_agent.network_mcp.server`
        :class:`NetworkMCPServer` — start, stop, and the operator surface.
"""

from workstation_agent.network_mcp.certs import CertificateInfo, ensure_certificate
from workstation_agent.network_mcp.credentials import DEFAULT_STATE_DIR, ensure_token
from workstation_agent.network_mcp.hardening import Hardening, validate_json_body
from workstation_agent.network_mcp.listeners import BindFailure, BoundAddress, endpoint_url
from workstation_agent.network_mcp.server import NetworkEndpointInfo, NetworkMCPServer
from workstation_agent.network_mcp.tools import (
    SERVED_FAMILIES,
    SERVED_TOOLS,
    SERVED_TOOLS_BY_NAME,
    ServedTool,
    served_tool_names,
    validate_tool_names,
)

__all__ = [
    "DEFAULT_STATE_DIR",
    "SERVED_FAMILIES",
    "SERVED_TOOLS",
    "SERVED_TOOLS_BY_NAME",
    "BindFailure",
    "BoundAddress",
    "CertificateInfo",
    "Hardening",
    "NetworkEndpointInfo",
    "NetworkMCPServer",
    "ServedTool",
    "endpoint_url",
    "ensure_certificate",
    "ensure_token",
    "served_tool_names",
    "validate_json_body",
    "validate_tool_names",
]
