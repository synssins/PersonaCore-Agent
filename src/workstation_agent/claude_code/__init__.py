"""Claude Code integration for PersonaCore-Agent.

Provides two directions of integration:

Direction 1 — The agent's own MCP server (:mod:`workstation_agent.mcp_host.mcp_server`)
lets Claude Code (and any other MCP host) drive the agent over a static named pipe
``\\\\.\\pipe\\PC-Agent-MCP``.

Direction 2 — :class:`~workstation_agent.claude_code.driver.ClaudeCodeDriver` wraps
the ``claude-agent-sdk`` to spawn a Claude Code session from within the agent, with
voice-mediated tool-call approvals.

Direction 2.5 — :mod:`workstation_agent.claude_code.presence` detects whether a
Claude Code process is already running on the workstation and, if possible, which
project directory it has open.

The :mod:`workstation_agent.plugins.claude_code_bridge` first-party plugin exposes
all three directions over MCP so the agent's LLM layer can invoke them as tools.
"""
