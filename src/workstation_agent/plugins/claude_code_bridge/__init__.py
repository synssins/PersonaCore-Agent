"""First-party plugin: Claude Code bridge.

Exposes three tools via MCP so the agent's LLM layer can trigger Claude Code
sessions and inspect Claude Code's running state:

- ``claude_code.invoke(prompt, cwd?, voice_approval)`` — starts a Claude Code
  session via :class:`~workstation_agent.claude_code.driver.ClaudeCodeDriver`
  and streams events back as MCP notifications.
- ``claude_code.presence()`` — returns ``{running: bool, cwd?: str}`` by
  calling :func:`~workstation_agent.claude_code.presence.is_running` and
  :func:`~workstation_agent.claude_code.presence.active_project`.
- ``claude_code.list_recent_sessions(limit?)`` — enumerates
  ``~/.claude/projects/*/`` and returns session metadata.

The plugin runs as a subprocess (like every other MCP plugin in SPEC-03B) and
communicates with the host over stdin/stdout JSON-RPC 2.0.  It has no
network access and runs in a Job Object with memory limits.

Permissions declared in ``plugin.toml``::

    declared_permissions = [
        'tool:claude_code.invoke',
        'tool:claude_code.presence',
        'tool:claude_code.list_recent_sessions',
    ]
"""
