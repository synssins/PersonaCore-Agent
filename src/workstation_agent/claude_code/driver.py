"""ClaudeCodeDriver — claude-agent-sdk wrapper with voice-mediated tool approval.

The driver spawns a Claude Code session for a single user turn, streams events
back to the caller, and intercepts tool-use events to seek voice confirmation
from the user before allowing execution.

Usage::

    async def my_handler():
        driver = ClaudeCodeDriver(tts=speaker, audio_session=audio_session)
        async for event in driver.run("refactor my code", cwd=Path("/project")):
            print(event)

Voice-mediated approval
-----------------------
When Claude Code requests a tool call, the driver:

1. Speaks a challenge via *tts* (``TTSSpeaker``):
   ``"Claude Code wants to run: <tool>. Say yes to approve, no to deny."``
2. Waits up to *approval_timeout_s* seconds for an STT reply from
   *audio_session*  (a callable ``() -> Awaitable[str | None]``).
3. If the reply starts with "yes" (case-insensitive) the call is approved;
   everything else (including timeout) is treated as a deny.

The sdk's ``permission_mode`` is set to ``"dontAsk"`` so it doesn't prompt on
the terminal; instead the driver handles it through the voice loop.

Fake transport for tests
------------------------
Pass a *transport* argument to inject a custom :class:`Transport` implementation
(see ``tests/fakes/fake_claude_sdk.py``).  The driver will use that transport
instead of spawning a real ``claude`` subprocess.
"""
# ruff: noqa: ANN401, PLC0415, TC003

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator, Callable, Coroutine
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

# Default voice-approval timeout in seconds.
DEFAULT_APPROVAL_TIMEOUT_S = 20.0


@dataclass
class CCEvent:
    """Wrapper around a raw claude-agent-sdk message.

    ``kind`` is one of:
    - ``"assistant"`` — an AssistantMessage (may contain text or tool_use blocks)
    - ``"result"`` — a ResultMessage (terminal)
    - ``"system"`` — a SystemMessage
    - ``"user"`` — a UserMessage (rare in unidirectional mode)
    - ``"tool_use"`` — synthesised by the driver when voice approval resolves
    - ``"denied"`` — synthesised when a tool call is denied
    - ``"unknown"`` — anything else
    """

    kind: str
    raw: Any = field(default=None)
    tool_name: str | None = field(default=None)
    tool_input: dict[str, Any] = field(default_factory=dict)
    approved: bool = field(default=True)


# Type alias for the voice-approval hook injected by callers / tests.
# Signature: (tool_name, tool_input) -> approved (bool)
ToolUseHook = Callable[[str, dict[str, Any]], Coroutine[Any, Any, bool]]

# Type alias for the STT reply getter injected by callers / tests.
# Signature: () -> reply (str | None), with internal timeout.
SttGetter = Callable[[], Coroutine[Any, Any, str | None]]


class ClaudeCodeDriver:
    """Wrap the claude-agent-sdk and add voice-mediated tool approval.

    Parameters
    ----------
    tts:
        Any object with an ``async speak(text: str)`` method.  May be None in
        which case the approval challenge is only logged.
    audio_session:
        A callable ``() -> Awaitable[str | None]`` that returns the next STT
        reply (or None on timeout).  Used to collect the "yes/no" answer.
    approval_timeout_s:
        Seconds to wait for a voice reply before treating as "deny".
    transport:
        Optional custom Transport for testing (injected instead of spawning a
        real subprocess).
    """

    def __init__(
        self,
        *,
        tts: Any | None = None,
        audio_session: SttGetter | None = None,
        approval_timeout_s: float = DEFAULT_APPROVAL_TIMEOUT_S,
        transport: Any | None = None,
    ) -> None:
        self._tts = tts
        self._audio_session = audio_session
        self._approval_timeout_s = approval_timeout_s
        self._transport = transport

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(
        self,
        prompt: str,
        *,
        cwd: Path | None = None,
        on_tool_use: ToolUseHook | None = None,
    ) -> AsyncIterator[CCEvent]:
        """Return an async iterator that streams events from a Claude Code session.

        ``on_tool_use`` overrides the default voice-approval hook entirely when
        provided (useful for tests that inject a deterministic hook).
        """
        return self._stream(prompt, cwd=cwd, on_tool_use=on_tool_use)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _stream(
        self,
        prompt: str,
        *,
        cwd: Path | None = None,
        on_tool_use: ToolUseHook | None = None,
    ) -> AsyncIterator[CCEvent]:
        """Actual async generator that drives the SDK and yields CCEvent."""
        from claude_agent_sdk import ClaudeAgentOptions, query
        from claude_agent_sdk.types import AssistantMessage, ResultMessage, ToolUseBlock

        options = ClaudeAgentOptions(
            permission_mode="dontAsk",
            cwd=str(cwd) if cwd else None,
        )

        hook = on_tool_use or self._default_voice_hook

        async for msg in query(
            prompt=prompt,
            options=options,
            transport=self._transport,
        ):
            if isinstance(msg, AssistantMessage):
                # Yield a plain assistant event, then handle any tool_use blocks.
                yield CCEvent(kind="assistant", raw=msg)

                for block in msg.content:
                    if isinstance(block, ToolUseBlock):
                        approved = await hook(block.name, block.input)
                        if approved:
                            yield CCEvent(
                                kind="tool_use",
                                raw=block,
                                tool_name=block.name,
                                tool_input=block.input,
                                approved=True,
                            )
                        else:
                            log.info("tool_use denied: %s", block.name)
                            yield CCEvent(
                                kind="denied",
                                raw=block,
                                tool_name=block.name,
                                tool_input=block.input,
                                approved=False,
                            )

            elif isinstance(msg, ResultMessage):
                yield CCEvent(kind="result", raw=msg)

            else:
                kind = type(msg).__name__.lower().replace("message", "")
                yield CCEvent(kind=kind or "unknown", raw=msg)

    async def _default_voice_hook(
        self,
        tool_name: str,
        tool_input: dict[str, Any],  # noqa: ARG002
    ) -> bool:
        """Speak approval challenge; wait for STT reply; return decision."""
        challenge = (
            f"Claude Code wants to run: {tool_name}. "
            "Say yes to approve, no to deny."
        )
        log.info("voice approval challenge: %s", challenge)

        if self._tts is not None:
            try:
                await self._tts.speak(challenge)
                # Wait briefly for TTS to play before listening
                await asyncio.sleep(0.5)
            except Exception:
                log.warning("TTS speak failed during approval challenge", exc_info=True)

        if self._audio_session is None:
            log.warning("no audio_session configured; denying tool_use %s", tool_name)
            return False

        try:
            reply: str | None = await asyncio.wait_for(
                self._audio_session(),
                timeout=self._approval_timeout_s,
            )
        except TimeoutError:
            log.info(
                "voice approval timed out after %.0fs for tool %s — denying",
                self._approval_timeout_s,
                tool_name,
            )
            return False

        if reply is None:
            log.info("audio_session returned None for tool %s — denying", tool_name)
            return False

        approved = reply.strip().lower().startswith("yes")
        log.info("voice approval reply=%r approved=%s tool=%s", reply, approved, tool_name)
        return approved
