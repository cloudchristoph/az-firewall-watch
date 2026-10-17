"""The shared state every tool works on, held in the server's lifespan context."""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from mcp.server.mcpserver import Context

from .buffer import LogBuffer
from .config import ServerConfig
from .context import ContextHolder
from .stream import StreamWorker


@dataclass
class AppState:
    """One server process: its configuration, the log buffer, the stream and the policy context."""

    config: ServerConfig
    buffer: LogBuffer
    stream: StreamWorker
    context: ContextHolder
    started_at: float = field(default_factory=time.time)

    @classmethod
    def create(cls, config: ServerConfig) -> AppState:
        """Wire the parts together: the stream feeds the buffer and tells the context what it sees."""
        buffer = LogBuffer(config.buffer_size)
        context = ContextHolder(enabled=config.policy_context, firewall_id=config.firewall_id)
        stream = StreamWorker(config.eventhub, buffer,
                              on_firewall_id=context.set_firewall_id,
                              on_rows=context.note_rows)
        return cls(config=config, buffer=buffer, stream=stream, context=context)


def get_state(ctx: Context[Any, Any]) -> AppState:
    """The :class:`AppState` of the server handling this request."""
    state = ctx.request_context.lifespan_context
    if not isinstance(state, AppState):
        raise RuntimeError("The server lifespan did not provide an AppState.")
    return state


__all__ = ["AppState", "get_state"]
