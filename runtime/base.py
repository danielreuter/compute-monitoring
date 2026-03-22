"""
Role contract for the monitoring runtime.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

from event_log import Event, Side

if TYPE_CHECKING:
    from runtime.engine import Runtime


class Role(Protocol):
    writer: Side

    def on_event(self, event: Event, runtime: Runtime) -> list[Event]: ...
    def on_tick(self, runtime: Runtime) -> list[Event]: ...
