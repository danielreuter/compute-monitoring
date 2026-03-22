"""
Participant contract for the monitoring runtime.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

from event_log import Event, Role

if TYPE_CHECKING:
    from runtime.engine import Runtime


class Participant(Protocol):
    writer: Role

    def on_event(self, event: Event, runtime: Runtime) -> list[Event]: ...
    def on_tick(self, runtime: Runtime) -> list[Event]: ...
