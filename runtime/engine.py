"""
Deterministic in-process runtime driver.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Iterable

from event_log import Event, EventLog
from runtime.base import Role


@dataclass
class Runtime:
    log: EventLog
    participants: list[Role]
    now: float = 0.0

    _queue: deque[Event] = field(default_factory=deque, init=False, repr=False)
    _id_counters: dict[str, int] = field(default_factory=dict, init=False, repr=False)
    _session_counters: dict[str, int] = field(default_factory=dict, init=False, repr=False)

    def emit(self, event: Event) -> None:
        self.log.append(event)
        self._queue.append(event)

    def emit_many(self, events: Iterable[Event]) -> None:
        for event in events:
            self.emit(event)

    def dispatch_until_quiescent(self) -> None:
        while self._queue:
            event = self._queue.popleft()
            for participant in self.participants:
                responses = participant.on_event(event, self)
                self.emit_many(responses)

    def tick(self, delta: float = 1.0) -> None:
        self.now += delta
        for participant in self.participants:
            responses = participant.on_tick(self)
            self.emit_many(responses)
        self.dispatch_until_quiescent()

    def make_event_id(self, prefix: str) -> str:
        count = self._id_counters.get(prefix, 0) + 1
        self._id_counters[prefix] = count
        return f"{prefix}-{count}"

    def make_session_id(self, prefix: str) -> str:
        count = self._session_counters.get(prefix, 0) + 1
        self._session_counters[prefix] = count
        return f"{prefix}-session-{count}"
