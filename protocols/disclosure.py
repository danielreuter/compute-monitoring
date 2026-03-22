"""
Disclosure: reads compliance outputs and emits public disclosure events.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import ClassVar

from event_log import (
    DISCLOSURE_READERS,
    Event,
    EventView,
    Role,
)
from protocols.compliance import ComplianceEvaluatedEvent
from runtime.base import Participant
from runtime.engine import Runtime


@dataclass(frozen=True, kw_only=True)
class DisclosurePublishedEvent(Event):
    compliant: bool
    summary: str

    views: ClassVar[frozenset[EventView]] = frozenset({EventView.DISCLOSURE})


@dataclass
class DisclosurePublisher:
    writer: Role = field(default=Role.VERIFIER, init=False)

    _emitted: bool = field(default=False, init=False, repr=False)

    def on_event(self, event: Event, runtime: Runtime) -> list[Event]:
        if isinstance(event, ComplianceEvaluatedEvent) and not self._emitted:
            self._emitted = True
            summary = (
                "all checks passed"
                if event.passed
                else f"compliance failed: {event.details}"
            )
            return [
                DisclosurePublishedEvent(
                    event_id=runtime.make_event_id("disclosure"),
                    timestamp=runtime.now,
                    writer=Role.VERIFIER,
                    readers=DISCLOSURE_READERS,
                    compliant=event.passed,
                    summary=summary,
                )
            ]
        return []

    def on_tick(self, runtime: Runtime) -> list[Event]:
        return []
