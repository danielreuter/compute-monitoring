"""
Core event log primitives for the CCM prototype.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import ClassVar, Iterable


class Role(Enum):
    PROVER = "prover"
    VERIFIER = "verifier"
    PROVING_PARTY = "proving_party"
    VERIFYING_PARTY = "verifying_party"


class EventView(Enum):
    TRANSCRIPT = "transcript"
    VERIFICATION = "verification"
    DISCLOSURE = "disclosure"


TRANSCRIPT_READERS = frozenset({Role.PROVER, Role.VERIFIER})
VERIFICATION_READERS = frozenset({Role.VERIFIER})
DISCLOSURE_READERS = frozenset({Role.PROVING_PARTY, Role.VERIFYING_PARTY})


@dataclass(frozen=True, kw_only=True)
class Event:
    event_id: str
    timestamp: float
    writer: Role
    readers: frozenset[Role]

    views: ClassVar[frozenset[EventView]] = frozenset()


@dataclass
class EventLog:
    events: list[Event] = field(default_factory=list)

    def append(self, event: Event) -> None:
        self.events.append(event)

    def extend(self, events: Iterable[Event]) -> None:
        self.events.extend(events)

    def of_type[T: Event](self, event_type: type[T]) -> list[T]:
        return [event for event in self.events if isinstance(event, event_type)]

    def in_view(self, view: EventView) -> list[Event]:
        return [event for event in self.events if view in type(event).views]

    def visible_to(self, reader: Role) -> list[Event]:
        return [event for event in self.events if reader in event.readers]

    def transcript(self) -> list[Event]:
        return self.in_view(EventView.TRANSCRIPT)
