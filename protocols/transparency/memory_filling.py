"""
Memory filling protocol: continuous proof-of-space via random data challenges.

The verifier fills the prover's memory with random bytes and periodically audits
that the prover still holds the data. This occupies a known amount of memory,
proving the prover cannot repurpose it for covert computation.
"""

from __future__ import annotations

import hashlib
import random
from dataclasses import dataclass, field
from typing import ClassVar

from event_log import (
    Event,
    EventView,
    Role,
    TRANSCRIPT_READERS,
    VERIFICATION_READERS,
)
from runtime.base import Participant
from runtime.engine import Runtime


# --- Transcript events ---


@dataclass(frozen=True, kw_only=True)
class MemoryFillingAcceptedEvent(Event):
    session_id: str
    fill_size_bytes: int
    data_digest: str

    views: ClassVar[frozenset[EventView]] = frozenset({EventView.TRANSCRIPT})


# --- Verification events ---


@dataclass(frozen=True, kw_only=True)
class MemoryFillSentEvent(Event):
    session_id: str
    fill_size_bytes: int
    data: bytes
    data_digest: str

    views: ClassVar[frozenset[EventView]] = frozenset({EventView.VERIFICATION})


@dataclass(frozen=True, kw_only=True)
class MemoryAuditRequestedEvent(Event):
    session_id: str
    audit_id: str
    offset: int
    length: int

    views: ClassVar[frozenset[EventView]] = frozenset({EventView.VERIFICATION})


@dataclass(frozen=True, kw_only=True)
class MemoryAuditRespondedEvent(Event):
    session_id: str
    in_reply_to: str
    offset: int
    data: bytes

    views: ClassVar[frozenset[EventView]] = frozenset({EventView.VERIFICATION})


@dataclass(frozen=True, kw_only=True)
class MemoryAuditEvaluatedEvent(Event):
    session_id: str
    audit_id: str
    passed: bool
    details: str

    views: ClassVar[frozenset[EventView]] = frozenset({EventView.VERIFICATION})


@dataclass(frozen=True, kw_only=True)
class MemoryAuditTimedOutEvent(Event):
    session_id: str
    audit_id: str
    details: str

    views: ClassVar[frozenset[EventView]] = frozenset({EventView.VERIFICATION})


@dataclass(frozen=True, kw_only=True)
class MemoryFillStoppedEvent(Event):
    session_id: str
    reason: str
    audits_passed: int
    audits_failed: int
    passed: bool
    details: str

    views: ClassVar[frozenset[EventView]] = frozenset({EventView.VERIFICATION})


# --- Prover participant ---


@dataclass
class MemoryFillingProver:
    writer: Role = field(default=Role.PROVER, init=False)

    _held_data: dict[str, bytes] = field(default_factory=dict, init=False, repr=False)
    _pending_accept: list[tuple[str, int, str]] = field(
        default_factory=list, init=False, repr=False
    )

    def on_event(self, event: Event, runtime: Runtime) -> list[Event]:
        if isinstance(event, MemoryFillSentEvent):
            return self._handle_fill(event, runtime)
        if isinstance(event, MemoryAuditRequestedEvent):
            return self._handle_audit(event, runtime)
        if isinstance(event, MemoryFillStoppedEvent):
            self._held_data.pop(event.session_id, None)
            return []
        return []

    def on_tick(self, runtime: Runtime) -> list[Event]:
        events: list[Event] = []
        for session_id, fill_size, digest in self._pending_accept:
            events.append(
                MemoryFillingAcceptedEvent(
                    event_id=runtime.make_event_id("memory-fill-accepted"),
                    timestamp=runtime.now,
                    writer=Role.PROVER,
                    readers=TRANSCRIPT_READERS,
                    session_id=session_id,
                    fill_size_bytes=fill_size,
                    data_digest=digest,
                )
            )
        self._pending_accept.clear()
        return events

    def _handle_fill(
        self, event: MemoryFillSentEvent, runtime: Runtime
    ) -> list[Event]:
        self._held_data[event.session_id] = event.data
        self._pending_accept.append(
            (event.session_id, event.fill_size_bytes, event.data_digest)
        )
        return []

    def _handle_audit(
        self, event: MemoryAuditRequestedEvent, runtime: Runtime
    ) -> list[Event]:
        data = self._held_data.get(event.session_id)
        if data is None:
            return []
        chunk = data[event.offset : event.offset + event.length]
        return [
            MemoryAuditRespondedEvent(
                event_id=runtime.make_event_id("memory-audit-responded"),
                timestamp=runtime.now,
                writer=Role.PROVER,
                readers=VERIFICATION_READERS,
                session_id=event.session_id,
                in_reply_to=event.audit_id,
                offset=event.offset,
                data=chunk,
            )
        ]


# --- Verifier participant ---


@dataclass
class _FillingSession:
    fill_data: bytes
    audits_completed: int = 0
    audits_passed: int = 0
    audits_failed: int = 0
    last_audit_tick: float = 0.0
    pending_audit: tuple[str, int, int, float] | None = None  # (audit_id, offset, length, sent_time)


@dataclass
class MemoryFillingVerifier:
    writer: Role = field(default=Role.VERIFIER, init=False)
    fill_size_bytes: int = 1024
    audit_interval_ticks: float = 1.0
    audit_count: int = 5
    audit_chunk_length: int = 16
    timeout_ticks: float = 3.0
    seed: int | None = None

    _sessions: dict[str, _FillingSession] = field(
        default_factory=dict, init=False, repr=False
    )
    _started: bool = field(default=False, init=False, repr=False)
    _rng: random.Random = field(default_factory=random.Random, init=False, repr=False)

    def __post_init__(self) -> None:
        if self.seed is not None:
            self._rng = random.Random(self.seed)

    def on_event(self, event: Event, runtime: Runtime) -> list[Event]:
        if isinstance(event, MemoryAuditRespondedEvent):
            return self._evaluate_response(event, runtime)
        return []

    def on_tick(self, runtime: Runtime) -> list[Event]:
        events: list[Event] = []

        # Start session on first tick
        if not self._started:
            self._started = True
            events.extend(self._start_session(runtime))
            return events

        # Process active sessions
        finished: list[str] = []
        for session_id, session in self._sessions.items():
            # Check for timeout on pending audit
            if session.pending_audit is not None:
                audit_id, offset, length, sent_time = session.pending_audit
                if runtime.now - sent_time >= self.timeout_ticks:
                    session.pending_audit = None
                    session.audits_completed += 1
                    session.audits_failed += 1
                    events.append(
                        MemoryAuditTimedOutEvent(
                            event_id=runtime.make_event_id("memory-audit-timeout"),
                            timestamp=runtime.now,
                            writer=Role.VERIFIER,
                            readers=VERIFICATION_READERS,
                            session_id=session_id,
                            audit_id=audit_id,
                            details=f"timed out after {self.timeout_ticks} ticks",
                        )
                    )

            # Check if session is complete
            if session.audits_completed >= self.audit_count:
                passed = session.audits_failed == 0
                details = f"{session.audits_passed} passed, {session.audits_failed} failed"
                events.append(
                    MemoryFillStoppedEvent(
                        event_id=runtime.make_event_id("memory-fill-stopped"),
                        timestamp=runtime.now,
                        writer=Role.VERIFIER,
                        readers=VERIFICATION_READERS,
                        session_id=session_id,
                        reason="completed",
                        audits_passed=session.audits_passed,
                        audits_failed=session.audits_failed,
                        passed=passed,
                        details=details,
                    )
                )
                finished.append(session_id)
                continue

            # Send next audit if interval has elapsed and no pending audit
            if (
                session.pending_audit is None
                and runtime.now - session.last_audit_tick >= self.audit_interval_ticks
            ):
                audit_id = runtime.make_event_id("memory-audit")
                max_offset = max(0, len(session.fill_data) - self.audit_chunk_length)
                offset = self._rng.randint(0, max_offset) if max_offset > 0 else 0
                length = min(self.audit_chunk_length, len(session.fill_data) - offset)
                session.pending_audit = (audit_id, offset, length, runtime.now)
                session.last_audit_tick = runtime.now
                events.append(
                    MemoryAuditRequestedEvent(
                        event_id=audit_id,
                        timestamp=runtime.now,
                        writer=Role.VERIFIER,
                        readers=VERIFICATION_READERS,
                        session_id=session_id,
                        audit_id=audit_id,
                        offset=offset,
                        length=length,
                    )
                )

        for session_id in finished:
            del self._sessions[session_id]

        return events

    def _start_session(self, runtime: Runtime) -> list[Event]:
        fill_data = self._rng.randbytes(self.fill_size_bytes)
        data_digest = hashlib.sha256(fill_data).hexdigest()[:16]
        session_id = runtime.make_session_id("memory-fill")
        self._sessions[session_id] = _FillingSession(fill_data=fill_data)
        return [
            MemoryFillSentEvent(
                event_id=runtime.make_event_id("memory-fill-sent"),
                timestamp=runtime.now,
                writer=Role.VERIFIER,
                readers=VERIFICATION_READERS,
                session_id=session_id,
                fill_size_bytes=self.fill_size_bytes,
                data=fill_data,
                data_digest=data_digest,
            )
        ]

    def _evaluate_response(
        self, event: MemoryAuditRespondedEvent, runtime: Runtime
    ) -> list[Event]:
        session = self._sessions.get(event.session_id)
        if session is None or session.pending_audit is None:
            return []

        audit_id, offset, length, _ = session.pending_audit
        if event.in_reply_to != audit_id:
            return []

        expected = session.fill_data[offset : offset + length]
        passed = event.data == expected
        details = "match" if passed else f"mismatch at offset {offset}"

        session.pending_audit = None
        session.audits_completed += 1
        if passed:
            session.audits_passed += 1
        else:
            session.audits_failed += 1

        return [
            MemoryAuditEvaluatedEvent(
                event_id=runtime.make_event_id("memory-audit-evaluated"),
                timestamp=runtime.now,
                writer=Role.VERIFIER,
                readers=VERIFICATION_READERS,
                session_id=event.session_id,
                audit_id=audit_id,
                passed=passed,
                details=details,
            )
        ]
