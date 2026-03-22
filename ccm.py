"""
Confidential Compute Monitoring (CCM)

Thin façade re-exporting the main runtime types and providing a debug summary helper.
"""

from __future__ import annotations

from typing import TypeVar

from event_log import Event, EventLog
from runtime import Participant, Runtime  # noqa: F401 — re-export
from protocols.transparency.correctness import CorrectnessEvaluatedEvent
from protocols.transparency.memory_filling import MemoryFillStoppedEvent
from protocols.transparency.utilization import (
    CovertCapacityEstimatedEvent,
    NetworkUtilizationEvaluatedEvent,
    SanitizationFrequencyEvaluatedEvent,
    ScheduleCoverageEvaluatedEvent,
)
from protocols.compliance import ComplianceEvaluatedEvent
from protocols.disclosure import DisclosurePublishedEvent


T = TypeVar("T", bound=Event)


def _latest_of_type(log: EventLog, event_type: type[T]) -> T | None:
    events = log.of_type(event_type)
    return events[-1] if events else None


def render_summary(log: EventLog) -> str:
    transcript_events = log.transcript()
    lines = [
        f"Events: {len(log.events)}",
        f"Transcript events: {len(transcript_events)}",
        "",
        "Latest verification events:",
    ]

    verification_events: list[Event | None] = [
        _latest_of_type(log, CorrectnessEvaluatedEvent),
        _latest_of_type(log, ScheduleCoverageEvaluatedEvent),
        _latest_of_type(log, SanitizationFrequencyEvaluatedEvent),
        _latest_of_type(log, NetworkUtilizationEvaluatedEvent),
        _latest_of_type(log, MemoryFillStoppedEvent),
    ]
    for event in verification_events:
        if event is None:
            continue
        status = "PASS" if event.passed else "FAIL"
        lines.append(f"  [{status}] {type(event).__name__}: {event.details}")

    capacity_event = _latest_of_type(log, CovertCapacityEstimatedEvent)
    if capacity_event is not None:
        lines += [
            "",
            "Latest covert capacity estimate:",
            f"  I/O:         {capacity_event.io_capacity_bits:.0f} bits",
            f"  Persistence: {capacity_event.persistence_capacity_bytes:.0f} bytes",
            f"  Sustained:   {capacity_event.sustained_memory_bytes:.0f} bytes",
            f"  Compute:     {capacity_event.compute_capacity_flops:.0f} FLOP",
        ]

    compliance_event = _latest_of_type(log, ComplianceEvaluatedEvent)
    if compliance_event is not None:
        status = "PASS" if compliance_event.passed else "FAIL"
        lines += [
            "",
            f"Compliance: [{status}] {compliance_event.details}",
        ]

    disclosure_event = _latest_of_type(log, DisclosurePublishedEvent)
    if disclosure_event is not None:
        lines += [
            "",
            "Latest disclosure:",
            f"  Compliant: {disclosure_event.compliant}",
            f"  Summary: {disclosure_event.summary}",
        ]

    return "\n".join(lines)
