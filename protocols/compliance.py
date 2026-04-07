"""
Compliance verification: reads transparency outputs and emits a single compliance result.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import ClassVar

from event_log import (
    Event,
    EventView,
    Side,
    VERIFICATION_READERS,
)
from protocols.transparency.correctness import (
    CorrectnessEvaluatedEvent,
    InferenceClaimedEvent,
)
from protocols.transparency.remote_attestation import RemoteAttestationEvaluatedEvent
from protocols.transparency.memory_filling import MemoryAuditEvaluatedEvent
from protocols.transparency.utilization import (
    NetworkUtilizationEvaluatedEvent,
    SanitizationFrequencyEvaluatedEvent,
    ScheduleCoverageEvaluatedEvent,
)
from runtime.base import Role
from runtime.engine import Runtime


@dataclass(frozen=True, kw_only=True)
class ComplianceEvaluatedEvent(Event):
    passed: bool
    details: str

    views: ClassVar[frozenset[EventView]] = frozenset({EventView.VERIFICATION})


@dataclass
class ComplianceVerifier:
    writer: Side = field(default=Side.VERIFIER, init=False)
    approved_models: frozenset[str] = frozenset()

    _emitted: bool = field(default=False, init=False, repr=False)

    def on_event(self, event: Event, runtime: Runtime) -> list[Event]:
        return []

    def on_tick(self, runtime: Runtime) -> list[Event]:
        if self._emitted:
            return []

        # Check model approval from transcript
        claims = runtime.log.of_type(InferenceClaimedEvent)
        used_models = frozenset(c.model_id for c in claims)
        unapproved = used_models - self.approved_models

        # Gather transparency results
        failures: list[str] = []

        if unapproved:
            failures.append(f"unapproved models: {sorted(unapproved)}")

        correctness_events = runtime.log.of_type(CorrectnessEvaluatedEvent)
        for ce in correctness_events:
            if not ce.passed:
                failures.append(f"correctness check failed for {ce.request_id}: {ce.details}")

        schedule_events = runtime.log.of_type(ScheduleCoverageEvaluatedEvent)
        if schedule_events and not schedule_events[-1].passed:
            failures.append(f"schedule coverage failed: {schedule_events[-1].details}")

        sanitization_events = runtime.log.of_type(SanitizationFrequencyEvaluatedEvent)
        if sanitization_events and not sanitization_events[-1].passed:
            failures.append(f"sanitization frequency failed: {sanitization_events[-1].details}")

        network_events = runtime.log.of_type(NetworkUtilizationEvaluatedEvent)
        if network_events and not network_events[-1].passed:
            failures.append(f"network utilization failed: {network_events[-1].details}")

        attestation_events = runtime.log.of_type(RemoteAttestationEvaluatedEvent)
        if attestation_events and not attestation_events[-1].passed:
            failures.append(f"remote attestation failed: {attestation_events[-1].details}")

        memory_audit_events = runtime.log.of_type(MemoryAuditEvaluatedEvent)
        for mae in memory_audit_events:
            if not mae.passed:
                failures.append(f"memory filling audit failed: {mae.details}")

        # Need at least some transparency data
        has_transparency = bool(
            schedule_events or sanitization_events or network_events or correctness_events
        )
        if not has_transparency and not claims:
            return []  # nothing to evaluate yet

        if not has_transparency:
            failures.append("no transparency verification results available")

        passed = len(failures) == 0
        details = "compliant" if passed else "; ".join(failures)

        self._emitted = True
        return [
            ComplianceEvaluatedEvent(
                event_id=runtime.make_event_id("compliance"),
                timestamp=runtime.now,
                writer=Side.VERIFIER,
                readers=VERIFICATION_READERS,
                passed=passed,
                details=details,
            )
        ]
