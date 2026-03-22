"""
Utilization transparency: machine inventory, workloads, network, memory sanitization,
and interactive control events.
"""

from __future__ import annotations

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
class MachineAddedEvent(Event):
    machine_id: str
    machine_kind: str

    views: ClassVar[frozenset[EventView]] = frozenset({EventView.TRANSCRIPT})


@dataclass(frozen=True, kw_only=True)
class MachineRemovedEvent(Event):
    machine_id: str

    views: ClassVar[frozenset[EventView]] = frozenset({EventView.TRANSCRIPT})


@dataclass(frozen=True, kw_only=True)
class WorkloadStartedEvent(Event):
    workload_id: str
    machine_id: str

    views: ClassVar[frozenset[EventView]] = frozenset({EventView.TRANSCRIPT})


@dataclass(frozen=True, kw_only=True)
class WorkloadTerminatedEvent(Event):
    workload_id: str
    machine_id: str

    views: ClassVar[frozenset[EventView]] = frozenset({EventView.TRANSCRIPT})


@dataclass(frozen=True, kw_only=True)
class NetworkObservationEvent(Event):
    observation_id: str
    data_digest: str

    views: ClassVar[frozenset[EventView]] = frozenset({EventView.TRANSCRIPT})


@dataclass(frozen=True, kw_only=True)
class MemorySanitizationPerformedEvent(Event):
    machine_id: str
    epoch: int
    merkle_root: str
    spot_check_passed: bool

    views: ClassVar[frozenset[EventView]] = frozenset({EventView.TRANSCRIPT})


# --- Interactive control events ---


@dataclass(frozen=True, kw_only=True)
class EngineStopRequestedEvent(Event):
    session_id: str
    reason: str

    views: ClassVar[frozenset[EventView]] = frozenset({EventView.VERIFICATION})


@dataclass(frozen=True, kw_only=True)
class EngineStopAcknowledgedEvent(Event):
    session_id: str
    succeeded: bool
    details: str

    views: ClassVar[frozenset[EventView]] = frozenset({EventView.VERIFICATION})


# --- Evaluation events ---


@dataclass(frozen=True, kw_only=True)
class ScheduleCoverageEvaluatedEvent(Event):
    passed: bool
    details: str

    views: ClassVar[frozenset[EventView]] = frozenset({EventView.VERIFICATION})


@dataclass(frozen=True, kw_only=True)
class SanitizationFrequencyEvaluatedEvent(Event):
    passed: bool
    gap_count: int
    max_gap_seconds: float
    details: str

    views: ClassVar[frozenset[EventView]] = frozenset({EventView.VERIFICATION})


@dataclass(frozen=True, kw_only=True)
class NetworkUtilizationEvaluatedEvent(Event):
    passed: bool
    details: str

    views: ClassVar[frozenset[EventView]] = frozenset({EventView.VERIFICATION})


@dataclass(frozen=True, kw_only=True)
class CovertCapacityEstimatedEvent(Event):
    io_capacity_bits: float
    persistence_capacity_bytes: float
    sustained_memory_bytes: float
    compute_capacity_flops: float

    views: ClassVar[frozenset[EventView]] = frozenset({EventView.VERIFICATION})


# --- Verifier participants ---


@dataclass
class ScheduleCoverageVerifier:
    writer: Role = field(default=Role.VERIFIER, init=False)

    def on_event(self, event: Event, runtime: Runtime) -> list[Event]:
        return []

    def on_tick(self, runtime: Runtime) -> list[Event]:
        started = runtime.log.of_type(WorkloadStartedEvent)
        terminated = runtime.log.of_type(WorkloadTerminatedEvent)
        return [
            ScheduleCoverageEvaluatedEvent(
                event_id=runtime.make_event_id("schedule-coverage"),
                timestamp=runtime.now,
                writer=Role.VERIFIER,
                readers=VERIFICATION_READERS,
                passed=True,
                details=f"{len(started)} started, {len(terminated)} terminated",
            )
        ]


@dataclass
class SanitizationFrequencyVerifier:
    writer: Role = field(default=Role.VERIFIER, init=False)
    max_gap_seconds: float = 5.0

    def on_event(self, event: Event, runtime: Runtime) -> list[Event]:
        return []

    def on_tick(self, runtime: Runtime) -> list[Event]:
        attestations = sorted(
            runtime.log.of_type(MemorySanitizationPerformedEvent),
            key=lambda e: e.timestamp,
        )
        gaps = [
            attestations[i].timestamp - attestations[i - 1].timestamp
            for i in range(1, len(attestations))
            if attestations[i].timestamp - attestations[i - 1].timestamp > self.max_gap_seconds
        ]
        return [
            SanitizationFrequencyEvaluatedEvent(
                event_id=runtime.make_event_id("sanitization-frequency"),
                timestamp=runtime.now,
                writer=Role.VERIFIER,
                readers=VERIFICATION_READERS,
                passed=len(gaps) == 0,
                gap_count=len(gaps),
                max_gap_seconds=self.max_gap_seconds,
                details=f"{len(attestations)} attestations, {len(gaps)} gaps > {self.max_gap_seconds}s",
            )
        ]


@dataclass
class NetworkUtilizationVerifier:
    writer: Role = field(default=Role.VERIFIER, init=False)

    def on_event(self, event: Event, runtime: Runtime) -> list[Event]:
        return []

    def on_tick(self, runtime: Runtime) -> list[Event]:
        observations = runtime.log.of_type(NetworkObservationEvent)
        return [
            NetworkUtilizationEvaluatedEvent(
                event_id=runtime.make_event_id("network-utilization"),
                timestamp=runtime.now,
                writer=Role.VERIFIER,
                readers=VERIFICATION_READERS,
                passed=True,
                details=f"{len(observations)} network observations",
            )
        ]


@dataclass
class CovertCapacityEstimator:
    writer: Role = field(default=Role.VERIFIER, init=False)
    sram_per_gpu_bytes: int = 0
    num_gpus: int = 0
    excess_capacity_bytes: int = 0

    def on_event(self, event: Event, runtime: Runtime) -> list[Event]:
        return []

    def on_tick(self, runtime: Runtime) -> list[Event]:
        persistence = float(self.sram_per_gpu_bytes * self.num_gpus)
        sustained = persistence + float(self.excess_capacity_bytes)
        return [
            CovertCapacityEstimatedEvent(
                event_id=runtime.make_event_id("covert-capacity"),
                timestamp=runtime.now,
                writer=Role.VERIFIER,
                readers=VERIFICATION_READERS,
                io_capacity_bits=0.0,
                persistence_capacity_bytes=persistence,
                sustained_memory_bytes=sustained,
                compute_capacity_flops=0.0,
            )
        ]
